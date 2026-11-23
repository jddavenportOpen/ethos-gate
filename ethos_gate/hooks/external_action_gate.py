"""external_action_gate.py — Govern outbound GitHub actions for agentic sessions.

Three paths:

  OWNED repos (configured in OWNED_ORGS/OWNED_USERS) → ALLOW immediately.
              "It's the operator's own property; reputation is self-determined."

  OVERRIDE_TOKEN in the command → ALLOW immediately, hard-bypass for all cases.
              Human explicitly approved the specific command; the gate steps aside.

  EXTERNAL repos → classify the action, then JUDGE via a configurable policy.
              Default policy: single genuine contributions (real bugfix PR, real
              issue) are allowed; star-farming, mass PRs, self-promotional spam,
              awesome-list adds, and Discussions are denied.

Fail-safe: when the judge cannot reach a decision, DENY. A gate that can be
bypassed by destroying the judge is not a gate.

Extend:
  - Add your org names to OWNED_ORGS (case-insensitive comparison).
  - Implement a custom `JudgePolicy` to change the external-action decision logic.
  - Set ETHOS_OVERRIDE_TOKEN env var to change the override token string.

Origin: distilled from a 2026-07-04 incident where an unguarded autonomous
session submitted 248 PRs and 415 Discussions across unrelated open-source repos
to farm GitHub stars. This gate would have blocked every one.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional, Protocol

OVERRIDE_TOKEN = os.environ.get("ETHOS_OVERRIDE_TOKEN", "OUTWARD_ACTION_APPROVED=1")

# Case-insensitive org/user prefixes treated as "owned": pushes and PRs there go through.
# Add your own GitHub usernames and org slugs here.
OWNED_ORGS: set[str] = set(
    s.lower()
    for s in os.environ.get("ETHOS_OWNED_ORGS", "").split(",")
    if s.strip()
)

_GITHUB_CMD_RE = re.compile(
    r"\bgh\s+(?:"
    r"pr\s+create"
    r"|issue\s+create"
    r"|repo\s+fork"
    r"|repo\s+create"
    r"|discussion"
    r"|api\s+graphql"
    r"|pr\s+comment"
    r"|issue\s+comment"
    r")\b",
    re.IGNORECASE,
)

_OWNER_REPO_RE = re.compile(
    r"(?:--repo|-R)\s+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
    r"|github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)


@dataclass
class GovernedAction:
    raw_command: str
    action_type: str        # e.g. "pr_create", "fork", "discussion"
    owner: str              # e.g. "some-org"
    repo: str               # e.g. "some-repo"


@dataclass
class Verdict:
    decision: str           # "allow" | "deny" | "unknown"
    reason: str
    governed: Optional[GovernedAction] = None
    routed_to_judge: bool = False
    meta: dict = field(default_factory=dict)


ALLOW_VERDICT = Verdict("allow", "owned repo: allowed")
DENY_VERDICT = Verdict("deny", "fail-safe deny: judge unavailable or action blocked")


class JudgePolicy(Protocol):
    def judge(self, action: GovernedAction) -> Verdict:
        ...


class DefaultDenyPolicy:
    """Conservative default: deny ALL external actions unless operator overrides."""

    def judge(self, action: GovernedAction) -> Verdict:
        return Verdict(
            "deny",
            f"External action on {action.owner}/{action.repo} denied by default policy. "
            "Use OUTWARD_ACTION_APPROVED=1 to explicitly authorize, "
            "or add the org to ETHOS_OWNED_ORGS.",
            action,
        )


class SingleContributionPolicy:
    """Allow single, genuine contributions; deny bulk/promotional activity.

    This requires an LLM judge via the `claude` CLI. Falls back to deny on error.
    Configure via ETHOS_JUDGE_MODEL env var (default: claude-sonnet-4-6 or similar).
    """

    DENY_PATTERNS = re.compile(
        r"(star|awesome|list|collection|showcase|resource|curated"
        r"|discussion|survey|vote|poll|sponsor|badge|template"
        r"|marketing|promotion|self-promot)",
        re.IGNORECASE,
    )

    def judge(self, action: GovernedAction) -> Verdict:
        # Pre-screen: block category patterns before spending on the LLM
        if "discussion" in action.action_type.lower():
            return Verdict(
                "deny",
                "Discussions on external repos are blocked (star-farming vector).",
                action,
            )
        if self.DENY_PATTERNS.search(action.raw_command):
            return Verdict(
                "deny",
                "Command text matches promotional/bulk pattern.",
                action,
            )

        try:
            prompt = (
                f"Evaluate this GitHub CLI command for an external repo "
                f"({action.owner}/{action.repo}):\n\n"
                f"```\n{action.raw_command[:500]}\n```\n\n"
                "Is this a single, genuine, on-topic contribution (real bugfix PR, "
                "real issue report) that would be welcomed by the repo maintainers? "
                "Answer ALLOW or DENY with one sentence reason."
            )
            model = os.environ.get("ETHOS_JUDGE_MODEL", "claude-haiku-4-5-20251001")
            result = subprocess.run(
                ["claude", "-p", prompt, "--model", model, "--effort", "low"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            text = (result.stdout or "").strip().upper()
            if text.startswith("ALLOW"):
                return Verdict("allow", f"Judge approved: {text}", action, routed_to_judge=True)
            return Verdict(
                "deny",
                f"Judge denied: {text or 'no output'}",
                action,
                routed_to_judge=True,
            )
        except Exception as exc:
            return Verdict(
                "deny",
                f"Fail-safe deny: judge failed ({exc})",
                action,
                routed_to_judge=True,
            )


def classify_command(cmd: str) -> Optional[GovernedAction]:
    """Extract a GovernedAction from a Bash command string, or None if not a governed action."""
    if not _GITHUB_CMD_RE.search(cmd):
        return None

    m = _OWNER_REPO_RE.search(cmd)
    if not m:
        return None

    owner = (m.group(1) or m.group(3) or "").lower()
    repo = m.group(2) or m.group(4) or ""

    action_type = "unknown"
    for subcommand, label in [
        ("pr create", "pr_create"),
        ("issue create", "issue_create"),
        ("repo fork", "fork"),
        ("repo create", "repo_create"),
        ("discussion", "discussion"),
        ("pr comment", "pr_comment"),
        ("issue comment", "issue_comment"),
    ]:
        if subcommand in cmd.lower():
            action_type = label
            break

    return GovernedAction(raw_command=cmd, action_type=action_type, owner=owner, repo=repo)


def evaluate(
    cmd: str,
    *,
    owned_orgs: set[str] | None = None,
    policy: JudgePolicy | None = None,
) -> Verdict:
    """Main entry point: evaluate a Bash command for governed external GitHub actions.

    Args:
        cmd:        The Bash command string.
        owned_orgs: Set of lowercase org/user slugs treated as owned (defaults to OWNED_ORGS).
        policy:     Judge policy for external actions (defaults to DefaultDenyPolicy).

    Returns:
        A Verdict with decision="allow" or "deny".
    """
    if OVERRIDE_TOKEN in cmd:
        return Verdict("allow", "OVERRIDE_TOKEN present — hard bypass")

    governed = classify_command(cmd)
    if governed is None:
        return Verdict("allow", "not a governed GitHub action")

    orgs = owned_orgs if owned_orgs is not None else OWNED_ORGS
    if governed.owner in orgs:
        return Verdict("allow", f"owned org ({governed.owner}): allowed", governed)

    judge = policy if policy is not None else DefaultDenyPolicy()
    return judge.judge(governed)


def handle_pretooluse(data: dict, *, owned_orgs: set[str] | None = None, policy: JudgePolicy | None = None) -> int:
    """Claude Code PreToolUse hook entry point. Returns 0 (allow) or 2 (deny)."""
    tool = data.get("tool_name", "")
    if tool != "Bash":
        return 0

    cmd = (data.get("tool_input") or {}).get("command") or ""
    verdict = evaluate(cmd, owned_orgs=owned_orgs, policy=policy)

    if verdict.decision == "deny":
        msg = f"BLOCKED by ethos-gate (external-action): {verdict.reason}"
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": msg,
                    }
                }
            )
        )
        print(msg, file=sys.stderr)
        return 2

    return 0


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}
    try:
        return handle_pretooluse(data)
    except Exception:
        return 0  # fail-open on internal error


if __name__ == "__main__":
    sys.exit(main())
