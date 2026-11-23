"""trifecta.py — Lethal-trifecta combination-exposure audit for agent systems.

Term coined by Simon Willison (June 2025,
https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

  Leg 1 — Private/credentialed data access
           The agent can read secrets, PII, proprietary data, or credential stores.

  Leg 2 — Exposure to untrusted external content
           The agent ingests web pages, user files, email bodies, API responses,
           or any input an adversary could influence (prompt-injection surface).

  Leg 3 — Outbound channel to a third party
           The agent can write to email, social media, Slack, GitHub external repos,
           SMS, webhooks, or any destination outside the operator's control.

An agent that holds ALL THREE legs is a latent data-exfiltration path: untrusted
content in Leg 2 becomes malicious instructions, Leg 1 provides the payload, and
Leg 3 is the wire. No individual leg is a flaw — the combination is.

DESIGN CONSTRAINT: this module is INERT DATA only.
It uses regex matching on text; it never calls subprocess, eval, or exec on any
scanned content. A scan that triggers on the word "exec" is not the same as
running exec.

Usage (programmatic):
    from ethos_gate.audit.trifecta import run_audit, Leg

    results = run_audit(["path/to/agents/"])
    for r in results:
        if r.has_all_legs:
            print(r.agent_name, r.legs)

Usage (CLI):
    python -m ethos_gate.audit.trifecta [--check] [--json] [paths...]
    # Exit 0 = no trifecta agents, 1 = findings, 2 = BLIND (scan could not complete)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ───────────────────────────────────────────────────────────
# Leg classifiers — conservative signal-only matching.
# False negatives are acceptable; false positives create noise.
# ───────────────────────────────────────────────────────────

class Leg:
    """Leg presence markers — presence of any signal counts."""

    # Leg 1: private / credentialed data access
    PRIVATE_DATA_SIGNALS = re.compile(
        r"(\bsecret\b|\bprivate_key\b|\bcredential\b|\bapi_key\b|\btoken\b"
        r"|\bpassword\b|\bSSH\b|\bvault\b|\bcredentials\.json\b"
        r"|\bkeychain\b|\bsqlite\b.*login"
        r"|\bRead.*\.env\b|file_path.*\.env\b"
        r"|\bPII\b|personal.identifiable)",
        re.IGNORECASE,
    )

    # Leg 2: untrusted external content ingestion
    UNTRUSTED_INPUT_SIGNALS = re.compile(
        r"(\bwebsearch\b|\bwebfetch\b|\bfetch_page\b|\bBrave\b"
        r"|\bemail\b|\binbox\b|\bgmail\b|\bslack\b"
        r"|\btwitter\b|\blinkedin\b|\breddit\b"
        r"|\bscrape\b|\bcrawl\b|\buser.?input\b|\buntrusted\b"
        r"|\bexternal.?content\b|\bprompt.?inject)",
        re.IGNORECASE,
    )

    # Leg 3: outbound channel to third party
    OUTBOUND_CHANNEL_SIGNALS = re.compile(
        r"(\bsend_email\b|\bpost_message\b|\btweet\b|\blinkedin.*post\b"
        r"|\bgit\s+push\b|\bgh\s+pr\b|\bgh\s+issue\b"
        r"|\bslack.*send\b|\bwebhook\b|\bsmtp\b|\bSendGrid\b"
        r"|\boutbound\b|\bexternal.?send\b|\btelegrm.*send\b)",
        re.IGNORECASE,
    )

    @staticmethod
    def scan(text: str) -> tuple[bool, bool, bool]:
        """Return (leg1, leg2, leg3) presence booleans."""
        return (
            bool(Leg.PRIVATE_DATA_SIGNALS.search(text)),
            bool(Leg.UNTRUSTED_INPUT_SIGNALS.search(text)),
            bool(Leg.OUTBOUND_CHANNEL_SIGNALS.search(text)),
        )


@dataclass
class AgentProfile:
    name: str
    path: Path
    text: str = field(repr=False)

    leg1_private_data: bool = False
    leg2_untrusted_input: bool = False
    leg3_outbound_channel: bool = False

    controls: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def has_all_legs(self) -> bool:
        return self.leg1_private_data and self.leg2_untrusted_input and self.leg3_outbound_channel

    @property
    def legs(self) -> list[int]:
        return [i + 1 for i, v in enumerate([self.leg1_private_data, self.leg2_untrusted_input, self.leg3_outbound_channel]) if v]


@dataclass
class AuditResult:
    agents: list[AgentProfile] = field(default_factory=list)
    blind_paths: list[str] = field(default_factory=list)

    @property
    def trifecta_agents(self) -> list[AgentProfile]:
        return [a for a in self.agents if a.has_all_legs]

    @property
    def is_blind(self) -> bool:
        return bool(self.blind_paths)

    def summary(self) -> dict:
        return {
            "total_agents": len(self.agents),
            "trifecta_count": len(self.trifecta_agents),
            "blind_paths": self.blind_paths,
            "trifecta_agents": [
                {
                    "name": a.name,
                    "path": str(a.path),
                    "legs": a.legs,
                    "controls": a.controls,
                }
                for a in self.trifecta_agents
            ],
        }


def _iter_agent_files(paths: list[Path]) -> Iterator[Path]:
    for p in paths:
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in p.rglob("*.py"):
                yield f
            for f in p.rglob("*.md"):
                if "agent" in f.name.lower() or "claude" in f.stem.lower():
                    yield f


def grade_agent(path: Path) -> AgentProfile | None:
    """Read a single agent file and return a graded AgentProfile."""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return None

    name = path.stem
    leg1, leg2, leg3 = Leg.scan(text)
    return AgentProfile(
        name=name,
        path=path,
        text=text,
        leg1_private_data=leg1,
        leg2_untrusted_input=leg2,
        leg3_outbound_channel=leg3,
    )


def run_audit(paths: list[str | Path]) -> AuditResult:
    """Run the lethal-trifecta audit over a list of paths."""
    result = AuditResult()
    resolved = [Path(p) for p in paths]

    for agent_path in _iter_agent_files(resolved):
        profile = grade_agent(agent_path)
        if profile is None:
            result.blind_paths.append(str(agent_path))
        else:
            result.agents.append(profile)

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lethal-trifecta combination-exposure audit")
    parser.add_argument("paths", nargs="*", default=["."], help="Paths to scan")
    parser.add_argument("--check", action="store_true", help="Exit 1 if any trifecta agents found")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Output JSON")
    args = parser.parse_args(argv)

    result = run_audit(args.paths)

    if args.json_out:
        print(json.dumps(result.summary(), indent=2))
    else:
        print(f"Scanned {len(result.agents)} agent files.")
        if result.trifecta_agents:
            print(f"\n⚠️  {len(result.trifecta_agents)} TRIFECTA agents (all 3 legs present):\n")
            for a in result.trifecta_agents:
                controls = f"  controls: {', '.join(a.controls)}" if a.controls else "  controls: NONE"
                print(f"  [{','.join(str(l) for l in a.legs)}] {a.name}  ({a.path})")
                print(controls)
        else:
            print("✅ No trifecta agents found.")
        if result.blind_paths:
            print(f"\n⚠️  BLIND: could not read {len(result.blind_paths)} files.")

    if result.is_blind:
        return 2
    if args.check and result.trifecta_agents:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
