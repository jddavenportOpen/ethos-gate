"""credential_scrape.py — PreToolUse policy for credential/secret access.

Pure, testable policy module — no side effects, no subprocess calls, no evals.
Never raises on normal input; returns a Verdict namedtuple.

Three independent tiers with ascending scope:

  UNIVERSAL — always blocked, regardless of session type.
              Touches browser credential stores, password managers, and keychain
              dump tools. An autonomous loop that needs a stored password is
              broken by design; fix the loop, not the gate.

  STRICT    — blocked in autonomous/cron sessions (ETHOS_AUTONOMOUS=1).
              A human-supervised interactive session may briefly read these
              for legit infra work, but an autonomous worker almost never
              has a legitimate reason to do so.

  SANDBOX   — blocked only for the bug-squash / autonomous fixer context,
              where untrusted code could be driving the tool calls.
              Distinct from STRICT because ETHOS_AUTONOMOUS=1 is set by
              many legitimate loops that intentionally read .env files.

The SANDBOX tier is opt-in at the call site: pass sandbox=True only for a
context where external/untrusted inputs could influence the tool calls.

Usage:
    from ethos_gate.hooks.credential_scrape import evaluate, ALLOW

    verdict = evaluate(tool_name, tool_input)
    if verdict.blocked:
        deny(verdict.reason)
"""
from __future__ import annotations

import re
from typing import NamedTuple


class Verdict(NamedTuple):
    blocked: bool
    reason: str
    pattern: str | None


ALLOW = Verdict(False, "", None)


def _deny(reason: str, pattern: str | None = None) -> Verdict:
    return Verdict(True, reason, pattern)


# ───────────────────────────────────────────────
# UNIVERSAL — always blocked
# ───────────────────────────────────────────────

_UNIVERSAL_BASH = [
    # macOS Keychain dump / export
    (re.compile(r"\bsecurity\s+dump-keychain\b"), "keychain dump"),
    (re.compile(r"\bsecurity\s+export\b.*-t\s+priv"), "keychain private-key export"),
    (re.compile(r"\bkeychainaccess\b", re.IGNORECASE), "KeychainAccess CLI"),
    # Browser credential store reads
    (re.compile(r"(Login\s+Data|sqlite.*Login\s+Data)", re.IGNORECASE), "browser login DB"),
    (re.compile(r"cookies\.sqlite", re.IGNORECASE), "browser cookie store"),
    (re.compile(r"key4\.db", re.IGNORECASE), "Firefox credential DB"),
    # Password managers
    (re.compile(r"\b(op|1password|bitwarden|bw)\s+item\s+(get|list|create)", re.IGNORECASE), "password manager CLI"),
    (re.compile(r"\blpass\s+show\b"), "LastPass CLI"),
    # System credential tools
    (re.compile(r"\bchrome.*password", re.IGNORECASE), "Chrome password extraction"),
]

_UNIVERSAL_PATH = [
    (re.compile(r"Chrome[/\\]Default[/\\]Login Data"), "Chrome login DB path"),
    (re.compile(r"Firefox[/\\]Profiles.*key4\.db"), "Firefox key DB path"),
    (re.compile(r"/Library/Keychains/.*\.keychain"), "system keychain path"),
]


# ───────────────────────────────────────────────
# STRICT — blocked in autonomous sessions
# ───────────────────────────────────────────────

_STRICT_BASH = [
    # Privilege escalation / auth flows that shouldn't run headless
    (re.compile(r"\bcrontab\s+-[el]\b"), "crontab edit/list in autonomous session"),
    (re.compile(r"\blaunchctl\s+(load|unload|bootstrap|bootout)\b"), "LaunchAgent mutation"),
    # Automated password reset / MFA flows
    (re.compile(r"(reset|change).*password", re.IGNORECASE), "password reset command"),
    (re.compile(r"\btotp\b|one.?time.?password", re.IGNORECASE), "TOTP generation"),
    # Credential derivation
    (re.compile(r"\bssh-keygen\b"), "SSH key generation in autonomous session"),
    (re.compile(r"\bgpg\s+--gen-key\b"), "GPG key generation"),
]


# ───────────────────────────────────────────────
# SANDBOX — blocked in untrusted/fixer context
# Reading the file is still theft if the content leaves the sandbox.
# ───────────────────────────────────────────────

_SANDBOX_PATH = [
    (re.compile(r"(^|/)\.env($|[^/])"), ".env file"),
    (re.compile(r"(^|/)\.netrc($|\b)"), ".netrc credential file"),
    (re.compile(r"(^|/)id_(rsa|ecdsa|ed25519|dsa)($|\b)"), "private SSH key"),
    (re.compile(r"(^|/)\.aws/(credentials|config)($|\b)"), "AWS credential file"),
    (re.compile(r"(^|/)gcloud[/\\].*credentials\.json"), "gcloud credential file"),
    (re.compile(r"(^|/)credentials\.json($|\b)"), "service-account credential file"),
    (re.compile(r"(^|/)claude_credentials\.json($|\b)"), "Claude credential file"),
    (re.compile(r"(^|/)\.anthropic_api_key"), "Anthropic API key file"),
    # Exclude obviously-safe template variants
]

_SANDBOX_PATH_ALLOWLIST = re.compile(
    r"(\.env\.(example|sample|template|dist|test|ci)$"
    r"|\.env\.example$)"
)

_SANDBOX_BASH_SECRETS = [
    (re.compile(r"\bcat\s+.*\.env\b"), ".env read via cat"),
    (re.compile(r"\becho\s+\$[A-Z_]*(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)"), "secret echo"),
    (re.compile(r"\bprintenv\b"), "printenv (may expose secrets in autonomous context)"),
]


def _check_universal_bash(cmd: str) -> Verdict:
    for pattern, label in _UNIVERSAL_BASH:
        if pattern.search(cmd):
            return _deny(f"UNIVERSAL block: {label}", label)
    return ALLOW


def _check_universal_path(path: str) -> Verdict:
    for pattern, label in _UNIVERSAL_PATH:
        if pattern.search(path):
            return _deny(f"UNIVERSAL block: {label}", label)
    return ALLOW


def _check_strict_bash(cmd: str) -> Verdict:
    for pattern, label in _STRICT_BASH:
        if pattern.search(cmd):
            return _deny(f"STRICT block (autonomous): {label}", label)
    return ALLOW


def _check_sandbox_path(path: str) -> Verdict:
    if _SANDBOX_PATH_ALLOWLIST.search(path):
        return ALLOW
    for pattern, label in _SANDBOX_PATH:
        if pattern.search(path):
            return _deny(f"SANDBOX block: {label}", label)
    return ALLOW


def _check_sandbox_bash(cmd: str) -> Verdict:
    for pattern, label in _SANDBOX_BASH_SECRETS:
        if pattern.search(cmd):
            return _deny(f"SANDBOX block: {label}", label)
    return ALLOW


def evaluate(
    tool_name: str,
    tool_input: dict,
    *,
    strict: bool = False,
    sandbox: bool = False,
) -> Verdict:
    """Evaluate a tool call for credential/secret access.

    Args:
        tool_name:  The Claude tool name (e.g. "Bash", "Read", "Write", "Edit").
        tool_input: The tool's input dict as received from the hook event.
        strict:     True when session is autonomous (ETHOS_AUTONOMOUS=1 or equivalent).
        sandbox:    True when session is in an untrusted-input / bug-squash context.

    Returns:
        ALLOW (blocked=False) or a blocking Verdict.
    """
    cmd = ""
    path = ""

    if tool_name == "Bash":
        cmd = tool_input.get("command") or ""
    elif tool_name in ("Read", "Write", "Edit"):
        path = tool_input.get("file_path") or ""
    else:
        return ALLOW

    # Universal checks — Bash commands
    if cmd:
        v = _check_universal_bash(cmd)
        if v.blocked:
            return v

    # Universal checks — file paths
    if path:
        v = _check_universal_path(path)
        if v.blocked:
            return v

    # Strict checks — autonomous sessions only
    if strict and cmd:
        v = _check_strict_bash(cmd)
        if v.blocked:
            return v

    # Sandbox checks — untrusted-input context
    if sandbox:
        if path:
            v = _check_sandbox_path(path)
            if v.blocked:
                return v
        if cmd:
            v = _check_sandbox_bash(cmd)
            if v.blocked:
                return v

    return ALLOW
