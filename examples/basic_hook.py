#!/usr/bin/env python3
"""basic_hook.py — Minimal combined PreToolUse/Stop hook using ethos-gate.

This is the recommended single-file entrypoint for most deployments.
Configure via environment variables (see claude_settings_example.json).

Wire it in your claude settings:

  PreToolUse matcher=".*":  python3 examples/basic_hook.py
  Stop:                     python3 examples/basic_hook.py

The hook reads the event type from the JSON payload and routes to the
appropriate handler. Fails open on any internal error.
"""
import json
import os
import sys

# Make the package importable from the examples/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ethos_gate.hooks.irreversible_guard import handle_pretooluse, handle_stop
from ethos_gate.hooks.credential_scrape import evaluate as credential_evaluate
from ethos_gate.hooks.external_action_gate import handle_pretooluse as github_gate


def main() -> int:
    if os.environ.get("HARNESS_VERIFY") != "1":
        return 0

    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # fail-open on malformed input

    event = data.get("hookEventName") or (
        "PreToolUse" if "tool_name" in data else "Stop"
    )

    if event == "Stop":
        return handle_stop(data)

    # PreToolUse — run each gate; first deny wins
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    sid = str(data.get("session_id", ""))[:8]

    # Gate 1: credential scrape (always on)
    strict = os.environ.get("ETHOS_AUTONOMOUS", "") == "1"
    sandbox = os.environ.get("ETHOS_SANDBOX", "") == "1"
    verdict = credential_evaluate(tool_name, tool_input, strict=strict, sandbox=sandbox)
    if verdict.blocked:
        msg = f"BLOCKED by ethos-gate (credential): {verdict.reason}"
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }
        }))
        return 2

    # Gate 2: irreversible action guard (only when armed)
    code = handle_pretooluse(data)
    if code != 0:
        return code

    # Gate 3: external GitHub action gate
    code = github_gate(data)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)  # fail-open
