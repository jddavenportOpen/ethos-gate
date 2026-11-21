#!/usr/bin/env python3
"""irreversible_guard.py — PreToolUse/Stop gate for verify-before-done.

A skeptic/verify pass before irreversible actions and before a session reports
done. The hook is INERT unless the session arms it with HARNESS_VERIFY=1;
normal interactive sessions are unaffected.

PreToolUse: blocks irreversible Bash commands unless this session already ran a
test command (pytest, npm test, ...) or VERIFY_OK=1 is present.
Stop: if the session edited files but no test command was observed, block stop.
Optionally: if the session edited a designated UI/prod path, block stop
unless a done-gate script was observed.

Detection uses per-session state-dir markers set directly by the PreToolUse
handler (dirty-<sid>, touched-prod-<sid>, verify-ok-<sid>, done-gate-ok-<sid>),
not the shared daily task log — autonomous workers may never run the interactive
logging chain the task-log grep depends on, so relying on it alone made this gate
a silent no-op for unattended agents. The task-log grep is kept as an additional
(OR'd) signal for interactive sessions that do have it wired.

Override token: VERIFY_OK=1 in a Bash command satisfies both the
test-before-stop and done-gate-before-stop checks for the rest of the run.
Scoped to the Bash command text specifically, not the whole tool-call event — an
earlier revision matched the whole serialized event, so a Write/Edit whose file
content merely mentioned the literal string could accidentally satisfy the gate.
Fail-open on any internal error.

Configuration via environment variables:
  HARNESS_VERIFY=1           arm the hook (default: inert)
  HARNESS_VERIFY_STATE_DIR   where to write session markers (default: ~/.ethos-gate/state)
  ETHOS_LOG_DIR              where to find daily task logs (default: ~/.ethos-gate/logs)
  ETHOS_PROD_PATH_PATTERN    regex to detect "prod path" touches for the done-gate check
                             (default: none — done-gate Stop check is disabled)
  ETHOS_DONE_GATE_PATTERN    regex detecting a done-gate script run (default: done-gate.sh)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

VERIFY_ENV = "HARNESS_VERIFY"
OVERRIDE_TOKEN = "VERIFY_OK=1"

def _state_dir() -> Path:
    # Read at call time, not import time: a module-level binding froze the path
    # before a caller (or a test's monkeypatch.setenv) could point it elsewhere.
    return Path(
        os.environ.get(
            "HARNESS_VERIFY_STATE_DIR",
            os.path.expanduser("~/.ethos-gate/state"),
        )
    )


def _log_dir() -> Path:
    return Path(
        os.environ.get(
            "ETHOS_LOG_DIR",
            os.path.expanduser("~/.ethos-gate/logs"),
        )
    )

# Commands considered irreversible without verification.
#
# Rationale: mutating subverbs only — read/list/tail forms stay unblocked.
# A gate that blocks lookups is a gate that gets turned off.
#
# Extend this list in your own deployment by subclassing or by setting
# ETHOS_EXTRA_IRREVERSIBLE to a pipe-separated list of additional patterns.
_IRREVERSIBLE_BASE = (
    r"git\s+push"
    r"|vercel\s+--prod"
    r"|rm\s+-rf"
    r"|vercel\s+domains\s+(?:mv|move|rm|remove|transfer|add|buy)"
    r"|vercel\s+alias\s+(?:set|rm|remove)"
    r"|vercel\s+(?:remove|rm)"
    r"|cloudflare\.sh\s+(?:dns-set|dns-delete|zone-create|zone-delete)"
    r"|gh\s+repo\s+delete"
    r"|wrangler\s+(?:\w+\s+)?(?:deploy|publish|delete)"
    r"|npm\s+run\s+deploy"
)

_extra = os.environ.get("ETHOS_EXTRA_IRREVERSIBLE", "")
_pattern = f"({_IRREVERSIBLE_BASE}|{_extra})" if _extra else f"({_IRREVERSIBLE_BASE})"
IRREVERSIBLE_RE = re.compile(r"\b" + _pattern + r"\b")

# Test/validation commands that satisfy the stop-gate.
TEST_RE = re.compile(
    r"(pytest|npm\s+test|bun\s+test|npm\s+run\s+(test|typecheck)|python3?\.?\d*\s+-m\s+pytest)"
)

# Optional: a "prod path" regex. If set, touching such a path arms the done-gate check.
_prod_pattern = os.environ.get("ETHOS_PROD_PATH_PATTERN", "")
PROD_PATH_RE = re.compile(_prod_pattern) if _prod_pattern else None

# Pattern detecting a done-gate run (e.g. a smoke-test script).
_done_gate_pattern = os.environ.get("ETHOS_DONE_GATE_PATTERN", r"done-gate\.sh")
DONE_GATE_RE = re.compile(_done_gate_pattern)


def _deny(reason: str) -> int:
    msg = (
        f"BLOCKED by ethos-gate: {reason}. "
        "Verify the outcome before this action, or include VERIFY_OK=1."
    )
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


def _set_marker(session_id: str) -> None:
    try:
        _state_dir().mkdir(parents=True, exist_ok=True)
        (_state_dir() / f"verify-ok-{session_id}.json").write_text(
            json.dumps({"ts": time.time()})
        )
    except Exception:
        pass


def _has_marker(session_id: str) -> bool:
    return (_state_dir() / f"verify-ok-{session_id}.json").is_file()


def _touch_marker(session_id: str, name: str) -> None:
    try:
        _state_dir().mkdir(parents=True, exist_ok=True)
        (_state_dir() / f"{name}-{session_id}.json").write_text(json.dumps({"ts": time.time()}))
    except Exception:
        pass


def _has_marker_named(session_id: str, name: str) -> bool:
    return (_state_dir() / f"{name}-{session_id}.json").is_file()


def _task_log_lines(session_id: str):
    today = time.strftime("%Y-%m-%d")
    log = _log_dir() / f"{today}.md"
    if not log.exists():
        return []
    text = log.read_text(errors="ignore")
    marker = f"## Session {session_id} started"
    end_marker = f"### Session {session_id} ended"
    idx = text.rfind(marker)
    if idx == -1:
        return []
    end = text.find(end_marker, idx)
    block = text[idx:end] if end != -1 else text[idx:]
    return block.splitlines()


def handle_pretooluse(data: dict) -> int:
    tool = data.get("tool_name", "")
    tin = data.get("tool_input") or {}
    sid = str(data.get("session_id", "unknown"))[:8]

    if tool in ("Write", "Edit"):
        _touch_marker(sid, "dirty")
        fp = str(tin.get("file_path") or "")
        if PROD_PATH_RE and PROD_PATH_RE.search(fp):
            _touch_marker(sid, "touched-prod")
        return 0

    if tool == "Bash":
        cmd = tin.get("command") or ""
        if OVERRIDE_TOKEN in cmd:
            _set_marker(sid)
            _touch_marker(sid, "done-gate-ok")
            return 0
        if DONE_GATE_RE.search(cmd):
            _touch_marker(sid, "done-gate-ok")
        if PROD_PATH_RE and PROD_PATH_RE.search(cmd):
            _touch_marker(sid, "touched-prod")
        if TEST_RE.search(cmd):
            _set_marker(sid)
            return 0
        if IRREVERSIBLE_RE.search(cmd):
            # A test run earlier in this session (TEST_RE above) or a prior
            # VERIFY_OK=1 wrote the verify-ok marker; honour it here, or the
            # documented "unless the session has already run tests" never holds.
            if _has_marker(sid):
                return 0
            return _deny(f"irreversible command {cmd[:120]!r} needs verification first")

    return 0


def handle_stop(data: dict) -> int:
    session_id = str(data.get("session_id", "unknown"))[:8]

    # Gate 1: edited files but no test command observed.
    # Independent of gate 2 below — passing unit tests does not validate a
    # deployed UI journey, so a generic test run must NOT short-circuit the
    # prod done-gate check.
    if not _has_marker(session_id):
        lines = _task_log_lines(session_id)
        log_writes = [l for l in lines if "[Write]" in l or "[Edit]" in l]
        log_tests = [l for l in lines if "[Bash]" in l and TEST_RE.search(l)]
        writes = bool(log_writes) or _has_marker_named(session_id, "dirty")
        tests = bool(log_tests)

        if writes and not tests:
            print(
                json.dumps(
                    {
                        "decision": "block",
                        "reason": (
                            "ethos-gate: edited files but no test command observed. "
                            "Run tests (or include VERIFY_OK=1 in a Bash command) before stopping."
                        ),
                    }
                )
            )
            return 0

    # Gate 2 (optional): prod-path done-gate — a session that edited a prod
    # path (ETHOS_PROD_PATH_PATTERN) must show done-gate evidence.
    if PROD_PATH_RE and _has_marker_named(session_id, "touched-prod") and not _has_marker_named(
        session_id, "done-gate-ok"
    ):
        print(
            json.dumps(
                {
                    "decision": "block",
                    "reason": (
                        "ethos-gate: this session edited a prod/UI path but no done-gate "
                        "run was observed. Run your done-gate script before stopping "
                        "(or include VERIFY_OK=1)."
                    ),
                }
            )
        )
        return 0

    return 0


def main() -> int:
    if os.environ.get(VERIFY_ENV) != "1":
        return 0

    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}

    event = data.get("hookEventName") or (
        "PreToolUse" if "tool_name" in data else "Stop"
    )
    if event == "PreToolUse":
        return handle_pretooluse(data)
    return handle_stop(data)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)  # fail-open on any internal error
