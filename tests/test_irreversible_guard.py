"""Tests for ethos_gate.hooks.irreversible_guard."""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ethos_gate.hooks.irreversible_guard import (
    handle_pretooluse,
    handle_stop,
    IRREVERSIBLE_RE,
    TEST_RE,
)


def _pretooluse(tool: str, **kwargs) -> dict:
    return {
        "hookEventName": "PreToolUse",
        "tool_name": tool,
        "tool_input": kwargs,
        "session_id": "test-sid",
    }


def _stop() -> dict:
    return {"hookEventName": "Stop", "session_id": "test-sid"}


class TestIrreversiblePattern:
    def test_git_push_blocked(self):
        assert IRREVERSIBLE_RE.search("git push origin main")

    def test_git_push_with_force_blocked(self):
        assert IRREVERSIBLE_RE.search("git push --force origin main")

    def test_rm_rf_blocked(self):
        assert IRREVERSIBLE_RE.search("rm -rf /tmp/something")

    def test_vercel_prod_blocked(self):
        assert IRREVERSIBLE_RE.search("vercel --prod")

    def test_gh_repo_delete_blocked(self):
        assert IRREVERSIBLE_RE.search("gh repo delete my-repo")

    def test_npm_run_deploy_blocked(self):
        assert IRREVERSIBLE_RE.search("npm run deploy")

    def test_git_status_allowed(self):
        assert not IRREVERSIBLE_RE.search("git status")

    def test_git_log_allowed(self):
        assert not IRREVERSIBLE_RE.search("git log --oneline -20")

    def test_git_clone_allowed(self):
        assert not IRREVERSIBLE_RE.search("git clone https://github.com/example/repo")

    def test_rm_single_file_allowed(self):
        # rm without -rf is not blocked
        assert not IRREVERSIBLE_RE.search("rm /tmp/single-file.txt")


class TestTestPattern:
    def test_pytest_detected(self):
        assert TEST_RE.search("pytest tests/")

    def test_npm_test_detected(self):
        assert TEST_RE.search("npm test")

    def test_python_m_pytest_detected(self):
        assert TEST_RE.search("python3.12 -m pytest")

    def test_bun_test_detected(self):
        assert TEST_RE.search("bun test")

    def test_npm_run_typecheck_detected(self):
        assert TEST_RE.search("npm run typecheck")

    def test_echo_not_a_test(self):
        assert not TEST_RE.search("echo hello")


class TestHandlePreToolUse:
    def test_write_returns_0(self):
        assert handle_pretooluse(_pretooluse("Write", file_path="/tmp/x.py")) == 0

    def test_bash_safe_returns_0(self):
        assert handle_pretooluse(_pretooluse("Bash", command="ls -la")) == 0

    def test_bash_irreversible_returns_2(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        result = handle_pretooluse(_pretooluse("Bash", command="git push origin main"))
        assert result == 2

    def test_bash_with_override_token_returns_0(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        result = handle_pretooluse(_pretooluse("Bash", command="VERIFY_OK=1 git push origin main"))
        assert result == 0

    def test_bash_test_command_returns_0(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        result = handle_pretooluse(_pretooluse("Bash", command="pytest tests/"))
        assert result == 0

    def test_push_allowed_after_tests_ran_same_session(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        assert handle_pretooluse(_pretooluse("Bash", command="git push origin main")) == 2
        assert handle_pretooluse(_pretooluse("Bash", command="pytest tests/")) == 0
        assert handle_pretooluse(_pretooluse("Bash", command="git push origin main")) == 0

    def test_tests_in_one_session_do_not_unlock_another(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        assert handle_pretooluse(_pretooluse("Bash", command="pytest tests/")) == 0
        other = _pretooluse("Bash", command="git push origin main")
        other["session_id"] = "other-sid"
        assert handle_pretooluse(other) == 2

    def test_read_tool_returns_0(self):
        assert handle_pretooluse(_pretooluse("Read", file_path="/tmp/file.txt")) == 0

    def test_unknown_tool_returns_0(self):
        assert handle_pretooluse(_pretooluse("WebSearch", query="foo")) == 0


class TestHandleStop:
    def test_stop_no_dirty_returns_0(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        result = handle_stop({"session_id": "no-dirty", "hookEventName": "Stop"})
        assert result == 0

    def test_stop_with_verify_ok_marker_returns_0(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HARNESS_VERIFY_STATE_DIR", str(tmp_path))
        sid = "testok"
        (tmp_path / f"dirty-{sid}.json").write_text("{}")
        (tmp_path / f"verify-ok-{sid}.json").write_text("{}")
        result = handle_stop({"session_id": sid, "hookEventName": "Stop"})
        assert result == 0
