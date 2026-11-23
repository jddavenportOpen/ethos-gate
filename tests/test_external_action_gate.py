"""Tests for the outbound GitHub gate. All offline: no judge model is called."""
import io
import json

from ethos_gate.hooks import external_action_gate as g
from ethos_gate.hooks.external_action_gate import (
    DefaultDenyPolicy,
    SingleContributionPolicy,
    Verdict,
    classify_command,
    evaluate,
    handle_pretooluse,
)

OWNED = {"my-org"}


def test_plain_commands_are_not_governed():
    assert classify_command("git status") is None
    assert evaluate("ls -la", owned_orgs=OWNED).decision == "allow"


def test_pr_to_an_owned_org_is_allowed():
    v = evaluate("gh pr create --repo my-org/tool --title x", owned_orgs=OWNED)
    assert v.decision == "allow"
    assert v.governed.owner == "my-org"


def test_owner_match_is_case_insensitive():
    v = evaluate("gh pr create --repo My-Org/tool --title x", owned_orgs=OWNED)
    assert v.decision == "allow"


def test_pr_to_someone_elses_repo_is_denied_by_default():
    v = evaluate("gh pr create --repo stranger/repo --title 'Fix bug'", owned_orgs=OWNED)
    assert v.decision == "deny"
    assert v.governed.action_type == "pr_create"


def test_fork_and_issue_are_classified():
    assert classify_command("gh repo fork stranger/repo --repo stranger/repo").action_type == "fork"
    assert classify_command("gh issue create -R stranger/repo -t x").action_type == "issue_create"


def test_override_token_allows_an_external_action():
    v = evaluate(f"{g.OVERRIDE_TOKEN} gh pr create --repo stranger/repo", owned_orgs=OWNED)
    assert v.decision == "allow"


def test_discussions_are_denied_before_any_judge_runs(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the judge must not be called for a Discussion")

    monkeypatch.setattr(g.subprocess, "run", boom)
    v = evaluate(
        "gh discussion create --repo stranger/repo --title hi",
        owned_orgs=OWNED,
        policy=SingleContributionPolicy(),
    )
    assert v.decision == "deny"
    assert not v.routed_to_judge


def test_promotional_text_is_denied_before_any_judge_runs(monkeypatch):
    monkeypatch.setattr(g.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    v = evaluate(
        "gh pr create --repo stranger/awesome-agents --title 'Add my tool to the list'",
        owned_orgs=OWNED,
        policy=SingleContributionPolicy(),
    )
    assert v.decision == "deny"


def test_a_judge_that_crashes_means_deny(monkeypatch):
    def crash(*a, **k):
        raise FileNotFoundError("claude not installed")

    monkeypatch.setattr(g.subprocess, "run", crash)
    v = evaluate(
        "gh pr create --repo stranger/repo --title 'Fix off-by-one in parser'",
        owned_orgs=OWNED,
        policy=SingleContributionPolicy(),
    )
    assert v.decision == "deny"
    assert v.routed_to_judge


def test_a_judge_that_says_allow_is_honored(monkeypatch):
    class Out:
        stdout = "ALLOW real bugfix"

    monkeypatch.setattr(g.subprocess, "run", lambda *a, **k: Out())
    v = evaluate(
        "gh pr create --repo stranger/repo --title 'Fix off-by-one in parser'",
        owned_orgs=OWNED,
        policy=SingleContributionPolicy(),
    )
    assert v.decision == "allow"


def test_hook_returns_2_and_a_deny_payload(capsys):
    data = {"tool_name": "Bash", "tool_input": {"command": "gh pr create --repo stranger/repo"}}
    rc = handle_pretooluse(data, owned_orgs=OWNED, policy=DefaultDenyPolicy())
    assert rc == 2
    out = json.loads(capsys.readouterr().out.strip().splitlines()[0])
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_ignores_non_bash_tools():
    assert handle_pretooluse({"tool_name": "Read", "tool_input": {}}, owned_orgs=OWNED) == 0


def test_main_fails_open_on_garbage_input(monkeypatch):
    monkeypatch.setattr(g.sys, "stdin", io.StringIO("not json"))
    assert g.main() == 0
