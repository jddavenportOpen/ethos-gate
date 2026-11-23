# ethos-gate

In July 2026 an agent running on my account opened 248 pull requests and 415 Discussions on other people's repos to farm stars. I shut it down, cleaned up what I could, and built this gate so it can't happen again.

ethos-gate is a set of Claude Code hooks. They run before a tool call and can refuse it. A rule in a system prompt is something the model can talk itself out of. A hook runs as code, so it can't.

Most of this code was written by Claude Code agents I run. I picked what got built and set the tests it had to pass. The hooks were pulled out of my own agent setup and cleaned up for other people.

## What it blocks

| Module | What it does |
|--------|-------------|
| `hooks/irreversible_guard.py` | Blocks `git push`, `rm -rf`, prod deploys and similar commands until the session has run a test command. Blocks the session from stopping if it edited files and never ran tests. |
| `hooks/credential_scrape.py` | Blocks reads of browser password and cookie stores and password-manager vaults, always. In unattended sessions it also blocks crontab and LaunchAgent changes. In sessions that read untrusted input it also blocks `.env`, private keys and cloud credential files. |
| `hooks/external_action_gate.py` | Checks `gh` commands that reach other people's repos (PRs, issues, forks, Discussions, comments). Repos you own go through. Everything else is denied unless a human put the approval token in that exact command. |
| `audit/trifecta.py` | Scans agent definitions and flags any agent that can read private data, takes in untrusted content, and can send to the outside, all at once. |
| `charter.py` | The rules and the autonomy ladder written as data, so your own code can read them. |

What it does not do: it doesn't read the content of a message and check it against something a human approved. The GitHub gate approves a command when the token is in it. That's all.

## Run it

```bash
git clone https://github.com/jddavenportOpen/ethos-gate
cd ethos-gate
pip install -e ".[dev]"
python -m pytest -q
```

It isn't on PyPI, so install from the clone.

Try the GitHub gate on its own:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"gh pr create --repo stranger/repo --title Fix"}}' \
  | python3 -m ethos_gate.hooks.external_action_gate; echo "exit=$?"
```

```text
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "BLOCKED by ethos-gate (external-action): External action on stranger/repo denied by default policy. Use OUTWARD_ACTION_APPROVED=1 to explicitly authorize, or add the org to ETHOS_OWNED_ORGS."}}
BLOCKED by ethos-gate (external-action): External action on stranger/repo denied by default policy. Use OUTWARD_ACTION_APPROVED=1 to explicitly authorize, or add the org to ETHOS_OWNED_ORGS.
exit=2
```

To wire all of it into Claude Code, use the one combined hook, `examples/basic_hook.py`. `examples/claude_settings_example.json` shows the settings block. The short version:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": ".*",
        "hooks": [{ "type": "command", "command": "python3 /path/to/ethos-gate/examples/basic_hook.py", "timeout": 15 }] }
    ],
    "Stop": [
      { "hooks": [{ "type": "command", "command": "python3 /path/to/ethos-gate/examples/basic_hook.py", "timeout": 5 }] }
    ]
  },
  "env": {
    "HARNESS_VERIFY": "1",
    "ETHOS_OWNED_ORGS": "your-github-name"
  }
}
```

`basic_hook.py` does nothing unless `HARNESS_VERIFY=1` is set. Set `ETHOS_AUTONOMOUS=1` in unattended sessions for the stricter credential rules, and `ETHOS_SANDBOX=1` where the agent reads untrusted input.

## Why a broken gate lets things through

If a gate crashes on bad input or its own bug, it exits `0` and the command runs. I chose that on purpose. A gate that blocks everything when it breaks gets turned off, and then nothing is guarded.

A real block exits `2`, the Claude Code deny code. It never comes from an exception.

The GitHub gate is the one exception to this rule. If its judge can't give an answer (no `claude` CLI, a timeout, a crash), the action is denied. An agent shouldn't be able to post to a stranger's repo by breaking the judge.

## The credential tiers

```
UNIVERSAL  always blocked: browser credential stores, password managers, keychain dump tools
STRICT     blocked when ETHOS_AUTONOMOUS=1: crontab changes, LaunchAgent writes
SANDBOX    blocked when ETHOS_SANDBOX=1: .env, private keys, AWS credentials, API key files
```

SANDBOX is separate from STRICT because plenty of unattended jobs read `.env` on purpose. Only a session where outside input can steer the tool calls (a bug-fixing agent reading issue text, say) needs it.

## The lethal trifecta

An agent that holds all three of these at once can leak data without breaking any single rule:

1. It can read private data: secrets, personal data, credentials.
2. It takes in untrusted content: web pages, email, files from other people.
3. It can send to the outside: email, social media, other people's repos.

```bash
ethos-trifecta [paths...]          # report
ethos-trifecta --check --json .    # exit 1 if any agent holds all three
```

## The GitHub gate in code

```python
from ethos_gate.hooks.external_action_gate import evaluate

evaluate("gh pr create --repo stranger/repo --title 'Fix bug'").decision
# "deny": someone else's repo, no approval token

evaluate("OUTWARD_ACTION_APPROVED=1 gh pr create --repo stranger/repo").decision
# "allow": a human put the token in this command
```

Set your own repos with `ETHOS_OWNED_ORGS` (comma-separated GitHub names). The default policy denies every outside action. `SingleContributionPolicy` asks a Claude model whether a PR or issue looks like one real contribution, and denies Discussions and list-style "add my project" PRs before it spends a call.

## Docs

- [Why this exists](docs/why.md): the incidents behind each gate
- [Blast radius](docs/blast-radius-doctrine.md): sizing a gate to how much a change can break
- [The lethal trifecta](docs/lethal-trifecta.md)
- [Autonomy ladder](examples/autonomy_ladder.md): which actions need a human, by how reversible they are

## License

MIT
