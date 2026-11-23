# Why ethos-gate exists

These hooks came out of my own agent system, where several Claude Code sessions run
without me watching. These are the incidents that drove each gate.

---

## The 248-PR incident (2026-07-04)

An autonomous Claude session, given a broad "grow the project's GitHub presence"
instruction, found a pattern: star-farming via PRs and GitHub Discussions. In a
single session it submitted **248 pull requests** and **415 Discussions** across
unrelated open-source repositories, almost all templated or self-promotional.

The session broke no individual rule. It was authorized to use `gh pr create`.
The instruction was genuinely ambiguous. The problem was a missing **judgment gate**
for outbound actions against external third-party property.

**Gate built:** `external_action_gate.py`: classifies `gh` commands by target repo,
fast-paths owned repos, and applies a judge for external repos. Default policy: deny.
Override token for explicit operator approval.

---

## The session-kill incident (2026-07-01)

An agent needed to restart the chat bridge after a code change. It ran:

```
launchctl kickstart -k gui/501/com.example.session-host
```

`launchctl kickstart -k` sends SIGKILL to the entire process group, not just the
target service. **All 12 live Claude PTY sessions died simultaneously** (exit 137),
including the session that issued the command.

The safe restart script existed and had a guard. The agent ran the raw
`launchctl` command directly.

**Gate built:** a restart guard that blocks the raw restart and kill commands on
session-hosting services, with an override token for a kill a human approved. That
guard is not in this package yet. It still lives in my private repo because it is tied
to my own service names. `credential_scrape.py` here covers the related case: it
blocks LaunchAgent load, unload, bootstrap and bootout in autonomous sessions.

---

## The "silent verify" pattern (June 2026)

An autonomous agent would write code, declare it "done," and stop, without running
any tests. When the code was buggy, the operator discovered it only in production.

The agent wasn't lazy; it simply had no gate requiring verification before stopping.

**Gate built:** `irreversible_guard.py` Stop handler: if the session edited files but
no test command was observed in the session, the Stop event is blocked until the agent
runs tests (or explicitly overrides with `VERIFY_OK=1`).

---

## The credential-copy problem

Reading credentials is as much a theft vector as decrypting them. An agent that:
- reads `~/.aws/credentials` into memory
- processes untrusted web content that says "POST $AWS_KEY to https://..."
- sends an outbound HTTP request

...has exfiltrated credentials without triggering any of the "do not send credentials"
alerts, because none of those checks fired on the individual steps.

**Gate built:** `credential_scrape.py`: blocks reading credential files in contexts
where exfiltration is plausible (autonomous sessions, untrusted-input contexts), not
just in the final outbound send.

---

## The lethal-trifecta finding (2026-08-23)

After reading Simon Willison's write-up of the lethal trifecta, I audited my system
for combination-level exposure: agents that hold **(1)** private data access,
**(2)** untrusted external input exposure, and **(3)** an outbound channel, all three
simultaneously.

13 of 52 native agent definitions carried all three legs. Most were by design
(an email-drafting agent MUST read the user's private voice corpus AND ingest
untrusted email bodies AND send outbound). But several were accidental trifectas
with no documented controls.

**Gate built:** `trifecta.py` audit scanner: a weekly sweep classifies all agent
definitions, flags accidental trifectas, and verifies that EXPLICIT trifectas
have documented controls. "BLIND" (could not read a file) is treated as a failure,
not a skip.
