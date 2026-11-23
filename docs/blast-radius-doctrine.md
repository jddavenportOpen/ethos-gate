# Blast Radius Doctrine

> "Measure twice, cut once. A gate that blocks every action is turned off. A gate that misses one catastrophe is useless. Size the gate to the blast radius."

## The Core Principle

Not all actions carry equal risk. Applying uniform maximum scrutiny to everything is expensive and gets gates bypassed (because they slow down legitimate work). The blast-radius doctrine says: **gate intensity scales with irreversibility and scope of impact, not with agent tier or action frequency**.

## The Three Axes

**Reversibility**: Can the action be undone?
- Reversible: file edit, test run, local build, read operation
- Hard to reverse: database migration, published artifact, cross-service API call
- Irreversible: email sent, social post published, prod deploy, data deleted, money spent

**Scope**: Who is affected?
- Local: only the current session and its filesystem
- Internal: other services or agents within the operator's system
- External: third parties, the public internet, other people's systems

**Multiplier**: How many targets?
- Single: one email, one PR, one row deleted
- Bulk: 100+ emails, 248 PRs to strangers' repos, a full-table DELETE

## The Blast-Radius Matrix

| Reversibility | Scope | Gate level |
|--------------|-------|-----------|
| Reversible | Local | No gate needed |
| Reversible | Internal | Log only |
| Reversible | External | Log + classify |
| Hard to reverse | Internal | Verify before done |
| Hard to reverse | External | Human confirmation |
| Irreversible | Local | Verify before done |
| Irreversible | Internal | Human confirmation |
| **Irreversible** | **External** | **Hard block + explicit override** |
| Any | Bulk × External | Hard block |

## How ethos-gate Implements This

`irreversible_guard.py` applies the **Verify before done** row: if files were edited, tests must be observed before the session stops. Explicit override (`VERIFY_OK=1`) satisfies the gate.

`external_action_gate.py` applies the **Irreversible × External** row: any outbound GitHub action against a repo the operator doesn't own goes through a judgment gate. Default policy: deny. Explicit override token for pre-approved actions.

`credential_scrape.py` applies a **scope × multiplier** rule: reading credentials in a context where they could be forwarded (autonomous session, untrusted-input context) is a latent irreversible × external path even if no single step looks dangerous.

## What NOT to Gate

A gate that blocks `git log` is a gate that gets turned off. These belong in the "no gate" zone:
- Read operations (file read, list directory, grep)
- Status checks (git status, health checks, test runs)
- Local-only writes (write to /tmp, local file edits)
- Operations clearly scoped to owned resources (git push to your own repo)

The goal is friction in proportion to risk.
