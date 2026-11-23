# Autonomy Ladder

The autonomy ladder maps `(reversibility, agent_tier)` to required human oversight.
Use it when deciding whether an autonomous agent should pause and ask.

## The Three-Tier Reversibility Axis

| Tier | Definition | Examples |
|------|-----------|---------|
| **Reversible** | Can be undone with no lasting effect | Edit a file, run a test, build locally, read a secret (not send it) |
| **Hard to reverse** | Costly or difficult to undo, but recoverable | Schema migration, cross-service API call, merging a PR |
| **Irreversible** | Cannot be undone once taken | Send email, post to social media, deploy to prod, delete data, spend money |

## The Agent Tier Axis

| Tier | Description | Model class |
|------|------------|------------|
| T0 | Human / operator | none |
| T1 | CEO / orchestrator | Opus |
| T2 | Domain orchestrators | Sonnet |
| T3 | Specialists | Sonnet / Haiku |
| T4 | Workers | Haiku |

## The Ladder

```
Reversibility      Agent tier    Required oversight
──────────────     ──────────    ──────────────────
Reversible         T4 (any)      AUTO: proceed
Hard-to-reverse    T2+           VERIFY: confirm with orchestrator
Irreversible       T1+           GATE: explicit human approval
(anything)         T4 for irrev  DENY: always escalate
```

## Quick-reference Rules

1. **File edits, test runs, local builds** → AUTO at every tier.
2. **Schema migrations, cross-service mutations** → T2 must verify with orchestrator before reporting done.
3. **Email, social, prod deploy, money, deletes** → ANY tier must pause and get a human yes on the specific action.
4. **An autonomous background worker should never take a Tier-3 action on its own**: wire the gate and surface it for approval.

## Why This Matters

An agent that autonomously sends emails, posts to LinkedIn, or deploys to production on behalf of an operator has a blast radius proportional to its network reach. The autonomy ladder keeps blast radius bounded by requiring human review at the tier where irreversibility kicks in.

See `ethos_gate/charter.py` for the dataclass representation of this ladder.
