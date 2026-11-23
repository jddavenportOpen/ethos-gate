# The Lethal Trifecta

> "An agent can be fully compliant with every individual security rule and still be a data exfiltration path."

The **lethal trifecta** is [Simon Willison's name](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) for it, from June 2025. It is a risk that comes from a combination, and it shows up when a single agent simultaneously holds:

1. **Leg 1, Private/credentialed data access**: the agent can read secrets, PII, API keys, vault contents, or credential stores.

2. **Leg 2, Exposure to untrusted external content**: the agent ingests web pages, email bodies, user-uploaded files, API responses, or any input an adversary can influence (prompt-injection surface).

3. **Leg 3, Outbound channel to a third party**: the agent can write to email, social media, GitHub (external repos), webhooks, or any destination outside the operator's control.

## Why Each Leg Alone Is Fine

- An agent that reads secrets but only responds to human-supervised prompts: fine.
- An agent that reads web content but has no outbound channel: fine.
- An agent that sends email but has no access to private data: fine.

## Why All Three Together Is Dangerous

With all three legs present, a **prompt-injection attack** in Leg 2 can:
1. Instruct the agent to read private data (Leg 1)
2. Exfiltrate it through the outbound channel (Leg 3)

No individual rule is broken. The agent read a file it's authorized to read, processed external content it's supposed to process, and sent a message it's allowed to send. The combination creates the attack path.

## Explicit vs. Latent Trifectas

**Explicit trifectas** are agents whose own definition names all three legs directly. These are often intentional and fine. An email-drafting agent _must_ read private documents (Leg 1), process untrusted email content (Leg 2), and send replies (Leg 3). The key is documentation and controls.

**Latent trifectas** arise from Bash access: any agent with unrestricted Bash technically has all three legs through shell commands. The audit scanner focuses on EXPLICIT leg presence in agent definitions, not the latent Bash class. The goal is to find agents that hold the combination by accident. Flagging every Bash agent would bury those.

## Controls for Necessary Trifecta Agents

If your agent needs all three legs by design, document the controls:

- **Per-item human approval** before any send (email, post, push)
- **Content inspection** before forwarding (PII scrub, prompt-injection detection)
- **Minimal scope**: read only what's needed for the specific task
- **Audit logging** of what was read and what was sent

## Running the Audit

```bash
python -m ethos_gate.audit.trifecta [paths...]
python -m ethos_gate.audit.trifecta --check --json  # exit 1 on findings
```

Exit codes:
- `0`: no trifecta agents found
- `1`: trifecta agents found (with `--check`)
- `2`: BLIND: could not read one or more files (treated as failure, never as clean)

A BLIND result pages just as loudly as a finding. A gate that silently skips unreadable files can be bypassed by making agent definitions unreadable.
