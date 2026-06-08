# Security Policy

## What vaulter is (and isn't)

Vaulter is a **defensive, read-only auditing tool** for operators and developers
to inspect the hygiene of a HashiCorp Vault KV engine **they are already
authorized to access**.

- It authenticates with a **valid Vault token you supply** and reads only the
  secrets that token's policies permit. It cannot read anything you couldn't
  already read with `vault kv get`.
- It performs **no credential guessing, no brute forcing, and no authentication
  attempts** against Vault or anything else. Remove the token and it does
  nothing.
- Every secret it reads is **logged by Vault's own audit device**, exactly like
  any other authorized read.

It is **not** an exploitation, harvesting, or privilege-escalation tool, and
must not be used to access data you are not authorized to access.

## Threat model

| Concern | Posture |
|---------|---------|
| Token exposure | Read from the `VAULT_TOKEN` env var only — never a CLI flag, so not visible in `ps`/argv or shell history. Never logged by the CLI or the GitHub Action. |
| Secret values in output | Masked by default. `--show-values` is an explicit opt-in and emits a warning. |
| Secrets at rest | Vaulter never writes secrets to disk. Output goes to stdout for the caller to handle. |
| Search/value patterns | `--key`/`--value` are RE2 regexes (linear time, no ReDoS); capped at 1024 chars. They are not secrets and should not contain any. |
| Transport | TLS verification is on by default; `--insecure` is opt-in and intended only for local development. |
| Path handling | `--mount`/`--prefix` reject path traversal and absolute paths. |
| Privilege | Use a token scoped to the least privilege needed (read/list on the target mount/prefix) and a short TTL. Vaulter introspects nothing beyond what the token can already reach. |

## Responsible use

Only run vaulter against Vault instances and paths you own or are explicitly
authorized to audit. Treat any output produced with `--show-values` (including
generated HTML/Markdown reports) as sensitive material.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Use GitHub's private vulnerability reporting: the repository's **Security**
  tab → **"Report a vulnerability"**. This opens a private advisory visible only
  to the maintainers.

Please include reproduction steps and the affected version. We aim to
acknowledge reports within a few business days.
