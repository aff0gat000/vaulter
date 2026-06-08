# Using Vaulter

Vaulter has two commands — `search` and `audit` — that walk a HashiCorp Vault KV
engine and report on its contents. It is **read-only**: it reads only what your
token already permits and never writes secrets to disk.

## Authentication

Vaulter uses the standard Vault environment variables:

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=s.xxxxx        # read from the environment ONLY, never a flag
```

The token is **never** accepted as a CLI flag, so it does not appear in the
process list (`ps`) or shell history. Use a token scoped to least privilege
(read/list on the target mount/prefix) with a short TTL.

## `search`

Find keys or values matching a regular expression (Go RE2 syntax).

```bash
vaulter search --key "password|token|secret"
vaulter search --value "prod\.example\.com" --prefix apps/
vaulter search --key "DB_" --mount secret --show-values
```

At least one of `--key` / `--value` is required. Patterns are capped at 1024
characters; RE2 runs in linear time, so patterns cannot cause ReDoS.

## `audit`

Scan secrets against built-in rules that flag non-secret / config-like data.

```bash
vaulter audit --prefix legacy/
vaulter audit --json
vaulter audit --format html > vault-audit.html
vaulter audit --fail-on-severity error      # gate CI
```

See the [README](../README.md#audit-rules) for the full rule list.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mount, -m` | `secret` | KV engine mount path |
| `--kv-version` | `2` | KV engine version (1 or 2) |
| `--prefix, -p` | `""` | Path prefix to scan under |
| `--format` | `table` | `table`, `json`, `markdown`, `html` |
| `--json` | `false` | Shorthand for `--format json` |
| `--insecure` | `false` | Skip TLS verification (development only) |
| `--timeout` | `30s` | Vault request timeout |
| `--show-values` | `false` | Reveal values (masked by default) |
| `--key, -k` | | Regex for keys (`search` only) |
| `--value, -v` | | Regex for values (`search` only) |
| `--fail-on-severity` | `none` | Exit 2 when findings reach `none`/`warning`/`error` (`audit` only) |

## Output formats

- **table** (default) — human-readable; results to stdout, a summary to stderr.
- **json** — `{ "secrets_scanned", "matches", "findings" }`. All record fields
  use lowercase keys (`path`, `key`, `value`, `rule`, `severity`), so the output
  is stable for `jq`.
- **markdown** / **html** — a self-contained report with a severity summary and
  a findings/matches table, suitable as a CI artifact. The HTML report escapes
  all values and is safe to open in a browser.

Values are masked (`********`) unless `--show-values` is passed, in which case a
warning is printed because cleartext then appears in output and any report files.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (no gate, or gate not reached) |
| `1` | Operational error — bad config, Vault/connection failure, invalid flag |
| `2` | Audit gate tripped — findings reached `--fail-on-severity` |

For `audit`, vaulter always prints a machine-readable summary to stderr:

```
vaulter audit summary: scanned=42 errors=1 warnings=7
```

## Partial-access tokens

Paths the token cannot list or read (HTTP 403) are **skipped** instead of
failing the whole walk, so a least-privilege token still audits everything it can
reach. The number of skipped paths is reported on stderr; in the library it is
available via `Client.SkippedPaths()`.

## CI integration (GitHub Action)

```yaml
- name: Audit Vault for non-secret data
  uses: aff0gat000/vaulter@v1
  with:
    command: audit
    vault-addr: ${{ secrets.VAULT_ADDR }}
    vault-token: ${{ secrets.VAULT_TOKEN }}
    mount: secret
    prefix: apps/
    fail-on-severity: error   # none | warning | error
```

The action delegates gating to the CLI's `--fail-on-severity` and renders a job
summary. A ready-to-copy workflow lives at
[`.github/workflows/vault-audit-example.yml`](../.github/workflows/vault-audit-example.yml).

## Library usage

```go
import (
	"context"
	"fmt"

	"github.com/aff0gat000/vaulter/pkg/vaulter"
)

func main() {
	// Address/Token default to VAULT_ADDR / VAULT_TOKEN when left empty.
	c, err := vaulter.New(vaulter.Config{Mount: "secret"})
	if err != nil {
		panic(err)
	}

	findings, scanned, err := c.Audit(context.Background(), "apps/", vaulter.AuditOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("scanned %d secrets, %d findings\n", scanned, len(findings))

	if skipped := c.SkippedPaths(); len(skipped) > 0 {
		fmt.Printf("skipped %d paths (insufficient permission)\n", len(skipped))
	}
}
```

`Audit` accepts custom rules and a show-values toggle via `AuditOptions`; leave
`Rules` nil to use `vaulter.DefaultRules()`. Results can be rendered to HTML or
Markdown via `pkg/vaulter/report`.
