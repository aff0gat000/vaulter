# Vaulter

Search and audit HashiCorp Vault KV secrets for non-secret data, misconfigurations, and sensitive patterns.

## Install

```bash
go install github.com/yb/vaulter@latest
```

Or build from source:

```bash
make build
```

Or use Docker:

```bash
docker build -t vaulter .
docker run --rm -e VAULT_ADDR -e VAULT_TOKEN vaulter search --key "password"
```

## Quick Start

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=s.xxxxx

# Search for keys matching a pattern
vaulter search --key "password|token|secret"

# Search for values matching a pattern
vaulter search --value "prod\.example\.com"

# Audit secrets for non-secret data
vaulter audit
```

## Commands

### `search`

Search secrets by key or value regex pattern.

```bash
vaulter search --key "DB_" --mount secret --prefix apps/
vaulter search --value "changeme" --show-values
```

### `audit`

Scan secrets against built-in rules to find data that probably shouldn't be in Vault.

```bash
vaulter audit --mount secret --prefix legacy/
vaulter audit --json
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mount, -m` | `secret` | KV engine mount path |
| `--kv-version` | `2` | KV engine version (1 or 2) |
| `--prefix, -p` | `""` | Path prefix to search under |
| `--format` | `table` | Output format: `table`, `json`, `markdown`, `html` |
| `--json` | `false` | Shorthand for `--format json` |
| `--insecure` | `false` | Skip TLS verification |
| `--timeout` | `30s` | Vault request timeout |
| `--show-values` | `false` | Show secret values (masked by default) |
| `--key, -k` | | Regex pattern for keys (search only) |
| `--value, -v` | | Regex pattern for values (search only) |

## Security

Vaulter is a **read-only auditing tool**. It authenticates with a Vault token
you already hold and only reads secrets that token is permitted to read — it
performs no credential guessing and cannot access anything beyond your existing
authorization. See [SECURITY.md](SECURITY.md) for the threat model and
responsible-use guidance.

**Credential handling**
- The token is read from the **`VAULT_TOKEN` environment variable only** — never
  a CLI flag — so it never appears in the process list or shell history.
- In the GitHub Action, always pass the token from a secret
  (`${{ secrets.VAULT_TOKEN }}`); it is set as an env var and never logged.

**Data handling**
- **Values are masked by default** (`********`); `--show-values` is an explicit
  opt-in and prints a warning, since cleartext values then appear in output and
  any report files you write.
- Vaulter does **not** persist secrets — nothing is written to disk; output goes
  to stdout for you to handle. Every read is recorded by Vault's own audit
  device.
- `--key` / `--value` are **regular expressions**, not secrets — don't paste
  sensitive values into them (they are visible in the process list).

**Transport & input**
- **TLS verification is enforced.** Use `--insecure` only for development.
- Path traversal in `--mount` and `--prefix` is rejected.
- Patterns are capped at 1024 characters; Go's RE2 regex engine runs in linear
  time, so patterns cannot cause ReDoS.
- A request timeout prevents hanging on unreachable Vault instances.

## Audit Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `config-like-key` | warning | Keys like host, port, region, timeout — including compound keys (`db_host`, `api_url`) |
| `feature-flag-key` | warning | Keys like `enable_*`, `feature_*`, `*_enabled` |
| `boolean-value` | warning | Values that are true/false/yes/no |
| `numeric-only-value` | warning | Purely numeric values |
| `ip-address-value` | warning | IPv4 addresses (optionally with a port) |
| `url-value` | warning | http(s)/ftp URLs stored as values |
| `file-path-value` | warning | Filesystem paths (`/etc/...`, `./...`, `C:\...`) |
| `email-value` | warning | Email addresses |
| `empty-value` | error | Empty or whitespace-only values |
| `placeholder-value` | error | Values containing changeme, TODO, etc. |
| `large-value` | warning | Values over 10KB |
| `json-blob` | warning | JSON objects or arrays stored as values |
| `base64-config` | warning | Keys suggesting base64-encoded config |

## Examples

```bash
# Search with JSON output
vaulter search --key "api_key" --json | jq '.matches[]'

# Audit a specific path
vaulter audit --prefix services/legacy/ --json

# KV v1 engine
vaulter search --key "pass" --kv-version 1 --mount kv

# Show actual values
vaulter search --key "password" --show-values

# Generate a shareable report (values stay masked unless --show-values)
vaulter audit --format html > vault-audit.html
vaulter audit --format markdown > vault-audit.md
```

## Reports

`--format markdown` and `--format html` render a self-contained report with a
severity summary and a findings/matches table — handy as a CI artifact or for
review by people who don't use the CLI. Findings are sorted with errors first,
and values remain masked unless `--show-values` is passed. The HTML report
escapes all values, so it is safe to open in a browser.

## Library Usage

Vaulter can be embedded in Go programs via the `pkg/vaulter` package:

```go
import (
	"context"
	"fmt"

	"github.com/yb/vaulter/pkg/vaulter"
)

func main() {
	// Address/Token default to VAULT_ADDR / VAULT_TOKEN when left empty.
	c, err := vaulter.New(vaulter.Config{Mount: "secret"})
	if err != nil {
		panic(err)
	}

	// Audit a path against the built-in rules (values masked by default).
	findings, scanned, err := c.Audit(context.Background(), "apps/", vaulter.AuditOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("scanned %d secrets, %d findings\n", scanned, len(findings))

	// Search keys/values by regex.
	matches, _, err := c.Search(context.Background(), "apps/", vaulter.SearchOptions{
		KeyPattern: "password|token",
		ShowValues: false,
	})
	_ = matches
	_ = err
}
```

`Audit` accepts custom rules and a show-values toggle via `AuditOptions`:
`c.Audit(ctx, prefix, vaulter.AuditOptions{Rules: myRules, ShowValues: false})`.
Leave `Rules` nil to use `vaulter.DefaultRules()`.

Results can be rendered to HTML or Markdown via `pkg/vaulter/report`:

```go
import "github.com/yb/vaulter/pkg/vaulter/report"

findings, scanned, _ := c.Audit(context.Background(), "apps/")
report.HTML(os.Stdout, report.Data{
	Command:  "audit",
	Mount:    "secret",
	Prefix:   "apps/",
	Scanned:  scanned,
	Findings: findings,
	Generated: time.Now(),
})
```

## GitHub Action

Vaulter ships a reusable Docker action for running search/audit in CI/CD. The
`audit` command can gate a pipeline: it fails the job when findings reach a
severity threshold.

```yaml
- name: Audit Vault for non-secret data
  uses: your-org/vaulter@v1
  with:
    command: audit
    vault-addr: ${{ secrets.VAULT_ADDR }}
    vault-token: ${{ secrets.VAULT_TOKEN }}
    mount: secret
    prefix: apps/
    fail-on-severity: error   # none | warning | error
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `command` | `audit` | `audit` or `search` |
| `vault-addr` | | Vault address (sets `VAULT_ADDR`) |
| `vault-token` | | Vault token (sets `VAULT_TOKEN`); use a secret |
| `mount` | `secret` | KV engine mount path |
| `kv-version` | `2` | KV engine version (1 or 2) |
| `prefix` | | Path prefix to scan under |
| `key` | | Regex for keys (search only) |
| `value` | | Regex for values (search only) |
| `json` | `false` | Emit JSON output |
| `show-values` | `false` | Reveal values (avoid in CI logs) |
| `insecure` | `false` | Skip TLS verification |
| `timeout` | `30s` | Vault request timeout |
| `fail-on-severity` | `error` | For audit, fail the job at this severity (`none`/`warning`/`error`) |

A ready-to-copy workflow lives at
[`.github/workflows/vault-audit-example.yml`](.github/workflows/vault-audit-example.yml).

## Contributing

```bash
make test            # Run unit tests
make cover           # Generate coverage report
make integration     # Run end-to-end tests against Vault in Docker (one shot)
make integration-up  # Start a local seeded Vault and leave it running
make integration-down # Tear down the local Vault
make lint       # Run go vet + staticcheck
make sast       # Run gosec + govulncheck
make docker     # Build Docker image
make docker-scan # Scan Docker image with trivy
```

For local testing against a real Vault, start a seeded dev Vault in one line
(Mac and Linux):

```bash
./start-local.sh          # start + seed; ./start-local.sh down to stop
```

Automated and manual flows are documented in
[`test/integration/README.md`](test/integration/README.md).
