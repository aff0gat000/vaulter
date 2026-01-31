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
| `--json` | `false` | Output as JSON |
| `--insecure` | `false` | Skip TLS verification |
| `--timeout` | `30s` | Vault request timeout |
| `--show-values` | `false` | Show secret values (masked by default) |
| `--key, -k` | | Regex pattern for keys (search only) |
| `--value, -v` | | Regex pattern for values (search only) |

## Security

- **Values are masked by default.** Use `--show-values` to display them.
- **TLS verification is enforced.** Use `--insecure` only for development.
- Path traversal in `--mount` and `--prefix` is rejected.
- Regex patterns are limited to 1024 characters to prevent ReDoS.
- Request timeout prevents hanging on unreachable Vault instances.

## Audit Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `config-like-key` | warning | Keys like host, port, region, timeout |
| `boolean-value` | warning | Values that are true/false/yes/no |
| `numeric-only-value` | warning | Purely numeric values |
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
```

## Contributing

```bash
make test       # Run tests
make cover      # Generate coverage report
make lint       # Run go vet + staticcheck
make sast       # Run gosec + govulncheck
make docker     # Build Docker image
make docker-scan # Scan Docker image with trivy
```
