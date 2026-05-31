# Contributing to Vaulter

Thanks for your interest in improving Vaulter! Contributions of all kinds are
welcome — bug reports, fixes, new audit rules, docs, and tests.

## Getting started

You need **Go** (the version in [`go.mod`](go.mod)) and, for the end-to-end
tests, a working **Docker** with Compose.

```bash
git clone https://github.com/aff0gat000/vaulter
cd vaulter
make build        # build the ./vaulter binary
make test         # unit tests with -race
make integration  # end-to-end against a real Vault in Docker (see test/integration/README.md)
```

## Development workflow

1. Open an issue first for anything non-trivial so we can agree on the approach.
2. Create a branch off `main`.
3. Make your change with tests. Keep the code style consistent with the
   surrounding code; run `gofmt`/`go vet`.
4. Make sure the following pass locally:
   ```bash
   go vet ./...
   make test
   go mod tidy && git diff --exit-code go.mod go.sum   # deps stay tidy
   ```
5. Open a pull request describing the change and linking the issue.

## Adding or changing audit rules

Audit rules live in [`internal/rules/rules.go`](internal/rules/rules.go). When
adding or modifying a rule:

- Favor **precision over recall** — a noisy rule that fires on legitimate values
  is worse than no rule. Prefer whole-value or token matches over broad
  substring matches.
- Add table-driven test cases in `internal/rules/rules_test.go`, including
  **negative cases** that must *not* match (regressions against false positives).
- Update the Audit Rules table in the [README](README.md).

## Security

This is a security tool. Never commit real secrets, tokens, or internal
hostnames — the test fixtures use clearly fake values. To report a vulnerability,
see [SECURITY.md](SECURITY.md) (please do not open a public issue for security
problems).

## Licensing of contributions

By submitting a contribution, you agree that it is licensed under the project's
[Apache License 2.0](LICENSE).
