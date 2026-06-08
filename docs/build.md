# Building Vaulter

Vaulter is a single Go module that produces three artifacts from one codebase:

- a **Go library** (`github.com/aff0gat000/vaulter/pkg/vaulter`)
- a **CLI binary** (`vaulter`)
- a **container image** / GitHub Action

It depends only on the Go standard library plus two well-established modules
(`spf13/cobra` for the CLI and `hashicorp/vault/api` for Vault access); see
[`go.mod`](../go.mod).

## Prerequisites

- **Go** — the version is pinned in [`go.mod`](../go.mod). The `go` directive
  declares the minimum language version; the `toolchain` directive selects the
  exact toolchain releases are built with (Go downloads it automatically when
  `GOTOOLCHAIN=auto`, the default).
- **Docker** (optional) — for the container image and the end-to-end
  integration tests.

## Build from source

```bash
git clone https://github.com/aff0gat000/vaulter
cd vaulter
make build        # produces ./vaulter
./vaulter --version
```

`make build` compiles with `-trimpath` and stamps the version via `-ldflags`, so
the binary contains no local filesystem paths (reproducible builds). To build
without make:

```bash
go build -trimpath -ldflags "-X github.com/aff0gat000/vaulter/cmd.Version=$(git describe --tags --always)" -o vaulter .
```

## Install as a CLI

```bash
go install github.com/aff0gat000/vaulter@latest
```

This installs the latest tagged release into `$(go env GOPATH)/bin`.

## Use as a Go module

```bash
go get github.com/aff0gat000/vaulter@latest
```

See [usage.md](usage.md#library-usage) for the API.

## Build the container image

```bash
make docker                       # tags vaulter:<version>
# or directly:
docker build -t vaulter --build-arg VERSION=$(git describe --tags --always) .
```

The image is a multi-stage build: a `golang:1.25-alpine` builder (CGO disabled,
`-trimpath`) producing a static binary, copied into a minimal `alpine` runtime
that runs as a non-root user. Base images are **pinned by digest** for
reproducible, tamper-evident builds; [Dependabot](../.github/dependabot.yml)
keeps the digests current.

## Reproducible builds

- `CGO_ENABLED=0` produces a static, portable binary.
- `-trimpath` removes local paths from the binary.
- GoReleaser sets `mod_timestamp` to the commit timestamp so archive contents
  are deterministic.

## Verifying releases

Each tagged release (via [`.github/workflows/release.yml`](../.github/workflows/release.yml)):

- builds cross-platform archives with GoReleaser,
- emits a **CycloneDX SBOM** per archive,
- **signs** `checksums.txt` with cosign (keyless / Sigstore), and
- builds, pushes, and signs the GHCR image with **SLSA provenance** and an SBOM.

To verify a downloaded archive:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/aff0gat000/vaulter' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum -c checksums.txt
```

To verify the container image and inspect its attestations:

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/aff0gat000/vaulter' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/aff0gat000/vaulter:latest

cosign download sbom ghcr.io/aff0gat000/vaulter:latest
```

## Test, lint, and scan

```bash
make test         # unit tests with -race
make cover        # coverage report -> coverage.html
make lint         # go vet + staticcheck
make sast         # gosec + govulncheck
make integration  # end-to-end against a real Vault in Docker
```

CI runs the same checks on every push and PR (see
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)): vet, race tests with
coverage, build, `go mod verify`, a tidiness check, `gosec`, `govulncheck`, a
Docker build, and the integration suite.
