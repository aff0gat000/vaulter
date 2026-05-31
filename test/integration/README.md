# Local testing & integration

This directory contains everything needed to run vaulter against a **real
Vault** locally — no external server required. It works on macOS (including
Apple Silicon / M-series) and Linux.

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Runs Vault (`hashicorp/vault`) in dev mode on `127.0.0.1:8200`, root token `root`. The image is pulled by Docker on first run. |
| `seed.sh` | Writes the **dummy data** under `secret/apps/` (a real secret plus config-like / placeholder junk). |
| `run.sh` | Automated end-to-end test: build → up → seed → assert → tear down. |
| `dev.sh` | Interactive helper: bring the seeded Vault **up and leave it running**, or tear it **down**. |

> The Vault dev server is **ephemeral and in-memory** — it is reseeded on every
> start and nothing persists. Safe to throw away.

## Prerequisites

You need **Go** and **Docker** — specifically the `docker` CLI with a running
daemon and Docker Compose. The scripts are runtime-agnostic: they only call
`docker` / `docker compose` and don't require any particular Docker
distribution. Verify your setup with:

```bash
docker version && docker compose version
```

**Linux (straight Docker Engine):**
```bash
sudo apt-get update
sudo apt-get install -y golang-go docker.io docker-compose-v2   # or docker-ce + docker-compose-plugin
sudo usermod -aG docker "$USER"   # then log out/in so `docker` works without sudo
```

**macOS (incl. M4 / Apple Silicon):**
```bash
brew install go
```
Docker's daemon is Linux-only, so on macOS it runs inside a lightweight Linux
VM. Provision that VM with whatever Docker runtime your organization has
approved, start it, then confirm `docker` and `docker compose` work.

The scripts auto-detect either the `docker compose` plugin (v2) or the legacy
`docker-compose` (v1). On Apple Silicon everything runs natively as `arm64` —
the base images are multi-arch.

## Automated test (one shot)

Runs the full cycle and asserts the results, then cleans up. This is what CI
runs.

```bash
make integration
```

Success prints `PASS: integration tests succeeded.`

## Interactive (start it and poke at it)

Bring up a seeded Vault and leave it running — simplest is the root one-liner:

```bash
./start-local.sh           # start + seed (./start-local.sh down to stop)
```

Equivalent: `make integration-up` / `make integration-down`, or
`./test/integration/dev.sh up` / `down`.

Then point your shell at it and try the CLI (run from the repo root):

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

./vaulter audit  --prefix apps/
./vaulter audit  --prefix apps/ --format markdown
./vaulter audit  --prefix apps/ --format html > report.html   # macOS: open report.html  |  Linux: xdg-open report.html
./vaulter search --key 'password|token' --prefix apps/
./vaulter search --key password --show-values --prefix apps/  # reveals the real value
```

Tear it down when finished:

```bash
make integration-down      # or: ./test/integration/dev.sh down
```

## Manual steps (what the scripts do under the hood)

```bash
# 1. start Vault
cd test/integration
docker compose up -d
#    wait until ready
docker compose exec -T -e VAULT_ADDR=http://127.0.0.1:8200 vault vault status

# 2. seed dummy data
./seed.sh

# 3. build the binary and point at Vault (from repo root)
cd ../..
go build -o vaulter .
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

# 4. run vaulter
./vaulter audit --prefix apps/

# 5. tear down
cd test/integration
docker compose down -v
```

## What gets seeded

| Path | Keys | Why |
|------|------|-----|
| `secret/apps/payments` | `password`, `api_token` | Legitimate secrets — should *not* trip audit rules |
| `secret/apps/orders` | `db_host`, `port`, `debug`, `enable_cache`, `service_url`, `bind_ip`, `config_path`, `owner_email` | Config-like / non-secret data that audit flags |
| `secret/apps/legacy` | `password=changeme`, `unused=""` | Placeholder and empty values (error severity) |

## Troubleshooting

- **`Cannot connect to the Docker daemon`** — the daemon isn't running. Start
  it (on macOS, start your Linux-VM Docker runtime first).
- **Port 8200 already in use** — something else (maybe a real Vault) is bound to
  it. Stop it, or change the published port in `docker-compose.yml`.
- **`docker compose` not found** — install Compose v2 (`docker-compose-v2` or
  `docker-compose-plugin`); the scripts also fall back to legacy
  `docker-compose` (v1).
- **Permission denied talking to Docker on Linux** — add yourself to the
  `docker` group (see prerequisites) and re-login.
