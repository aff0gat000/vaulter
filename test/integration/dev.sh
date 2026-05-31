#!/usr/bin/env bash
# Local dev helper: bring up a throwaway Vault (dev mode) seeded with dummy
# data, build the vaulter binary, and leave everything running so you can poke
# at it. Tear it down with `dev.sh down`.
#
# Works on macOS (incl. Apple Silicon) and Linux with either the `docker
# compose` plugin (v2) or the legacy `docker-compose` (v1).
#
# Usage:
#   ./test/integration/dev.sh up     # start + seed (default)
#   ./test/integration/dev.sh down   # stop + remove
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

VAULT_ADDR_LOCAL="http://127.0.0.1:8200"
VAULT_TOKEN_LOCAL="root"

# Detect a working Docker Compose command.
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "error: need 'docker compose' (Docker Desktop/OrbStack) or 'docker-compose'." >&2
  exit 1
fi
COMPOSE="$DC -f $SCRIPT_DIR/docker-compose.yml"

up() {
  echo "==> Starting Vault (dev mode) in Docker"
  $COMPOSE up -d

  echo "==> Waiting for Vault to become ready"
  ready=
  for _ in $(seq 1 30); do
    if $COMPOSE exec -T -e VAULT_ADDR="$VAULT_ADDR_LOCAL" vault vault status >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 2
  done
  [ -n "$ready" ] || { echo "error: Vault did not become ready in time" >&2; exit 1; }

  echo "==> Seeding dummy data"
  COMPOSE="$COMPOSE" "$SCRIPT_DIR/seed.sh"

  echo "==> Building vaulter binary"
  ( cd "$ROOT_DIR" && go build -o vaulter . )

  cat <<EOF

Vault is running at $VAULT_ADDR_LOCAL (token: $VAULT_TOKEN_LOCAL)
Dummy data is under secret/apps/ (apps/payments, apps/orders, apps/legacy).

Point your shell at it:

  export VAULT_ADDR=$VAULT_ADDR_LOCAL
  export VAULT_TOKEN=$VAULT_TOKEN_LOCAL

Then try (from $ROOT_DIR):

  ./vaulter audit --prefix apps/
  ./vaulter audit --prefix apps/ --format markdown
  ./vaulter audit --prefix apps/ --format html > report.html   # open report.html / xdg-open report.html
  ./vaulter search --key 'password|token' --prefix apps/
  ./vaulter search --key password --show-values --prefix apps/

Tear it all down when finished:

  $SCRIPT_DIR/dev.sh down
EOF
}

down() {
  echo "==> Tearing down Vault"
  $COMPOSE down -v --remove-orphans
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $(basename "$0") [up|down]" >&2; exit 2 ;;
esac
