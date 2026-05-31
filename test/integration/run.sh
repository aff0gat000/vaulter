#!/usr/bin/env bash
# End-to-end integration test: spin up a real Vault in Docker, seed it, and run
# the built vaulter binary against it, asserting on the output.
#
# Usage: test/integration/run.sh   (or: make integration)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml"

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

cleanup() {
  echo "Tearing down Vault..."
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

assert_contains() {
  # assert_contains <haystack> <needle> <message>
  case "$1" in
    *"$2"*) ;;
    *) fail "$3 (expected to find '$2')" ;;
  esac
}

assert_not_contains() {
  case "$1" in
    *"$2"*) fail "$3 (did not expect '$2')" ;;
  esac
}

echo "==> Building vaulter binary"
( cd "$ROOT_DIR" && go build -o vaulter . )
VAULTER="$ROOT_DIR/vaulter"

echo "==> Starting Vault (dev mode) in Docker"
COMPOSE="$COMPOSE" $COMPOSE up -d --wait

echo "==> Seeding secrets"
COMPOSE="$COMPOSE" "$SCRIPT_DIR/seed.sh"

echo "==> Running: vaulter audit --json"
AUDIT_JSON="$("$VAULTER" audit --json --mount secret --prefix apps/)"
echo "$AUDIT_JSON"

# Every enhanced/legacy rule we seeded data for should fire.
for rule in config-like-key feature-flag-key boolean-value numeric-only-value \
            ip-address-value url-value file-path-value email-value \
            placeholder-value empty-value; do
  assert_contains "$AUDIT_JSON" "\"$rule\"" "audit did not report rule $rule"
done

# The legitimate password value must NOT leak (masked by default) and must not
# be flagged as a placeholder.
assert_not_contains "$AUDIT_JSON" "S3cr3t-P@ss-9182" "real secret value leaked in audit output"

echo "==> Running: vaulter search --key 'password|token' --json"
SEARCH_JSON="$("$VAULTER" search --key 'password|token' --json --mount secret --prefix apps/)"
echo "$SEARCH_JSON"
assert_contains "$SEARCH_JSON" "\"password\"" "search did not match the password key"
assert_contains "$SEARCH_JSON" "\"api_token\"" "search did not match the api_token key"
assert_not_contains "$SEARCH_JSON" "S3cr3t-P@ss-9182" "search leaked masked value without --show-values"

echo "==> Running: vaulter search --value with --show-values"
SHOW_JSON="$("$VAULTER" search --key 'password' --show-values --json --mount secret --prefix apps/payments)"
assert_contains "$SHOW_JSON" "S3cr3t-P@ss-9182" "search --show-values did not reveal the value"

echo ""
echo "PASS: integration tests succeeded."
