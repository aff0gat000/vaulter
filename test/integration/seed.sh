#!/usr/bin/env bash
# Seed the dev Vault with a mix of real secrets and config-like / non-secret
# data so the audit and search commands have something meaningful to find.
set -euo pipefail

COMPOSE="${COMPOSE:-docker compose}"

vault_exec() {
  $COMPOSE exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root vault "$@"
}

echo "Seeding Vault..."

# A legitimate secret (should NOT trip audit rules).
vault_exec vault kv put secret/apps/payments \
  password='S3cr3t-P@ss-9182' \
  api_token='tok_live_4f9a8b7c6d5e'

# Config-like junk that should be flagged by the audit rules.
vault_exec vault kv put secret/apps/orders \
  db_host='db.internal.example.com' \
  port='5432' \
  debug='true' \
  enable_cache='yes' \
  service_url='https://orders.example.com' \
  bind_ip='10.0.0.12' \
  config_path='/etc/orders/config.yaml' \
  owner_email='ops@example.com'

# Placeholder / empty values (error severity).
vault_exec vault kv put secret/apps/legacy \
  password='changeme' \
  unused=''

echo "Seed complete."
