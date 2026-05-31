#!/usr/bin/env bash
# One-line local test environment for vaulter.
#
# Starts a throwaway Vault (dev mode) in Docker, seeds it with dummy data, and
# builds the vaulter binary so you can run audit/search against real Vault.
# Works on macOS (incl. Apple Silicon / M-series) and Linux.
#
#   ./start-local.sh         # start + seed, leave running
#   ./start-local.sh down    # stop + remove
#
# Full docs: test/integration/README.md
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/test/integration/dev.sh" "${1:-up}"
