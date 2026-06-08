#!/bin/sh
# Entrypoint for the vaulter GitHub Action. Maps action inputs (passed as
# VAULTER_* env vars plus VAULT_ADDR/VAULT_TOKEN) to a vaulter invocation.
#
# Gating is delegated to vaulter itself via --fail-on-severity: vaulter exits
# with code 2 when findings reach the threshold, which fails the job. This
# script only translates inputs and renders a short job summary.
set -eu

CMD="${VAULTER_COMMAND:-audit}"
FAIL_ON="${VAULTER_FAIL_ON:-error}"

set -- "$CMD"

[ -n "${VAULTER_MOUNT:-}" ]      && set -- "$@" --mount "$VAULTER_MOUNT"
[ -n "${VAULTER_KV_VERSION:-}" ] && set -- "$@" --kv-version "$VAULTER_KV_VERSION"
[ -n "${VAULTER_PREFIX:-}" ]     && set -- "$@" --prefix "$VAULTER_PREFIX"
[ -n "${VAULTER_TIMEOUT:-}" ]    && set -- "$@" --timeout "$VAULTER_TIMEOUT"
[ "${VAULTER_INSECURE:-false}" = "true" ]    && set -- "$@" --insecure
[ "${VAULTER_SHOW_VALUES:-false}" = "true" ] && set -- "$@" --show-values
[ "${VAULTER_JSON:-false}" = "true" ]        && set -- "$@" --json

if [ "$CMD" = "search" ]; then
  [ -n "${VAULTER_KEY:-}" ]   && set -- "$@" --key "$VAULTER_KEY"
  [ -n "${VAULTER_VALUE:-}" ] && set -- "$@" --value "$VAULTER_VALUE"
fi

if [ "$CMD" = "audit" ]; then
  set -- "$@" --fail-on-severity "$FAIL_ON"
fi

echo "+ vaulter $*" >&2

# Capture stderr (where vaulter prints its machine-readable audit summary) while
# stdout streams normally. vaulter's own exit code drives the job result.
err_file="$(mktemp)"
set +e
vaulter "$@" 2>"$err_file"
status=$?
set -e
cat "$err_file" >&2

# Render a job summary for audit runs from the "vaulter audit summary:" line.
if [ "$CMD" = "audit" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  summary="$(grep -E 'vaulter audit summary:' "$err_file" | tail -n1 || true)"
  errors=$(printf '%s' "$summary" | sed -n 's/.*errors=\([0-9]*\).*/\1/p')
  warnings=$(printf '%s' "$summary" | sed -n 's/.*warnings=\([0-9]*\).*/\1/p')
  {
    echo "### vaulter audit"
    echo ""
    echo "- errors: **${errors:-0}**"
    echo "- warnings: **${warnings:-0}**"
    echo "- fail-on-severity: \`$FAIL_ON\`"
  } >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
fi

rm -f "$err_file"
exit "$status"
