#!/bin/sh
# Entrypoint for the vaulter GitHub Action. Maps action inputs (passed as
# VAULTER_* env vars plus VAULT_ADDR/VAULT_TOKEN) to a vaulter invocation, and
# optionally fails the job when audit findings reach a severity threshold.
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

if [ "$CMD" = "search" ]; then
  [ -n "${VAULTER_KEY:-}" ]   && set -- "$@" --key "$VAULTER_KEY"
  [ -n "${VAULTER_VALUE:-}" ] && set -- "$@" --value "$VAULTER_VALUE"
fi

# When gating an audit on severity, we need JSON to count findings.
WANT_JSON="${VAULTER_JSON:-false}"
if [ "$CMD" = "audit" ] && [ "$FAIL_ON" != "none" ]; then
  WANT_JSON="true"
fi
[ "$WANT_JSON" = "true" ] && set -- "$@" --json

echo "+ vaulter $*" >&2

# Audit gating path: capture output, count by severity, decide exit code.
if [ "$CMD" = "audit" ] && [ "$FAIL_ON" != "none" ]; then
  OUT="$(vaulter "$@")"
  echo "$OUT"

  errors=$(printf '%s' "$OUT" | grep -Eoc '"Severity":[[:space:]]*"error"' || true)
  warnings=$(printf '%s' "$OUT" | grep -Eoc '"Severity":[[:space:]]*"warning"' || true)
  errors=${errors:-0}
  warnings=${warnings:-0}
  total=$((errors + warnings))

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### vaulter audit"
      echo ""
      echo "- errors: **$errors**"
      echo "- warnings: **$warnings**"
      echo "- fail-on-severity: \`$FAIL_ON\`"
    } >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true
  fi

  case "$FAIL_ON" in
    error)
      if [ "$errors" -gt 0 ]; then
        echo "::error::vaulter audit found $errors error-severity finding(s)" >&2
        exit 1
      fi
      ;;
    warning)
      if [ "$total" -gt 0 ]; then
        echo "::error::vaulter audit found $total finding(s) at or above warning" >&2
        exit 1
      fi
      ;;
    *)
      echo "::error::unknown fail-on-severity '$FAIL_ON' (use none|warning|error)" >&2
      exit 2
      ;;
  esac
  exit 0
fi

# Non-gating path: run vaulter and pass through its exit code.
exec vaulter "$@"
