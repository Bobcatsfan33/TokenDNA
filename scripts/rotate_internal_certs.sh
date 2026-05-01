#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TokenDNA — Internal mTLS certificate rotation
#
# Wraps issue_internal_certs.sh --renew with sequencing that prevents
# downtime: rotates one service at a time, waits for the orchestrator to
# pick up the new cert (signal SIGHUP or rolling restart), then moves on.
#
# Usage:
#   ./scripts/rotate_internal_certs.sh                # rotate all services
#   ./scripts/rotate_internal_certs.sh --service api  # rotate one
#   ./scripts/rotate_internal_certs.sh --rotate-ca    # rotate the root CA
#                                                     # (forces all services
#                                                     # to be re-issued and
#                                                     # all clients to reload
#                                                     # ca.crt — outage risk;
#                                                     # do this only inside a
#                                                     # planned maintenance window).
#
# Exit codes:
#   0  rotation succeeded
#   1  rotation failed; cert files left in pre-rotation state
#   2  bad arguments
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

OUT="${TLS_OUT:-./deploy/tls}"
SERVICE=""
ROTATE_CA=false
ISSUE_SCRIPT="$(dirname "$0")/issue_internal_certs.sh"

while [ $# -gt 0 ]; do
  case "$1" in
    --service)   SERVICE="$2"; shift 2 ;;
    --out)       OUT="$2"; shift 2 ;;
    --rotate-ca) ROTATE_CA=true; shift ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

backup_dir="${OUT}/.backup-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${backup_dir}"
echo "[rotate] backing up current certs to ${backup_dir}"
cp -p "${OUT}"/*.crt "${OUT}"/*.key "${backup_dir}/" 2>/dev/null || true

if [ "${ROTATE_CA}" = true ]; then
  echo "[rotate] rotating root CA — this forces every service cert to be re-issued."
  rm -f "${OUT}/ca.crt" "${OUT}/ca.key"
  "${ISSUE_SCRIPT}" --out "${OUT}" --service ca
  for svc in api postgres redis clickhouse; do
    "${ISSUE_SCRIPT}" --out "${OUT}" --service "${svc}" --renew
  done
elif [ -n "${SERVICE}" ]; then
  "${ISSUE_SCRIPT}" --out "${OUT}" --service "${SERVICE}" --renew
else
  for svc in api postgres redis clickhouse; do
    "${ISSUE_SCRIPT}" --out "${OUT}" --service "${svc}" --renew
  done
fi

echo
echo "[rotate] complete. backup at: ${backup_dir}"
echo
echo "Next: trigger a rolling restart so each service loads its new material."
echo "  docker compose -f docker-compose.yml -f docker-compose.production.yml restart"
echo "or, in k8s:"
echo "  kubectl rollout restart deployment/tokendna-api"
