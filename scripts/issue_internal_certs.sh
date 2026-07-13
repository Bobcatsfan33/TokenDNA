#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TokenDNA — Internal mTLS certificate issuance
#
# Generates a self-signed root CA + service certificates for the four internal
# components that need mutual TLS:
#
#   - api          (FastAPI / uvicorn)
#   - postgres
#   - redis
#   - clickhouse
#
# Usage:
#   ./scripts/issue_internal_certs.sh                         # writes to ./deploy/tls
#   ./scripts/issue_internal_certs.sh --out /etc/tokendna/tls
#   ./scripts/issue_internal_certs.sh --service api --renew   # renew one service
#
# Notes:
#   - For dev / pilot deployments. Production-grade rotation should drive this
#     same script from a secret-manager backed orchestrator (HashiCorp Vault
#     PKI, AWS Private CA, cert-manager).
#   - Service common-names match the docker-compose service names so containers
#     can verify each other by hostname.
#   - The CA cert is written to ${OUT}/ca.crt and trusted by all services.
#   - The CA private key (${OUT}/ca.key) MUST live on a secured host or a
#     hardware module — never bake it into a container image.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

OUT="./deploy/tls"
SERVICE=""
RENEW=false
DAYS_CA=3650            # 10 years for the root CA
DAYS_LEAF=825           # 27 months — matches CA/Browser Forum guidance for leaf certs
KEY_BITS=4096

while [ $# -gt 0 ]; do
  case "$1" in
    --out)     OUT="$2"; shift 2 ;;
    --service) SERVICE="$2"; shift 2 ;;
    --renew)   RENEW=true; shift ;;
    --days-ca) DAYS_CA="$2"; shift 2 ;;
    --days-leaf) DAYS_LEAF="$2"; shift 2 ;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "${OUT}"
chmod 700 "${OUT}"

CA_KEY="${OUT}/ca.key"
CA_CRT="${OUT}/ca.crt"

# ── Root CA ─────────────────────────────────────────────────────────────────
if [ ! -f "${CA_CRT}" ] || [ "${RENEW}" = true ] && [ "${SERVICE}" = "ca" ]; then
  echo "[ca] Generating new internal CA (RSA-${KEY_BITS})"
  openssl genrsa -out "${CA_KEY}" "${KEY_BITS}"
  chmod 600 "${CA_KEY}"
  openssl req -new -x509 -sha256 -days "${DAYS_CA}" -key "${CA_KEY}" -out "${CA_CRT}" \
    -subj "/CN=TokenDNA Internal CA/O=TokenDNA/OU=Trust Authority"
  echo "[ca] CA cert: ${CA_CRT}"
fi

# ── Per-service leaf cert ───────────────────────────────────────────────────
issue_service() {
  local svc="$1"
  local key="${OUT}/${svc}.key"
  local csr="${OUT}/${svc}.csr"
  local crt="${OUT}/${svc}.crt"
  local extfile="${OUT}/${svc}.ext"

  if [ -f "${crt}" ] && [ "${RENEW}" != true ]; then
    echo "[${svc}] cert exists; skipping (use --renew --service ${svc} to rotate)"
    return 0
  fi

  echo "[${svc}] issuing leaf cert"
  openssl genrsa -out "${key}" "${KEY_BITS}"
  chmod 600 "${key}"
  openssl req -new -key "${key}" -out "${csr}" \
    -subj "/CN=${svc}/O=TokenDNA"

  cat > "${extfile}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt
[alt]
DNS.1 = ${svc}
DNS.2 = ${svc}.local
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

  openssl x509 -req -in "${csr}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${crt}" -days "${DAYS_LEAF}" -sha256 -extfile "${extfile}"

  rm -f "${csr}" "${extfile}"
  chmod 644 "${crt}"
  echo "[${svc}] cert: ${crt}"
}

if [ -n "${SERVICE}" ] && [ "${SERVICE}" != "ca" ]; then
  issue_service "${SERVICE}"
else
  for svc in api postgres redis clickhouse; do
    issue_service "${svc}"
  done
fi

echo
echo "Done. Files in ${OUT}:"
ls -l "${OUT}"
echo
echo "Next steps:"
echo "  1. Mount ${OUT} into each container at /etc/tokendna/tls (read-only)."
echo "  2. Set TLS_CA_CERT_PATH=/etc/tokendna/tls/ca.crt and the per-service"
echo "     TLS_*_CERT_PATH / TLS_*_KEY_PATH env vars (see modules/security/mtls.py)."
echo "  3. Set REDIS_TLS=true and CLICKHOUSE_SECURE=true."
echo "  4. Restart the stack."
