# Internal mTLS — operations guide

TokenDNA's internal services (FastAPI ↔ Redis, ClickHouse, Postgres) run mutual TLS so an attacker on the internal network can't passively read or actively inject into the service-to-service traffic. This is a SOC 2 / FedRAMP / IL5 requirement and a precondition for the trust-authority story (your CA is only as trustworthy as the wires it ships certs over).

## Quickstart (dev)

```bash
# 1. Issue a fresh CA + service certs into ./deploy/tls
./scripts/issue_internal_certs.sh

# 2. Point the env at the cert bundle
export TLS_CA_CERT_PATH=$PWD/deploy/tls/ca.crt
export TLS_API_CERT_PATH=$PWD/deploy/tls/api.crt
export TLS_API_KEY_PATH=$PWD/deploy/tls/api.key
export TLS_REDIS_CERT_PATH=$PWD/deploy/tls/redis.crt
export TLS_REDIS_KEY_PATH=$PWD/deploy/tls/redis.key
export TLS_CLICKHOUSE_CERT_PATH=$PWD/deploy/tls/clickhouse.crt
export TLS_CLICKHOUSE_KEY_PATH=$PWD/deploy/tls/clickhouse.key
export TLS_POSTGRES_CERT_PATH=$PWD/deploy/tls/postgres.crt
export TLS_POSTGRES_KEY_PATH=$PWD/deploy/tls/postgres.key
export REDIS_TLS=true
export CLICKHOUSE_SECURE=true

# 3. Boot the stack
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

The startup logs will print `mTLS active (env=production, ca=...)` once `modules.security.mtls.load_or_raise()` has resolved the bundle.

## Production posture

| Posture                                            | What                                                       | When |
|----------------------------------------------------|------------------------------------------------------------|------|
| **Self-signed internal CA** (this repo's default)  | `scripts/issue_internal_certs.sh`                          | Pilot / single-tenant deployment |
| **HashiCorp Vault PKI**                            | Vault issues short-lived (24h) certs; agent renews         | Multi-region production |
| **AWS Private CA (ACM-PCA)**                       | Same model with AWS-managed root + audit log               | AWS-native deployments |
| **cert-manager + Let's Encrypt (external traffic only)** | Public ingress edge                                  | When the service is exposed beyond a trusted network |

The Python helper at `modules/security/mtls.py` is provider-agnostic — it reads file paths from env vars. Whatever issuance system you use just needs to drop files into the configured paths and (optionally) signal SIGHUP for hot reload.

## Environment variables

| Var                              | Purpose                                                       |
|----------------------------------|---------------------------------------------------------------|
| `TLS_CA_CERT_PATH`               | Trusted root CA — all services + clients verify against this   |
| `TLS_API_CERT_PATH` / `_KEY_PATH`| Server cert presented by FastAPI                              |
| `TLS_REDIS_CERT_PATH` / `_KEY_PATH` | Client cert presented to Redis                             |
| `TLS_CLICKHOUSE_CERT_PATH` / `_KEY_PATH` | Client cert presented to ClickHouse                    |
| `TLS_POSTGRES_CERT_PATH` / `_KEY_PATH` | Client cert presented to Postgres                       |
| `REDIS_TLS=true`                 | Toggles `rediss://` scheme                                    |
| `CLICKHOUSE_SECURE=true`         | Toggles HTTPS on the ClickHouse HTTP interface                |

## Fail-closed behaviour

Per `modules.security.mtls.load_or_raise`:
- `TOKENDNA_ENV` ∈ `{production, prod, il4, il5, il6}` AND any of `TLS_CA_CERT_PATH` / `TLS_API_CERT_PATH` / `TLS_API_KEY_PATH` is missing → **`MTLSConfigError`** at startup; the API process refuses to come up.
- Any other environment → logs an INFO message and continues with plain TCP (the dev `docker compose up` path keeps working).

This matches the secret-gate pattern (`modules/security/secret_gate.py`) — production refuses to start without proper material; dev tells you what's missing and runs anyway.

## Rotation

```bash
# Rotate just the API cert (no downtime — issuance + rolling restart)
./scripts/rotate_internal_certs.sh --service api

# Rotate every service leaf cert (still no downtime if you do a rolling restart)
./scripts/rotate_internal_certs.sh

# Rotate the root CA — outage risk; do inside a maintenance window
./scripts/rotate_internal_certs.sh --rotate-ca
```

Each rotation backs up the current state to `./deploy/tls/.backup-<utc-timestamp>/` before overwriting, so the previous bundle can be restored if the new one fails to load.

Recommended cadence:
- **Leaf certs**: every 27 months (matches CA/Browser Forum guideline). Set a recurring `/schedule` agent to open a rotation PR 60 days before expiry.
- **Root CA**: every 10 years. Plan ahead — every active service needs a new CA in its trust store.

## Verification checklist

After rotation, confirm:

```bash
# 1. New cert is the one services see
openssl x509 -in deploy/tls/api.crt -noout -dates -issuer -subject

# 2. The CA still signs the new leaf
openssl verify -CAfile deploy/tls/ca.crt deploy/tls/api.crt

# 3. The API negotiates TLS with client cert
curl -vk --cacert deploy/tls/ca.crt \
  --cert deploy/tls/redis.crt --key deploy/tls/redis.key \
  https://localhost:8000/api/health

# 4. Redis accepts the TLS handshake
redis-cli --tls --cert deploy/tls/api.crt --key deploy/tls/api.key \
  --cacert deploy/tls/ca.crt -h localhost -p 6379 ping
```

## Threat model + non-coverage

mTLS protects:
- Eavesdropping on internal traffic between services
- Active man-in-the-middle on the internal network
- Impersonation of one internal service by another (a compromised Redis box can't forge a request to the API)

mTLS does **not** protect against:
- A compromised root CA private key (treat `ca.key` like the most sensitive secret in the system; rotate on any suspected exposure)
- A compromised service host (the leaf cert + key live alongside the process; if the host is owned, the cert is owned)
- Application-layer abuse from a properly authenticated client (that's what `policy_guard` + `mcp_inspector` cover)

---

## Internal API plane (:8443) — peer authorization (T-2)

The data-store mTLS above protects FastAPI ↔ Redis/ClickHouse/Postgres. The
**internal API plane** adds a second listener so the collector, edge worker,
and batch jobs reach the API itself over mutual TLS:

| Port | Surface | Auth |
|------|---------|------|
| `:8000` | external API (ingress-terminated) | OIDC bearer |
| `:8443` | internal plane | mutual TLS, client cert REQUIRED + SPIFFE peer allowlist |

- **Listener**: `modules/security/mtls_server.py` builds a TLS 1.3-only,
  `CERT_REQUIRED` context and runs `uvicorn` on `:8443`. Run it as a second
  process in the image or a dedicated Deployment.
- **Authorization (not just authentication)**: `modules/security/mtls_peer.py`
  `require_internal_peer` checks the verified peer cert's SAN URI against the
  SPIFFE allowlist (`spiffe://tokendna/{collector,edge-worker,migration-job}`,
  overridable via `TLS_INTERNAL_PEER_ALLOWLIST`). A valid cert from the CA with
  an unlisted identity still gets **403**. Mount it on internal routes:

  ```python
  from fastapi import APIRouter, Depends
  from modules.security.mtls_peer import require_internal_peer
  router = APIRouter(prefix="/internal", dependencies=[Depends(require_internal_peer)])
  ```

- **PKI + rotation**: `deploy/helm/tokendna/templates/internal-pki.yaml`
  (enable with `internalPKI.enabled=true`) defines a cert-manager `Issuer` +
  `Certificate`s (90d cert / 30d renew, ECDSA P-256). Deleting a leaf secret
  triggers automatic reissue with no application restart.
- **Collector client**: `collector/tokendna_collector/transport/internal_client.py`
  presents the collector cert and verifies the API against the internal CA
  (stdlib `ssl`, consistent with the collector's minimal-dependency design).

**Negative tests** (`tests/test_mtls_peer.py`): no client cert → 403 (mTLS
required); valid cert with unlisted SPIFFE URI → 403; listener context is TLS
1.3-only and `CERT_REQUIRED`.
