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
