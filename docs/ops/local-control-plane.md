# TokenDNA Local Control Plane

TokenDNA is packaged as local-first security infrastructure. Customer
identity, agent-runtime, and policy data should remain inside the environment
where the agents and identities operate.

## Deployable Artifacts

| Artifact | Package | Runs where | Purpose |
|---|---|---|---|
| `tokendna-sdk` | Python wheel / `pip` | Inside agent applications | Emits signed agent action, workflow, attestation, and policy-verdict evidence. |
| `tokendna-collector` | Wheel, `pipx`, signed OCI image, or systemd package | Near identity providers, SIEMs, cloud logs, and MCP gateways | Pulls customer-side telemetry, normalizes it, buffers outages, and streams into the local control plane. |
| `tokendna-control-plane` | Signed OCI image, Docker Compose pilot, Helm chart, air-gapped image bundle | Customer VPC, Kubernetes cluster, appliance VM, or enclave | Stores identity evidence, builds trust graphs, evaluates policies, issues findings, and exposes APIs/UI/SIEM outputs. |
| `tokendna-policy-packs` | Signed bundle | Imported into the control plane | Versioned rules, detection content, compliance mappings, and policy defaults. |

## Runtime Topology

```text
Agent apps / MCP clients
  -> tokendna-sdk
  -> local verify / attest / normalize endpoints

Identity, cloud, and SIEM systems
  -> tokendna-collector
  -> local disk buffer during outages
  -> /api/v1/ingest

Local control plane
  -> FastAPI API and dashboard
  -> Postgres for durable product state
  -> Redis for revocation, rate limits, and hot profiles
  -> ClickHouse for high-volume event analytics
  -> SIEM/ticketing/webhook outputs
```

## Production Gates

Before promotion, create a production env file and run both gates:

```bash
cp .env.production.example .env
# Replace every change-me value in .env with generated secrets.

set -a
. ./.env
set +a

python3 scripts/preflight_prod.py --environment production
python3 scripts/postgres_smoke.py
```

The preflight fails production when:

- `DEV_MODE=true`
- OIDC issuer/audience are missing
- required HMAC and attestation secrets are missing, weak, or still placeholders
- SQLite is selected as the production backend
- `TOKENDNA_PG_DSN` and `DATABASE_URL` disagree
- modules still bypass the shared storage backend with direct
  `sqlite3.connect` usage

The Postgres smoke test exercises tenant creation/API-key lookup, metering,
UIS event persistence, policy bundle storage, decision audit storage, and
staged-rollout grants against the configured Postgres DSN.

## Docker Compose Appliance Pilot

For a local appliance VM or customer-side pilot:

```bash
cp .env.production.example .env
# Edit .env, replacing every change-me value.

docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres redis clickhouse
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate

docker compose -f docker-compose.yml -f docker-compose.production.yml up -d tokendna
```

The deployment gate runs inside the same Compose network as Postgres, so
operators do not need `psql`, local Python Postgres drivers, or a host-exposed
Postgres port. The control plane binds the API to `127.0.0.1:8000` by default.
Put the customer's local reverse proxy, private load balancer, or service mesh
in front of it for TLS, SSO, and network policy.

## Packaging Guidance

Use `pip` only for the SDK. Use `pipx`, a signed container image, or an
OS-native package for the collector. Use containers/Helm/an appliance bundle
for the control plane because it owns migrations, durable storage, TLS, RBAC,
SSO, policy packs, and operational lifecycle.

Air-gapped customer bundles should include:

- signed control-plane and collector images
- SDK and collector wheels
- SBOMs and provenance attestations
- policy-pack signatures
- Helm chart and Docker Compose pilot manifest
- upgrade, backup, restore, and preflight runbooks

## Data Egress Posture

The default enterprise posture is no hosted TokenDNA dependency. Optional
vendor-side services may provide signed policy-pack updates or anonymized
reputation intelligence, but the local control plane remains authoritative for
identity evidence, policy decisions, audit logs, and enforcement.
