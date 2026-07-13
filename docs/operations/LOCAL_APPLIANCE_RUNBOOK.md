# TokenDNA Local Appliance Runbook

TokenDNA is intended to run where agent identities, workflow events, and policy decisions already live. The production shape is a customer-local control plane, not a hosted SaaS dependency.

## Deployment Boundary

The appliance includes:

- FastAPI control plane and operator console.
- Postgres for identity, policy, audit, and product state.
- Redis for rate limiting and runtime cache.
- ClickHouse for analytical event flows.
- TokenDNA SDK, collector, and platform packages for local agent and identity integrations.

## First Install

1. Copy `.env.production.example` to `.env`.
2. Replace every `change-me` value with a generated secret or environment-specific setting.
3. Start the data plane:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres redis clickhouse
```

4. Run the deployment gate:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate
```

5. Start the control plane:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d tokendna
```

6. Open the operator console at `http://127.0.0.1:8000/dashboard`.

## Required Gates

Run these before every production start or upgrade:

```bash
python scripts/preflight_prod.py --environment production
python scripts/migrate_storage.py
python scripts/postgres_smoke.py
```

In Docker, prefer the single appliance gate:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate
```

The gate fails closed if production secrets are placeholders, Postgres is not configured, storage modules bypass the shared backend, migrations fail, or the live identity/product smoke path cannot write and read state.

## Schema Migrations

TokenDNA records applied revisions in `tokendna_schema_migrations`.

Check status:

```bash
python scripts/migrate_storage.py --status
```

Apply pending migrations:

```bash
python scripts/migrate_storage.py
```

The API also applies migrations during startup and exposes status in `/api/operator/status` and the System Health view.

## Health Checks

Unauthenticated liveness:

```bash
curl -f http://127.0.0.1:8000/
```

Authenticated operator status:

```bash
curl -H "X-API-Key: <operator-key>" http://127.0.0.1:8000/api/operator/status
```

The status response should show `migrations.up_to_date=true`, `storage_backend.backend=postgres`, and healthy Redis/ClickHouse indicators for a fully live appliance.

## Backup And Restore

Back up Postgres before upgrades:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml exec postgres \
  pg_dump -U tokendna -d tokendna > tokendna-postgres.sql
```

Restore into a clean database, then run the deployment gate before restarting the API.

ClickHouse data is analytical. Preserve it when incident history or long-horizon reporting is required; otherwise Postgres is the recovery source of truth for control-plane state.

## Upgrade Procedure

1. Stop the API container.
2. Back up Postgres.
3. Pull or load the new signed image.
4. Run `tokendna-deployment-gate`.
5. Start the API container.
6. Confirm the operator console shows current migrations and healthy dependencies.

## Troubleshooting

If `preflight_prod.py` fails, fix the named environment variable first. Do not bypass this gate in production.

If `migrate_storage.py --status` shows pending revisions, run `migrate_storage.py` or the Docker deployment gate.

If Postgres smoke fails after migrations, keep the API stopped and inspect the failed module path. Smoke failures indicate the product’s identity, policy, audit, or rollout state cannot round-trip safely.

If Docker commands fail from `~`, `cd` into the TokenDNA repository first. Compose files and scripts live in the repo root.
