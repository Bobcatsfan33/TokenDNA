# TokenDNA — Production Deployment Guide

_Sprint D-1 | Last updated: 2026-04-22_

---

## Prerequisites

| Component | Minimum version | Purpose |
|-----------|----------------|---------|
| Python | 3.11+ | Runtime |
| PostgreSQL | 15+ | Primary datastore (production) |
| Redis | 7+ | Rate limiting, caching, revocation |
| ClickHouse | 23+ | Telemetry analytics |

---

## Environment Variables

### Required (production)

```env
# Auth
PASSPORT_SIGNING_SECRET=<random 64-byte hex>

# Database — Postgres (production)
TOKENDNA_DB_BACKEND=postgres
TOKENDNA_PG_DSN=postgresql://user:password@host:5432/tokendna
TOKENDNA_PG_POOL_MIN=5
TOKENDNA_PG_POOL_MAX=20

# Redis
REDIS_HOST=redis.internal
REDIS_PORT=6379
REDIS_PASSWORD=<your-password>
REDIS_TLS=true

# ClickHouse
CLICKHOUSE_HOST=clickhouse.internal
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=tokendna
CLICKHOUSE_PASSWORD=<your-password>
CLICKHOUSE_DB=tokendna
CLICKHOUSE_SECURE=true
```

### Rate Limiting

```env
RATE_LIMIT_PER_MINUTE=60       # Authenticated endpoints (per tenant+IP)
RATE_LIMIT_OPEN_PER_MINUTE=30  # Open/unauthenticated endpoints (IP only)
```

Open endpoints protected by `RATE_LIMIT_OPEN_PER_MINUTE`:
- `POST /api/passport/verify` — third-party passport validation
- `POST /api/verifier/challenge/{id}/respond` — challenge response submission
- `GET /api/passport/{id}/status` — revocation check

### Production Safety

```env
DEV_MODE=false   # MUST be false in production (enforced at startup)
```

---

## Database Migration: SQLite → PostgreSQL

### Phase 1 — Dual-write (validate Postgres writes in parallel)

```env
TOKENDNA_DB_BACKEND=sqlite     # SQLite is still source of truth
TOKENDNA_DB_DUAL_WRITE=true    # Write to Postgres in parallel
TOKENDNA_PG_DSN=postgresql://...
```

During dual-write mode:
- All reads come from SQLite
- Writes go to both SQLite (primary) and Postgres (secondary)
- If Postgres write fails, it is logged and swallowed — SQLite write succeeds

### Phase 2 — Cut over to Postgres

After validating data parity:

```env
TOKENDNA_DB_BACKEND=postgres
TOKENDNA_DB_DUAL_WRITE=false
TOKENDNA_PG_DSN=postgresql://...
```

### Phase 3 — Decommission SQLite

Once stable on Postgres for ≥7 days, remove SQLite files and dual-write config.

---

## pg_connection Usage in Modules

New modules should use the unified connection factory instead of calling `sqlite3.connect()` directly:

```python
from modules.storage.pg_connection import get_db_conn, adapt_sql

def insert_record(tenant_id: str, data: dict) -> None:
    sql = adapt_sql("INSERT INTO my_table (tenant_id, payload) VALUES (?, ?)")
    with get_db_conn() as conn:
        conn.execute(sql, (tenant_id, json.dumps(data)))
        # commit is automatic on context exit (no exception)
```

`adapt_sql()` converts `?` placeholders to `%s` when Postgres is active.
`get_db_conn()` is backend-transparent — the same code runs on SQLite (dev) and Postgres (prod).

---

## Checklist Before First Customer

- [ ] `TOKENDNA_DB_BACKEND=postgres` with valid `TOKENDNA_PG_DSN`
- [ ] Redis available and `REDIS_PASSWORD` set
- [ ] `DEV_MODE=false`
- [ ] `PASSPORT_SIGNING_SECRET` is a production secret (not the dev default)
- [ ] `RATE_LIMIT_OPEN_PER_MINUTE` tuned for expected traffic
- [ ] ClickHouse connected for telemetry pipeline
- [ ] Trivy scan clean on Docker image
- [ ] 3 consecutive green test runs post-deploy

---

## Monitoring

| Signal | Where | Alert threshold |
|--------|-------|----------------|
| 429 rate on open endpoints | ClickHouse / telemetry | >5% of requests |
| PG pool exhaustion | App logs (`BackendUnavailableError`) | Any occurrence |
| Redis unavailable | `GET /api/health` → `redis: false` | Any occurrence |
| Test suite regression | CI | Any failure blocks deploy |
