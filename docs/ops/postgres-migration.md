# TokenDNA — Postgres Migration

This document tracks which modules support both SQLite and Postgres, the
migration approach, and the state of the rollout.

## Why migrate

SQLite is fine for a single-process developer workflow but is the wrong
storage layer for production:

* Single writer at a time → tail-latency cliff under concurrent ingest.
* No replication / streaming WAL → no zero-loss failover.
* No native materialized views or partial indexes — half the analytical
  queries we need fall back to full scans.

Postgres closes all three gaps and keeps SQL portability for the simple
CRUD shape every TokenDNA module uses today.

## Migration approach

We do **not** rewrite each module's queries. The migration is mechanical:

1. Replace the per-module `_get_conn()` / `_cursor()` helpers with the
   shared `modules.storage.pg_connection.get_db_conn()` context manager.
2. Wrap the cursor in `AdaptedCursor`, which auto-translates SQLite-style
   `?` placeholders to psycopg `%s` when running against Postgres.
3. Replace any `executescript(...)` block with a tuple of statements
   passed through `modules.storage.ddl_runner.run_ddl()`. psycopg cursors
   only accept one statement at a time; the runner handles both backends.
4. Drop SQLite-specific PRAGMAs from the DDL — `get_db_conn()` applies
   them in SQLite mode.

The rest of each module's SQL — `INSERT … ON CONFLICT DO NOTHING`,
recursive CTEs for graph traversal, `INTEGER` boolean columns — is
already portable.

### Activating Postgres

```bash
export TOKENDNA_DB_BACKEND=postgres
export TOKENDNA_PG_DSN="postgresql://tokendna:***@db:5432/tokendna"
```

The pool is sized via `TOKENDNA_PG_POOL_MIN` / `TOKENDNA_PG_POOL_MAX`
(defaults `2` / `10`).

## Migration status

| Module | Migrated | Notes |
|--------|----------|-------|
| `modules/identity/passport.py` | ✅ |  uses `AdaptedCursor` |
| `modules/identity/uis_store.py` | ✅ | dual-write capable |
| `modules/identity/trust_graph.py` | ✅ | recursive CTE on PG |
| `modules/identity/intent_correlation.py` | ✅ | |
| `modules/identity/blast_radius.py` | ✅ | PG read path stubbed |
| `modules/identity/verifier_reputation.py` | ✅ | |
| `modules/identity/delegation_receipt.py` | ✅ | |
| `modules/identity/workflow_attestation.py` | ✅ | |
| `modules/identity/honeypot_mesh.py` | ✅ | |
| `modules/identity/compliance_posture.py` | ✅ | |
| `modules/product/threat_sharing.py` | ✅ | |
| `modules/product/threat_sharing_flywheel.py` | ✅ | |
| `modules/product/staged_rollout.py` | ✅ | |
| `modules/identity/policy_guard.py` | ✅ | this PR |
| `modules/identity/agent_lifecycle.py` | ✅ | this PR |
| `modules/identity/permission_drift.py` | ✅ | this PR |
| `modules/identity/mcp_inspector.py` | ✅ | this PR |
| `modules/identity/mcp_gateway.py` | ✅ | this PR |
| `modules/identity/agent_discovery.py` | ✅ | this PR |
| `modules/identity/enforcement_plane.py` | ✅ | this PR |
| `modules/identity/cert_dashboard.py` | ⏳ | follow-up |
| `modules/identity/policy_advisor.py` | ⏳ | follow-up |
| `modules/identity/behavioral_dna.py` | ⏳ | follow-up |
| `modules/identity/compliance_engine.py` | ⏳ | follow-up |
| `modules/identity/attestation_store.py` | ⏳ | follow-up |

## Verification

For each migrated module:

```bash
# SQLite (default) — must pass
pytest tests/test_<module>.py -v

# Postgres — requires TOKENDNA_PG_DSN
TOKENDNA_DB_BACKEND=postgres TOKENDNA_PG_DSN=$DSN \
  pytest tests/test_<module>.py -v
```

Postgres test runs are not part of the default CI; they need a live
Postgres and are gated behind a `pg_integration` mark in the next sprint
(PR-D introduces the Alembic baseline that the integration tests use).

## Known gaps

* `INTEGER` columns used as booleans require Postgres 15+'s implicit
  cast, or the rare query that filters `WHERE col = 1` to be rewritten
  as `WHERE col != 0`.
* `INSERT OR REPLACE` is not standard SQL — none of the migrated modules
  use it, but watch for it in future modules.
* SQLite's `last_insert_rowid()` is auto-mapped by `AdaptedCursor.lastrowid`,
  but Postgres returns it only when the table has a sequence — TokenDNA
  uses explicit UUIDs everywhere so this is moot today.
