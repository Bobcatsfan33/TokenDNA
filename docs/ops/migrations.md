# TokenDNA Storage Migrations

TokenDNA uses a lightweight runtime migration registry for the local control-plane appliance. The registry lives in `modules/storage/migrations.py`, records revisions in `tokendna_schema_migrations`, and uses the same shared storage connection factory as the API.

Alembic files remain in the repository for compatibility with older operator notes, but the production gate and API startup now use the TokenDNA migration registry.

## Common Operations

Apply pending migrations:

```bash
python scripts/migrate_storage.py
```

Check status without applying:

```bash
python scripts/migrate_storage.py --status
```

Run the full local appliance gate:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm tokendna-deployment-gate
```

## Production Contract

The migration path is intentionally shared:

- API startup runs `apply_migrations()`.
- The Docker deployment gate runs `apply_migrations()` before live smoke testing.
- CI runs preflight, migrations, smoke, and status checks against live Postgres.
- `/api/operator/status` exposes migration head, current revision, pending revisions, and errors.

If migration application fails, the API fails startup and the deployment gate exits non-zero.

## Adding A Revision

1. Add a new `Migration(...)` entry to `MIGRATIONS` in `modules/storage/migrations.py`.
2. Keep the revision id sortable, for example `YYYYMMDDNNNN_description`.
3. Make the migration idempotent where possible.
4. Add or update tests in `tests/test_storage_migrations.py`.
5. Run the live Postgres deployment gate before release.

## Baseline Philosophy

The baseline migration calls every module-level schema initializer once and records the revision only after all initializers succeed. A partial failure is never marked applied.

This keeps the deployment gate honest: if any backend module cannot initialize against the configured production storage, the product does not start and CI cannot pass silently.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `TOKENDNA_DB_BACKEND=postgres is required` | Smoke was run without production storage env | Source `.env` from the repo root or run the Docker deployment gate. |
| `storage migrations are not up to date` | Pending revision exists | Run `python scripts/migrate_storage.py`. |
| Baseline migration failed | One module initializer raised | Inspect the named module in the error, fix the DDL or env issue, then rerun the gate. |
| `tokendna_schema_migrations` is empty on a populated DB | The DB predates the registry | Run `python scripts/migrate_storage.py` during a maintenance window so the baseline can validate and record schema state. |
