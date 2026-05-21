# TokenDNA Production Rollout Checklist

This checklist captures minimum controls before promoting to production.

## 1) Environment preflight

Run:

```bash
python3 scripts/preflight_prod.py --environment production
python3 scripts/postgres_smoke.py
```

This validates critical environment variables and recommended settings:

- `ENVIRONMENT=production`
- `TOKENDNA_ENV=production` (activates `modules/security/secret_gate.py`)
- `DEV_MODE=false`
- strong keys present (`ATTESTATION_CA_SECRET`, `AUDIT_HMAC_KEY`, `DNA_HMAC_KEY`)
  and no production secret still contains `change-me`
- module HMAC secrets present and not the published dev defaults
  (`TOKENDNA_DELEGATION_SECRET`, `TOKENDNA_WORKFLOW_SECRET`,
  `TOKENDNA_HONEYPOT_SECRET`, `TOKENDNA_POSTURE_SECRET`)
- operator/runtime thresholds configured (`EDGE_DECISION_SLO_MS`, `RATE_LIMIT_PER_MINUTE`)
- `TOKENDNA_DB_BACKEND=postgres` and `TOKENDNA_PG_DSN` set — SQLite is dev-only.
  `DATA_BACKEND` / `DATABASE_URL` are accepted compatibility aliases, but
  the TokenDNA-specific names should be present in production manifests.
- storage modules use the shared backend abstraction; any remaining direct
  `sqlite3.connect` usage is reported as a production blocker.
- the Postgres smoke test can create/query tenant API keys, usage metering,
  UIS events, policy bundles, decision audits, and staged-rollout grants.

For the Compose appliance pilot:

```bash
cp .env.production.example .env
# Edit .env, replacing every change-me value.
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres redis clickhouse
```

The FastAPI app calls `assert_production_secrets()` on startup. When
`TOKENDNA_ENV=production`, missing/weak/dev-default secrets cause the
process to refuse to start. See `docs/ops/backup-dr.md` for key
provisioning and rotation, and `docs/ops/external-engagements.md` for
the pen-test and compliance gates that follow this checklist.

## 2) Key rotation drill (staging first)

Run:

```bash
python3 scripts/rotation_drill.py --tenant-id <tenant-id> --agent-id <agent-id>
```

What it does:

1. Issues cert with legacy key.
2. Issues cert with rotated key.
3. Verifies both.
4. Revokes legacy cert.
5. Verifies revoked behavior.

The script fails non-zero if rotation invariants are violated.

## 3) Runtime SLO and reliability gate

Set and monitor:

- `EDGE_DECISION_SLO_MS`
- `EDGE_SLO_VIOLATION_ACTION`

Use `/api/operator/status` for current runtime posture and SLO targets.

## 4) CI load/security smoke

CI executes:

```bash
python3 tests/load_security_smoke.py --base-url http://localhost:8000 --timeout 2.0 --assert-p95-ms 250
```

Tune threshold for production as traffic grows.

## 5) Compliance automation schedule

Run scheduled artifact generation:

```bash
python3 scripts/compliance_scheduler.py --tenant-id <tenant-id> --frameworks disa_stig fedramp emass --output-dir ./artifacts/compliance
```

Produces signed OSCAL/eMASS snapshots that can be ingested downstream.
