# Production deployment runbook

This is the document an SRE picks up at 2am when something is on fire and the engineer who deployed it is asleep. Step-by-step, no implicit context.

## Topology assumptions

```
            Cloudflare Worker (edge enforcement)
                       │
              [mTLS internal CA]
                       │
   ┌───────────────────▼───────────────────────────┐
   │  FastAPI / uvicorn  (n × stateless replicas)  │
   └───┬───────────────┬───────────────┬───────────┘
       │               │               │
       ▼               ▼               ▼
  Postgres 16      Redis 7         ClickHouse
  (TDE / EBS)      (Sentinel)      (replicated MergeTree)
```

Stateless tier: any number of API replicas, fronted by an L7 LB (ALB / Cloudflare LB / nginx).
Stateful tier: Postgres (primary + read replica), Redis (3-node Sentinel), ClickHouse (2-shard × 2-replica).

## Pre-deployment checklist

| Item                                              | Done? |
|---------------------------------------------------|-------|
| Compute sized: ≥4 vCPU / 8GB per API replica      |       |
| Postgres ≥16: ≥4 vCPU / 16GB / 200GB SSD          |       |
| Redis ≥7: 3 nodes ≥2 vCPU / 4GB each              |       |
| ClickHouse ≥24: 4 nodes ≥4 vCPU / 16GB / 500GB    |       |
| Internal CA issued (`scripts/issue_internal_certs.sh`) |  |
| Cert paths mounted into containers, env set       |       |
| Secrets provisioned (see "Secret provisioning") |       |
| Alembic migrations applied (`alembic upgrade head`) |     |
| Health endpoint reachable on port 8000            |       |
| Cloudflare Worker `wrangler deploy` succeeded     |       |
| KV namespace populated by first cron run          |       |
| Grafana dashboards loaded                         |       |
| Alert rules wired to PagerDuty / Slack            |       |

## Infrastructure sizing (per 1k agents / 50 rps sustained)

| Tier             | Per-shard footprint                  | Notes |
|------------------|--------------------------------------|-------|
| API              | 2 × `c6i.xlarge` (4 vCPU / 8GB)      | Scale linearly with rps. p99 holds at <100 ms up to 4× this with no ClickHouse degradation. |
| Postgres         | 1 × `m6g.xlarge` + 1 read replica    | 200 GB SSD; switch to `r6g.xlarge` if posture-statement queries dominate. |
| Redis            | 3 × `cache.r7g.large`                | Sentinel quorum; dataset stays ≤4 GB at this scale. |
| ClickHouse       | 4 × `r6g.xlarge` (2 shards × 2 reps) | 500 GB SSD per node; partition pruning keeps queries hot. |
| Worker           | Cloudflare Workers Unbound (per-rps cost) | Scales globally; no sizing decision. |

## TLS / certificate provisioning

External (clients ↔ edge): use whatever your edge CA is (Cloudflare Universal SSL, ACM, Let's Encrypt). The Worker handles termination.

Internal (API ↔ Redis / ClickHouse / Postgres): `scripts/issue_internal_certs.sh` for the dev / pilot path; HashiCorp Vault PKI or AWS Private CA for production. See `docs/operations/MTLS.md` for the full matrix.

```bash
# Pilot path
./scripts/issue_internal_certs.sh --out /etc/tokendna/tls
# Set the env vars listed in docs/operations/MTLS.md
```

## Secret provisioning

Required env vars (refuses to start without):

| Var                         | Source                                                |
|-----------------------------|-------------------------------------------------------|
| `TOKENDNA_DELEGATION_SECRET`| AWS Secrets Manager / Vault / GCP Secret Manager      |
| `TOKENDNA_WORKFLOW_SECRET`  | Same                                                  |
| `TOKENDNA_HONEYPOT_SECRET`  | Same                                                  |
| `TOKENDNA_POSTURE_SECRET`   | Same                                                  |
| `ATTESTATION_CA_SECRET`     | Same — or `ATTESTATION_KEY_BACKEND=aws_kms` + key id  |
| `EDGE_SYNC_TOKEN`           | Worker secret + backend env (must match)              |
| `FIELD_CRYPTO_KEY` / `_KEYRING` | Same — for at-rest column encryption              |

Generate fresh values with:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

The secret_gate (`modules/security/secret_gate.py`) rejects:
- Empty values
- The published dev defaults
- Secrets shorter than 32 bytes

## Database initialization

```bash
# In the API container or any host with backend access
alembic upgrade head
```

If migrations fail mid-stream:
1. The API process exits non-zero — **do not** restart with `--allow-out-of-sync` (this masks real problems).
2. `alembic current` shows the stuck revision.
3. Roll back: `alembic downgrade -1`.
4. Inspect `alembic/versions/<id>.py` for the offending op.
5. Fix the migration script in a follow-up PR (never edit the live one in place).

## Health checks

```bash
curl -fsS https://<api-host>/api/health | jq .
# {
#   "redis":      {"ok": true},
#   "clickhouse": {"ok": true},
#   "postgres":   {"ok": true},
#   "tor_list":   {"ok": true, "count": 13...},
#   "fips":       {"active": true, "environment": "production"}
# }
```

| Check        | Healthy when                                    | If unhealthy                                  |
|--------------|--------------------------------------------------|-----------------------------------------------|
| `redis.ok`     | Sentinel reports primary alive               | See "Redis primary failover" runbook below   |
| `clickhouse.ok`| Last write within 30s                        | See "ClickHouse degraded" runbook            |
| `postgres.ok`  | Connection established + read returns         | See "Postgres failover" runbook              |
| `fips.active`  | `production` env + FIPS mode active           | Block deploy; investigate kernel/OpenSSL FIPS|

The Cloudflare Worker hits `/api/health` every 60s; if 3 consecutive checks fail, it serves a 503 to clients with a `Retry-After: 60` header.

## Deployment

```bash
# Compose path
docker compose -f docker-compose.yml -f docker-compose.production.yml pull
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --no-deps tokendna

# Helm path
helm upgrade tokendna ./deploy/helm/tokendna \
  -f values.production.yaml \
  --set image.tag=v$(cat tokendna_sdk/__init__.py | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

# Plain kubectl path
kubectl apply -f deploy/k8s/
kubectl rollout status deployment/tokendna-api --timeout=5m
```

## Rollback procedure

```bash
# Compose path
docker compose -f docker-compose.yml -f docker-compose.production.yml pull tokendna:<previous-tag>
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --no-deps tokendna

# Helm path
helm rollback tokendna   # rolls to previous release

# kubectl path
kubectl rollout undo deployment/tokendna-api
kubectl rollout status deployment/tokendna-api --timeout=5m
```

**Hard rule**: every release tag is immutable. Don't re-tag `:latest` over a known-bad image. Always roll *forward* with a new tag, even if the only change is a one-line revert.

## Monitoring

Grafana dashboards are in `deploy/grafana/`. Apply to your Grafana instance:

```bash
for f in deploy/grafana/*.json; do
  curl -X POST -H "Authorization: Bearer $GRAFANA_TOKEN" \
       -H "Content-Type: application/json" \
       -d @"$f" \
       "$GRAFANA_URL/api/dashboards/import"
done
```

Critical dashboards:
- **Runtime Risk Engine** — request volume, p50/p99 latency, BLOCK/STEP_UP/REVOKE rates per tenant.
- **Trust Graph** — anomalies-per-hour, top affected agents, federation handshake activity.
- **Compliance Posture** — control coverage scores per framework, evidence-package generation lag.
- **Edge Worker** — cache hit rate on cert-revocation + drift, snapshot freshness.

## Alerting

Wire the rules in `deploy/grafana/alerts.json` to your PagerDuty / Slack:

| Alert                                         | Severity | Page when                                         |
|-----------------------------------------------|----------|---------------------------------------------------|
| `BLOCK rate spike > 10× baseline`             | Page     | True for 5 min                                    |
| `REVOKE issued`                               | Page     | Always (one alert per event, deduped per agent)   |
| `p99 /secure > 100 ms`                        | Page     | True for 5 min                                    |
| `Postgres replication lag > 60 s`             | Page     | True for 2 min                                    |
| `Edge snapshot age > 5 min`                   | Page     | True for 1 min                                    |
| `FIPS mode dropped`                           | Page     | Always (single occurrence)                        |
| `Drift score average climbing > 5%/hr tenant` | Slack    | True for 30 min                                   |

## Post-deploy validation

Within 5 minutes of deploy:

```bash
# Smoke
curl -fsS https://<api-host>/api/health
# Run the demo arc against the live tenant
python3 scripts/demo_runtime_risk_engine.py --tenant <prod-tenant> --scene self-mod
# Confirm a BLOCK appears in the dashboard within 5s
```

Within 30 minutes:

- Check the Grafana dashboards for any red panels.
- Confirm the Edge Worker snapshot age <2 min.
- Run `scripts/load_test_realistic.py --smoke` against the staging mirror.
