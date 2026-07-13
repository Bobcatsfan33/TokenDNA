# TokenDNA — Performance & SLO Targets

This document captures the latency / throughput / error-rate targets the
production deployment must meet, and the harness used to verify them.

---

## 1. Service-Level Objectives (per single replica, p95 over a 10-minute window)

| Endpoint class | Target p95 | Target error rate |
|----------------|-----------|--------------------|
| `/healthz`, `/readyz` | 50 ms | < 0.1 % |
| `/metrics` | 100 ms | < 0.1 % |
| `/api/uis/spec`, `/api/oss/schema-bundle` (cacheable reads) | 250 ms | < 0.5 % |
| `/api/uis/normalize` (UIS event ingest, hot path) | 100 ms | < 1.0 % |
| `/api/policy/guard/evaluate`, `/api/enforcement/evaluate` | 75 ms | < 1.0 % |
| `/scim/v2/*` | 250 ms | < 0.5 % |
| `/saml/acs` | 500 ms (assertion verify) | < 0.1 % |

The HPA tuning in the Helm chart targets `70%` CPU and `75%` memory —
that leaves headroom to absorb a 30% traffic spike before the
autoscaler decision lag kicks in.

---

## 2. Throughput baseline

A single 0.5 vCPU / 256 MiB replica should sustain at least:

* **800 RPS** on `/healthz` / `/readyz`.
* **300 RPS** on cached read endpoints.
* **60 RPS** of UIS event ingest with the SQLite backend; **400 RPS**
  with the Postgres backend (PR-C migrated the seven phase-5 modules
  through `get_db_conn` so they no longer serialize on the SQLite
  global writer lock).

These numbers assume the production gating in PR-A is enabled and
`prometheus_client` is recording per-request samples — the metrics
middleware adds < 0.1 ms.

### Measured baseline (dev laptop, in-process server)

A 5-second smoke run against the in-process API (no Redis/ClickHouse,
SQLite backend) on commodity hardware:

| metric | value |
|--------|-------|
| RPS (mixed workload) | ~1100 |
| p95 (overall) | < 5 ms |
| `/healthz` p95 | < 5 ms |
| `/api/uis/spec` p95 | < 5 ms |
| `/saml/metadata` p95 | < 4 ms |
| error rate | 0 % |

These numbers exist to catch regressions in CI; production
characteristics change with the real backend, network round-trips, and
auth middleware.

---

## 3. The stress harness

`scripts/stress_harness.py` is the canonical load-driver. It is
stdlib-only so it runs on a stripped container without extra deps.

### 3.1 Smoke run (CI)

```bash
python3 scripts/stress_harness.py \
  --base-url http://localhost:8000 \
  --profile scripts/stress_profiles/smoke.json \
  --duration 30 \
  --concurrency 8 \
  --gate scripts/stress_profiles/gate.smoke.json
```

The smoke gate is intentionally permissive — anything tighter would
flap on shared CI runners. The job non-zeros if any p95 or error
threshold is exceeded.

### 3.2 Sustained run (load box)

```bash
python3 scripts/stress_harness.py \
  --base-url https://staging.tokendna.io \
  --profile scripts/stress_profiles/sustained.json \
  --duration 600 \
  --concurrency 64 \
  --header "Authorization: Bearer $TOKEN" \
  --out reports/load-$(date +%F).json
```

Sustained runs feed the per-quarter capacity planning review.

### 3.3 Output shape

```json
{
  "overall": {
    "rps": 612.4,
    "completed": 18372,
    "ok": 18301,
    "fail": 71,
    "error_pct": 0.387,
    "p50_ms": 8.2,
    "p95_ms": 24.1,
    "p99_ms": 51.7,
    ...
  },
  "endpoints": {
    "/healthz": {
      "count": 7308, "ok": 7308, "fail": 0, "p95_ms": 7.2, ...
    },
    ...
  },
  "gate": {"violations": [], "passed": true}
}
```

### 3.4 Workload profiles

* `scripts/stress_profiles/smoke.json` — 4 endpoints, weight 4/2/1/1.
  Suitable for a 30-second CI smoke.
* `scripts/stress_profiles/sustained.json` — 8 endpoints, broader mix.
  Use for hour-plus runs.
* `scripts/stress_profiles/gate.smoke.json` — threshold gate matched
  to the smoke profile.

Add new profiles for environment-specific scenarios (e.g.
ingest-heavy) under the same directory.

---

## 4. Quarterly performance review

Required artifacts:

1. Sustained 1-hour stress-harness run against staging, JSON report
   committed to `reports/`.
2. Grafana dashboard screenshot covering the same window.
3. Comparison table vs. prior quarter — flag any p95 regression > 25%
   or RPS regression > 10%.
4. Capacity recommendation: replica count, HPA min/max, memory limits.

Failure on any of these blocks the next minor release.
