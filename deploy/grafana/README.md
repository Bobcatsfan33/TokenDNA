# TokenDNA — Grafana Dashboards & Alerts

Two dashboards + a PrometheusRule alert bundle. Pair them with the
metrics emitted by `modules/observability/metrics.py` (PR #36).

## Dashboards

| File | UID | Purpose |
|------|-----|---------|
| `tokendna-overview.json` | `tokendna-overview` | Top-level service health: RPS, error rate, p50/p95/p99, top routes, UIS / policy throughput. |
| `tokendna-security.json` | `tokendna-security` | Security signals: secret-gate failures, 4xx surface, policy BLOCK rate, UIS DENY rate. |

### Import

Both dashboards have a `${datasource}` template variable so you don't
need to hard-code your Prometheus datasource UID at import time.

* Grafana UI → **Dashboards → Import → Upload JSON file** → pick the
  Prometheus datasource when prompted.
* Or via the HTTP API:

  ```bash
  curl -X POST -H "Authorization: Bearer $GRAFANA_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$(jq '{dashboard:., overwrite:true, folderUid:\"tokendna\"}' deploy/grafana/tokendna-overview.json)" \
    https://grafana.example.com/api/dashboards/db
  ```

* Or via Helm if you run `grafana/grafana` with sidecar discovery —
  drop the JSON files into a ConfigMap labeled per the sidecar's
  `dashboardLabel` setting.

## Alerts

`alert-rules.yaml` defines six rules in two groups:

* `tokendna.slo` — page-level rules for error rate, latency,
  secret-gate failures, readiness flapping.
* `tokendna.security` — warn-level rules for policy BLOCK spikes and
  UIS DENY bursts.

### Apply

If you run prometheus-operator:

```bash
# wrap as a PrometheusRule before applying
kubectl apply -f deploy/grafana/alert-rules.yaml -n monitoring
```

If you run a vanilla Prometheus, paste the `groups:` body into your
`prometheus.yml` rule files include path.

## What to do when something fires

Each alert has a `runbook_url` annotation pointing at the relevant
section of `docs/ops/`. The two highest-severity alerts are:

* **TokendnaSecretGateFailure** — never expected in steady state.
  An HMAC secret in production matched a published dev default, was
  too short, or was missing entirely. Stop the rollout and check the
  secret manager. See `docs/ops/backup-dr.md`.
* **TokendnaHighErrorRate** — sustained 5xx > 1%. Check
  `/readyz` on each pod and the most recent deploy. See
  `docs/ops/observability.md`.
