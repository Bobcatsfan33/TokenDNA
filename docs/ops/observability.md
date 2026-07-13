# TokenDNA — Observability Runbook

This document covers the three runtime observability surfaces:

* **Metrics** — Prometheus scrape at `/metrics`.
* **Tracing** — OpenTelemetry OTLP/HTTP exporter when configured.
* **Error reporting** — Sentry SDK when configured.

All three are opt-in: when the relevant environment variable is unset, or
the optional dependency is not installed, the module degrades to a no-op.
Production must enable at least metrics + error reporting.

---

## 1. Health and probe endpoints

| Path | Purpose | Auth | Behavior |
|------|---------|------|----------|
| `/` | Legacy summary | none | Mixed health + identity. |
| `/healthz` | Liveness probe | none | Always 200 while the process is up. |
| `/readyz` | Readiness probe | none | 200 when Redis + ClickHouse healthy; 503 otherwise. |
| `/metrics` | Prometheus scrape | none (network-restricted) | OpenMetrics text. |

`/metrics` should not be reachable from the public internet. Restrict it
to the cluster's metrics namespace via NetworkPolicy / firewall.

---

## 2. Metrics

The Prometheus exporter is in `modules/observability/metrics.py`. When
`prometheus_client` is installed the metrics below are emitted; otherwise
the module returns a stub body so scrape configs do not error.

### Core metrics

| Metric | Type | Labels |
|--------|------|--------|
| `tokendna_http_requests_total` | counter | method, route, status_class |
| `tokendna_http_request_duration_seconds` | histogram | method, route |
| `tokendna_uis_events_total` | counter | protocol, decision |
| `tokendna_policy_decisions_total` | counter | module, decision |
| `tokendna_secret_gate_failures_total` | counter | env_var |

### Alerts and dashboards

Ready-to-apply Prometheus rules and Grafana dashboards live under
`deploy/grafana/`:

* `tokendna-overview.json` — service-level dashboard (RPS, error rate,
  latency, top routes, UIS / policy throughput).
* `tokendna-security.json` — security-signal dashboard (secret-gate
  failures, policy BLOCK rate, UIS DENY bursts).
* `alert-rules.yaml` — six rules across two groups (`tokendna.slo`,
  `tokendna.security`); page-level alerts include `runbook_url`
  annotations.

See `deploy/grafana/README.md` for import instructions.

The two highest-severity rules are inlined here for reference:

```promql
# 5xx error rate above 1% over 10 minutes — page
sum(rate(tokendna_http_requests_total{status_class="5xx"}[10m]))
  / clamp_min(sum(rate(tokendna_http_requests_total[10m])), 1) > 0.01

# Secret gate failed at startup — page immediately
increase(tokendna_secret_gate_failures_total[5m]) > 0
```

### Prometheus scrape sample

```yaml
- job_name: tokendna-api
  metrics_path: /metrics
  scrape_interval: 15s
  scrape_timeout: 10s
  static_configs:
    - targets: ["tokendna:8000"]
  relabel_configs:
    - source_labels: [__address__]
      target_label: instance
```

---

## 3. Tracing (OpenTelemetry)

`modules/observability/tracing.py` wires up an OTLP/HTTP span exporter
when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

### Required dependencies (production)

```
pip install \
  opentelemetry-sdk \
  opentelemetry-exporter-otlp-proto-http \
  opentelemetry-instrumentation-fastapi
```

### Environment variables

| Var | Purpose | Default |
|-----|---------|---------|
| `OTEL_SERVICE_NAME` | service name | `tokendna` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | collector URL (required) | _unset → tracing disabled_ |
| `OTEL_EXPORTER_OTLP_HEADERS` | `key=value,key=value` | _unset_ |
| `OTEL_TRACES_SAMPLER_ARG` | float `[0,1]` ratio | `0.1` |
| `OTEL_RESOURCE_ATTRIBUTES` | extra attributes | _unset_ |

### What gets traced

* Every FastAPI request (auto via `FastAPIInstrumentor`).
* Manual spans inside hot-path modules can be added with the standard
  `tracer = trace.get_tracer(__name__)` pattern.

We deliberately keep the default sample rate low (10%) — high-volume
ingestion endpoints (UIS event stream) generate enough traces that
100% sampling is cost-prohibitive at scale.

---

## 4. Error reporting (Sentry)

`modules/observability/error_reporting.py` initializes the Sentry SDK
when `SENTRY_DSN` is set.

### Required dependencies (production)

```
pip install sentry-sdk
```

### Environment variables

| Var | Purpose | Default |
|-----|---------|---------|
| `SENTRY_DSN` | project DSN (required) | _unset → disabled_ |
| `SENTRY_ENVIRONMENT` | environment label | `$ENVIRONMENT` or `dev` |
| `SENTRY_RELEASE` | release tag | `$APP_VERSION` or `dev` |
| `SENTRY_TRACES_SAMPLE_RATE` | float `[0,1]` | `0.1` |

### PII / secret hygiene

`send_default_pii=False` is set unconditionally and a `before_send` hook
strips:

* Headers named `authorization`, `cookie`, `x-api-key`, etc.
* Env-var-style keys for every TokenDNA HMAC secret + AWS / Postgres / Vault tokens.
* Any string matching `Bearer\s+\S+` in messages and breadcrumbs.

If you add a new secret env var, also add it to `_REDACT_KEYS` in
`error_reporting.py`.

---

## 5. Smoke test

```bash
curl -fsS localhost:8000/healthz   # 200 ok
curl -fsS localhost:8000/readyz    # 200 ok or 503 degraded
curl -fsS localhost:8000/metrics | head
```

A passing `/metrics` response in production must include
`tokendna_http_requests_total` non-zero counters within a minute of the
first request.
