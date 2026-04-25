# TokenDNA — Kubernetes Deployment Runbook

The canonical deploy path is the Helm chart in
`deploy/helm/tokendna/`. Plain-YAML manifests in `deploy/k8s/` are a
fallback for clusters that cannot run Helm.

## Helm install

```bash
# 1. Create the namespace and secret (one-time)
kubectl create namespace tokendna
kubectl create secret generic tokendna-secrets -n tokendna \
  --from-literal=TOKENDNA_DELEGATION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=TOKENDNA_WORKFLOW_SECRET="$(openssl rand -hex 32)" \
  --from-literal=TOKENDNA_HONEYPOT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=TOKENDNA_POSTURE_SECRET="$(openssl rand -hex 32)" \
  --from-literal=DATABASE_URL="postgresql://tokendna:***@db:5432/tokendna" \
  --from-literal=AUDIT_HMAC_KEY="$(openssl rand -hex 32)" \
  --from-literal=DNA_HMAC_KEY="$(openssl rand -hex 32)" \
  --from-literal=ATTESTATION_CA_SECRET="$(openssl rand -hex 32)"

# 2. Install the chart
helm install tokendna deploy/helm/tokendna \
  --namespace tokendna \
  --set image.tag=0.1.0
```

A pre-install Helm hook runs `alembic upgrade head` against
`DATABASE_URL` before the rolling deployment proceeds. Roll-backs use
`helm rollback`; the migration job is **not** automatically reversed —
operate Alembic by hand for that.

## Hardening defaults

The chart ships with these production defaults; edit `values.yaml` only
if you understand the trade-off.

* `runAsNonRoot: true`, `runAsUser: 10001`
* `readOnlyRootFilesystem: true` (uses emptyDir for `/tmp` and cache)
* `allowPrivilegeEscalation: false`, all caps dropped
* `seccompProfile.type: RuntimeDefault`
* `automountServiceAccountToken: false`
* Topology spread across hostnames; `PodDisruptionBudget` minAvailable=2
* `NetworkPolicy` restricts ingress to `ingress-nginx` + `monitoring`

## Probes

* `/healthz` — liveness, always returns 200 while the process is up.
* `/readyz` — readiness, 503 when Redis or ClickHouse are down.
* `/metrics` — Prometheus exposition (scraped by ServiceMonitor when
  the prometheus-operator CRD is present).

## Upgrades

```bash
helm upgrade tokendna deploy/helm/tokendna \
  --namespace tokendna \
  --set image.tag=0.2.0 \
  --atomic --timeout 5m
```

`--atomic` rolls back automatically if the upgrade fails. The pre-upgrade
migration job runs first; if it fails, the deployment is unchanged.

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Pod CrashLoopBackOff with "ConfigurationError" | secret_gate caught a missing or weak HMAC secret | Check the `tokendna-secrets` Secret; rotate any value matching a published dev default. |
| ServiceMonitor not picked up | prometheus-operator CRD not installed | Set `observability.prometheus.enabled=false` and scrape via pod annotations only, or install the operator. |
| Migration job hangs | DB unreachable from Kubernetes | Verify NetworkPolicy egress and that `DATABASE_URL` resolves from inside the pod. |
| HPA never scales | `metrics-server` not installed | Install it or set `autoscaling.enabled=false`. |
