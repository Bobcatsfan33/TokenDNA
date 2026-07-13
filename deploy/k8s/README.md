# Plain Kubernetes manifests

These manifests are a Helm-free fallback for clusters that cannot run Helm
(air-gapped FedRAMP environments, certain regulated infrastructures).

For all other deployments use the Helm chart in `../helm/tokendna/` — it
is the canonical and supported deployment path.

## Apply

```bash
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

kubectl apply -n tokendna -f deployment.yaml -f service.yaml
```

`deployment.yaml` is intentionally minimal: it does not include HPA,
PDB, NetworkPolicy, or ServiceMonitor. Add them per the Helm chart if
your cluster supports them.
