# Incident response playbook

What to do when **TokenDNA itself** has an incident — not when a customer's agent misbehaves (that's the dashboard's whole job). This is the document the on-call engineer opens when their pager fires.

## On-call rotation

| Tier            | Who                                  | Escalation timeout |
|-----------------|---------------------------------------|---------------------|
| L1              | Primary on-call (PagerDuty rota)     | 5 min               |
| L2              | Secondary on-call                     | 15 min              |
| L3              | Engineering manager                   | 30 min              |
| L4              | CTO                                   | 60 min              |

Escalation is automatic on ack-timeout. **L4 page = wake the CTO**: only acceptable for active customer impact >5 min, full-region outage, or suspected security breach.

## Severity matrix

| Sev   | Definition                                                           | Initial response                          | Comms            |
|-------|----------------------------------------------------------------------|-------------------------------------------|------------------|
| SEV-1 | Active customer impact OR confirmed security breach                  | All hands; CTO paged; war room opened     | Status page + customer notification within 30 min |
| SEV-2 | Significant degraded service for one customer or one region          | On-call engages within 5 min              | Status page banner; affected customer email |
| SEV-3 | Background latency creep, slow data pipeline, single replica down    | Investigated within 1 business hour       | Internal Slack only |
| SEV-4 | Cosmetic / documentation / non-impacting                              | Triaged in next standup                   | None             |

## Universal opening checklist (any sev)

Before anything else:

1. **Acknowledge the page**. Stops the auto-escalation timer.
2. **Open the war room**: `#incident-<utc-stamp>` Slack channel + a video call.
3. **Pin the alert**: paste the PagerDuty/Slack alert text into the channel as the first message.
4. **Check Grafana** before SSH'ing anywhere — the Runtime Risk Engine + Edge Worker dashboards usually answer 80% of the question.
5. **Check the recent deploys**: `git log --oneline --since='2 hours ago' main`.
6. **Pick one IC** (incident commander) — they don't fix anything; they coordinate.

## Scenario playbooks

### A. Bad deploy (most common)

Symptoms: spike in 5xx or p99 immediately after a deploy.

```bash
# Roll back
helm rollback tokendna     # or kubectl rollout undo deployment/tokendna-api
kubectl rollout status deployment/tokendna-api --timeout=5m

# Confirm health
curl -fsS https://<api-host>/api/health
```

If the health check is still failing post-rollback, the issue is data-tier; jump to scenario B/C/D as appropriate.

### B. Postgres primary down

Symptoms: `postgres.ok=false` for >30 s; sustained 503s on read paths.

1. Check replication lag on the sync replica: `SELECT * FROM pg_stat_replication;` against the replica.
2. If lag is 0: `pg_ctl promote` on the sync replica.
3. Update the connection-string secret in your secret manager.
4. Bounce the API: `kubectl rollout restart deployment/tokendna-api`.
5. Validate writes: `curl -X POST https://<api-host>/api/uis/event -d ...`.
6. Replace the lost primary (IaC pipeline) within 24 h — never run prod without two writers' worth of standby.

### C. Redis whole cluster down

Symptoms: `redis.ok=false`; nonce-replay attacks possible during the outage.

1. The API enters degraded mode automatically — clients keep getting 200s, but DPoP nonce checks become best-effort.
2. **Decide**: do you tolerate the degraded enforcement window (acceptable for ≤15 min for most customers) or do you take the platform down?
   - Tolerate: page customer ops with a banner.
   - Refuse: edit the Cloudflare Worker var `EMERGENCY_DENY=true` — every request returns 503 until Redis is back.
3. Restore Redis from RDB snapshot or rebuild from Postgres.

### D. Cloudflare Worker outage

Symptoms: customers report 5xx but our API health is fine.

This is out of our hands. Document the Cloudflare incident ID in the war room, post the customer comms, and wait. Do not "fail open" by removing the Worker — that strips the entire edge enforcement layer.

### E. Suspected security breach (SEV-1)

Symptoms: anything from credential leak alert to detection of an unauthorised admin operation.

1. **Page the CTO**. SEV-1 by definition.
2. **Open a private incident channel** — invite only the IC, CTO, security lead, and the on-call engineer. Do not discuss in `#incident-*` until containment is confirmed.
3. **Containment**: rotate any potentially exposed credentials immediately. The four classes of secrets that warrant a mass rotation:
   - **Attestation CA key**: see "Mass attestation revocation" below + "Emergency CA key rotation".
   - **Tenant API keys**: invalidate via `POST /api/admin/keys/<id>/revoke`. Notify the affected tenant.
   - **EDGE_SYNC_TOKEN**: rotate the worker secret + the backend env in lock-step.
   - **FIELD_CRYPTO_KEY** / `_KEYRING`: rotate via `field_crypto`'s versioned-keyring path; old ciphertexts remain readable until re-encrypted.
4. **Forensic audit**: see "Hash-chain forensic audit procedure" below.
5. **Customer notification**: per the SEV-1 comms timeline, even if the breach scope is contained.
6. **Post-mortem**: blameless, within 5 business days. Public version on the status page if customer data was potentially exposed.

## Mass attestation revocation

When you need to invalidate every issued attestation cert in a tenant or globally — for example, a CA key compromise, or a partner organization unceremoniously leaving the federation.

```bash
# Per-tenant: revoke every active cert for one tenant
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" \
  "https://<api-host>/api/admin/certificates/revoke-all" \
  -d '{"tenant_id": "<tenant>", "reason": "ca_key_rotation"}'

# Global (use with extreme care; affects every tenant):
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" \
  "https://<api-host>/api/admin/certificates/revoke-all" \
  -d '{"global": true, "reason": "ca_key_compromise_2026_<id>"}'
```

What this does:
- Marks every cert with `status=revoked` in `attestation_certificates`.
- Appends a `REVOKE` entry to the certificate transparency log per cert (preserves audit chain).
- Within 60 s the Cloudflare Worker's KV cache picks up the revocations via the next snapshot refresh; new requests bearing the revoked certs get 401 at the edge.

## Emergency CA key rotation

```bash
# 1. Provision a new key in KMS (or CloudHSM for IL5)
aws kms create-key \
  --description "TokenDNA CA $(date -u +%Y%m%d) emergency rotation" \
  --customer-master-key-spec RSA_2048 \
  --key-usage SIGN_VERIFY

# 2. Note the new KeyId (format: arn:aws:kms:...:key/<uuid>)
NEW_KEY_ID=alias/tokendna-ca-$(date -u +%Y%m%d-emergency)
aws kms create-alias --alias-name "$NEW_KEY_ID" --target-key-id <new-key-uuid>

# 3. Rotate the active key + add to the keyring (no downtime; old certs still verify)
python3 -c "
from modules.identity.trust_authority import rotate_active_key
print(rotate_active_key(
    'ca-emergency-$(date -u +%Y%m%d)',
    algorithm='RS256', backend='aws_kms',
    kms_key_id='$NEW_KEY_ID',
))
"

# 4. Persist the updated ATTESTATION_KEYRING_JSON / ATTESTATION_ACTIVE_KEY_ID
#    to your secret manager — the rotate_active_key call only updates env in
#    the running process; production needs the secret manager update for the
#    next pod to pick it up.

# 5. Bounce the API
kubectl rollout restart deployment/tokendna-api

# 6. Verify a fresh issuance picks up the new key
curl -X POST -H "X-API-Key: $TENANT_KEY" \
  "https://<api-host>/api/agent/certificates/issue" -d '{...}' | jq .ca_key_id
# → should match the new key_id
```

The old key stays in the keyring so every previously-issued cert keeps verifying. If the rotation was triggered by suspected compromise of the OLD key, follow up with **"Mass attestation revocation"** above to invalidate any cert signed by the compromised key.

## Hash-chain forensic audit

The certificate transparency log (`certificate_transparency_log` table) is hash-chained: every entry includes the SHA-256 of its predecessor + a Merkle root over the tenant's history. To verify integrity after a suspected breach:

```bash
# Per-tenant verification — flags the first divergence if any
curl -fsS -H "X-API-Key: $TENANT_KEY" \
  "https://<api-host>/api/agent/certificates/transparency-log/verify" \
  | jq .

# Healthy:
# {"integrity": {"valid": true, "checked": 12345, "last_log_index": 12345}}

# Compromised:
# {"integrity": {"valid": false, "first_bad_log_index": 4711,
#                "expected_hash": "...", "actual_hash": "..."}}
```

If `valid=false`, the log has been tampered with from `first_bad_log_index` onward. Do NOT touch the table; instead:

1. Snapshot the table (`pg_dump compliance_evidence_packages certificate_transparency_log`).
2. Pull the equivalent from your Postgres backup just before the suspected breach window.
3. The diff identifies which entries were altered + by which user/process (cross-reference with audit log).

## Customer comms templates

### SEV-1 initial (within 30 min of detection)

> We're investigating an active incident affecting TokenDNA. Customer impact is currently **{{none / partial / full}}**. We've engaged our incident response team. We'll update at {{HH:MM UTC}} or sooner. Status page: status.tokendna.io.

### SEV-1 update (every 30 min)

> Update on the incident detected at {{utc}}: {{one-sentence current state}}. Mitigation in progress: {{one-sentence what we're doing}}. Next update at {{HH:MM UTC}}.

### SEV-1 resolved

> The incident detected at {{utc}} is resolved. Total customer impact: **{{minutes}}**. Root cause: {{one-sentence}}. Public post-mortem will be published within 5 business days.

## Post-mortem template

`docs/operations/post-mortems/<utc-date>-<slug>.md`:

```markdown
# Post-mortem — <slug>

**Date**: <utc>
**Severity**: SEV-N
**Duration**: <hh:mm>
**Customer impact**: <description>

## Timeline (UTC)
- HH:MM — first signal
- HH:MM — page acknowledged
- HH:MM — root cause identified
- HH:MM — mitigation deployed
- HH:MM — customer impact ended
- HH:MM — incident closed

## Root cause
<what actually happened, no blame>

## Detection
<how we found out — what worked, what didn't>

## Response
<what we did, in order, with timestamps>

## What went well
- ...

## What didn't go well
- ...

## Action items
- [ ] <item> — owner: <name> — due: <date>
```

Action items file as Linear / Jira tickets immediately; review at the next monthly engineering all-hands.
