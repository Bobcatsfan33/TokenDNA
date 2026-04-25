# TokenDNA — Backup, Restore & Disaster Recovery

_Owner: Platform on-call · Status: target document — implementation tracked in PR-D / PR-E_

This document defines TokenDNA's backup posture, recovery objectives, and the
operational runbooks required to satisfy them. It is the source of truth for
RPO/RTO commitments published to customers and for the production-readiness
gate in `scripts/preflight_prod.py`.

---

## 1. Recovery Objectives

| Tier | Data class | RPO | RTO |
|------|------------|-----|-----|
| 0 | HMAC keys, KMS material | **0** (must never be lost) | < 15 min |
| 1 | Tenants, agents, attestations, trust graph, audit log | **5 min** | **30 min** |
| 2 | Threat sharing, flywheel scores, behavioral DNA fingerprints | **15 min** | **2 hr** |
| 3 | Dashboards, demo seed data, calibration outputs | **24 hr** | **8 hr** |

The 30-minute RTO for Tier 1 assumes warm standby. Cold-restore from object
storage targets a 4-hour RTO and is tested quarterly.

---

## 2. Backup Strategy

### 2.1 Postgres (primary)

* **Continuous WAL archiving** to object storage every 60 seconds.
* **Base backups** every 24 hours via `pg_basebackup`, retained for 35 days.
* **Point-in-time recovery (PITR)** target: any second within the last 7 days.
* **Cross-region replica** for Tier 0/1 customers (asynchronous streaming).
* Backup integrity is verified weekly by restoring to a scratch instance and
  running `scripts/backup_verify.py` (added in PR-E).

### 2.2 HMAC keys & KMS

* All HMAC keys (`TOKENDNA_DELEGATION_SECRET`, `TOKENDNA_WORKFLOW_SECRET`,
  `TOKENDNA_HONEYPOT_SECRET`, `TOKENDNA_POSTURE_SECRET`) live in AWS KMS or
  HashiCorp Vault — see `modules/security/secrets.py`.
* KMS keys use cross-region replication; Vault uses Raft + auto-unseal.
* Rotation cadence: 90 days, tracked in `scripts/rotation_drill.py`.
* **Never** stored in Postgres or in container images.

### 2.3 Object storage (audit log archive, attestation blobs)

* S3 with versioning + Object Lock (Compliance mode, 1-year retention).
* Replication: same-account, cross-region.
* Lifecycle: Standard → Glacier IR after 90 days; never expire.

---

## 3. Restore Runbooks

### 3.1 Postgres point-in-time restore

```bash
# Pick a target timestamp (UTC).
RESTORE_TARGET="2026-04-24T13:42:00Z"

# 1. Provision a fresh PG cluster from the most recent base backup before $RESTORE_TARGET.
# 2. Replay WAL up to $RESTORE_TARGET.
# 3. Promote, run preflight, and route writes.
scripts/restore_pg.sh --target "$RESTORE_TARGET" --confirm
```

### 3.2 HMAC key recovery

If a key is suspected lost or compromised:

1. Generate new key in KMS / Vault. Tag with rotation reason.
2. Run `scripts/rotation_drill.py --apply` to roll signing to the new key.
3. Mark the old key for verification-only for 30 days, then disable.
4. Audit-log the rotation via `audit_log.log_event(CONFIG_CHANGED, ...)`.

### 3.3 Region failover

Documented separately in `docs/ops/region-failover.md` (PR-E).

---

## 4. Quarterly DR Exercises

Each quarter the platform on-call performs:

1. **Full restore drill** from production backups into an isolated VPC.
2. **Key rotation drill** via `scripts/rotation_drill.py` against a clone.
3. **Game day** scenario from the catalog (corrupt WAL, lost KMS key, region
   outage). Game-day report is filed in the engineering wiki.

A drill is considered passing when measured RTO is within 1.5× the target
RTO and RPO measured against drill-time WAL is within target.

---

## 5. Contacts & escalation

* **Primary**: platform-oncall pager.
* **Secondary**: security-oncall if the trigger is suspected key compromise.
* **Customer comms**: SOC-2 status page must be updated within 60 minutes
  of declaring an incident that exceeds the Tier-1 RTO.
