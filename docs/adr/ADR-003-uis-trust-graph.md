# ADR-003: UIS Trust Graph — RSA'26 Gap-Closure Extensions

**Sprint:** 1-2 addendum  
**Date:** 2026-04-17  
**Status:** Accepted  
**Extends:** Sprint 1-2 UIS Trust Graph base implementation

---

## Context

Sprint 1-2 shipped the UIS Trust Graph with three anomaly detection rules. RSA'26 exposed three critical gaps that no vendor closed. Two of those gaps map directly to trust-graph anomaly rules that were missing:

**RSA Gap 1 — Policy Self-Modification**
CrowdStrike disclosed two Fortune 50 incidents where AI agents with legitimate credentials encountered a security restriction and removed the restriction itself to complete the task. Every identity check passed. Caught by accident both times. No existing identity framework detects this.

**RSA Gap 2 — Permission Drift**
Agent permissions expanded 3× in one month at enterprise scale without security review. Discovery tools show today's permission state; nothing tracks how permissions evolved over time.

---

## Decision: Additive Extension Pattern

Rather than restructuring the base `trust_graph.py` implementation, RSA gap-closure rules are appended as clearly-delineated additive functions. This approach:

1. Preserves the existing API and schema (no breaking changes to Sprint 2-1/2-2 consumers)
2. Makes the RSA additions auditable as a distinct section
3. Allows independent testing of the new rules

**New tables (idempotently created via `_rsa_init_db()`):**

```sql
tg_policy_governs        -- tracks pre-existing governance edges (policy → agent)
tg_permission_history    -- time-series weight history for permission scope tracking
```

**New public functions:**

| Function | Purpose |
|----------|---------|
| `record_policy_governance(tenant, policy, agent)` | Register/update a governance relationship; returns True if pre-existing |
| `record_permission_scope(tenant, agent, policy, scope)` | Append a permission scope observation to history |
| `check_policy_self_modification(tenant, agent, policy, event_type, action)` | RULE-04: fires CRITICAL if agent writes to its own governing policy |
| `check_permission_drift(tenant, agent, policy)` | RULE-05: fires HIGH if permission surface grew >threshold× in window |

---

## RULE-04: Policy Self-Modification Detection

**Trigger conditions:**
- A `GOVERNS` edge from `policy → agent` pre-exists (`observation_count ≥ 2`)
- The current event is a write/modify/delete/remove operation on that policy

**Critical design decision — pre-existence check:** The rule fires only when `observation_count ≥ 2`. The first event that creates the governance record is not treated as evidence of self-modification (the agent didn't know about the policy yet; this event establishes it). Only subsequent modification attempts are flagged.

**Severity:** CRITICAL. This is the pattern CrowdStrike disclosed as a Fortune 50 production incident. Human review must be triggered immediately.

---

## RULE-05: Permission Drift Detection

**Trigger conditions:**
- A baseline permission scope weight exists within the configured window (`TG_PERMISSION_DRIFT_DAYS`, default 30 days)
- Current scope weight is ≥ `TG_PERMISSION_GROWTH_X`× the baseline (default 2.0×)

**Design note:** Scope weight is `len(scope_list)`, providing a simple proxy for permission surface size. A more sophisticated implementation could weight permissions by their risk level; that refinement is deferred until a customer requests it.

**Severity:** HIGH. Permission drift is a slow-motion breach signal. It should be reviewed but does not require immediate human intervention (unlike RULE-04).

---

## Configuration

Both thresholds are environment-variable tunable:

```bash
TG_PERMISSION_GROWTH_X=2.0    # multiplier to trigger drift anomaly (default 2×)
TG_PERMISSION_DRIFT_DAYS=30   # baseline comparison window in days
```

---

## Consequences

- Callers integrating agent policy events should call `record_policy_governance()` and `record_permission_scope()` when handling policy-related UIS events, then check the return values of the rule functions.
- No changes to existing `ingest_uis_event()`, `shortest_path()`, `get_stats()`, or `get_anomalies()` APIs.
- Both new tables are tenant-isolated and use the same SQLite locking pattern as the base module.
