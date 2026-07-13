# ADR-002 — UIS Exploit Narrative Layer (UIS v1.1)

**Status:** Accepted  
**Date:** 2026-04-15  
**Authors:** Forge (engineering), Claude (spec review)  
**Supersedes:** N/A  
**Followed by:** ADR-003 (UIS Trust Graph, Sprint 1-2)

---

## Context

The Universal Identity Schema (UIS) v1.0 normalizes authentication and identity
events into eight field sets: `identity`, `auth`, `token`, `session`,
`behavior`, `lifecycle`, `threat`, and `binding`. While this normalization is
protocol-agnostic and operationally useful, the resulting events are data
points — they describe *what happened* but not *why it matters*.

Three downstream features planned for Phases 2 and 3 require events to carry
chain-semantic meaning:

1. **UIS Trust Graph (Sprint 1-2)** — builds a queryable graph of trust
   relationships between events. Requires each event to declare how it
   transitions from one trust state to another.
2. **Exploit Intent Correlation Engine (Sprint 2-2)** — matches event sequences
   against attack playbooks. Requires each event to carry inferred intent
   (objective) and transition type (pivot) for stream-processing.
3. **Agent Permission Blast Radius Simulator (Sprint 2-1)** — models reachability
   under compromise. Requires event payload to describe what was transmitted or
   executed.

Without a narrative layer, these features would need ad-hoc retrofitting of
each event source at build time — doubling the work and creating divergent
inference logic.

---

## Decision

Extend UIS to v1.1 by adding an optional `narrative` block to every event.
The block contains four fields:

| Field | Type | Description |
|---|---|---|
| `precondition` | `string \| null` | State or prerequisite that must have held for this event to occur |
| `pivot` | `string \| null` | Transition type — matches a MITRE ATT&CK-mapped key (see Appendix A) |
| `payload` | `string \| null` | What was executed or transmitted (auth method, token type, bindings) |
| `objective` | `string \| null` | Inferred or declared attacker/actor intent |
| `confidence` | `"HIGH" \| "MEDIUM" \| "LOW" \| null` | Inference confidence level |
| `mitre` | `object \| null` | MITRE ATT&CK metadata for the pivot type |
| `inference_rules` | `string[]` | List of rule IDs that fired during inference |
| `backfill` | `boolean` | Present and `true` only on backfilled legacy events |

### Schema evolution strategy

- **UIS v1.0 wire format remains valid.** The `narrative` block is additive.
  Any consumer ignoring unknown keys continues to work unchanged.
- Events without a narrative block are treated as v1.0. Events with a narrative
  block report `uis_version: "1.1"`.
- The `normalize_identity_event` function in `modules/identity/uis.py` now
  always attaches a narrative block (auto-inferred). Callers that need to
  suppress narrative can strip the key.
- Legacy events already stored in `uis_events` can be backfilled on read
  using `backfill_narrative()` from `modules/identity/uis_narrative.py`.

### Inference engine

`modules/identity/uis_narrative.py` implements a 12-rule inference engine:

**HIGH confidence rules (R-01 to R-05):** fire on hard signals with no
ambiguity — impossible travel, explicit lateral movement flag, revoked identity
re-authenticating, high-risk event without MFA, supply chain indicator.

**MEDIUM confidence rules (R-06 to R-10):** fire on correlated soft signals —
velocity anomaly + elevated risk tier, pattern deviation > 0.6, scope
escalation indicator, unbound machine identity, agent delegation indicator.

**LOW confidence rules (R-11 to R-12):** heuristic inference — elevated risk
score above 50 with no other signal, dormant identity becoming active.

Rules are ordered by confidence. The first matching rule sets `pivot` and
`confidence`; multiple rules may contribute to `precondition` and `objective`.
All matching rule IDs are recorded in `inference_rules` for auditability.

### MITRE ATT&CK mapping

Every pivot type maps to one MITRE ATT&CK technique (see Appendix A). The
mapping is stored in `MITRE_PIVOT_MAP` and attached to the `mitre` field when
a pivot is inferred or overridden. This enables correlation with external threat
intelligence feeds and SIEM platforms that consume MITRE-structured data.

### SDK caller overrides

`sdk_normalize_uis_event()` accepts four optional narrative override parameters
(`narrative_precondition`, `narrative_pivot`, `narrative_payload`,
`narrative_objective`). Caller-supplied values take precedence over
auto-inference and are marked `confidence: "HIGH"` (authoritative source).
Unknown pivot values supplied by callers do not have MITRE metadata attached —
callers should use values from `MITRE_PIVOT_MAP` where possible.

### Storage

`uis_events` table gains a `narrative_json` column (SQLite: `TEXT`, PostgreSQL:
`JSONB`). The column is populated on insert and is nullable for backward
compatibility with pre-v1.1 rows. Schema migration is zero-downtime: `init_db()`
calls `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (idempotent).

---

## Consequences

### Positive

- Trust Graph (ADR-003), Intent Correlation Engine, and Blast Radius Simulator
  can consume narrative fields directly without their own inference logic.
- Existing v1.0 consumers are unaffected — the `narrative` key is additive.
- MITRE ATT&CK alignment enables out-of-the-box SIEM correlation for operators
  using Splunk, Elastic, or Microsoft Sentinel.
- Caller-supplied overrides support high-fidelity scenarios (red team, forensics)
  where auto-inference is insufficient.
- Inference rules are auditable — every narrative block records which rules fired.

### Negative / Trade-offs

- Every event now runs through the inference engine on the hot path (normalized
  on ingest). The engine is CPU-only, O(1) per event, and adds < 0.5ms to the
  normalization pipeline based on benchmarks. Acceptable for the v1.1 scope.
- The inference engine produces LOW-confidence inferences from limited signals.
  Downstream consumers must gate on `confidence` to avoid acting on noisy data.
- Adding `narrative_json` to the store widens row size by ~200 bytes on average.
  At 1M events/day this is ~200 MB/day of additional storage — acceptable.

### Open questions (deferred to ADR-003)

- How does the Trust Graph use `pivot` values? (Answer to be specified in ADR-003.)
- Should `narrative` be queryable via the UIS list API with filter parameters?
  (Deferred — current list endpoints return full event JSON which includes narrative.)
- Should pivot values be an explicit enum validated on ingest, or remain an
  open string with a recommended vocabulary? (Current: open string + documented
  vocabulary. Enum validation would be a breaking change to the SDK.)

---

## Appendix A — MITRE ATT&CK Pivot Map

| Pivot Type | Tactic | Technique ID | Technique Name |
|---|---|---|---|
| `privilege_escalation` | Privilege Escalation | T1548 | Abuse Elevation Control Mechanism |
| `lateral_movement` | Lateral Movement | T1550 | Use Alternate Authentication Material |
| `credential_access` | Credential Access | T1528 | Steal Application Access Token |
| `scope_escalation` | Privilege Escalation | T1134 | Access Token Manipulation |
| `token_replay` | Credential Access | T1550.001 | Use Alternate Auth Material: Application Access Token |
| `impossible_travel` | Defense Evasion | T1556 | Modify Authentication Process |
| `identity_compromise` | Initial Access | T1078 | Valid Accounts |
| `delegation_abuse` | Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft |
| `context_switch` | Defense Evasion | T1036 | Masquerading |
| `agent_hijack` | Execution | T1059 | Command and Scripting Interpreter |
| `supply_chain_compromise` | Initial Access | T1195 | Supply Chain Compromise |
| `mfa_bypass` | Defense Evasion | T1556.006 | Modify Auth Process: Multi-Factor Authentication |
| `persistence` | Persistence | T1098 | Account Manipulation |
| `data_exfiltration` | Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| `reconnaissance` | Reconnaissance | T1598 | Phishing for Information |

---

## Appendix B — Five UIS Event Categories

The inference engine classifies every event into one of five categories to
provide objective fallback when no specific signal fires:

| Category | Objective | Classification Logic |
|---|---|---|
| `auth_success` | `establish_session` | No lifecycle/threat signal; auth method present |
| `auth_failure` | `probe_credentials` | Auth method contains "fail" or "deny" |
| `scope_change` | `acquire_privilege` | `scope_escalation_detected` in indicators |
| `lifecycle_event` | `maintain_persistence` | Identity revoked or expired |
| `threat_detected` | `execute_attack` | risk_score ≥ 70 or risk_tier high/critical |

---

## Appendix C — Downstream POC Gate

Sprint 1-1 gate requires "at least one downstream consumer POC confirms the
schema is sufficient to reconstruct an attack story from chained events with
narrative fields populated." The gate is fulfilled by
`tests/test_uis_narrative.py::TestAttackStoryReconstruction`, which:

1. Constructs a three-event chain (credential probe → impossible-travel auth →
   lateral movement)
2. Runs each event through the inference engine
3. Calls a story reconstructor that reads `narrative.pivot`, `narrative.objective`,
   `narrative.confidence`, and `narrative.mitre.technique_id`
4. Asserts the reconstructed story is coherent and references MITRE techniques

The `_reconstruct_story()` function in the test is the reference implementation
of how the Exploit Intent Correlation Engine will consume narrative fields.
