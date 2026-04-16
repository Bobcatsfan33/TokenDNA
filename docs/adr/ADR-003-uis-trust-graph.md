# ADR-003 — UIS Trust Graph

**Status:** Accepted  
**Date:** 2026-04-15  
**Authors:** Forge (engineering)  
**Depends on:** ADR-002 (UIS Exploit Narrative Layer)  
**Followed by:** ADR-004 (Agent Permission Blast Radius Simulator, Sprint 2-1)

---

## Context

Sprint 1-1 enriched every UIS event with chain-semantic narrative fields
(`precondition`, `pivot`, `payload`, `objective`). These fields describe *what
happened at each step*, but give no picture of the *structural relationships*
between principals over time.

Three Phase 2 features require a graph of the trust topology:

1. **Agent Permission Blast Radius Simulator (Sprint 2-1)** — "if agent X is
   compromised, which nodes does it reach?" requires a pre-built reachability
   graph.
2. **Exploit Intent Correlation Engine (Sprint 2-2)** — multi-hop attack
   playbooks require the engine to walk the graph to verify whether observed
   events form a plausible chain.
3. **Autonomous Verifier Reputation Network (Sprint 3-2)** — trust score
   propagation requires knowing which verifiers have been used with which
   issuers.

Without a persistent graph, each of these features would have to reconstruct
trust relationships from raw event logs on every query — O(n) scans that become
prohibitively slow at production event volumes.

---

## Decision

Build `modules/identity/trust_graph.py` — an incrementally maintained graph of
agents, workloads, tools, issuers, and verifiers extracted from UIS events.

### Graph model

**Node types:** `agent` | `workload` | `tool` | `issuer` | `verifier` | `tenant`  
**Edge types:** `delegates_to` | `attested_by` | `issued_by` | `uses_tool` | `verified_by`

Nodes and edges carry `first_seen`, `last_seen`, and `observation_count` /
`weight` counters. High weight = established relationship; weight=1 = brand new.

### Storage

SQLite default (two tables: `tg_nodes`, `tg_edges`) — consistent with the
rest of the data-plane. PostgreSQL is used automatically when `TOKENDNA_PG_DSN`
is set; schema and upsert SQL are identical modulo parameter placeholder style.
A `tg_anomalies` table is created on first use to persist detected anomalies.

Shortest-path queries use a **recursive CTE** (BFS). This works on SQLite 3.35+
(available on all supported platforms) and PostgreSQL 8.4+.

### Ingestion

`trust_graph.ingest_uis_event()` is called from `uis_store.insert_event()` as a
fire-and-forget hook. Exceptions are caught and logged — graph ingestion never
blocks event persistence (graceful degradation).

Node and edge upserts are **idempotent**: SQLite `ON CONFLICT DO UPDATE` / PG
`ON CONFLICT DO UPDATE` increment counters without duplicating rows.

### Anomaly detection

Three signals are evaluated on every insert:

| Signal | Trigger | Severity |
|---|---|---|
| `NEW_TOOL_IN_STABLE_AGENT_TOOLKIT` | Agent with ≥`TG_MIN_STABLE_OBS` (default 5) observations suddenly uses a tool it has never used before | medium |
| `UNFAMILIAR_VERIFIER_IN_TRUST_PATH` | An issuer with ≥`TG_MIN_STABLE_OBS` observations uses a brand-new verifier | high |
| `DELEGATION_DEPTH_EXCEEDED` | Delegation chain for a subject exceeds `TG_MAX_DELEGATION_DEPTH` (default 4) hops | high |

Both thresholds are environment-variable tunable without code changes.

### API surface

Three new endpoints wired to `api.py`:

| Endpoint | Description |
|---|---|
| `GET /api/graph/path/{from}?to={to}` | Shortest trust path between two nodes |
| `GET /api/graph/anomalies` | Detected anomalies, newest-first |
| `GET /api/graph/stats` | Node count, edge count, type breakdowns, anomaly count |

---

## Consequences

### Positive

- Blast Radius Simulator (Sprint 2-1) can query reachability directly from
  the graph instead of scanning raw events.
- Intent Correlation Engine (Sprint 2-2) can verify multi-hop attack chains
  using graph traversal.
- Anomaly detection fires in real time on every event with < 1ms overhead
  (SQLite lookups, no ML).
- Graph stats provide instant observability into the trust topology for operators.

### Negative / Trade-offs

- Graph storage grows proportionally with distinct (tenant, node, edge) tuples.
  In practice this is bounded by the number of unique principals, not event
  volume — expected to remain small (< 100K nodes per tenant in year 1).
- Anomaly detection uses SQLite-only path for now. PG path stubs return empty
  results — acceptable for the current SQLite-first deployment; PG anomaly
  detection is a Sprint 1-2 follow-on item.
- Recursive CTE shortest-path has O(V+E) cost per query; acceptable for
  trust graphs which are small and shallow (typical depth ≤ 6).

### Deferred to later sprints

- Graph visualization UI (deferred to Sprint 2-1 where Blast Radius visual is built)
- PG-native anomaly detection (deferred to Sprint 3-2 Verifier Reputation Network)
- Graph pruning / TTL for stale nodes (deferred — no production data yet)
- `delegates_to` edge population (requires explicit delegation claim in token;
  deferred until delegation token spec is finalized in Sprint 3-1)

---

## Appendix — Node extraction rules from UIS events

| UIS field | → Node type | → Label |
|---|---|---|
| `identity.agent_id` (if set) | `agent` | `agent_id` value |
| `identity.subject` (if no agent_id) | `workload` | `subject` value |
| `token.issuer` | `issuer` | issuer URL |
| `binding.attestation_id` | `verifier` | `attest:{attestation_id[:16]}` |
| `binding.spiffe_id` | `verifier` | SPIFFE URI |
| `auth.protocol + ":" + auth.method` | `tool` | e.g. `oidc:password` |
