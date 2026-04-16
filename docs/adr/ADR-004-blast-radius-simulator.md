# ADR-004 — Agent Permission Blast Radius Simulator

**Status:** Accepted  
**Date:** 2026-04-15  
**Authors:** Forge (engineering)  
**Depends on:** ADR-003 (UIS Trust Graph, Sprint 1-2)  
**Followed by:** ADR-005 (Exploit Intent Correlation Engine, Sprint 2-2)

---

## Context

The Trust Graph (ADR-003) provides a queryable topology of agents, tools,
issuers, and verifiers. This topology is necessary but not sufficient for a
defender to understand risk — the key question is not "who is connected to
whom" but "if this agent is compromised, how bad is it?"

The Blast Radius Simulator answers that question pre-execution: before a
policy change or agent deployment, an operator can ask "if agent X is
compromised at this point in time, what nodes does it reach, what actions
does it enable, and what is the impact score?"

This is the **single most visual, demo-worthy feature** in the roadmap. One
screenshot of the blast radius with color-coded severity closes more pipeline
than any text description. It is the RSA'26 demo centerpiece.

---

## Decision

Implement `modules/identity/blast_radius.py` consuming the Trust Graph to
compute agent reachability under a simulated compromise.

### Algorithm

BFS traversal from the compromised agent node, following **all edge types**
(a compromised agent can pivot along any trust relationship it holds). The
traversal is bounded by `max_hops` (default 6, configurable per request).

SQLite recursive CTE (same engine as Trust Graph shortest-path) executes the
BFS in a single query with loop-detection via path string membership check.

### Impact scoring

Each reached node contributes a weight based on its type:

| Node Type | Weight | Rationale |
|---|---|---|
| `tenant` | 50 | Full tenant compromise = complete control |
| `verifier` | 40 | Verifier compromise = trust infrastructure damage |
| `issuer` | 30 | Issuer compromise = credential issuance risk |
| `agent` | 20 | Lateral movement to another agent |
| `workload` | 15 | Data / compute access |
| `tool` | 10 | Further pivoting capability |

Score = sum of weights, capped at 100. Risk tier: low (0-20), medium (21-50),
high (51-80), critical (81-100).

### Policy intersection

For each simulation, the engine queries `policy_bundles` to find which policy
bundle IDs have their subject or scope overlapping any node label in the blast
radius. This tells operators "which existing policies would contain this blast?"

### Simulation history

Every simulation result is persisted to `blast_radius_simulations` (SQLite).
This enables trending: is the blast radius of a given agent growing over time?
Auditors can review who simulated what and when.

### API surface

Two new endpoints:

| Endpoint | Description |
|---|---|
| `POST /api/simulate/blast_radius` | Run a simulation, returns full result |
| `GET /api/simulate/blast_radius/history` | List recent simulations for tenant |

---

## Consequences

### Positive

- Operators can model risk before deploying agents — shift-left security.
- Impact score (0-100) provides a single number for executive reporting.
- Policy intersection answers "am I already protected?" without manual analysis.
- Simulation history enables drift detection: increasing blast radius = growing
  risk posture problem.
- Feeds Sprint 2-2 (Intent Correlation): correlation engine can weight events
  by blast radius of the involved agent.

### Negative / Trade-offs

- Recursive CTE BFS is O(V+E) per simulation. For typical trust graphs
  (< 10K nodes per tenant) this is < 5ms. For very large or deeply cyclic
  graphs, the `max_hops` cap prevents runaway queries.
- The loop-detection (`edge_path NOT LIKE '%' || dst || '%'`) is string-based
  and has O(path_length²) cost. Acceptable for shallow graphs; would need a
  proper visited-set approach for graphs with > 1000 nodes.
- PostgreSQL path is stubbed (returns `pg_blast_radius_not_implemented` error).
  PG BFS implementation is a Sprint 3-2 follow-on when PG becomes the primary
  data plane.

### Open questions (deferred)

- **Visualization UI**: the color-coded impact graph is deferred to Sprint 2-3
  (Polish). This sprint ships the data layer; the UI layer comes next.
- **Counterfactual simulation**: "what would the blast radius be if I added
  this policy?" — deferred to Sprint 3-1.
- **Time-point simulation**: "blast radius at time T in the past" — requires
  graph snapshots, deferred beyond Phase 3.
