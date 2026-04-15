# ADR-002: UIS Schema Evolution Strategy

**Status:** Accepted
**Date:** 2026-04-15
**Authors:** Forge (TokenDNA Engineering Agent)
**Sprint:** 1-1 (UIS Exploit Narrative Layer)

## Context

TokenDNA's Unified Identity Signal (UIS) events are the foundation for all downstream differentiation features: Blast Radius Simulator, Exploit Intent Correlation, Trust Graph, and the Attestation Portability Package. As these features ship across Phases 1-4, the UIS schema will evolve repeatedly.

We need a schema evolution strategy that:
1. Never breaks existing consumers (backward compatibility)
2. Supports incremental enrichment (new fields added over time)
3. Works across both the ClickHouse event store and the REST API
4. Enables migration of historical data without downtime
5. Scales to the open-standard ambitions of Phase 4

## Decision

### Versioned Additive Schema (VAS)

We adopt a **Versioned Additive Schema** approach:

1. **Schema version field:** Every UIS event carries `schema_version` (string, semver-like: "1.0", "1.1", "2.0"). This field is authoritative for determining which fields are available.

2. **Additive-only minor versions:** Minor version bumps (1.0 → 1.1) only ADD optional fields with null/zero defaults. No field removals, no type changes, no semantic changes to existing fields. Existing consumers that ignore unknown fields continue working unchanged.

3. **Major versions for breaking changes:** Major version bumps (1.x → 2.0) may rename, remove, or change field semantics. These require explicit migration functions and a deprecation period.

4. **Migration functions:** Each version bump ships with a `migrate_event_vX_to_vY()` function that upgrades older events in-place. Migrations are:
   - Idempotent (safe to run multiple times)
   - Non-destructive (original data preserved, new fields added)
   - Testable (unit tests for each migration path)

5. **ClickHouse schema alignment:** New columns added via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` with appropriate defaults. No column removal in minor versions.

6. **API response enrichment:** API responses include `schema_version` so consumers can detect available fields. Older events returned via API are migrated on-read to the latest schema version.

### Version History

| Version | Sprint | Changes |
|---------|--------|---------|
| 1.0 | Pre-consolidation | Base UIS event: DNA, scoring, threat signals, graph anomalies |
| 1.1 | 1-1 | + precondition, pivot, payload, objective (narrative fields) |
|     |     | + mitre_tactic, mitre_technique (ATT&CK mapping) |
|     |     | + narrative (human-readable story), confidence (0.0-1.0) |
|     |     | + uis_category (event classification) |

### Field Confidence Levels

For inferred fields (like narrative enrichment from Sprint 1-1), we track confidence:

| Confidence | Meaning | Example |
|------------|---------|---------|
| 0.0-0.3 | Low — default/fallback inference | Clean event with no risk signals |
| 0.3-0.6 | Medium — single weak signal | VPN/proxy detected |
| 0.6-0.8 | High — strong signal match | Impossible travel detected |
| 0.8-1.0 | Very high — authoritative source or multi-signal corroboration | Multiple high-severity signals |

Downstream consumers should use confidence to weight narrative data appropriately. The Intent Correlation Engine (Sprint 2-2) will use confidence as a playbook matching threshold.

## Consequences

### Positive
- **Zero-downtime evolution:** New fields appear automatically; old consumers unaffected
- **Historical enrichment:** Backfill scripts can enrich old events without schema migration
- **API simplicity:** Single event format across all versions; consumers check `schema_version` only if they care
- **Open-standard readiness:** Version discipline prepares UIS for the Phase 4 portability package

### Negative
- **Schema bloat over time:** Additive-only means columns accumulate. Mitigated by ClickHouse's columnar storage (unused columns ≈ zero cost) and periodic major-version consolidation
- **Null handling:** Consumers must handle null narrative fields for pre-v1.1 events. Mitigated by providing migration functions and on-read upgrade in the API layer

### Risks
- **Confidence calibration:** Initial confidence scores are heuristic-based. Will need recalibration with real production data in Phase 2
- **MITRE mapping drift:** ATT&CK framework updates may require mapping refreshes. Tracked as a periodic maintenance task

## Alternatives Considered

1. **Event sourcing with separate narrative events:** Rejected — adds query complexity and breaks the single-event-tells-the-story principle
2. **Fixed schema, no versioning:** Rejected — locks us out of Phase 2-4 features without painful migrations
3. **JSON blob for extension fields:** Rejected — loses ClickHouse query performance and type safety
