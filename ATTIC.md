# TokenDNA Attic — parked R&D options

This branch (`attic/2026-07`, cut from tag `v3.0.0-pre-simplification`) preserves
the full pre-simplification codebase. As the `main` branch is focused down to the
three-questions product (see `SIMPLIFICATION_PLAN.md`), components that are not
on the critical path are removed from `main` and preserved here.

**Nothing here is deleted or abandoned.** These are *validated architecture
options* — built, tested, and demonstrated — that a future owner (or an acquirer)
can re-activate. Each entry records what it is, why it was parked, its size, and
where to read more. Restore any item with `git checkout attic/2026-07 -- <path>`.

## Parked components

### `platform/` — cloud ingestion + stream-engine layer (BUSL-1.1, ~3,829 LOC, ~94 tests)
- **What:** A push/stream ingestion pipeline — `NormalizedEvent` schema, schema
  registry, `(tenant,event_id)` dedup, category→engine router, backpressure gate,
  and stream engines (`TrustGraph` / `BehavioralDNA` / `PermissionDrift` /
  `MCPChain` / `PolicyGuard` detect-mode), plus alert routing, SIEM forwarders,
  and compliance report generators.
- **Why parked:** Never wired into the request path; its engines *delegated* to
  the algorithms in `modules/identity/*` (see `platform/README.md`'s disposition
  map), which remain in the product. It was one half of an **open-core
  distribution bet** (Apache-2.0 `collector/` + BUSL-1.1 `platform/`). The
  product decision is now two artifacts — server + SDK — and a legible repo.
- **Re-activation:** self-contained under `platform/tokendna_platform/*`; the
  disposition map names every source→target migration. Re-add the editable
  install + `platform/tests` path to CI and it runs.
- **Provenance:** delivered in TokenDNA PRs **#80–#85** (deployment redesign,
  Sprints 1–12).

### `collector/` — edge telemetry collector (Apache-2.0, ~2,701 LOC, ~37 tests)
- **What:** Standalone edge collector — `BaseAdapter` ABC + adapters (Okta System
  Log, AWS CloudTrail, Azure Activity Log, DNS shadow-AI classifier) that
  normalize agent telemetry to `NormalizedEvent` and ship it over a stream/buffer/
  compress transport. Own Dockerfile, pyproject, and CI-ready tests.
- **Why parked:** In the simplified product, agent telemetry arrives via the
  **SDK/UIS**, not a separate collector daemon.
- **Now lives at:** its own archived repo —
  **https://github.com/Bobcatsfan33/tokendna-collector** (Apache-2.0 intact).
- **Provenance:** TokenDNA PRs **#80–#85**.

---

_Future Phase-1 cuts (federation, verifier reputation, threat-sharing, etc.)
append their entries below as they land on `main`._
