# ADR-007 — Autonomous Verifier Reputation Network

**Status:** Accepted  
**Sprint:** 3-2 (Weeks 15-16)  
**Date:** 2026-04-17  
**Author:** Forge (TokenDNA engineering)

---

## Context

Sprint 1-2 (planned) and Phase 0 established a trust federation where verifiers have a static `trust_score` set by operators at registration. This creates two problems:

1. **Stale scores.** A verifier that was trustworthy at registration may degrade over time (infrastructure issues, key rotation failures, adversarial behavior). The static score never reflects this.

2. **Gaming.** Any system where trust is set by registration and never updated is gameable — a compromised verifier retains its score indefinitely.

The quorum algorithm in `trust_federation.evaluate_federation_quorum()` weights votes by the static `trust_score`. This means a high-scoring but degraded verifier carries too much weight, and a newly-active but unproven verifier may be excluded prematurely.

---

## Decision

Introduce the **Autonomous Verifier Reputation Network** (`modules/identity/verifier_reputation.py`), a continuous measurement system that:

### 1. Challenge-Response Protocol

The Trust Authority issues cryptographic challenges to verifiers on a periodic basis. Each challenge contains:
- A unique 64-hex-char nonce
- An expiry window (default 30 seconds, `REPUTATION_CHALLENGE_TIMEOUT_S`)

Verifiers respond with `HMAC-SHA256(challenge_secret, nonce)` via `POST /api/verifier/challenge/{id}/respond`.

Outcomes:
| Outcome | Condition |
|---------|-----------|
| `CORRECT` | Response matches expected, within timeout window |
| `INCORRECT` | Response doesn't match expected |
| `TIMEOUT` | No response (or correct response) after expiry |
| `ERROR` | Verifier returned a server error |

### 2. Time-Decayed EMA Reputation Score

Each resolved challenge produces a score delta in `[-1.0, +1.0]`:
- CORRECT + fast (<1s): +1.0
- CORRECT + medium (<5s): +0.85
- CORRECT + slow: +0.70
- INCORRECT: −0.80
- TIMEOUT: −0.60
- ERROR: −0.40

The dynamic score is a **time-weighted average** using exponential decay with a configurable half-life (default 14 days, `REPUTATION_DECAY_HALF_LIFE_DAYS`):

```
weight(event) = exp(-ln(2) × age_days / half_life)
dynamic_score = Σ(weight × mapped_delta) / Σweight
```

Where `mapped_delta = (delta + 1.0) / 2.0` maps the score to `[0, 1]`.

This ensures **recent behavior dominates**: a verifier that was excellent 90 days ago but silent recently will drift toward the baseline, not retain its historical high score.

### 3. Effective Score Blending

Before a verifier has `MIN_RELIABLE_CHALLENGES` (default 3) resolved challenges, we can't trust the dynamic score alone. The effective score blends:

```
effective = dynamic × (total / min_reliable) + static × (1 - total / min_reliable)
```

This smoothly transitions from the operator-set static score to the fully-dynamic score as measurement history accumulates.

### 4. Reputation-Weighted Quorum

`evaluate_reputation_weighted_quorum()` supersedes the static `evaluate_federation_quorum()`:
- Uses `effective_score` (not static `trust_score`) as weight for each verifier's vote
- Excludes verifiers below `min_reputation` threshold (default 0.3) — badly-behaved verifiers can't influence quorum
- Sums weighted votes per verdict; dominant verdict wins if weight exceeds `min_weight` (default 0.6)
- Returns `QuorumVerdict` with confidence, weight breakdown, and `effective_action`

### 5. Anomaly Detection

`get_reputation_anomalies()` flags verifiers that exhibit:
- Score declining below 0.5 (trend DOWN + dynamic_score < 0.5)
- Reliability rate < 50% with reliable history
- Timeout rate > 50% with reliable history

Anomalies feed the dashboard reputation panel and can trigger operator alerts.

### 6. Backward Compatibility

- `trust_federation.evaluate_federation_quorum()` is unchanged — existing integrations continue to work
- Static `trust_score` field on `trust_federation_verifiers` is unchanged
- `sync_static_scores()` optionally pushes effective reputation scores back to static field (operator-initiated, only for reliable verifiers)
- The reputation module reads `trust_score` as the static fallback; no schema migration required

---

## Database Tables

```sql
reputation_challenges (
    challenge_id       TEXT PRIMARY KEY,
    verifier_id        TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    challenge_nonce    TEXT NOT NULL,
    expected_response  TEXT NOT NULL,  -- not exposed in API responses
    issued_at          TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    outcome            TEXT NOT NULL DEFAULT 'pending',
    resolved_at        TEXT,
    response_ms        INTEGER,
    submitted_response TEXT
)

reputation_scores (
    verifier_id       TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    dynamic_score     REAL NOT NULL DEFAULT 0.5,
    static_score      REAL NOT NULL DEFAULT 0.5,
    effective_score   REAL NOT NULL DEFAULT 0.5,
    total_challenges  INTEGER NOT NULL DEFAULT 0,
    correct           INTEGER NOT NULL DEFAULT 0,
    incorrect         INTEGER NOT NULL DEFAULT 0,
    timeouts          INTEGER NOT NULL DEFAULT 0,
    avg_response_ms   REAL,
    trend             TEXT NOT NULL DEFAULT 'stable',
    last_challenge_at TEXT,
    score_updated_at  TEXT NOT NULL,
    PRIMARY KEY (verifier_id, tenant_id)
)
```

`reputation_scores` is a **materialized view**: recomputed from raw challenge events after each resolution. The raw events in `reputation_challenges` are the source of truth.

---

## API Surface

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/verifier/{id}/challenge` | ADMIN | Issue challenge to verifier |
| POST | `/api/verifier/challenge/{id}/respond` | None | Verifier submits response (open) |
| GET | `/api/verifier/{id}/reputation` | Tenant | Get reputation + recent history |
| GET | `/api/verifier/reputation/leaderboard` | ANALYST | Sorted leaderboard for dashboard |
| GET | `/api/verifier/reputation/anomalies` | ANALYST | Anomaly detection results |
| POST | `/api/verifier/reputation/quorum` | Tenant | Reputation-weighted quorum evaluation |
| POST | `/api/verifier/reputation/expire-challenges` | ADMIN | Expire timed-out pending challenges |
| POST | `/api/verifier/reputation/sync-scores` | ADMIN | Push rep scores → static field |
| GET | `/api/verifier/{id}/challenges` | ANALYST | Full challenge history |
| GET | `/api/verifier/reputation/due-for-challenge` | ADMIN | Verifiers needing a challenge |

---

## Operational Model

**Periodic challenge runner:** A cron job or heartbeat calls:
1. `GET /api/verifier/reputation/due-for-challenge` — find verifiers not challenged in 24h
2. `POST /api/verifier/{id}/challenge` for each — issue challenges
3. Deliver nonces to verifier endpoints (out of band — depends on verifier registration)
4. `POST /api/verifier/reputation/expire-challenges` — clean up unanswered challenges

This runs autonomously without operator intervention after initial setup.

**Dashboard integration:** The `leaderboard` and `anomalies` endpoints feed the reputation graph panel. Trend arrows (UP/DOWN/STABLE) are derived from comparing recent-7-day score vs prior-7-30-day score.

**Revenue hook:** The per-query pricing model is enforced at the API layer (not in this module). The `get_reputation` function records a query event that the billing layer can count.

---

## Consequences

**Positive:**
- Self-healing: verifier quality measured continuously without manual score updates
- Adversary-resistant: compromised or slow verifiers lose quorum weight within days
- Transparent: full challenge history queryable; score derivation deterministic
- Backward-compatible: no migration required; static scores remain as fallback

**Neutral:**
- Challenge delivery to verifiers is out-of-band (verifiers must poll or accept push notifications from the Trust Authority) — Phase 4 work to standardize the delivery protocol
- Challenge nonce delivery is synchronous via API response; async push TBD

**Negative:**
- A verifier that is unreachable for 30+ days will approach baseline, not zero — by design (prevents permanent exile from a temporary outage), but may concern security-strict operators
- The HMAC-based challenge uses a symmetric secret — migrates to asymmetric challenge in Sprint 4 when the open spec is published

---

## Related

- ADR-005: Exploit Intent Correlation (Sprint 2-2, planned)
- ADR-006: Agent Identity Passport (Sprint 3-1) — passport trust_score influenced by verifier reputation
- Sprint 3-3: Identity Deception Mesh — reputation network used to identify decoy-touching verifiers
- Sprint 4-1: Attestation Portability Package — challenge-response protocol standardized as open spec
