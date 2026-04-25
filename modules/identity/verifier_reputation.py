"""
TokenDNA -- Autonomous Verifier Reputation Network (Sprint 3-2)

Upgrades verifier trust from static operator-set scores to dynamically
maintained reputation driven by:

  1. Challenge-Response Protocol
     The TokenDNA Trust Authority periodically sends cryptographic challenges
     to each registered verifier. Verifiers that respond correctly, quickly,
     and consistently gain reputation. Non-responders and incorrect responders
     lose it.

  2. Reputation Scoring with Decay
     Recent behavior matters more than ancient history. Reputation is a
     time-weighted exponential moving average (EMA) over challenge outcomes.
     A verifier that was great 90 days ago but silent recently drifts toward
     the baseline.

  3. Reputation-Weighted Quorum
     The quorum algorithm in trust_federation.evaluate_federation_quorum()
     is superseded by evaluate_reputation_weighted_quorum() which weights each
     verifier's vote by its current dynamic reputation score, not the static
     trust_score field.

  4. Reputation Lookup API
     External parties can query GET /api/verifier/reputation/{verifier_id}
     for current reputation + trend + challenge history (per-query pricing hook).

  5. Dashboard Visualization Data
     GET /api/verifier/reputation/leaderboard returns sorted reputation scores
     with trend direction for the dashboard reputation graph panel.

  6. Backward Compatibility
     All existing trust_federation functions continue to work. The static
     trust_score field remains the fallback when no reputation data exists.
     Dynamic scores are computed from the reputation_events table; the static
     field is only updated when an operator explicitly calls sync_static_scores().

Database tables (added idempotently via init_reputation_db()):
  - reputation_challenges: challenge issuance log
  - reputation_events: scored outcomes of each challenge
  - reputation_scores: materialized current score per verifier (cache)

ADR: docs/adr/ADR-007-verifier-reputation-network.md
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

from modules.storage.pg_connection import AdaptedCursor, get_db_conn


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_REPUTATION_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")
_CHALLENGE_SECRET = os.getenv(
    "REPUTATION_CHALLENGE_SECRET",
    "tokendna-challenge-dev-secret-change-in-prod",
)
# How long a verifier has to respond to a challenge (seconds)
_CHALLENGE_TIMEOUT_S = int(os.getenv("REPUTATION_CHALLENGE_TIMEOUT_S", "30"))
# EMA decay half-life in days (recent events carry more weight)
_DECAY_HALF_LIFE_DAYS = float(os.getenv("REPUTATION_DECAY_HALF_LIFE_DAYS", "14"))
# Score for a verifier with no history (inherits from static trust_score if available)
_BASELINE_SCORE = float(os.getenv("REPUTATION_BASELINE_SCORE", "0.5"))
# Minimum challenges before score is considered reliable
_MIN_RELIABLE_CHALLENGES = int(os.getenv("REPUTATION_MIN_RELIABLE", "3"))

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Enums & Dataclasses
# ---------------------------------------------------------------------------


class ChallengeOutcome(str, Enum):
    CORRECT = "correct"          # Responded correctly within timeout
    INCORRECT = "incorrect"      # Responded but with wrong answer
    TIMEOUT = "timeout"          # Did not respond within timeout
    ERROR = "error"              # Verifier returned an error
    PENDING = "pending"          # Challenge issued, not yet resolved


class TrendDirection(str, Enum):
    UP = "up"
    DOWN = "down"
    STABLE = "stable"


@dataclass
class ReputationChallenge:
    """A single cryptographic challenge issued to a verifier."""
    challenge_id: str
    verifier_id: str
    tenant_id: str
    challenge_nonce: str       # random hex challenge verifier must sign
    expected_response: str     # HMAC-SHA256 of nonce with challenge secret
    issued_at: str
    expires_at: str
    outcome: ChallengeOutcome = ChallengeOutcome.PENDING
    resolved_at: str | None = None
    response_ms: int | None = None   # actual response time in milliseconds
    submitted_response: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "verifier_id": self.verifier_id,
            "tenant_id": self.tenant_id,
            "challenge_nonce": self.challenge_nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "outcome": self.outcome.value,
            "resolved_at": self.resolved_at,
            "response_ms": self.response_ms,
            # Note: expected_response intentionally omitted from public dict
        }


@dataclass
class ReputationScore:
    """Current materialized reputation for a verifier."""
    verifier_id: str
    tenant_id: str
    dynamic_score: float          # 0.0–1.0 EMA-weighted score
    static_score: float           # operator-set fallback score
    effective_score: float        # what callers should use
    total_challenges: int
    correct_responses: int
    incorrect_responses: int
    timeout_responses: int
    reliability_rate: float       # correct / (correct + incorrect + timeout)
    avg_response_ms: float | None
    trend: TrendDirection
    last_challenge_at: str | None
    score_updated_at: str
    is_reliable: bool             # True when >= MIN_RELIABLE_CHALLENGES seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "verifier_id": self.verifier_id,
            "tenant_id": self.tenant_id,
            "dynamic_score": round(self.dynamic_score, 4),
            "static_score": round(self.static_score, 4),
            "effective_score": round(self.effective_score, 4),
            "total_challenges": self.total_challenges,
            "correct_responses": self.correct_responses,
            "incorrect_responses": self.incorrect_responses,
            "timeout_responses": self.timeout_responses,
            "reliability_rate": round(self.reliability_rate, 4),
            "avg_response_ms": (
                round(self.avg_response_ms, 1) if self.avg_response_ms else None
            ),
            "trend": self.trend.value,
            "last_challenge_at": self.last_challenge_at,
            "score_updated_at": self.score_updated_at,
            "is_reliable": self.is_reliable,
        }


@dataclass
class QuorumVerdict:
    """Reputation-weighted quorum evaluation result."""
    met: bool
    total_reputation_weight: float
    passing_weight: float
    required_weight: float
    participating_verifiers: int
    verdicts: dict[str, float]  # verdict → accumulated weight
    effective_action: str
    confidence: float


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


@contextmanager
def _cursor():
    """Yield an AdaptedCursor backed by the configured DB backend."""
    with get_db_conn(db_path=_REPUTATION_DB_PATH) as conn:
        yield AdaptedCursor(conn.cursor())


def init_reputation_db() -> None:
    """Create reputation tables (idempotent).

    Directory creation and PRAGMA configuration are handled by
    ``get_db_conn()``; no manual setup required here.
    """
    with _cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reputation_challenges (
                challenge_id       TEXT PRIMARY KEY,
                verifier_id        TEXT NOT NULL,
                tenant_id          TEXT NOT NULL,
                challenge_nonce    TEXT NOT NULL,
                expected_response  TEXT NOT NULL,
                issued_at          TEXT NOT NULL,
                expires_at         TEXT NOT NULL,
                outcome            TEXT NOT NULL DEFAULT 'pending',
                resolved_at        TEXT,
                response_ms        INTEGER,
                submitted_response TEXT
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_rep_challenges_verifier
                ON reputation_challenges(tenant_id, verifier_id, issued_at DESC)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_rep_challenges_outcome
                ON reputation_challenges(outcome, issued_at DESC)
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reputation_scores (
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
        """)


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _generate_nonce() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars


def _compute_expected_response(nonce: str) -> str:
    """HMAC-SHA256(challenge_secret, nonce) — what a correct verifier should return."""
    secret = _CHALLENGE_SECRET.encode("utf-8")
    return hmac.new(secret, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_challenge_response(nonce: str, secret: str) -> str:
    """
    Compute the expected response for a challenge nonce.
    Verifiers call this with their provisioned secret to respond to challenges.
    """
    return hmac.new(secret.encode("utf-8"), nonce.encode("utf-8"),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# EMA Reputation Scoring
# ---------------------------------------------------------------------------


def _time_weight(event_age_days: float, half_life: float = _DECAY_HALF_LIFE_DAYS) -> float:
    """
    Exponential decay weight. An event from today = 1.0.
    An event from half_life days ago = 0.5. From 2*half_life days ago = 0.25.
    """
    return math.exp(-math.log(2) * event_age_days / half_life)


def _outcome_delta(outcome: ChallengeOutcome, response_ms: int | None) -> float:
    """
    Convert a challenge outcome to a score contribution [-1.0, +1.0].
    Correct fast responses earn the most; timeouts/errors penalize most.
    """
    if outcome == ChallengeOutcome.CORRECT:
        # Bonus for fast responses (within 1s = full credit, 30s = 70%)
        if response_ms is not None and response_ms < 1000:
            return 1.0
        elif response_ms is not None and response_ms < 5000:
            return 0.85
        else:
            return 0.7
    elif outcome == ChallengeOutcome.INCORRECT:
        return -0.8   # wrong answer is almost as bad as no answer
    elif outcome == ChallengeOutcome.TIMEOUT:
        return -0.6   # non-response degrades score
    elif outcome == ChallengeOutcome.ERROR:
        return -0.4   # infrastructure error, partial penalty
    return 0.0


def _compute_dynamic_score(events: list[dict[str, Any]]) -> float:
    """
    Compute a time-decayed EMA score from a list of challenge outcomes.
    events: list of {outcome, response_ms, resolved_at} dicts, newest first
    Returns 0.0–1.0
    """
    if not events:
        return _BASELINE_SCORE

    now = datetime.now(timezone.utc)
    weighted_sum = 0.0
    weight_total = 0.0

    for ev in events:
        try:
            resolved = datetime.fromisoformat(str(ev["resolved_at"]))
            if resolved.tzinfo is None:
                resolved = resolved.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        age_days = (now - resolved).total_seconds() / 86400.0
        w = _time_weight(age_days)
        delta = _outcome_delta(
            ChallengeOutcome(ev["outcome"]),
            ev.get("response_ms"),
        )
        # Map delta from [-1, +1] to [0, 1] for the weighted avg
        weighted_sum += w * (delta + 1.0) / 2.0
        weight_total += w

    if weight_total == 0:
        return _BASELINE_SCORE

    return max(0.0, min(1.0, round(weighted_sum / weight_total, 4)))


def _compute_trend(events: list[dict[str, Any]]) -> TrendDirection:
    """
    Compare score from recent 7 days vs prior 7-30 days.
    Returns UP, DOWN, or STABLE.
    """
    now = datetime.now(timezone.utc)
    recent: list[dict[str, Any]] = []
    prior: list[dict[str, Any]] = []

    for ev in events:
        if ev.get("outcome") == ChallengeOutcome.PENDING.value:
            continue
        try:
            resolved = datetime.fromisoformat(str(ev["resolved_at"]))
            if resolved.tzinfo is None:
                resolved = resolved.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
        age_days = (now - resolved).total_seconds() / 86400.0
        if age_days <= 7:
            recent.append(ev)
        elif age_days <= 30:
            prior.append(ev)

    if not recent or not prior:
        return TrendDirection.STABLE

    recent_score = _compute_dynamic_score(recent)
    prior_score = _compute_dynamic_score(prior)
    delta = recent_score - prior_score
    if delta > 0.05:
        return TrendDirection.UP
    elif delta < -0.05:
        return TrendDirection.DOWN
    return TrendDirection.STABLE


# ---------------------------------------------------------------------------
# Challenge lifecycle
# ---------------------------------------------------------------------------


def issue_challenge(verifier_id: str, tenant_id: str) -> ReputationChallenge:
    """
    Issue a new cryptographic challenge to a verifier.
    The caller is responsible for delivering the challenge nonce to the verifier
    (e.g., via the verifier's registered callback URL or polling endpoint).
    """
    init_reputation_db()
    now = datetime.now(timezone.utc)
    challenge_id = f"chal-{uuid.uuid4().hex}"
    nonce = _generate_nonce()
    expected = _compute_expected_response(nonce)
    expires_at = (now + timedelta(seconds=_CHALLENGE_TIMEOUT_S)).isoformat()

    challenge = ReputationChallenge(
        challenge_id=challenge_id,
        verifier_id=verifier_id,
        tenant_id=tenant_id,
        challenge_nonce=nonce,
        expected_response=expected,
        issued_at=now.isoformat(),
        expires_at=expires_at,
    )

    with _cursor() as cur:
        cur.execute("""
            INSERT INTO reputation_challenges
                (challenge_id, verifier_id, tenant_id, challenge_nonce,
                 expected_response, issued_at, expires_at, outcome)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            challenge.challenge_id, challenge.verifier_id, challenge.tenant_id,
            challenge.challenge_nonce, challenge.expected_response,
            challenge.issued_at, challenge.expires_at,
            challenge.outcome.value,
        ))
    return challenge


def resolve_challenge(
    challenge_id: str,
    submitted_response: str,
) -> ReputationChallenge:
    """
    Resolve a challenge with the verifier's submitted response.
    Computes outcome (CORRECT / INCORRECT / TIMEOUT) and updates reputation.
    """
    init_reputation_db()
    with _cursor() as cur:
        cur.execute("SELECT * FROM reputation_challenges WHERE challenge_id=?",
                    (challenge_id,))
        row = cur.fetchone()

    if row is None:
        raise ValueError(f"Challenge {challenge_id} not found")

    if row["outcome"] != ChallengeOutcome.PENDING.value:
        raise ValueError(
            f"Challenge {challenge_id} already resolved: {row['outcome']}"
        )

    now = datetime.now(timezone.utc)
    issued_at = datetime.fromisoformat(str(row["issued_at"]))
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    expires_at = datetime.fromisoformat(str(row["expires_at"]))
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    response_ms = int((now - issued_at).total_seconds() * 1000)

    if now > expires_at:
        outcome = ChallengeOutcome.TIMEOUT
    elif hmac.compare_digest(submitted_response, row["expected_response"]):
        outcome = ChallengeOutcome.CORRECT
    else:
        outcome = ChallengeOutcome.INCORRECT

    resolved_at = now.isoformat()
    with _cursor() as cur:
        cur.execute("""
            UPDATE reputation_challenges
            SET outcome=?, resolved_at=?, response_ms=?, submitted_response=?
            WHERE challenge_id=?
        """, (outcome.value, resolved_at, response_ms, submitted_response, challenge_id))

    challenge = ReputationChallenge(
        challenge_id=challenge_id,
        verifier_id=row["verifier_id"],
        tenant_id=row["tenant_id"],
        challenge_nonce=row["challenge_nonce"],
        expected_response=row["expected_response"],
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        outcome=outcome,
        resolved_at=resolved_at,
        response_ms=response_ms,
        submitted_response=submitted_response,
    )

    # Refresh materialized reputation score
    _refresh_reputation(challenge.verifier_id, challenge.tenant_id)

    # Auto-wire ZTIX Periodic Proof-of-Control: a CORRECT challenge IS the
    # proof. Recording it here (instead of leaving the call to integration
    # docstrings) closes the drift risk where a future caller forgets to
    # invoke record_proof and verifiers silently get demoted.
    # Wrapped in try/except so a proof_of_control outage cannot block the
    # resolve flow — the worst case is one missed proof window, not a
    # broken challenge resolution.
    if outcome == ChallengeOutcome.CORRECT:
        try:
            from modules.identity import proof_of_control as _poc  # noqa: PLC0415
            _poc.record_proof(challenge.verifier_id, challenge.tenant_id)
        except Exception:  # noqa: BLE001
            import logging  # noqa: PLC0415
            logging.getLogger(__name__).exception(
                "proof_of_control.record_proof failed for verifier=%s tenant=%s "
                "(challenge=%s) — continuing",
                challenge.verifier_id, challenge.tenant_id, challenge_id,
            )

    return challenge


def expire_pending_challenges(tenant_id: str | None = None) -> int:
    """
    Mark all pending challenges past their expiry as TIMEOUT.
    Call this periodically (e.g., from the heartbeat or a background task).
    Returns count of challenges expired.
    """
    init_reputation_db()
    now = _utc_now()
    with _cursor() as cur:
        if tenant_id:
            cur.execute("""
                UPDATE reputation_challenges
                SET outcome='timeout', resolved_at=?
                WHERE outcome='pending' AND expires_at < ? AND tenant_id=?
            """, (now, now, tenant_id))
        else:
            cur.execute("""
                UPDATE reputation_challenges
                SET outcome='timeout', resolved_at=?
                WHERE outcome='pending' AND expires_at < ?
            """, (now, now))
        count = cur.rowcount

    # Refresh scores for affected verifiers
    if count > 0:
        with _cursor() as cur:
            if tenant_id:
                cur.execute("""
                    SELECT DISTINCT verifier_id FROM reputation_challenges
                    WHERE outcome='timeout' AND resolved_at=? AND tenant_id=?
                """, (now, tenant_id))
            else:
                cur.execute("""
                    SELECT DISTINCT verifier_id FROM reputation_challenges
                    WHERE outcome='timeout' AND resolved_at=?
                """, (now,))
            rows = cur.fetchall()

        for row in rows:
            _refresh_reputation(row["verifier_id"], tenant_id or "")

    return count


# ---------------------------------------------------------------------------
# Reputation materialization
# ---------------------------------------------------------------------------


def _refresh_reputation(verifier_id: str, tenant_id: str) -> ReputationScore:
    """
    Recompute and persist the materialized reputation score for a verifier.
    Called after each challenge resolution.
    """
    init_reputation_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT outcome, response_ms, resolved_at
            FROM reputation_challenges
            WHERE verifier_id=? AND tenant_id=? AND outcome != 'pending'
            ORDER BY resolved_at DESC
            LIMIT 200
        """, (verifier_id, tenant_id))
        events = [dict(r) for r in cur.fetchall()]

    dynamic_score = _compute_dynamic_score(events)
    trend = _compute_trend(events)

    total = len(events)
    correct = sum(1 for e in events if e["outcome"] == ChallengeOutcome.CORRECT.value)
    incorrect = sum(1 for e in events if e["outcome"] == ChallengeOutcome.INCORRECT.value)
    timeouts = sum(1 for e in events if e["outcome"] == ChallengeOutcome.TIMEOUT.value)

    response_times = [e["response_ms"] for e in events
                      if e.get("response_ms") is not None
                      and e["outcome"] == ChallengeOutcome.CORRECT.value]
    avg_ms = (sum(response_times) / len(response_times)) if response_times else None

    denominator = correct + incorrect + timeouts
    reliability = (correct / denominator) if denominator > 0 else 0.0

    last_challenge_at = events[0]["resolved_at"] if events else None
    now = _utc_now()

    # Effective score blends dynamic (if reliable) with static fallback
    static_score = _get_static_score(verifier_id, tenant_id)
    if total >= _MIN_RELIABLE_CHALLENGES:
        effective = dynamic_score
    else:
        # Blend: weight dynamic by (total / min_reliable) to transition smoothly
        blend = total / _MIN_RELIABLE_CHALLENGES
        effective = dynamic_score * blend + static_score * (1.0 - blend)

    effective = max(0.0, min(1.0, round(effective, 4)))

    with _cursor() as cur:
        cur.execute("""
            INSERT INTO reputation_scores
                (verifier_id, tenant_id, dynamic_score, static_score, effective_score,
                 total_challenges, correct, incorrect, timeouts, avg_response_ms,
                 trend, last_challenge_at, score_updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(verifier_id, tenant_id) DO UPDATE SET
                dynamic_score=excluded.dynamic_score,
                static_score=excluded.static_score,
                effective_score=excluded.effective_score,
                total_challenges=excluded.total_challenges,
                correct=excluded.correct,
                incorrect=excluded.incorrect,
                timeouts=excluded.timeouts,
                avg_response_ms=excluded.avg_response_ms,
                trend=excluded.trend,
                last_challenge_at=excluded.last_challenge_at,
                score_updated_at=excluded.score_updated_at
        """, (
            verifier_id, tenant_id, dynamic_score, static_score, effective,
            total, correct, incorrect, timeouts, avg_ms,
            trend.value, last_challenge_at, now,
        ))

    return ReputationScore(
        verifier_id=verifier_id,
        tenant_id=tenant_id,
        dynamic_score=dynamic_score,
        static_score=static_score,
        effective_score=effective,
        total_challenges=total,
        correct_responses=correct,
        incorrect_responses=incorrect,
        timeout_responses=timeouts,
        reliability_rate=reliability,
        avg_response_ms=avg_ms,
        trend=trend,
        last_challenge_at=last_challenge_at,
        score_updated_at=now,
        is_reliable=(total >= _MIN_RELIABLE_CHALLENGES),
    )


def _get_static_score(verifier_id: str, tenant_id: str) -> float:
    """Pull the operator-set trust_score from trust_federation_verifiers if available."""
    try:
        with _cursor() as cur:
            cur.execute("""
                SELECT trust_score FROM trust_federation_verifiers
                WHERE verifier_id=? AND tenant_id=?
            """, (verifier_id, tenant_id))
            row = cur.fetchone()
            if row is not None:
                return float(row["trust_score"])
    except Exception:
        pass
    return _BASELINE_SCORE


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def get_reputation(verifier_id: str, tenant_id: str) -> ReputationScore:
    """
    Get the current reputation score for a verifier.
    If no materialized score exists, returns a default based on static score.
    """
    init_reputation_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT * FROM reputation_scores WHERE verifier_id=? AND tenant_id=?
        """, (verifier_id, tenant_id))
        row = cur.fetchone()

    if row is not None:
        return _row_to_reputation(row)

    # No history yet — return baseline derived from static score
    static = _get_static_score(verifier_id, tenant_id)
    now = _utc_now()
    return ReputationScore(
        verifier_id=verifier_id,
        tenant_id=tenant_id,
        dynamic_score=static,
        static_score=static,
        effective_score=static,
        total_challenges=0,
        correct_responses=0,
        incorrect_responses=0,
        timeout_responses=0,
        reliability_rate=0.0,
        avg_response_ms=None,
        trend=TrendDirection.STABLE,
        last_challenge_at=None,
        score_updated_at=now,
        is_reliable=False,
    )


def _row_to_reputation(row: Any) -> ReputationScore:
    total = int(row["total_challenges"])
    correct = int(row["correct"])
    incorrect = int(row["incorrect"])
    timeouts = int(row["timeouts"])
    denom = correct + incorrect + timeouts
    return ReputationScore(
        verifier_id=row["verifier_id"],
        tenant_id=row["tenant_id"],
        dynamic_score=float(row["dynamic_score"]),
        static_score=float(row["static_score"]),
        effective_score=float(row["effective_score"]),
        total_challenges=total,
        correct_responses=correct,
        incorrect_responses=incorrect,
        timeout_responses=timeouts,
        reliability_rate=(correct / denom) if denom > 0 else 0.0,
        avg_response_ms=float(row["avg_response_ms"]) if row["avg_response_ms"] else None,
        trend=TrendDirection(row["trend"]),
        last_challenge_at=row["last_challenge_at"],
        score_updated_at=row["score_updated_at"],
        is_reliable=(total >= _MIN_RELIABLE_CHALLENGES),
    )


def list_reputations(
    tenant_id: str | None = None,
    limit: int = 50,
    sort_by: str = "effective_score",
) -> list[ReputationScore]:
    """List verifier reputations, sorted by score descending."""
    init_reputation_db()
    valid_sorts = {"effective_score", "dynamic_score", "total_challenges",
                   "last_challenge_at", "score_updated_at"}
    order_col = sort_by if sort_by in valid_sorts else "effective_score"

    clauses: list[str] = []
    params: list[Any] = []
    if tenant_id:
        clauses.append("tenant_id=?")
        params.append(tenant_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 500))

    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM reputation_scores {where} ORDER BY {order_col} DESC LIMIT ?",
            params,
        )
        return [_row_to_reputation(r) for r in cur.fetchall()]


def get_challenge_history(
    verifier_id: str,
    tenant_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return recent challenge history for a verifier (for dashboard / API)."""
    init_reputation_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT challenge_id, verifier_id, tenant_id, challenge_nonce,
                   issued_at, expires_at, outcome, resolved_at, response_ms
            FROM reputation_challenges
            WHERE verifier_id=? AND tenant_id=?
            ORDER BY issued_at DESC
            LIMIT ?
        """, (verifier_id, tenant_id, min(limit, 200)))
        return [dict(r) for r in cur.fetchall()]


def get_leaderboard(tenant_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """
    Return reputation leaderboard for dashboard visualization.
    Sorted by effective_score descending with trend direction.
    """
    reps = list_reputations(tenant_id=tenant_id, limit=limit)
    return [
        {
            "rank": i + 1,
            "verifier_id": r.verifier_id,
            "effective_score": round(r.effective_score, 4),
            "trend": r.trend.value,
            "reliability_rate": round(r.reliability_rate, 4),
            "total_challenges": r.total_challenges,
            "is_reliable": r.is_reliable,
            "last_challenge_at": r.last_challenge_at,
        }
        for i, r in enumerate(reps)
    ]


def get_reputation_anomalies(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """
    Return verifiers with anomalous reputation signals:
    - Score dropped > 0.2 in trend window
    - Reliability rate < 0.5 with >= MIN_RELIABLE_CHALLENGES
    - Timeout rate > 50%
    """
    reps = list_reputations(tenant_id=tenant_id, limit=500)
    anomalies: list[dict[str, Any]] = []
    for r in reps:
        reasons: list[str] = []
        if r.trend == TrendDirection.DOWN and r.dynamic_score < 0.5:
            reasons.append("score_declining_below_threshold")
        if r.is_reliable and r.reliability_rate < 0.5:
            reasons.append("low_reliability_rate")
        timeout_rate = (
            r.timeout_responses / r.total_challenges
            if r.total_challenges > 0 else 0.0
        )
        if r.is_reliable and timeout_rate > 0.5:
            reasons.append("high_timeout_rate")
        if reasons:
            anomalies.append({
                **r.to_dict(),
                "anomaly_reasons": reasons,
            })
    return anomalies


# ---------------------------------------------------------------------------
# Sync static scores from dynamic reputation
# ---------------------------------------------------------------------------


def sync_static_scores(tenant_id: str) -> int:
    """
    Update trust_federation_verifiers.trust_score with the current effective
    reputation score. Only updates verifiers with reliable (>= MIN_RELIABLE)
    reputation data.
    Returns count of verifiers updated.
    """
    init_reputation_db()
    reps = list_reputations(tenant_id=tenant_id, limit=500)
    count = 0
    for r in reps:
        if not r.is_reliable:
            continue
        try:
            with _cursor() as cur:
                cur.execute("""
                    UPDATE trust_federation_verifiers
                    SET trust_score=?
                    WHERE verifier_id=? AND tenant_id=?
                """, (r.effective_score, r.verifier_id, r.tenant_id))
                if cur.rowcount > 0:
                    count += 1
        except Exception:
            pass
    return count


# ---------------------------------------------------------------------------
# Reputation-weighted quorum
# ---------------------------------------------------------------------------


def evaluate_reputation_weighted_quorum(
    attestations: list[dict[str, Any]],
    *,
    tenant_id: str,
    min_weight: float = 0.6,     # minimum total weight of passing verifiers
    min_verifiers: int = 1,
    min_reputation: float = 0.3,  # exclude verifiers below this threshold
) -> QuorumVerdict:
    """
    Evaluate a quorum of verifier attestations weighted by current reputation.

    Unlike the static quorum in trust_federation.evaluate_federation_quorum()
    which weights by trust_score set at registration, this function uses the
    current effective_score from the reputation network.

    attestations: list of verifier attestation dicts (must contain 'verifier_id',
                  'verdict', 'confidence')
    min_weight:   required sum of reputation weights of agreeing verifiers
    min_verifiers: minimum number of verifiers that must participate
    min_reputation: exclude verifiers with effective_score below this threshold

    Returns QuorumVerdict with verdict breakdown and met/not-met status.
    """
    if not attestations:
        return QuorumVerdict(
            met=False,
            total_reputation_weight=0.0,
            passing_weight=0.0,
            required_weight=min_weight,
            participating_verifiers=0,
            verdicts={},
            effective_action="step_up",
            confidence=0.0,
        )

    verdict_weights: dict[str, float] = {}
    total_weight = 0.0
    participating = 0

    for att in attestations:
        verifier_id = str(att.get("verifier_id", ""))
        verdict = str(att.get("verdict", "deny"))
        confidence = float(att.get("confidence", 1.0))

        rep = get_reputation(verifier_id, tenant_id)
        score = rep.effective_score

        if score < min_reputation:
            continue  # Exclude low-reputation verifiers from quorum

        weighted_vote = score * confidence
        verdict_weights[verdict] = verdict_weights.get(verdict, 0.0) + weighted_vote
        total_weight += weighted_vote
        participating += 1

    # Determine winning verdict by highest accumulated weight
    if not verdict_weights:
        effective_action = "step_up"
    else:
        effective_action = max(verdict_weights, key=lambda k: verdict_weights[k])

    passing_weight = verdict_weights.get(effective_action, 0.0)
    quorum_met = (
        participating >= min_verifiers
        and passing_weight >= min_weight
    )
    confidence = (passing_weight / total_weight) if total_weight > 0 else 0.0

    return QuorumVerdict(
        met=quorum_met,
        total_reputation_weight=round(total_weight, 4),
        passing_weight=round(passing_weight, 4),
        required_weight=min_weight,
        participating_verifiers=participating,
        verdicts={k: round(v, 4) for k, v in verdict_weights.items()},
        effective_action=effective_action if quorum_met else "step_up",
        confidence=round(confidence, 4),
    )


# ---------------------------------------------------------------------------
# Sampling helpers (for periodic challenge batches)
# ---------------------------------------------------------------------------


def get_verifiers_due_for_challenge(
    tenant_id: str,
    max_age_hours: int = 24,
    limit: int = 50,
) -> list[str]:
    """
    Return verifier_ids that haven't been challenged in the last max_age_hours.
    Used by the periodic challenge runner (heartbeat or cron).
    """
    init_reputation_db()
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    ).isoformat()

    with _cursor() as cur:
        # Verifiers with no recent pending or resolved challenges
        cur.execute("""
            SELECT v.verifier_id
            FROM trust_federation_verifiers v
            LEFT JOIN (
                SELECT verifier_id, MAX(issued_at) AS last_challenged
                FROM reputation_challenges
                WHERE tenant_id=?
                GROUP BY verifier_id
            ) c ON v.verifier_id = c.verifier_id
            WHERE v.tenant_id=? AND v.status != 'revoked'
                AND (c.last_challenged IS NULL OR c.last_challenged < ?)
            LIMIT ?
        """, (tenant_id, tenant_id, cutoff, limit))
        return [row["verifier_id"] for row in cur.fetchall()]
