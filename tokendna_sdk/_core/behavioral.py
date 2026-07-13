"""
Per-agent behavioral baseline.

What this is
------------
A small, local-only anomaly detector. It tracks per-agent rolling
statistics over the most recent N sessions (default 50) and scores
the *current* session against them. The score is a number in
``[0.0, 1.0]`` we hand to ``client.verify`` so the server's policy
engine can decide what to do with it.

Signals captured
----------------
1. **Tool-call frequency** — per-session count, scored via z-score.
2. **Tool sequence familiarity** — fraction of consecutive (a → b)
   tool transitions in this session that were ever observed in the
   baseline. Low overlap = high anomaly.
3. **Unknown-tool ratio** — how many distinct tools this session
   touched that aren't in the agent's normal vocabulary.

Each signal is normalized to ``[0, 1]``; the final score is the max
across signals. We use max (not average) because a single strong
signal is more interesting than three weak ones.

Targets
-------
- Warmup: baseline marked usable (``is_warm()``) only after 5 sessions.
  Cold baselines emit score ``0.0`` regardless of session contents to
  keep false-positive rate under 10%.
- Persistence: baselines are stored as a single JSON file under
  ``~/.tokendna/baselines.json`` (or wherever the local root points).
- Concurrency: file writes are serialized with a per-store lock.

Server-mode note
----------------
When the SDK runs against a remote service, the server may also score
behavior. The local score still ships so the server can combine
signals; the client never *enforces* a behavioral verdict by itself.
"""

from __future__ import annotations

import json
import logging
import math
import statistics
import threading
from pathlib import Path
from typing import Any

from ..models import BehavioralBaseline, utc_now

logger = logging.getLogger(__name__)


DEFAULT_BASELINE_WINDOW = 50
WARMUP_SESSIONS = 5
DEFAULT_TOOL_VOCAB_SIZE = 32

# z-score above which a session counts as "extreme" for the frequency
# signal. 3 sigma ≈ 99.7th percentile assuming normality — set lower if
# the agent's session count is wildly bursty (the score is clamped to
# [0, 1] regardless).
FREQUENCY_Z_CUTOFF = 3.0


class BaselineStore:
    """File-backed store of per-agent baselines.

    Single JSON file with shape::

        {
          "agent-id-1": {
            "agent_id": "...",
            "sessions_observed": 12,
            "tool_call_mean": 4.2,
            "tool_call_stddev": 1.1,
            "common_tools": ["search", "fetch", ...],
            "common_sequences": [["search", "fetch"], ...],
            "session_counts": [3, 5, 4, ...],   # rolling window
            "updated_at": "..."
          },
          ...
        }

    The rolling-window list (``session_counts``) is what we recompute
    mean/stddev from each session; the dataclass fields are the
    cached summary for fast reads.
    """

    def __init__(self, path: str | Path,
                 *, window: int = DEFAULT_BASELINE_WINDOW) -> None:
        self.path = Path(path)
        self.window = window
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._loaded = False

    # ── persistence ───────────────────────────────────────────────────

    def _load(self) -> None:
        if self._loaded:
            return
        try:
            if self.path.exists():
                self._cache = json.loads(self.path.read_text("utf-8"))
            else:
                self._cache = {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("tokendna_sdk baselines unreadable; starting fresh: %s",
                           exc)
            self._cache = {}
        self._loaded = True

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._cache, sort_keys=True, indent=0),
                            encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            logger.warning("tokendna_sdk baselines persist failed: %s", exc)

    # ── reads ─────────────────────────────────────────────────────────

    def get(self, agent_id: str) -> BehavioralBaseline:
        with self._lock:
            self._load()
            raw = self._cache.get(agent_id)
            if not raw:
                return BehavioralBaseline(agent_id=agent_id)
            return BehavioralBaseline(
                agent_id=agent_id,
                sessions_observed=int(raw.get("sessions_observed", 0)),
                tool_call_mean=float(raw.get("tool_call_mean", 0.0)),
                tool_call_stddev=float(raw.get("tool_call_stddev", 0.0)),
                common_tools=list(raw.get("common_tools", [])),
                common_sequences=[list(s) for s in raw.get("common_sequences", [])],
                updated_at=str(raw.get("updated_at", utc_now())),
            )

    # ── writes ────────────────────────────────────────────────────────

    def record_session(self, agent_id: str, tool_calls: list[str]) -> None:
        """Append a finished session's tool-call sequence to the rolling
        window and recompute summary stats."""
        with self._lock:
            self._load()
            rec = self._cache.setdefault(agent_id, {
                "agent_id": agent_id,
                "session_counts": [],
                "tool_vocabulary": [],
                "sequence_vocabulary": [],
            })
            counts: list[int] = rec.setdefault("session_counts", [])
            counts.append(len(tool_calls))
            if len(counts) > self.window:
                del counts[: len(counts) - self.window]

            vocab: list[str] = rec.setdefault("tool_vocabulary", [])
            for t in tool_calls:
                if t not in vocab:
                    vocab.append(t)
            # cap vocab so the JSON doesn't grow without bound
            if len(vocab) > DEFAULT_TOOL_VOCAB_SIZE:
                del vocab[: len(vocab) - DEFAULT_TOOL_VOCAB_SIZE]

            seqs: list[list[str]] = rec.setdefault("sequence_vocabulary", [])
            for a, b in zip(tool_calls, tool_calls[1:]):
                pair = [a, b]
                if pair not in seqs:
                    seqs.append(pair)
            if len(seqs) > DEFAULT_TOOL_VOCAB_SIZE * 2:
                del seqs[: len(seqs) - DEFAULT_TOOL_VOCAB_SIZE * 2]

            mean = statistics.fmean(counts) if counts else 0.0
            stdev = (statistics.pstdev(counts) if len(counts) > 1 else 0.0)
            rec.update({
                "sessions_observed": len(counts),
                "tool_call_mean": mean,
                "tool_call_stddev": stdev,
                "common_tools": list(vocab),
                "common_sequences": [list(s) for s in seqs],
                "updated_at": utc_now(),
            })
            self._save()


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_session(baseline: BehavioralBaseline, tool_calls: list[str]) -> float:
    """Score the current session against the agent's baseline.

    Returns a float in ``[0.0, 1.0]``. Cold baselines (under 5 sessions)
    always return 0.0 — we'd rather under-score than burn the false
    positive budget while still learning.
    """
    if not baseline.is_warm():
        return 0.0
    if not tool_calls:
        return 0.0

    freq = _frequency_signal(baseline, len(tool_calls))
    vocab = _vocabulary_signal(baseline, tool_calls)
    seq = _sequence_signal(baseline, tool_calls)

    # Soft-max: amplify the strongest signal a little.
    return max(min(1.0, s) for s in (freq, vocab, seq))


def _frequency_signal(b: BehavioralBaseline, count: int) -> float:
    if b.tool_call_stddev <= 0.0:
        # No variance yet — only flag if we're wildly above the mean.
        if b.tool_call_mean <= 0:
            return 0.0
        return min(1.0, count / max(b.tool_call_mean * 5.0, 1.0))
    z = abs((count - b.tool_call_mean) / b.tool_call_stddev)
    if z < 1.0:
        return 0.0
    # Linear ramp from z=1 → 0.0 to z=FREQUENCY_Z_CUTOFF → 1.0.
    return min(1.0, (z - 1.0) / (FREQUENCY_Z_CUTOFF - 1.0))


def _vocabulary_signal(b: BehavioralBaseline, tool_calls: list[str]) -> float:
    if not b.common_tools:
        return 0.0
    distinct = set(tool_calls)
    known = set(b.common_tools)
    unknown = distinct - known
    if not distinct:
        return 0.0
    return len(unknown) / len(distinct)


def _sequence_signal(b: BehavioralBaseline, tool_calls: list[str]) -> float:
    if len(tool_calls) < 2 or not b.common_sequences:
        return 0.0
    known = {tuple(s) for s in b.common_sequences}
    transitions = list(zip(tool_calls, tool_calls[1:]))
    if not transitions:
        return 0.0
    unfamiliar = sum(1 for t in transitions if t not in known)
    return unfamiliar / len(transitions)


# ── Lightweight pattern detector for MCP / agent chains ───────────────────────

def detect_chain(tool_calls: list[str], pattern: list[str],
                  *, max_gap: int = 3) -> bool:
    """Bounded-gap subsequence match.

    Returns True iff ``pattern`` appears in order in ``tool_calls`` with
    no more than ``max_gap`` un-matched calls between consecutive pattern
    elements. Used by the MCP interceptor (Sprint 3) to flag classic
    exfil shapes like ``["read_file", "send_email"]`` even when the
    agent makes intervening tool calls.
    """
    if not pattern:
        return True
    i = 0
    last_match = -math.inf
    for idx, call in enumerate(tool_calls):
        if call == pattern[i]:
            if last_match != -math.inf and idx - last_match - 1 > max_gap:
                # gap too big — restart search from the next position
                # to allow overlapping matches.
                i = 0
                last_match = -math.inf
                if call == pattern[0]:
                    i = 1
                    last_match = idx
                continue
            last_match = idx
            i += 1
            if i == len(pattern):
                return True
    return False


__all__ = [
    "BaselineStore",
    "score_session",
    "detect_chain",
    "WARMUP_SESSIONS",
    "DEFAULT_BASELINE_WINDOW",
    "FREQUENCY_Z_CUTOFF",
]
