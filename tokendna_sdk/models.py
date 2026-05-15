"""
Typed data models for the SDK public surface.

These dataclasses are the *wire shape* between user code, the framework
middleware integrations, and the TokenDNA service. They're intentionally
plain stdlib dataclasses — no pydantic — so the SDK install stays
dependency-free.

Two conventions worth noting:

* All ``timestamp`` fields are ISO-8601 strings in UTC with the literal
  ``+00:00`` suffix. We hand-format these (see :func:`utc_now`) rather
  than relying on ``datetime.isoformat()`` so the wire format stays
  byte-stable across Python 3.9–3.13.
* ``tool_args_hash`` is the hex-encoded SHA-256 of a canonical-JSON
  serialization of the argument map. We hash rather than ship arguments
  by default to avoid leaking secrets via instrumentation — see
  :func:`hash_args`.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with the ``+00:00`` suffix.

    Hand-formatted for byte-stable wire output. ``datetime.isoformat()``
    on a UTC-aware datetime yields ``+00:00`` on 3.12+ but historically
    has varied with locale/precision; pinning the format here removes
    that drift.
    """
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def hash_args(args: dict[str, Any] | None) -> str:
    """SHA-256 of a canonical-JSON encoding of the arg map.

    Non-JSON-serializable values are coerced via ``repr()`` — we lose
    fidelity on those values but never crash the wedge.
    """
    if not args:
        return hashlib.sha256(b"{}").hexdigest()
    try:
        canonical = json.dumps(args, sort_keys=True, separators=(",", ":"),
                               default=repr)
    except TypeError:
        canonical = repr(sorted(args.items()))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def new_session_id() -> str:
    """Generate a session id. Public so framework adapters can correlate
    multiple events to the same agent run without re-inventing the format."""
    return f"sess-{uuid.uuid4().hex[:24]}"


# ── Identity ──────────────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    """The minimum identifying material an attested agent carries.

    ``framework`` distinguishes LangChain/CrewAI/AutoGen/plain — useful
    for downstream analytics. ``version`` is the agent's own version
    string (NOT the SDK version); we capture it so workflow attestations
    can pin to a specific agent build.
    """
    agent_id: str
    agent_type: str = "generic"
    framework: str = "plain"
    version: str = "0.0.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Events ────────────────────────────────────────────────────────────────────

@dataclass
class ToolCallEvent:
    """A single tool invocation. Emitted by ``@tool`` and by middleware
    after each ``wrap_tool_call`` hop. ``tool_args_hash`` lets us spot
    repeats without ever transmitting the arguments themselves."""
    agent_id: str
    tool_name: str
    tool_args_hash: str
    timestamp: str = field(default_factory=utc_now)
    session_id: str = field(default_factory=new_session_id)
    duration_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelCallEvent:
    """A single model invocation. Captured by ``wrap_model_call`` in the
    LangChain middleware and by the CrewAI/AutoGen adapters."""
    agent_id: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    timestamp: str = field(default_factory=utc_now)
    session_id: str = field(default_factory=new_session_id)
    duration_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Verdict ───────────────────────────────────────────────────────────────────

@dataclass
class PolicyVerdict:
    """Result of an explicit policy verification call.

    ``allow``/``deny``/``warn`` mirror the server's policy engine. ``reason``
    is a short machine-readable code (e.g. ``"scope:missing"``); ``message``
    is human-readable. ``score`` is the optional behavioral-anomaly score
    (0.0 = baseline, 1.0 = strongly anomalous).
    """
    decision: str  # "allow" | "deny" | "warn"
    reason: str = ""
    message: str = ""
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attestation:
    """Server-issued attestation receipt for a completed workflow.

    ``receipt_id`` is the canonical identifier downstream callers should
    forward when delegating further work. ``hops`` is the captured
    workflow trace as emitted by :func:`tokendna_sdk.get_agent_metadata`.
    """
    receipt_id: str
    agent_id: str
    issued_at: str = field(default_factory=utc_now)
    hops: list[dict[str, Any]] = field(default_factory=list)
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Behavioral baseline ───────────────────────────────────────────────────────

@dataclass
class BehavioralBaseline:
    """Rolling per-agent behavioral baseline.

    Stored locally in :class:`TokenDNALocalClient`; in remote mode the
    server is the source of truth. Used by the behavioral detector in
    :mod:`tokendna_sdk._core.behavioral`.
    """
    agent_id: str
    sessions_observed: int = 0
    tool_call_mean: float = 0.0
    tool_call_stddev: float = 0.0
    common_tools: list[str] = field(default_factory=list)
    common_sequences: list[list[str]] = field(default_factory=list)
    updated_at: str = field(default_factory=utc_now)

    def is_warm(self) -> bool:
        """A baseline is usable after 5 sessions — under that we suppress
        the behavioral signal entirely (per the <10% FPR target)."""
        return self.sessions_observed >= 5

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = [
    "AgentIdentity",
    "ToolCallEvent",
    "ModelCallEvent",
    "PolicyVerdict",
    "Attestation",
    "BehavioralBaseline",
    "utc_now",
    "hash_args",
    "new_session_id",
]
