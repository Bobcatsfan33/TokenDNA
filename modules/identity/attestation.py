"""
TokenDNA -- Agent supply chain attestation primitives.

Implements first-pass consolidation of AegisAI attestation capabilities into
TokenDNA:
  - Agent DNA fingerprint derivation for machine identities
  - 4D attestation record model (WHO/WHAT/HOW/WHY)
  - Deterministic attestation ID generation and integrity digest
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_agent_dna_fingerprint(
    agent_id: str,
    runtime_context: dict[str, Any],
    behavior_features: dict[str, Any],
) -> str:
    """
    Create a deterministic machine-identity fingerprint for an agent session.

    This is intentionally deterministic given the same inputs so downstream
    systems can correlate/compare fingerprints.
    """
    payload = {
        "agent_id": agent_id,
        "runtime": runtime_context,
        "behavior": behavior_features,
    }
    return _sha256_hex(_canonical_json(payload))


@dataclass
class AttestationRecord:
    attestation_id: str
    created_at: str
    who: dict[str, Any]
    what: dict[str, Any]
    how: dict[str, Any]
    why: dict[str, Any]
    integrity_digest: str
    agent_dna_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "created_at": self.created_at,
            "who": self.who,
            "what": self.what,
            "how": self.how,
            "why": self.why,
            "integrity_digest": self.integrity_digest,
            "agent_dna_fingerprint": self.agent_dna_fingerprint,
        }


def create_attestation_record(
    *,
    agent_id: str,
    owner_org: str,
    created_by: str,
    soul_hash: str,
    directive_hashes: list[str],
    model_fingerprint: str,
    mcp_manifest_hash: str,
    auth_method: str,
    dpop_bound: bool,
    mtls_bound: bool,
    behavior_confidence: float,
    declared_purpose: str,
    scope: list[str],
    delegation_chain: list[str],
    policy_trace_id: str | None = None,
    runtime_context: dict[str, Any] | None = None,
    behavior_features: dict[str, Any] | None = None,
) -> AttestationRecord:
    runtime_context = runtime_context or {}
    behavior_features = behavior_features or {}

    agent_dna = build_agent_dna_fingerprint(
        agent_id=agent_id,
        runtime_context=runtime_context,
        behavior_features=behavior_features,
    )

    who = {
        "agent_id": agent_id,
        "created_by": created_by,
        "owner_org": owner_org,
    }
    what = {
        "soul_hash": soul_hash,
        "directive_hashes": directive_hashes,
        "model_fingerprint": model_fingerprint,
        "mcp_manifest_hash": mcp_manifest_hash,
    }
    how = {
        "auth_method": auth_method,
        "dpop_bound": dpop_bound,
        "mtls_bound": mtls_bound,
        "behavior_confidence": round(float(behavior_confidence), 4),
    }
    why = {
        "declared_purpose": declared_purpose,
        "scope": scope,
        "delegation_chain": delegation_chain,
        "policy_trace_id": policy_trace_id,
    }

    integrity_payload = {
        "who": who,
        "what": what,
        "how": how,
        "why": why,
        "agent_dna": agent_dna,
    }
    digest = _sha256_hex(_canonical_json(integrity_payload))
    entropy = uuid.uuid4().hex
    attestation_id = _sha256_hex(f"{agent_id}:{time.time_ns()}:{entropy}")[:32]

    return AttestationRecord(
        attestation_id=attestation_id,
        created_at=_utc_now(),
        who=who,
        what=what,
        how=how,
        why=why,
        integrity_digest=digest,
        agent_dna_fingerprint=agent_dna,
    )

