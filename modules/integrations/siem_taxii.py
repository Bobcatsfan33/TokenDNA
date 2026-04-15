"""
TokenDNA -- STIX/TAXII formatting helpers for SIEM/SOAR integration.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def threat_signal_to_stix_indicator(signal: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a TokenDNA threat-intel signal into a STIX 2.1 indicator object.
    """
    indicator_id = f"indicator--{uuid.uuid4()}"
    signal_type = str(signal.get("signal_type", "unknown"))
    signal_hash = str(signal.get("signal_hash", ""))
    severity = str(signal.get("severity", "medium")).upper()
    confidence = int(float(signal.get("confidence", 0.5)) * 100)
    pattern = f"[x-tokendna-signal:type = '{signal_type}' AND x-tokendna-signal:hash = '{signal_hash}']"
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": _iso_now(),
        "modified": _iso_now(),
        "name": f"TokenDNA {signal_type} indicator",
        "description": f"Anonymized {signal_type} indicator from TokenDNA cross-tenant feed.",
        "pattern_type": "stix",
        "pattern": pattern,
        "valid_from": _iso_now(),
        "labels": ["tokendna", "identity-threat-intel", signal_type],
        "confidence": max(min(confidence, 100), 0),
        "x_tokendna_severity": severity,
        "x_tokendna_tenant_count": int(signal.get("tenant_count", 0)),
    }


def build_taxii_bundle(signals: list[dict[str, Any]]) -> dict[str, Any]:
    indicators = [threat_signal_to_stix_indicator(signal) for signal in signals]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": indicators,
    }

