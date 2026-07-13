from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.integrations.idp_events import adapt_idp_event
from modules.integrations.siem_taxii import build_taxii_bundle


def test_adapt_idp_event_okta_projection():
    event = {
        "actor": {"id": "u1", "displayName": "User One"},
        "client": {"ipAddress": "1.2.3.4", "userAgent": {"rawUserAgent": "UA"}},
        "transaction": {"id": "tx1"},
        "outcome": {"result": "SUCCESS"},
    }
    claims = adapt_idp_event("okta", event)
    assert claims["sub"] == "u1"
    assert claims["iss"] == "okta"


def test_build_taxii_bundle_from_signal_feed():
    bundle = build_taxii_bundle(
        [
            {
                "signal_type": "ip_hash",
                "signal_hash": "abc123",
                "severity": "high",
                "confidence": 0.8,
                "tenant_count": 4,
            }
        ]
    )
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 1
    assert bundle["objects"][0]["type"] == "indicator"

