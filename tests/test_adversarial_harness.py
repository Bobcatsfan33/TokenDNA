from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import adversarial_harness


def test_adversarial_harness_runs_and_returns_all_checks():
    result = adversarial_harness.run(strict=False)
    assert "ok" in result
    assert "checks" in result
    checks = result["checks"]
    assert isinstance(checks, list)
    names = {c["name"] for c in checks}
    assert "forged_certificate_detected" in names
    assert "scope_replay_escalation_handled" in names
    assert "intel_poisoning_suppressed" in names
    assert "tampered_federation_signature_detected" in names
    assert result["failed_count"] == len([c for c in checks if not c["ok"]])
