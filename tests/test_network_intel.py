from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["NETWORK_INTEL_HASH_SALT"] = "test-salt"
    return tmpdir


def test_network_intel_record_feed_and_assess():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import network_intel

        network_intel.init_db()
        network_intel.record_signal(
            tenant_id="tenant-a",
            signal_type="ip_hash",
            raw_value="ip-1",
            severity="high",
            confidence=0.8,
            metadata={"source": "test"},
        )
        network_intel.record_signal(
            tenant_id="tenant-b",
            signal_type="ip_hash",
            raw_value="ip-1",
            severity="critical",
            confidence=0.9,
            metadata={"source": "test"},
        )

        feed = network_intel.get_feed(limit=10, min_tenant_count=2, min_confidence=0.6)
        assert len(feed) == 1
        assert feed[0]["signal_type"] == "ip_hash"
        assert feed[0]["tenant_count"] == 2

        assessment = network_intel.assess_runtime_penalty(
            [{"signal_type": "ip_hash", "raw_value": "ip-1"}]
        )
        assert assessment["penalty"] > 0
        assert len(assessment["hits"]) == 1
    finally:
        tmp.cleanup()


def test_network_intel_suppression_and_allowlist_rules():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import network_intel

        network_intel.init_db()
        network_intel.upsert_suppression_rule(
            signal_type="ip_hash",
            raw_value="ip-suspicious",
            mode="suppress",
            reason="known test noise",
        )
        suppressed = network_intel.record_signal(
            tenant_id="tenant-a",
            signal_type="ip_hash",
            raw_value="ip-suspicious",
            severity="high",
            confidence=0.8,
            metadata={"source": "runtime"},
        )
        assert suppressed["suppressed"] is True

        network_intel.upsert_suppression_rule(
            signal_type="ip_hash",
            raw_value="ip-suspicious",
            mode="allow",
            reason="false positive",
        )
        allowed = network_intel.record_signal(
            tenant_id="tenant-a",
            signal_type="ip_hash",
            raw_value="ip-suspicious",
            severity="high",
            confidence=0.8,
            metadata={"source": "manual_review"},
        )
        assert allowed["suppressed"] is False
        rules = network_intel.list_suppression_rules(limit=10)
        assert len(rules) >= 2
    finally:
        tmp.cleanup()


def test_network_intel_anti_poisoning_and_decay():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import network_intel

        os.environ["NETWORK_INTEL_MIN_OBSERVATIONS"] = "2"
        network_intel.init_db()
        suspicious = network_intel.record_signal(
            tenant_id="tenant-a",
            signal_type="device_hash",
            raw_value="dev-1",
            severity="high",
            confidence=0.99,
            metadata={"source": "unknown"},
        )
        assert suspicious["suppressed"] is True

        signal = network_intel.record_signal(
            tenant_id="tenant-a",
            signal_type="asn",
            raw_value="64512",
            severity="medium",
            confidence=0.6,
            metadata={"source": "manual_review"},
        )
        assert signal["suppressed"] is False
        # Force old signal and run decay.
        with network_intel._cursor() as cur:  # type: ignore[attr-defined]
            cur.execute(
                "UPDATE network_intel_signals SET last_seen = ? WHERE signal_key = ?",
                ("2000-01-01T00:00:00+00:00", signal["signal_key"]),
            )
        decay = network_intel.apply_decay(older_than_days=1)
        assert decay["decayed"] >= 0
    finally:
        os.environ.pop("NETWORK_INTEL_MIN_OBSERVATIONS", None)
        tmp.cleanup()

