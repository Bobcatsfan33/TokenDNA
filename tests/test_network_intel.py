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

