from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import compliance


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    return tmpdir


def test_control_map_contains_framework():
    mapping = compliance.build_control_map("disa_stig")
    assert mapping["framework"] == "disa_stig"
    assert "IA-2" in mapping["controls"]


def test_generate_store_list_evidence_package_roundtrip():
    tmp = _setup_tmp_db()
    try:
        compliance.init_db()
        package = compliance.generate_evidence_package(
            tenant_id="tenant-1",
            framework="fedramp",
            inputs={
                "uis_event_count": 10,
                "attestation_count": 5,
                "certificate_count": 5,
                "revoked_certificate_count": 1,
                "drift_event_count": 2,
                "threat_signal_count": 4,
            },
        )
        compliance.store_evidence_package(package)
        rows = compliance.list_evidence_packages("tenant-1", framework="fedramp", limit=10)
        assert len(rows) == 1
        assert rows[0]["framework"] == "fedramp"
        assert rows[0]["summary"]["coverage_score"] > 0
    finally:
        tmp.cleanup()

