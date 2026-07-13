from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.product import metering
from modules.product.feature_gates import PlanTier


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-metering-export-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["ATTESTATION_CA_SECRET"] = "metering-export-secret"
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    return tmpdir


def test_billing_export_json_and_csv_signature_verification():
    tmp = _setup_tmp_db()
    try:
        metering.init_db()
        for _ in range(3):
            metering.record_usage(
                tenant_id="tenant-1",
                feature_key="policy.simulation.advanced",
                plan=PlanTier.PRO,
                amount=1,
                detail={"api": "/api/policy/bundles/simulate"},
            )

        export_json = metering.export_billing_statement(
            tenant_id="tenant-1",
            export_format="json",
            algorithm="HS256",
        )
        verify_json = metering.verify_billing_export_signature(export_json)
        assert verify_json["valid"] is True
        assert export_json["content_type"] == "application/json"

        export_csv = metering.export_billing_statement(
            tenant_id="tenant-1",
            export_format="csv",
            algorithm="HS256",
        )
        verify_csv = metering.verify_billing_export_signature(export_csv)
        assert verify_csv["valid"] is True
        assert export_csv["content_type"] == "text/csv"

        exports = metering.list_billing_exports(tenant_id="tenant-1", limit=10)
        assert len(exports) >= 2
        assert {e["export_format"] for e in exports}.issuperset({"json", "csv"})
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()
