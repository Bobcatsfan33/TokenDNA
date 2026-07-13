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
    db_path = Path(tmpdir.name) / "tokendna-metering-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    return tmpdir


def test_metering_blocks_hard_limit_for_free_tier():
    tmp = _setup_tmp_db()
    try:
        metering.init_db()
        usage = metering.record_usage(
            tenant_id="tenant-1",
            feature_key="compliance.signed_snapshots",
            plan=PlanTier.FREE,
            amount=1,
            detail={"api": "/api/compliance/evidence/snapshot"},
        )
        assert usage["usage"]["status"] == "blocked"
        rows = metering.get_monthly_usage(tenant_id="tenant-1")
        assert rows == []
    finally:
        tmp.cleanup()


def test_metering_tracks_usage_and_statement_for_pro_tier():
    tmp = _setup_tmp_db()
    try:
        metering.init_db()
        for _ in range(3):
            metering.record_usage(
                tenant_id="tenant-2",
                feature_key="policy.simulation.advanced",
                plan=PlanTier.PRO,
                amount=1,
                detail={"api": "/api/policy/bundles/simulate"},
            )
        usage_rows = metering.get_monthly_usage(tenant_id="tenant-2")
        assert len(usage_rows) == 1
        assert usage_rows[0]["used_amount"] == 3
        statement = metering.build_usage_statement(tenant_id="tenant-2")
        assert statement["totals"]["features"] == 1
        assert statement["totals"]["used_amount"] == 3
    finally:
        tmp.cleanup()
