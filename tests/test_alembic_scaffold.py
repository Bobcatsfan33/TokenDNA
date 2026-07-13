from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[1]


def test_alembic_ini_exists_and_points_at_alembic_dir():
    cfg = _REPO / "alembic.ini"
    assert cfg.exists()
    body = cfg.read_text()
    assert "script_location = alembic" in body
    assert "prepend_sys_path = ." in body


def test_alembic_env_resolves_url_from_pg_dsn(monkeypatch):
    """env.py prefers TOKENDNA_PG_DSN, then TOKENDNA_ALEMBIC_URL, then ini default."""
    env_path = _REPO / "alembic" / "env.py"
    text = env_path.read_text()
    # URL resolution is a small inline function — assert the priority order
    # by checking the source rather than executing env.py (which requires alembic).
    assert "TOKENDNA_PG_DSN" in text
    assert "TOKENDNA_ALEMBIC_URL" in text
    # PG DSN check must appear before ALEMBIC_URL fallback.
    assert text.index("TOKENDNA_PG_DSN") < text.index("TOKENDNA_ALEMBIC_URL")


def test_baseline_revision_lists_phase5_modules():
    baseline = _REPO / "alembic" / "versions" / "0001_baseline.py"
    assert baseline.exists()
    body = baseline.read_text()
    for required in (
        "modules.identity.policy_guard",
        "modules.identity.permission_drift",
        "modules.identity.agent_lifecycle",
        "modules.identity.mcp_inspector",
        "modules.identity.mcp_gateway",
        "modules.identity.agent_discovery",
        "modules.identity.enforcement_plane",
        "modules.identity.passport",
        "modules.identity.uis_store",
    ):
        assert required in body, f"baseline missing module: {required}"


def test_baseline_downgrade_is_blocked():
    baseline = _REPO / "alembic" / "versions" / "0001_baseline.py"
    body = baseline.read_text()
    # A bare downgrade must raise — production-data safety.
    assert "NotImplementedError" in body
    assert "alembic stamp head" in body
