"""
Tests for modules/identity/agent_dna.py — Behavioral DNA for machine/agent identity.

Sprint 3-2: at least 15 tests covering compute, deviation scoring, persistence,
and integration with the UIS normalize flow.
"""

from __future__ import annotations

import os
import tempfile
import threading

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(
    *,
    protocol: str = "spiffe",
    method: str = "mtls",
    risk_score: int = 10,
    country: str = "US",
    issuer: str = "https://auth.acme.io",
    mfa_asserted: bool = False,
    dpop_bound: bool = False,
    agent_id: str = "agt-test",
) -> dict:
    return {
        "identity": {"agent_id": agent_id, "subject": f"{agent_id}@acme.svc", "entity_type": "machine"},
        "auth": {"protocol": protocol, "method": method, "mfa_asserted": mfa_asserted},
        "token": {"issuer": issuer, "dpop_bound": dpop_bound},
        "session": {"country": country},
        "threat": {"risk_score": risk_score},
        "binding": {"dpop_bound": dpop_bound},
    }


def _make_baseline(
    *,
    protocol_distribution: dict | None = None,
    auth_method_distribution: dict | None = None,
    risk_mean: float = 10.0,
    risk_std: float = 2.0,
    risk_p95: float = 14.0,
    typical_countries: list | None = None,
    typical_issuers: list | None = None,
    agent_id: str = "agt-test",
) -> dict:
    from modules.identity.agent_dna import compute_agent_dna

    events = [_make_event(agent_id=agent_id)] * 4
    dna = compute_agent_dna(agent_id=agent_id, events=events)
    # Override specific fields for test isolation
    if protocol_distribution is not None:
        dna["protocol_distribution"] = protocol_distribution
    if auth_method_distribution is not None:
        dna["auth_method_distribution"] = auth_method_distribution
    if typical_countries is not None:
        dna["typical_countries"] = typical_countries
    if typical_issuers is not None:
        dna["typical_issuers"] = typical_issuers
    dna["risk_score_baseline"] = {"mean": risk_mean, "std_dev": risk_std, "p95": risk_p95}
    return dna


# ── compute_agent_dna ─────────────────────────────────────────────────────────

def test_compute_agent_dna_empty_events():
    from modules.identity.agent_dna import compute_agent_dna

    dna = compute_agent_dna("agt-empty", [])
    assert dna["version"] == 1
    assert dna["agent_id"] == "agt-empty"
    assert dna["event_count"] == 0
    assert dna["protocol_distribution"] == {}
    assert dna["auth_method_distribution"] == {}
    assert dna["mfa_rate"] == 0.0
    assert dna["dpop_rate"] == 0.0
    assert dna["typical_countries"] == []
    assert dna["typical_issuers"] == []
    assert dna["risk_score_baseline"]["mean"] == 0.0
    assert dna["risk_score_baseline"]["std_dev"] == 0.0
    assert isinstance(dna["fingerprint_hash"], str)
    assert len(dna["fingerprint_hash"]) == 64  # sha256 hex


def test_compute_agent_dna_protocol_distribution():
    """3 spiffe + 1 oidc → spiffe=0.75, oidc=0.25."""
    from modules.identity.agent_dna import compute_agent_dna

    events = [
        _make_event(protocol="spiffe"),
        _make_event(protocol="spiffe"),
        _make_event(protocol="spiffe"),
        _make_event(protocol="oidc"),
    ]
    dna = compute_agent_dna("agt-proto", events)
    assert dna["event_count"] == 4
    assert abs(dna["protocol_distribution"]["spiffe"] - 0.75) < 1e-6
    assert abs(dna["protocol_distribution"]["oidc"] - 0.25) < 1e-6


def test_compute_agent_dna_risk_baseline():
    """Verify mean, std_dev, and p95 are computed correctly."""
    from modules.identity.agent_dna import compute_agent_dna

    # risk scores: 10, 20, 30, 40  → mean=25, variance=125, std=11.18, p95=40
    events = [
        _make_event(risk_score=10),
        _make_event(risk_score=20),
        _make_event(risk_score=30),
        _make_event(risk_score=40),
    ]
    dna = compute_agent_dna("agt-risk", events)
    baseline = dna["risk_score_baseline"]
    assert abs(baseline["mean"] - 25.0) < 0.01
    # Population std_dev for [10,20,30,40]: sqrt(125) ≈ 11.18
    import math
    assert abs(baseline["std_dev"] - math.sqrt(125)) < 0.01
    # p95 of 4 items = ceil(0.95*4)-1 = ceil(3.8)-1 = 4-1 = index 3 → value 40
    assert baseline["p95"] == 40.0


def test_compute_agent_dna_fingerprint_hash_is_deterministic():
    """Same inputs always produce the same fingerprint_hash."""
    from modules.identity.agent_dna import compute_agent_dna

    events = [_make_event(agent_id="agt-det")] * 5
    dna1 = compute_agent_dna("agt-det", events)
    dna2 = compute_agent_dna("agt-det", events)
    assert dna1["fingerprint_hash"] == dna2["fingerprint_hash"]


def test_compute_agent_dna_fingerprint_hash_changes_on_different_input():
    """Different agent_id → different fingerprint_hash."""
    from modules.identity.agent_dna import compute_agent_dna

    events = [_make_event()] * 5
    dna_a = compute_agent_dna("agt-alpha", events)
    dna_b = compute_agent_dna("agt-beta", events)
    assert dna_a["fingerprint_hash"] != dna_b["fingerprint_hash"]


def test_compute_agent_dna_mfa_rate():
    """2 out of 4 events with mfa_asserted → rate 0.5."""
    from modules.identity.agent_dna import compute_agent_dna

    events = [
        _make_event(mfa_asserted=True),
        _make_event(mfa_asserted=True),
        _make_event(mfa_asserted=False),
        _make_event(mfa_asserted=False),
    ]
    dna = compute_agent_dna("agt-mfa", events)
    assert abs(dna["mfa_rate"] - 0.5) < 1e-6


def test_compute_agent_dna_typical_countries_threshold():
    """Country must appear in >10% of events to be 'typical'."""
    from modules.identity.agent_dna import compute_agent_dna

    # US in 9/10 events (90%), GB in 1/10 (10%) — GB is NOT > 10%, exactly at threshold
    events = [_make_event(country="US")] * 9 + [_make_event(country="GB")]
    dna = compute_agent_dna("agt-country", events)
    assert "US" in dna["typical_countries"]
    assert "GB" not in dna["typical_countries"]  # exactly 10%, not strictly greater


# ── compute_deviation_score ───────────────────────────────────────────────────

def test_compute_deviation_score_zero_for_matching_event():
    """An event perfectly matching the baseline should score near 0."""
    from modules.identity.agent_dna import compute_agent_dna, compute_deviation_score

    events = [_make_event(protocol="spiffe", method="mtls", risk_score=10, country="US")] * 10
    baseline = compute_agent_dna("agt-match", events)
    event = _make_event(protocol="spiffe", method="mtls", risk_score=10, country="US")
    score = compute_deviation_score(baseline, event)
    assert score == 0.0


def test_compute_deviation_score_new_protocol():
    """An unknown protocol should contribute at least +0.3."""
    from modules.identity.agent_dna import compute_deviation_score

    baseline = _make_baseline(protocol_distribution={"spiffe": 1.0})
    event = _make_event(protocol="oidc")  # not in baseline
    score = compute_deviation_score(baseline, event)
    assert score >= 0.3


def test_compute_deviation_score_new_country():
    """An unknown country should contribute at least +0.15."""
    from modules.identity.agent_dna import compute_deviation_score

    baseline = _make_baseline(typical_countries=["US"])
    event = _make_event(country="RU")
    score = compute_deviation_score(baseline, event)
    assert score >= 0.15


def test_compute_deviation_score_high_risk():
    """A risk_score > mean + 2*std should add +0.2 to the score."""
    from modules.identity.agent_dna import compute_deviation_score

    baseline = _make_baseline(risk_mean=10.0, risk_std=2.0)
    # 10 + 2*2 = 14; event risk=15 is above threshold
    event = _make_event(
        protocol="spiffe", method="mtls", risk_score=15, country="US", issuer="https://auth.acme.io"
    )
    # Patch baseline so protocol/method/country/issuer all match to isolate risk signal
    baseline["protocol_distribution"] = {"spiffe": 1.0}
    baseline["auth_method_distribution"] = {"mtls": 1.0}
    baseline["typical_countries"] = ["US"]
    baseline["typical_issuers"] = ["https://auth.acme.io"]
    score = compute_deviation_score(baseline, event)
    assert score > 0.0


def test_compute_deviation_score_clamped_to_one():
    """Multiple simultaneous deviations must not exceed 1.0."""
    from modules.identity.agent_dna import compute_deviation_score

    baseline = _make_baseline(
        protocol_distribution={"spiffe": 1.0},
        auth_method_distribution={"mtls": 1.0},
        risk_mean=0.0,
        risk_std=0.0,
        typical_countries=["US"],
        typical_issuers=["https://auth.acme.io"],
    )
    # Everything deviates: new protocol (+0.3), new method (+0.2), high risk (+0.2),
    # new country (+0.15), new issuer (+0.15) = 1.0 → clamped
    event = _make_event(
        protocol="custom", method="bearer", risk_score=999, country="CN", issuer="https://evil.io"
    )
    score = compute_deviation_score(baseline, event)
    assert score <= 1.0
    assert score == 1.0


# ── Persistence (store / get) ─────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Redirect all SQLite writes to a temp file for test isolation."""
    db_file = str(tmp_path / "test_agent_dna.db")
    monkeypatch.setenv("DATA_DB_PATH", db_file)
    # Re-import to pick up new env var in _db_path()
    import importlib
    import modules.identity.agent_dna as mod
    importlib.reload(mod)
    mod.build_agent_dna_store()
    yield mod


def test_store_and_get_agent_dna_roundtrip(tmp_db):
    """store_agent_dna then get_agent_dna returns identical data."""
    events = [_make_event(agent_id="agt-roundtrip")] * 5
    dna = tmp_db.compute_agent_dna("agt-roundtrip", events)
    tmp_db.store_agent_dna("tenant-1", dna)
    retrieved = tmp_db.get_agent_dna("tenant-1", "agt-roundtrip")
    assert retrieved is not None
    assert retrieved["agent_id"] == "agt-roundtrip"
    assert retrieved["fingerprint_hash"] == dna["fingerprint_hash"]
    assert retrieved["event_count"] == dna["event_count"]


def test_get_agent_dna_returns_none_when_missing(tmp_db):
    """Unknown agent should return None, not raise."""
    result = tmp_db.get_agent_dna("tenant-missing", "agt-nobody")
    assert result is None


def test_store_overwrites_previous_record(tmp_db):
    """Second store for same (tenant, agent) should replace the first."""
    events_small = [_make_event(agent_id="agt-overwrite")] * 3
    events_large = [_make_event(agent_id="agt-overwrite")] * 8
    dna_v1 = tmp_db.compute_agent_dna("agt-overwrite", events_small)
    dna_v2 = tmp_db.compute_agent_dna("agt-overwrite", events_large)
    tmp_db.store_agent_dna("tenant-x", dna_v1)
    tmp_db.store_agent_dna("tenant-x", dna_v2)
    retrieved = tmp_db.get_agent_dna("tenant-x", "agt-overwrite")
    assert retrieved["event_count"] == 8


# ── Integration with UIS normalize flow ──────────────────────────────────────

@pytest.fixture()
def uis_with_agent_dna(tmp_db, monkeypatch):
    """Reload uis module after pointing DATA_DB_PATH to the tmp db."""
    import importlib
    import modules.identity.uis as uis_mod
    importlib.reload(uis_mod)
    return uis_mod, tmp_db


def test_normalize_populates_dna_fingerprint_for_agents(uis_with_agent_dna):
    """After seeding a baseline, normalize sets behavior.dna_fingerprint."""
    uis_mod, agent_dna_mod = uis_with_agent_dna
    agent_id = "agt-fingerprint-test"
    tenant_id = "tenant-fp"

    # Seed a baseline
    events = [_make_event(agent_id=agent_id)] * 10
    dna = agent_dna_mod.compute_agent_dna(agent_id, events)
    agent_dna_mod.store_agent_dna(tenant_id, dna)

    # Normalize a new event for the same agent
    result = uis_mod.normalize_from_protocol(
        protocol="spiffe",
        tenant_id=tenant_id,
        tenant_name="Acme",
        subject=f"{agent_id}@acme.svc",
        claims={"agent_id": agent_id, "iss": "https://auth.acme.io"},
        request_context={"request_id": "req-1", "country": "US"},
        risk_context={},
    )
    assert result["behavior"]["dna_fingerprint"] == dna["fingerprint_hash"]


def test_normalize_populates_deviation_score(uis_with_agent_dna):
    """After seeding a baseline, behavior.pattern_deviation_score is a float."""
    uis_mod, agent_dna_mod = uis_with_agent_dna
    agent_id = "agt-devscore-test"
    tenant_id = "tenant-ds"

    events = [_make_event(agent_id=agent_id)] * 5
    dna = agent_dna_mod.compute_agent_dna(agent_id, events)
    agent_dna_mod.store_agent_dna(tenant_id, dna)

    result = uis_mod.normalize_from_protocol(
        protocol="spiffe",
        tenant_id=tenant_id,
        tenant_name="Acme",
        subject=f"{agent_id}@acme.svc",
        claims={"agent_id": agent_id, "iss": "https://auth.acme.io"},
        request_context={"request_id": "req-2", "country": "US"},
        risk_context={},
    )
    assert isinstance(result["behavior"]["pattern_deviation_score"], float)


def test_velocity_anomaly_set_on_high_deviation(uis_with_agent_dna):
    """deviation_score > 0.6 should set behavior.velocity_anomaly = True."""
    uis_mod, agent_dna_mod = uis_with_agent_dna
    agent_id = "agt-anomaly-test"
    tenant_id = "tenant-anom"

    # Establish a baseline with only spiffe/mtls/US
    events = [
        _make_event(agent_id=agent_id, protocol="spiffe", method="mtls", country="US",
                    issuer="https://auth.acme.io", risk_score=5)
    ] * 20
    dna = agent_dna_mod.compute_agent_dna(agent_id, events)
    agent_dna_mod.store_agent_dna(tenant_id, dna)

    # Send an event that deviates heavily: new protocol, new method, new country, new issuer
    result = uis_mod.normalize_from_protocol(
        protocol="custom",   # +0.3 (not in baseline)
        tenant_id=tenant_id,
        tenant_name="Acme",
        subject=f"{agent_id}@acme.svc",
        claims={
            "agent_id": agent_id,
            "iss": "https://evil.io",   # +0.15
            "auth_method": "password",  # +0.2
        },
        request_context={
            "request_id": "req-anom",
            "country": "CN",  # +0.15
        },
        risk_context={"risk_score": 0},
    )
    # Total = 0.3 + 0.2 + 0.15 + 0.15 = 0.8 → velocity_anomaly should be True
    assert result["behavior"]["velocity_anomaly"] is True


def test_normalize_no_baseline_does_not_raise(uis_with_agent_dna):
    """When there is no baseline yet, normalize should complete without error."""
    uis_mod, _ = uis_with_agent_dna
    result = uis_mod.normalize_from_protocol(
        protocol="spiffe",
        tenant_id="tenant-nobsl",
        tenant_name="Acme",
        subject="agt-new@acme.svc",
        claims={"agent_id": "agt-new"},
        request_context={"request_id": "req-nb"},
        risk_context={},
    )
    # behavior.dna_fingerprint may be None (from context) — no exception raised
    assert "behavior" in result
