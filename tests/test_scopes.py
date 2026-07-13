"""T-4: tests for per-route scope authorization (AC-6)."""
import asyncio

import pytest
from fastapi import HTTPException

from modules.auth import scopes


def _run(dep, claims):
    return asyncio.run(dep(claims=claims))


# ── held_scopes parsing ───────────────────────────────────────────────────────

def test_held_scopes_from_scp_list():
    assert scopes.held_scopes({"scp": ["policy:read", "policy:write"]}) == {
        "policy:read", "policy:write"
    }


def test_held_scopes_from_scp_string():
    assert scopes.held_scopes({"scp": "a:read a:write"}) == {"a:read", "a:write"}


def test_held_scopes_from_scope_string():
    assert scopes.held_scopes({"scope": "x:read y:write"}) == {"x:read", "y:write"}


def test_held_scopes_empty():
    assert scopes.held_scopes({}) == set()


# ── enforcement toggle ────────────────────────────────────────────────────────

def test_enforcement_default_off(monkeypatch):
    monkeypatch.delenv("TOKENDNA_SCOPES_ENFORCE", raising=False)
    assert scopes.enforcement_enabled() is False


def test_enforcement_on(monkeypatch):
    monkeypatch.setenv("TOKENDNA_SCOPES_ENFORCE", "true")
    assert scopes.enforcement_enabled() is True


# ── require_scopes behavior ───────────────────────────────────────────────────

def test_grants_when_scope_present():
    dep = scopes.require_scopes("policy:write")
    claims = {"sub": "u1", "scp": ["policy:write"]}
    assert _run(dep, claims) == claims


def test_log_only_allows_when_missing(monkeypatch):
    monkeypatch.delenv("TOKENDNA_SCOPES_ENFORCE", raising=False)
    events = []
    monkeypatch.setattr(scopes, "log_event", lambda *a, **k: events.append((a, k)))
    dep = scopes.require_scopes("policy:write")
    claims = {"sub": "u1", "org_id": "acme", "scp": ["policy:read"]}
    # log-only: returns claims, does NOT raise
    assert _run(dep, claims) == claims
    assert len(events) == 1
    detail = events[0][1]["detail"]
    assert detail["mode"] == "log_only"
    assert detail["missing"] == ["policy:write"]


def test_enforce_raises_403_when_missing(monkeypatch):
    monkeypatch.setenv("TOKENDNA_SCOPES_ENFORCE", "true")
    events = []
    monkeypatch.setattr(scopes, "log_event", lambda *a, **k: events.append((a, k)))
    dep = scopes.require_scopes("policy:write", "policy:admin")
    claims = {"sub": "u1", "tenant_id": "acme", "scp": ["policy:read"]}
    with pytest.raises(HTTPException) as exc:
        _run(dep, claims)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "insufficient_scope"
    assert set(exc.value.detail["missing"]) == {"policy:write", "policy:admin"}
    assert events and events[0][1]["detail"]["mode"] == "enforce"


def test_dev_mode_bypasses(monkeypatch):
    monkeypatch.setenv("TOKENDNA_SCOPES_ENFORCE", "true")
    dep = scopes.require_scopes("policy:write")
    claims = {"sub": "dev-user", "dev_mode": True}
    assert _run(dep, claims) == claims


# ── helpers ───────────────────────────────────────────────────────────────────

def test_scopes_for_tier_feature():
    assert scopes.scopes_for_tier_feature("ent.enforcement_plane") == ("enforcement_plane:write",)


def test_iter_scope_vocabulary():
    assert scopes.iter_scope_vocabulary(["policy"]) == [
        "policy:read", "policy:write", "policy:admin"
    ]
