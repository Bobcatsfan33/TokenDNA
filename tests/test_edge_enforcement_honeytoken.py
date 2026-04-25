"""
Honeytoken pre-check integration in edge_enforcement.

Coverage:
  - Presenting an active honeytoken short-circuits to a block decision
    with reasons=["honeytoken_presented"] and a deception entry in
    policy_trace.
  - Hit is recorded against the decoy via honeypot_mesh.record_decoy_hit.
  - Inactive/deactivated decoys do not trigger the short-circuit.
  - A non-honeytoken credential lets the real auth path run (we don't
    block legitimate traffic).
  - A failure inside honeypot_mesh.is_honeytoken does NOT crash the auth
    path — we fail open (the worst case is one missed decoy hit).
  - The honeytoken pre-check runs *before* certificate verification, so a
    presented decoy never reaches the cert path (no information leak).
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    db = str(tmp_path / "edge_hp.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    monkeypatch.setenv("TOKENDNA_HONEYPOT_SECRET", "edge-test-secret")
    yield db


@pytest.fixture()
def stack(tmp_db):
    import importlib

    import modules.identity.honeypot_mesh as hp
    import modules.identity.edge_enforcement as ee

    importlib.reload(hp)
    importlib.reload(ee)
    hp.init_db()
    return {"hp": hp, "ee": ee}


def _baseline_call(ee, **overrides):
    """Default call to evaluate_runtime_enforcement that exercises only the
    honeytoken path — provide an empty cert_id / no attestation so the rest
    of the engine is a no-op."""
    kwargs = dict(
        uis_event={"session": {"ip": "1.2.3.4"}},
        attestation=None,
        certificate=None,
        certificate_id="",
        request_headers={},
        observed_scope=[],
        required_scope=None,
    )
    kwargs.update(overrides)
    return ee.evaluate_runtime_enforcement(**kwargs)


class TestHoneytokenShortCircuit:
    def test_honeytoken_in_authorization_header_blocks(self, stack):
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]
        result = _baseline_call(
            stack["ee"],
            request_headers={"Authorization": f"Bearer {secret}"},
        )
        assert result["decision"]["action"] == "block"
        assert "honeytoken_presented" in result["decision"]["reasons"]
        assert result["honeytoken_hit"]["decoy_id"] == decoy.decoy_id
        assert result["authn_failure"] is True

    def test_honeytoken_in_xapikey_blocks(self, stack):
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]
        result = _baseline_call(
            stack["ee"],
            request_headers={"X-API-Key": secret},
        )
        assert result["decision"]["action"] == "block"
        assert result["honeytoken_hit"]["decoy_id"] == decoy.decoy_id

    def test_honeytoken_as_certificate_id_blocks(self, stack):
        decoy = stack["hp"].seed_honeytoken("tenant-test", kind="honeytoken_certificate")
        secret = decoy.as_dict()["secret_value"]
        # Certificate IDs are checked too — adversary may present a fake cert
        # id from a leaked database dump.
        result = _baseline_call(stack["ee"], certificate_id=secret)
        assert result["decision"]["action"] == "block"

    def test_hit_is_recorded(self, stack):
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]
        _baseline_call(
            stack["ee"],
            uis_event={"session": {"ip": "5.5.5.5", "request_path": "/secret"}},
            request_headers={"Authorization": f"Bearer {secret}", "User-Agent": "curl"},
        )
        hits = stack["hp"].get_decoy_hits("tenant-test")
        assert len(hits) == 1
        h = hits[0]
        assert h["decoy_id"] == decoy.decoy_id
        assert h["source_ip"] == "5.5.5.5"
        assert h["user_agent"] == "curl"

    def test_deactivated_decoy_does_not_trigger(self, stack):
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]
        stack["hp"].deactivate_decoy(decoy.decoy_id, tenant_id="tenant-test")
        # The presented value is no longer an active decoy — pre-check
        # returns None and we fall through to the real auth path. With no
        # certificate_id supplied the regular flow lets it through to the
        # ABAC step (the result won't carry honeytoken_hit).
        result = _baseline_call(
            stack["ee"],
            request_headers={"X-API-Key": secret},
        )
        assert "honeytoken_hit" not in result

    def test_non_honeytoken_passes_through(self, stack):
        result = _baseline_call(
            stack["ee"],
            request_headers={"X-API-Key": "definitely-not-a-decoy"},
        )
        assert "honeytoken_hit" not in result
        # Real auth path ran — decision shape includes timing breakdown.
        assert "timing" in result
        assert "policy_ms" in result["timing"]

    def test_honeypot_module_failure_fails_open(self, stack, monkeypatch):
        """A crash inside honeypot_mesh.is_honeytoken must NOT propagate to
        the auth path. The worst case is a missed decoy hit; the right case
        is never breaking real auth."""
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]

        def _explode(_token):
            raise RuntimeError("honeypot module exploded")

        monkeypatch.setattr(stack["hp"], "is_honeytoken", _explode)
        # The presented value would have matched, but the lookup raises.
        # Fail-open: result must still be returned (no exception bubbles).
        result = _baseline_call(
            stack["ee"],
            request_headers={"X-API-Key": secret},
        )
        # honeytoken_hit absent → real auth path ran.
        assert "honeytoken_hit" not in result

    def test_pre_check_runs_before_certificate_verification(self, stack):
        """Verifies the security property: a presented decoy never reaches
        certificate_verify, so timing / response shape don't reveal whether
        the value would have been a real credential."""
        decoy = stack["hp"].seed_honeytoken("tenant-test")
        secret = decoy.as_dict()["secret_value"]
        # Provide a real-looking certificate_id alongside — without
        # honeypot, this would go through the cert verify path. With
        # honeypot pre-check, it should short-circuit before that.
        result = _baseline_call(
            stack["ee"],
            certificate_id="cert-real-001",
            request_headers={"Authorization": f"Bearer {secret}"},
        )
        # honeytoken_hit set; cert_verify_ms is 0 (path didn't run).
        assert result["honeytoken_hit"]
        assert result["timing"]["cert_verify_ms"] == 0.0
        assert result["timing"]["drift_ms"] == 0.0
        assert result["timing"]["policy_ms"] == 0.0
