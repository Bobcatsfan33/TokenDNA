"""
Tests for the ZTIX-honesty PR.

Coverage:
  - /api/ztix/simulate response carries demo:true + warning + null
    production_endpoint so the demo nature is unambiguous server-side.
  - The returned ztix_token has demo:true, no signature, no binding.
  - proof_of_control._DEFAULT_INTERVAL_HOURS dropped from 24 to 1.
  - Module docstring no longer claims "Continuous"; says "Periodic".
  - resolve_challenge auto-wires record_proof on a CORRECT outcome,
    closing the integration-by-docstring drift risk.
  - Auto-wire is best-effort: a proof_of_control failure does not break
    challenge resolution.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# Demo-flag contract on /api/ztix/simulate
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "z.db"))
    monkeypatch.setenv("DEV_MODE", "true")

    # Pre-init the DB schemas the simulate route reaches into. We can't
    # rely on app lifespan because lifespan's startup_checks have side
    # effects (rate-limit DB, audit log, etc.) the test rig doesn't need.
    import modules.identity.attestation_store as ats
    import modules.identity.trust_graph as tg
    import modules.identity.uis_store as us
    import modules.identity.intent_correlation as ic
    ats.init_db()
    tg.init_db()
    us.init_db()
    ic.init_db()

    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id="t-ztix", tenant_name="Z",
        plan=Plan.ENTERPRISE, api_key_id="k", role="owner",
    )

    def _override():
        return tenant

    import modules.product.commercial_tiers as _ct
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


class TestSimulateDemoFlag:
    def test_response_carries_demo_true(self, app_client):
        resp = app_client.post("/api/ztix/simulate",
                               json={"agent_a": "agt-a", "agent_b": "agt-b"})
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("demo") is True
        assert body.get("warning")
        assert "production_endpoint" in body
        assert body["production_endpoint"] is None

    def test_token_marked_unsigned(self, app_client):
        body = app_client.post("/api/ztix/simulate",
                               json={"agent_a": "x", "agent_b": "y"}).json()
        token = body["ztix_token"]
        # Token-level marker — survives even if a caller persists just the
        # token without the wrapping response.
        assert token.get("demo") is True
        assert token.get("signature") is None
        assert token.get("binding") is None
        assert token["ztix_id"].startswith("ztix-demo-")

    def test_warning_mentions_no_signature(self, app_client):
        body = app_client.post("/api/ztix/simulate",
                               json={"agent_a": "x", "agent_b": "y"}).json()
        msg = body["warning"].lower()
        # The warning must surface the actual security property, not
        # just say "demo" — operators reading the JSON should learn the
        # specific gap.
        assert "not cryptographically bound" in msg or "not bound" in msg \
            or "no signature" in msg or "not be presented" in msg


# ─────────────────────────────────────────────────────────────────────────────
# proof_of_control default interval + naming
# ─────────────────────────────────────────────────────────────────────────────

class TestPeriodicNotContinuous:
    def test_default_interval_is_one_hour(self, monkeypatch):
        # Reload to pick up the default with no env override.
        monkeypatch.delenv("POC_DEFAULT_INTERVAL_HOURS", raising=False)
        import modules.identity.proof_of_control as poc
        importlib.reload(poc)
        assert poc._DEFAULT_INTERVAL_HOURS == 1

    def test_env_override_still_works(self, monkeypatch):
        monkeypatch.setenv("POC_DEFAULT_INTERVAL_HOURS", "6")
        import modules.identity.proof_of_control as poc
        importlib.reload(poc)
        assert poc._DEFAULT_INTERVAL_HOURS == 6

    def test_module_docstring_says_periodic(self):
        import modules.identity.proof_of_control as poc
        importlib.reload(poc)
        doc = poc.__doc__ or ""
        # The header should not claim "Continuous" any more — it oversells
        # the guarantee. "Periodic" is the honest name.
        assert "Periodic Proof-of-Control" in doc
        # And the rename note must explain the reasoning so future readers
        # don't try to re-rename it back.
        assert "renamed" in doc.lower() or "naming note" in doc.lower()


# ─────────────────────────────────────────────────────────────────────────────
# resolve_challenge auto-wires record_proof
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def reputation_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "rep.db"))
    monkeypatch.delenv("POC_DEFAULT_INTERVAL_HOURS", raising=False)

    import modules.storage.pg_connection as pgc
    pgc._pg_pool = None  # type: ignore[attr-defined]

    import modules.identity.verifier_reputation as vr
    import modules.identity.proof_of_control as poc
    importlib.reload(pgc)
    importlib.reload(vr)
    importlib.reload(poc)
    vr.init_reputation_db()
    poc.init_db()
    return vr, poc


class TestAutoWire:
    def test_correct_resolution_records_proof(self, reputation_stack):
        vr, poc = reputation_stack
        verifier_id = "v-1"
        tenant_id = "t-1"

        challenge = vr.issue_challenge(verifier_id, tenant_id)
        # Submit the EXPECTED response so outcome is CORRECT.
        resolved = vr.resolve_challenge(
            challenge.challenge_id, challenge.expected_response,
        )
        assert resolved.outcome == vr.ChallengeOutcome.CORRECT

        # The auto-wire should have called record_proof — verify by
        # querying the proof_of_control registry.
        reg = poc.get_proof_status(verifier_id, tenant_id)
        assert reg is not None
        assert reg.last_proof_at is not None

    def test_incorrect_resolution_does_not_record(self, reputation_stack):
        vr, poc = reputation_stack
        verifier_id = "v-2"
        tenant_id = "t-1"
        challenge = vr.issue_challenge(verifier_id, tenant_id)
        # Wrong response → INCORRECT outcome.
        resolved = vr.resolve_challenge(challenge.challenge_id, "definitely-wrong")
        assert resolved.outcome == vr.ChallengeOutcome.INCORRECT

        reg = poc.get_proof_status(verifier_id, tenant_id)
        # Either no proof entry exists at all, or last_proof_at is None.
        assert reg is None or reg.last_proof_at is None

    def test_proof_module_failure_does_not_break_resolve(
        self, reputation_stack, monkeypatch,
    ):
        """If proof_of_control raises, the challenge still resolves cleanly.
        The integration is best-effort; a proof_of_control outage cannot
        block challenge resolution."""
        vr, poc = reputation_stack
        verifier_id = "v-3"
        tenant_id = "t-1"

        def _explode(*_a, **_kw):
            raise RuntimeError("proof_of_control unavailable")

        monkeypatch.setattr(poc, "record_proof", _explode)

        challenge = vr.issue_challenge(verifier_id, tenant_id)
        resolved = vr.resolve_challenge(
            challenge.challenge_id, challenge.expected_response,
        )
        # Resolution still succeeds even though the auto-wire failed.
        assert resolved.outcome == vr.ChallengeOutcome.CORRECT


# ─────────────────────────────────────────────────────────────────────────────
# Source-level guard: the docstring "integration points" footgun is gone
# ─────────────────────────────────────────────────────────────────────────────

class TestSourceLevelGuards:
    def test_resolve_challenge_calls_record_proof(self):
        """The resolve_challenge function must reference record_proof in
        its source — otherwise the auto-wire was reverted and the
        integration drift footgun is back."""
        import modules.identity.verifier_reputation as vr
        src = inspect.getsource(vr.resolve_challenge)
        assert "record_proof" in src
        assert "ChallengeOutcome.CORRECT" in src
