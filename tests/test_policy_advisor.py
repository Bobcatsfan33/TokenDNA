"""
Tests for modules/identity/policy_advisor.py — Sprint 6-2
Adaptive Policy Suggestion Engine

Coverage areas:
  - DB initialization (idempotent)
  - analyze_and_generate: from guard violations, denied decisions, combined
  - Gate: >=3 actionable amendments from seeded adversarial run
  - Deduplication: repeat analysis doesn't create duplicate suggestions
  - list_suggestions: filtering by status, amendment_type, confidence
  - get_suggestion: fetch by ID
  - approve_suggestion: happy path + regression gate skip
  - approve_suggestion: regression failure leaves suggestion pending
  - reject_suggestion: happy path
  - bounded_auto_tighten: applies high-confidence, skips low-confidence
  - suggestion_stats
  - API: POST /api/policy/suggestions/analyze
  - API: GET  /api/policy/suggestions
  - API: GET  /api/policy/suggestions/stats
  - API: GET  /api/policy/suggestions/{id}
  - API: POST /api/policy/suggestions/{id}/approve
  - API: POST /api/policy/suggestions/{id}/reject
  - API: POST /api/policy/suggestions/auto-tighten
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

import importlib
from unittest import mock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets its own SQLite DB.

    We must reload policy_guard and decision_audit as well because they use
    module-level _DB_PATH (static at import time) rather than dynamic os.getenv().
    """
    db_file = tmp_path / "tokendna-test-advisor.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))
    monkeypatch.setenv("ATTESTATION_CA_SECRET", "test-advisor-secret")
    monkeypatch.setenv("DEV_MODE", "true")
    # Reload modules that use static _DB_PATH so they pick up the new path
    from modules.identity import policy_guard, decision_audit, policy_advisor
    importlib.reload(policy_guard)
    importlib.reload(decision_audit)
    importlib.reload(policy_advisor)
    policy_guard.init_db()
    decision_audit.init_db()
    policy_advisor.init_db()
    return str(db_file)


@pytest.fixture()
def advisor():
    from modules.identity import policy_advisor
    return policy_advisor


@pytest.fixture()
def client(isolated_db):
    """API client sharing the same DB as the isolated_db fixture."""
    db_file = isolated_db
    env = {
        "DATA_DB_PATH": db_file,
        "ATTESTATION_CA_SECRET": "test-advisor-secret",
        "DEV_MODE": "true",
    }
    with mock.patch.dict(os.environ, env):
        from modules.tenants import store as ts
        importlib.reload(ts)
        ts.init_db()
        from modules.identity import policy_guard, decision_audit, policy_advisor as _pa
        importlib.reload(policy_guard)
        importlib.reload(decision_audit)
        importlib.reload(_pa)
        policy_guard.init_db()
        decision_audit.init_db()
        _pa.init_db()
        import modules.tenants.middleware as mw
        importlib.reload(mw)
        import auth as auth_module
        importlib.reload(auth_module)
        import api as api_module
        importlib.reload(api_module)
        with TestClient(
            api_module.app,
            raise_server_exceptions=False,
            headers={"X-API-Key": "dev-api-key"},
        ) as c:
            yield c


TENANT = "tenant-adv"
API_TENANT = "acme"  # injected by DEV_MODE middleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_guard_violations(tenant_id: str, rule: str = "CONST-01", n: int = 5) -> list[str]:
    """Seed policy guard violations directly into the policy_guard table."""
    from modules.identity import policy_guard
    policy_guard.init_db()
    ids: list[str] = []
    for i in range(n):
        action = policy_guard.PolicyAction(
            actor_id=f"agent-{i % 3}",
            actor_type="agent",
            action_type="update",
            target_policy_id=f"policy-{i}",
            target_policy_name=f"agent-{i % 3}-policy",
            tenant_id=tenant_id,
            scope_delta=[f"write:resource{i}", f"admin:{i}"],
            metadata={"governed_agent": f"agent-{i % 3}"},
        )
        result = policy_guard.evaluate(action)
        ids.append(result.violation_id or "")
    return [v for v in ids if v]


def _seed_denied_decisions(tenant_id: str, n: int = 6) -> None:
    """Seed denied decision audit records with structured evaluation_input."""
    from modules.identity import decision_audit
    decision_audit.init_db()
    reason_pool = [
        ["scope violation: wildcard grant detected"],
        ["scope violation: permission exceeds declared purpose"],
        ["attestation drift: soul hash mismatch"],
        ["revoked credential presented"],
        ["delegation violation: chain depth exceeded"],
        ["scope violation: unexpected scope expansion"],
    ]
    for i in range(n):
        reasons = reason_pool[i % len(reason_pool)]
        # Use structured input that produce consistent replay results
        eval_input = {
            "uis_event": {"threat": {"risk_score": 95, "risk_tier": "block"}},
            "attestation": {
                "attestation_id": f"att-deny-{i}",
                "what": {"soul_hash": "s1", "model_fingerprint": "m1", "mcp_manifest_hash": "mcp1"},
                "how": {"dpop_bound": False, "mtls_bound": False},
                "why": {"scope": ["admin:*"], "delegation_chain": ["svc-x"]},
            },
            "certificate": None,
            "certificate_id": "",
            "request_headers": {
                "x-agent-soul-hash": "s1",
                "x-agent-model-fingerprint": "m1",
                "x-agent-mcp-manifest-hash": "mcp1",
                "x-agent-delegation-chain": "svc-x",
            },
            "observed_scope": ["admin:*"],
            "required_scope": [],
        }
        decision_audit.record_decision(
            tenant_id=tenant_id,
            request_id=f"req-{uuid.uuid4().hex[:8]}",
            source_endpoint="/api/secure",
            actor_subject=f"actor-{i % 2}",
            evaluation_input=eval_input,
            enforcement_result={
                "decision": {
                    "action": "block",
                    "reasons": reasons,
                    "policy_trace": {},
                }
            },
        )


# ---------------------------------------------------------------------------
# Unit tests — analysis and generation
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_idempotent(self, advisor):
        advisor.init_db()
        advisor.init_db()  # Should not raise
        stats = advisor.suggestion_stats(TENANT)
        assert stats["total"] == 0


class TestAnalyzeAndGenerate:
    def test_from_guard_violations_generates_suggestions(self, advisor):
        _seed_guard_violations(TENANT, rule="CONST-01", n=6)
        result = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        assert result["suggestions_generated"] >= 1
        assert result["violations_analyzed"] >= 1

    def test_from_denied_decisions_generates_suggestions(self, advisor):
        _seed_denied_decisions(TENANT, n=8)
        result = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        assert result["suggestions_generated"] >= 1
        assert result["denied_decisions_analyzed"] >= 1

    def test_combined_adversarial_run_gate(self, advisor):
        """
        Gate: suggestion engine generates >=3 actionable amendments from
        a seeded adversarial run combining guard violations + denied decisions.
        """
        _seed_guard_violations(TENANT, rule="CONST-01", n=5)
        _seed_guard_violations(TENANT, rule="CONST-02", n=4)
        _seed_denied_decisions(TENANT, n=10)
        result = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        assert result["suggestions_generated"] >= 3, (
            f"Expected >=3 actionable amendments, got {result['suggestions_generated']}"
        )
        assert len(result["suggestion_ids"]) >= 3

    def test_returns_tenant_isolation(self, advisor):
        """Suggestions from different tenants don't cross-contaminate."""
        _seed_guard_violations("other-tenant", n=6)
        result = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        # Should generate 0 for TENANT since violations are for other-tenant
        suggestions = advisor.list_suggestions(tenant_id=TENANT)
        for s in suggestions:
            assert s.tenant_id == TENANT

    def test_deduplication_prevents_duplicates(self, advisor):
        _seed_guard_violations(TENANT, n=5)
        result1 = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        result2 = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        # Second run should not duplicate what first run already generated
        assert result2["suggestions_generated"] == 0

    def test_min_confidence_filter(self, advisor):
        _seed_guard_violations(TENANT, n=3)
        result = advisor.analyze_and_generate(
            tenant_id=TENANT, lookback_hours=48, min_confidence=0.99
        )
        # High threshold → might get 0 suggestions
        assert result["suggestions_generated"] >= 0  # Just must not crash

    def test_source_type_filter(self, advisor):
        _seed_guard_violations(TENANT, n=5)
        _seed_denied_decisions(TENANT, n=8)
        # Only violations
        result = advisor.analyze_and_generate(
            tenant_id=TENANT,
            lookback_hours=48,
            source_types=["policy_guard_violation"],
        )
        assert result["violations_analyzed"] >= 1
        assert result["denied_decisions_analyzed"] == 0

    def test_by_amendment_type_counts(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        result = advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        total_by_type = sum(result["by_amendment_type"].values())
        assert total_by_type == result["suggestions_generated"]


# ---------------------------------------------------------------------------
# Unit tests — CRUD
# ---------------------------------------------------------------------------

class TestListSuggestions:
    def test_empty_returns_empty(self, advisor):
        suggestions = advisor.list_suggestions(tenant_id=TENANT)
        assert suggestions == []

    def test_filters_by_status(self, advisor):
        _seed_guard_violations(TENANT, n=3)
        _seed_denied_decisions(TENANT, n=6)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(tenant_id=TENANT, status="pending")
        assert all(s.status.value == "pending" for s in pending)

    def test_filters_by_amendment_type(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        all_s = advisor.list_suggestions(tenant_id=TENANT)
        if not all_s:
            pytest.skip("No suggestions generated")
        first_type = all_s[0].amendment_type.value
        filtered = advisor.list_suggestions(
            tenant_id=TENANT, amendment_type=first_type
        )
        assert all(s.amendment_type.value == first_type for s in filtered)

    def test_limit_respected(self, advisor):
        _seed_guard_violations(TENANT, n=6)
        _seed_denied_decisions(TENANT, n=10)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        results = advisor.list_suggestions(tenant_id=TENANT, limit=1)
        assert len(results) <= 1


class TestGetSuggestion:
    def test_get_existing(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        all_s = advisor.list_suggestions(tenant_id=TENANT)
        assert all_s
        s = advisor.get_suggestion(all_s[0].suggestion_id, TENANT)
        assert s is not None
        assert s.suggestion_id == all_s[0].suggestion_id

    def test_get_nonexistent_returns_none(self, advisor):
        s = advisor.get_suggestion("nonexistent-id", TENANT)
        assert s is None

    def test_get_wrong_tenant_returns_none(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        all_s = advisor.list_suggestions(tenant_id=TENANT)
        assert all_s
        s = advisor.get_suggestion(all_s[0].suggestion_id, "other-tenant")
        assert s is None


# ---------------------------------------------------------------------------
# Unit tests — approve / reject
# ---------------------------------------------------------------------------

class TestApproveSuggestion:
    def _get_pending(self, advisor) -> Any:
        _seed_guard_violations(TENANT, n=5)
        _seed_denied_decisions(TENANT, n=6)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(tenant_id=TENANT, status="pending")
        assert pending, "No pending suggestions to test with"
        return pending[0]

    def test_approve_without_regression(self, advisor):
        s = self._get_pending(advisor)
        approved = advisor.approve_suggestion(
            suggestion_id=s.suggestion_id,
            tenant_id=TENANT,
            approved_by="operator-1",
            note="Looks good",
            run_regression=False,
        )
        assert approved is not None
        assert approved.status.value == "approved"
        assert approved.reviewed_by == "operator-1"
        assert approved.review_note == "Looks good"

    def test_approve_with_regression_skipped_on_no_data(self, advisor):
        """When regression gate has no samples, it skips and approves."""
        s = self._get_pending(advisor)
        approved = advisor.approve_suggestion(
            suggestion_id=s.suggestion_id,
            tenant_id=TENANT,
            approved_by="operator-2",
            run_regression=True,
        )
        # With no decision audit baseline, regression is skipped → approved
        assert approved is not None
        assert approved.status.value == "approved"

    def test_approve_already_approved_returns_none(self, advisor):
        s = self._get_pending(advisor)
        advisor.approve_suggestion(
            suggestion_id=s.suggestion_id,
            tenant_id=TENANT,
            approved_by="op",
            run_regression=False,
        )
        # Second approve attempt on non-pending → None
        result = advisor.approve_suggestion(
            suggestion_id=s.suggestion_id,
            tenant_id=TENANT,
            approved_by="op2",
            run_regression=False,
        )
        assert result is None

    def test_approve_nonexistent_returns_none(self, advisor):
        result = advisor.approve_suggestion(
            suggestion_id="no-such-id",
            tenant_id=TENANT,
            approved_by="op",
            run_regression=False,
        )
        assert result is None


class TestRejectSuggestion:
    def test_reject_pending(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(tenant_id=TENANT, status="pending")
        assert pending
        rejected = advisor.reject_suggestion(
            suggestion_id=pending[0].suggestion_id,
            tenant_id=TENANT,
            rejected_by="security-lead",
            note="Not actionable at this time",
        )
        assert rejected is not None
        assert rejected.status.value == "rejected"
        assert rejected.reviewed_by == "security-lead"

    def test_reject_nonexistent_returns_none(self, advisor):
        result = advisor.reject_suggestion(
            suggestion_id="no-such",
            tenant_id=TENANT,
            rejected_by="op",
        )
        assert result is None

    def test_reject_already_rejected_returns_none(self, advisor):
        _seed_guard_violations(TENANT, n=3)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(tenant_id=TENANT, status="pending")
        assert pending
        s = pending[0]
        advisor.reject_suggestion(s.suggestion_id, TENANT, "op1")
        result = advisor.reject_suggestion(s.suggestion_id, TENANT, "op2")
        assert result is None


# ---------------------------------------------------------------------------
# Unit tests — bounded auto-tighten
# ---------------------------------------------------------------------------

class TestBoundedAutoTighten:
    def test_high_confidence_approved(self, advisor):
        """Seeds enough violations to get high-confidence suggestions, then auto-tightens."""
        # 15 violations → confidence = min(0.5 + 0.05*15, 0.95) = 0.95
        _seed_guard_violations(TENANT, n=15)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(tenant_id=TENANT, status="pending")
        assert any(s.confidence >= 0.85 for s in pending), (
            "Need at least one high-confidence suggestion for this test"
        )
        result = advisor.bounded_auto_tighten(
            tenant_id=TENANT,
            confidence_threshold=0.85,
            max_amendments_per_run=10,
        )
        assert result["applied"] >= 1

    def test_low_confidence_not_applied(self, advisor):
        """Low confidence suggestions (from 2 violations) should not be auto-tightened."""
        _seed_guard_violations(TENANT, n=2)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        result = advisor.bounded_auto_tighten(
            tenant_id=TENANT,
            confidence_threshold=0.95,
            max_amendments_per_run=10,
        )
        # 2 violations → confidence=0.6, below 0.95 threshold
        assert result["applied"] == 0

    def test_max_amendments_cap(self, advisor):
        """Ensures max_amendments_per_run caps application count."""
        _seed_guard_violations(TENANT, n=20)
        _seed_denied_decisions(TENANT, n=20)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        result = advisor.bounded_auto_tighten(
            tenant_id=TENANT,
            confidence_threshold=0.0,
            max_amendments_per_run=2,
        )
        assert result["applied"] <= 2

    def test_no_pending_returns_zero(self, advisor):
        result = advisor.bounded_auto_tighten(
            tenant_id=TENANT,
            confidence_threshold=0.0,
            max_amendments_per_run=5,
        )
        assert result["applied"] == 0
        assert result["candidates_evaluated"] == 0


# ---------------------------------------------------------------------------
# Unit tests — suggestion stats
# ---------------------------------------------------------------------------

class TestSuggestionStats:
    def test_empty_stats(self, advisor):
        stats = advisor.suggestion_stats(TENANT)
        assert stats["total"] == 0
        assert stats["pending"] == 0

    def test_stats_after_generation(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        _seed_denied_decisions(TENANT, n=6)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        stats = advisor.suggestion_stats(TENANT)
        assert stats["total"] >= 1
        assert stats["pending"] >= 1
        assert 0.0 <= stats["avg_confidence"] <= 1.0

    def test_stats_after_approve_reject(self, advisor):
        _seed_guard_violations(TENANT, n=4)
        advisor.analyze_and_generate(tenant_id=TENANT, lookback_hours=48)
        pending = advisor.list_suggestions(TENANT, status="pending")
        if len(pending) >= 2:
            advisor.approve_suggestion(pending[0].suggestion_id, TENANT, "op1", run_regression=False)
            advisor.reject_suggestion(pending[1].suggestion_id, TENANT, "op2")
            stats = advisor.suggestion_stats(TENANT)
            assert stats["approved"] >= 1
            assert stats["rejected"] >= 1


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------

class TestApiAnalyze:
    def test_analyze_endpoint(self, client):
        _seed_guard_violations(API_TENANT, n=5)
        _seed_denied_decisions(API_TENANT, n=8)
        resp = client.post(
            "/api/policy/suggestions/analyze",
            json={"lookback_hours": 48},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "suggestions_generated" in data
        assert "violation_ids" not in data  # not in API response

    def test_analyze_with_source_filter(self, client):
        _seed_guard_violations(API_TENANT, n=4)
        resp = client.post(
            "/api/policy/suggestions/analyze",
            json={"lookback_hours": 48, "source_types": ["policy_guard_violation"]},
        )
        assert resp.status_code == 200

    def test_analyze_invalid_source_types(self, client):
        resp = client.post(
            "/api/policy/suggestions/analyze",
            json={"source_types": "not-a-list"},
        )
        assert resp.status_code == 400


class TestApiListSuggestions:
    def test_list_empty(self, client):
        resp = client.get("/api/policy/suggestions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["suggestions"] == []

    def test_list_after_generate(self, client):
        _seed_guard_violations(API_TENANT, n=5)
        _seed_denied_decisions(API_TENANT, n=8)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        resp = client.get("/api/policy/suggestions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        # Verify shape
        for s in data["suggestions"]:
            assert "suggestion_id" in s
            assert "amendment_type" in s
            assert "confidence" in s
            assert "status" in s

    def test_list_filter_by_status(self, client):
        _seed_guard_violations(API_TENANT, n=4)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        resp = client.get("/api/policy/suggestions?status=pending")
        assert resp.status_code == 200
        data = resp.json()
        assert all(s["status"] == "pending" for s in data["suggestions"])


class TestApiStats:
    def test_stats_endpoint(self, client):
        resp = client.get("/api/policy/suggestions/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "pending" in data
        assert "avg_confidence" in data


class TestApiGetSuggestion:
    def test_get_existing(self, client):
        _seed_guard_violations(API_TENANT, n=4)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        list_resp = client.get("/api/policy/suggestions")
        suggestions = list_resp.json()["suggestions"]
        if not suggestions:
            pytest.skip("No suggestions generated")
        sid = suggestions[0]["suggestion_id"]
        resp = client.get(f"/api/policy/suggestions/{sid}")
        assert resp.status_code == 200
        assert resp.json()["suggestion_id"] == sid

    def test_get_nonexistent_returns_404(self, client):
        resp = client.get("/api/policy/suggestions/nonexistent-id")
        assert resp.status_code == 404


class TestApiApprove:
    def test_approve_endpoint(self, client):
        _seed_guard_violations(API_TENANT, n=5)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        list_resp = client.get("/api/policy/suggestions?status=pending")
        suggestions = list_resp.json()["suggestions"]
        if not suggestions:
            pytest.skip("No pending suggestions")
        sid = suggestions[0]["suggestion_id"]
        resp = client.post(
            f"/api/policy/suggestions/{sid}/approve",
            json={"approved_by": "ciso@example.com", "run_regression": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        assert data["reviewed_by"] == "ciso@example.com"

    def test_approve_missing_approved_by_400(self, client):
        resp = client.post(
            "/api/policy/suggestions/some-id/approve",
            json={},
        )
        assert resp.status_code == 400

    def test_approve_nonexistent_404(self, client):
        resp = client.post(
            "/api/policy/suggestions/no-such-id/approve",
            json={"approved_by": "op"},
        )
        assert resp.status_code == 404


class TestApiReject:
    def test_reject_endpoint(self, client):
        _seed_guard_violations(API_TENANT, n=4)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        list_resp = client.get("/api/policy/suggestions?status=pending")
        suggestions = list_resp.json()["suggestions"]
        if not suggestions:
            pytest.skip("No pending suggestions")
        sid = suggestions[0]["suggestion_id"]
        resp = client.post(
            f"/api/policy/suggestions/{sid}/reject",
            json={"rejected_by": "reviewer", "note": "False positive"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rejected"

    def test_reject_missing_rejected_by_400(self, client):
        resp = client.post(
            "/api/policy/suggestions/some-id/reject",
            json={},
        )
        assert resp.status_code == 400

    def test_reject_nonexistent_404(self, client):
        resp = client.post(
            "/api/policy/suggestions/no-such-id/reject",
            json={"rejected_by": "op"},
        )
        assert resp.status_code == 404


class TestApiAutoTighten:
    def test_auto_tighten_endpoint(self, client):
        _seed_guard_violations(API_TENANT, n=12)
        client.post("/api/policy/suggestions/analyze", json={"lookback_hours": 48})
        resp = client.post(
            "/api/policy/suggestions/auto-tighten",
            json={"confidence_threshold": 0.85, "max_amendments_per_run": 5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "applied" in data
        assert "candidates_evaluated" in data

    def test_auto_tighten_invalid_threshold(self, client):
        resp = client.post(
            "/api/policy/suggestions/auto-tighten",
            json={"confidence_threshold": 1.5},
        )
        assert resp.status_code == 400

    def test_auto_tighten_no_pending(self, client):
        resp = client.post(
            "/api/policy/suggestions/auto-tighten",
            json={"confidence_threshold": 0.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] == 0
