"""
Tests for Exploit Intent Correlation Engine (Sprint 2-2).

Coverage:
  - init_db + built-in playbook seeding (15 playbooks)
  - _step_matches: category, mitre_technique, pivot, objective, min_confidence, risk_tier
  - correlate_event: no match on single event for multi-step playbook
  - correlate_event: match fires when all steps satisfied in sequence
  - correlate_event: state expires after window_seconds
  - correlate_event: subject-scoped state isolation
  - correlate_event: match emitted only once (state reset after match)
  - add_playbook: creates custom playbook
  - add_playbook: validates severity and steps
  - delete_playbook: deletes custom; refuses builtin
  - get_playbooks: returns builtins + custom
  - get_matches: returns matches with filters
  - uis_store integration: correlate_event called on insert (non-fatal)
"""

from __future__ import annotations

import json
import os
import time

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path):
    db = str(tmp_path / "test.db")
    old = os.environ.get("DATA_DB_PATH")
    os.environ["DATA_DB_PATH"] = db
    yield db
    if old is None:
        os.environ.pop("DATA_DB_PATH", None)
    else:
        os.environ["DATA_DB_PATH"] = old


@pytest.fixture()
def ice(tmp_db):
    import importlib
    import modules.identity.intent_correlation as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-ice-test"


def _event(
    category: str = "auth_anomaly",
    mitre_technique: str = "T1078",
    pivot: str = "",
    objective: str = "gain_access",
    confidence: float = 0.8,
    risk_tier: str = "high",
    subject: str = "user@x.com",
) -> dict:
    return {
        "event_id": f"ev-{category}-{time.time_ns()}",
        "event_timestamp": "2026-04-16T00:00:00+00:00",
        "identity": {"subject": subject, "entity_type": "human",
                     "tenant_id": TENANT, "tenant_name": "T",
                     "machine_classification": "user", "agent_id": None},
        "threat": {"risk_score": 80 if risk_tier == "high" else 30,
                   "risk_tier": risk_tier, "indicators": [], "lateral_movement": False},
        "uis_narrative": {
            "category": category,
            "mitre_technique": mitre_technique,
            "mitre_tactic": "TA0006",
            "pivot": pivot,
            "objective": objective,
            "confidence": confidence,
            "narrative": f"Test: {category}",
            "schema_version": "1.1",
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# init_db + built-in playbooks
# ─────────────────────────────────────────────────────────────────────────────

class TestInitDB:
    def test_tables_created(self, ice, tmp_db):
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        assert "intent_playbooks" in tables
        assert "intent_matches" in tables
        assert "intent_match_state" in tables

    def test_builtin_playbooks_seeded(self, ice):
        playbooks = ice.get_playbooks()
        builtins = [p for p in playbooks if p["builtin"]]
        assert len(builtins) == 15

    def test_init_idempotent(self, ice):
        """Calling init_db() twice does not duplicate built-in playbooks."""
        ice.init_db()
        playbooks = ice.get_playbooks()
        builtins = [p for p in playbooks if p["builtin"]]
        assert len(builtins) == 15  # Still exactly 15

    def test_builtin_playbooks_have_required_fields(self, ice):
        for pb in ice.get_playbooks():
            assert pb["name"]
            assert pb["description"]
            assert pb["severity"] in ("low", "medium", "high", "critical")
            assert isinstance(pb["steps"], list)
            assert len(pb["steps"]) >= 1
            assert pb["window_seconds"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# Step matching
# ─────────────────────────────────────────────────────────────────────────────

class TestStepMatches:
    def test_category_match(self, ice):
        ev = _event(category="credential_abuse")
        assert ice._step_matches({"category": "credential_abuse"}, ev)
        assert not ice._step_matches({"category": "lateral_movement"}, ev)

    def test_mitre_exact_match(self, ice):
        ev = _event(mitre_technique="T1078")
        assert ice._step_matches({"mitre_technique": "T1078"}, ev)
        assert not ice._step_matches({"mitre_technique": "T1550"}, ev)

    def test_mitre_prefix_match(self, ice):
        ev = _event(mitre_technique="T1550.001")
        assert ice._step_matches({"mitre_technique": "T1550"}, ev)
        assert ice._step_matches({"mitre_technique": "T1550.001"}, ev)
        assert not ice._step_matches({"mitre_technique": "T1550.002"}, ev)

    def test_pivot_exact_match(self, ice):
        ev = _event(pivot="lateral_movement")
        assert ice._step_matches({"pivot": "lateral_movement"}, ev)
        assert not ice._step_matches({"pivot": "privilege_escalation"}, ev)

    def test_objective_substring_match(self, ice):
        ev = _event(objective="gain_admin_access")
        assert ice._step_matches({"objective": "admin"}, ev)
        assert not ice._step_matches({"objective": "exfiltrate"}, ev)

    def test_min_confidence_pass(self, ice):
        ev = _event(confidence=0.8)
        assert ice._step_matches({"min_confidence": 0.5}, ev)
        assert ice._step_matches({"min_confidence": 0.8}, ev)
        assert not ice._step_matches({"min_confidence": 0.9}, ev)

    def test_risk_tier_minimum(self, ice):
        ev = _event(risk_tier="high")
        assert ice._step_matches({"risk_tier": "low"}, ev)
        assert ice._step_matches({"risk_tier": "high"}, ev)
        assert not ice._step_matches({"risk_tier": "critical"}, ev)

    def test_empty_step_matches_everything(self, ice):
        ev = _event()
        assert ice._step_matches({}, ev)

    def test_multiple_conditions_and_logic(self, ice):
        ev = _event(category="credential_abuse", mitre_technique="T1528", confidence=0.7)
        assert ice._step_matches({"category": "credential_abuse", "mitre_technique": "T1528", "min_confidence": 0.6}, ev)
        assert not ice._step_matches({"category": "credential_abuse", "min_confidence": 0.9}, ev)


# ─────────────────────────────────────────────────────────────────────────────
# Correlation: no match
# ─────────────────────────────────────────────────────────────────────────────

class TestNoMatch:
    def test_single_event_no_match_for_two_step_playbook(self, ice):
        # All built-in playbooks have ≥2 steps
        ev = _event(category="auth_anomaly", confidence=0.9)
        matches = ice.correlate_event(TENANT, ev)
        assert matches == []

    def test_wrong_category_no_state_advance(self, ice):
        # Step 1 needs credential_abuse; we send auth_anomaly — no state created
        pid = ice.add_playbook(
            TENANT, "TestPB", "desc", "high",
            [{"category": "credential_abuse"}, {"category": "lateral_movement"}],
        )
        ev = _event(category="auth_anomaly")
        ice.correlate_event(TENANT, ev)
        # No state should exist for this playbook+subject
        import sqlite3
        conn = sqlite3.connect(os.environ["DATA_DB_PATH"])
        row = conn.execute(
            "SELECT * FROM intent_match_state WHERE playbook_id=?", (pid,)
        ).fetchone()
        conn.close()
        assert row is None


# ─────────────────────────────────────────────────────────────────────────────
# Correlation: match fires
# ─────────────────────────────────────────────────────────────────────────────

class TestMatchFires:
    def _two_step_playbook(self, ice) -> str:
        return ice.add_playbook(
            TENANT, "2-Step Test", "test", "high",
            [{"category": "auth_anomaly"}, {"category": "privilege_escalation"}],
            window_seconds=3600,
        )

    def test_two_step_match(self, ice):
        pid = self._two_step_playbook(ice)
        ev1 = _event(category="auth_anomaly")
        ev2 = _event(category="privilege_escalation")
        m1 = ice.correlate_event(TENANT, ev1)
        m2 = ice.correlate_event(TENANT, ev2)
        assert m1 == []
        # Multiple built-in playbooks may also fire; verify ours is among them
        assert any(m.playbook_id == pid for m in m2)

    def test_match_contains_both_event_ids(self, ice):
        pid = self._two_step_playbook(ice)
        ev1 = _event(category="auth_anomaly")
        ev1["event_id"] = "ev-step1"
        ev2 = _event(category="privilege_escalation")
        ev2["event_id"] = "ev-step2"
        ice.correlate_event(TENANT, ev1)
        matches = ice.correlate_event(TENANT, ev2)
        assert "ev-step1" in matches[0].matched_events
        assert "ev-step2" in matches[0].matched_events

    def test_match_severity_from_playbook(self, ice):
        pid = self._two_step_playbook(ice)
        ice.correlate_event(TENANT, _event(category="auth_anomaly"))
        matches = ice.correlate_event(TENANT, _event(category="privilege_escalation"))
        assert matches[0].severity == "high"

    def test_match_confidence_positive(self, ice):
        self._two_step_playbook(ice)
        ice.correlate_event(TENANT, _event(category="auth_anomaly", confidence=0.8))
        matches = ice.correlate_event(TENANT, _event(category="privilege_escalation", confidence=0.9))
        assert matches[0].confidence > 0

    def test_match_persisted_to_db(self, ice):
        self._two_step_playbook(ice)
        ice.correlate_event(TENANT, _event(category="auth_anomaly"))
        ice.correlate_event(TENANT, _event(category="privilege_escalation"))
        matches_db = ice.get_matches(TENANT)
        assert len(matches_db) >= 1

    def test_state_reset_after_match(self, ice):
        """After a match fires, state is cleared so another occurrence can match."""
        pid = self._two_step_playbook(ice)
        ice.correlate_event(TENANT, _event(category="auth_anomaly", subject="reset-user@x.com"))
        ice.correlate_event(TENANT, _event(category="privilege_escalation", subject="reset-user@x.com"))
        # Send another sequence — our playbook should fire again
        ice.correlate_event(TENANT, _event(category="auth_anomaly", subject="reset-user@x.com"))
        matches2 = ice.correlate_event(TENANT, _event(category="privilege_escalation", subject="reset-user@x.com"))
        assert any(m.playbook_id == pid for m in matches2)

    def test_three_step_playbook_requires_all_three(self, ice):
        pid = ice.add_playbook(
            TENANT, "3-Step", "d", "critical",
            [{"category": "auth_anomaly"}, {"category": "lateral_movement"}, {"category": "exfiltration"}],
        )
        ice.correlate_event(TENANT, _event(category="auth_anomaly"))
        m1 = ice.correlate_event(TENANT, _event(category="lateral_movement"))
        assert m1 == []  # Not done yet
        m2 = ice.correlate_event(TENANT, _event(category="exfiltration"))
        assert len(m2) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Subject isolation
# ─────────────────────────────────────────────────────────────────────────────

class TestSubjectIsolation:
    def test_different_subjects_independent_state(self, ice):
        pid = ice.add_playbook(
            TENANT, "Subject Isolation", "d", "high",
            [{"category": "auth_anomaly"}, {"category": "privilege_escalation"}],
        )
        # Step 1 for subject-A
        ice.correlate_event(TENANT, _event(category="auth_anomaly", subject="alice@x.com"))
        # Step 1 for subject-B (should not inherit subject-A's state)
        ice.correlate_event(TENANT, _event(category="auth_anomaly", subject="bob@x.com"))
        # Step 2 for subject-A → our playbook should fire
        matches = ice.correlate_event(TENANT, _event(category="privilege_escalation", subject="alice@x.com"))
        # Filter to our specific playbook match
        our_match = [m for m in matches if m.playbook_id == pid]
        assert len(our_match) == 1
        assert our_match[0].subject == "alice@x.com"

    def test_tenant_isolation(self, ice):
        pid = ice.add_playbook(
            "tenant-X", "TenantIso", "d", "high",
            [{"category": "auth_anomaly"}, {"category": "lateral_movement"}],
        )
        ice.correlate_event("tenant-X", _event(category="auth_anomaly"))
        # Step 2 sent to different tenant — should NOT fire
        matches = ice.correlate_event("tenant-Y", _event(category="lateral_movement"))
        assert matches == []


# ─────────────────────────────────────────────────────────────────────────────
# Window expiry
# ─────────────────────────────────────────────────────────────────────────────

class TestWindowExpiry:
    def test_expired_state_reset(self, ice):
        """State older than window_seconds is discarded before matching."""
        pid = ice.add_playbook(
            TENANT, "Expiry Test", "d", "medium",
            [{"category": "auth_anomaly"}, {"category": "privilege_escalation"}],
            window_seconds=1,  # 1 second window
        )
        ice.correlate_event(TENANT, _event(category="auth_anomaly"))
        # Force expiry by manipulating the DB
        import sqlite3
        conn = sqlite3.connect(os.environ["DATA_DB_PATH"])
        conn.execute("UPDATE intent_match_state SET expires_at=0")
        conn.commit()
        conn.close()
        # Step 2 — state expired, should not match
        matches = ice.correlate_event(TENANT, _event(category="privilege_escalation"))
        assert matches == []


# ─────────────────────────────────────────────────────────────────────────────
# Playbook CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestPlaybookCRUD:
    def test_add_playbook_returns_id(self, ice):
        pid = ice.add_playbook(TENANT, "MyPB", "d", "high", [{"category": "auth_anomaly"}])
        assert pid.startswith("custom:")

    def test_add_playbook_appears_in_list(self, ice):
        ice.add_playbook(TENANT, "ListTest", "d", "medium", [{"category": "auth_anomaly"}])
        pbs = ice.get_playbooks(TENANT, include_builtin=False)
        custom = [p for p in pbs if p["name"] == "ListTest"]
        assert len(custom) == 1

    def test_add_playbook_invalid_severity(self, ice):
        with pytest.raises(ValueError, match="severity"):
            ice.add_playbook(TENANT, "Bad", "d", "extreme", [{"category": "auth_anomaly"}])

    def test_add_playbook_no_steps_raises(self, ice):
        with pytest.raises(ValueError):
            ice.add_playbook(TENANT, "NoSteps", "d", "low", [])

    def test_delete_custom_playbook(self, ice):
        pid = ice.add_playbook(TENANT, "ToDelete", "d", "low", [{"category": "auth_anomaly"}])
        deleted = ice.delete_playbook(TENANT, pid)
        assert deleted is True
        pbs = ice.get_playbooks(TENANT, include_builtin=False)
        assert not any(p["playbook_id"] == pid for p in pbs)

    def test_delete_builtin_refused(self, ice):
        pbs = ice.get_playbooks(include_builtin=True)
        builtin_id = next(p["playbook_id"] for p in pbs if p["builtin"])
        result = ice.delete_playbook(TENANT, builtin_id)
        assert result is False

    def test_delete_nonexistent_returns_false(self, ice):
        assert ice.delete_playbook(TENANT, "custom:doesnotexist") is False

    def test_playbooks_have_step_details(self, ice):
        pid = ice.add_playbook(
            TENANT, "StepTest", "d", "high",
            [{"category": "auth_anomaly", "min_confidence": 0.6}],
        )
        pbs = ice.get_playbooks(TENANT, include_builtin=False)
        pb = next(p for p in pbs if p["playbook_id"] == pid)
        assert pb["steps"][0]["min_confidence"] == 0.6


# ─────────────────────────────────────────────────────────────────────────────
# get_matches filters
# ─────────────────────────────────────────────────────────────────────────────

class TestGetMatchesFilters:
    def _fire_match(self, ice, severity="high", category1="auth_anomaly",
                    category2="privilege_escalation", subject="u@x.com") -> str:
        pid = ice.add_playbook(
            TENANT, f"FM-{time.time_ns()}", "d", severity,
            [{"category": category1}, {"category": category2}],
        )
        ice.correlate_event(TENANT, _event(category=category1, subject=subject))
        ice.correlate_event(TENANT, _event(category=category2, subject=subject))
        return pid

    def test_get_all_matches(self, ice):
        self._fire_match(ice)
        results = ice.get_matches(TENANT)
        assert len(results) >= 1

    def test_severity_filter(self, ice):
        self._fire_match(ice, severity="medium",
                         category1="credential_abuse", category2="lateral_movement",
                         subject="u1@x.com")
        results_high = ice.get_matches(TENANT, severity="high")
        results_med = ice.get_matches(TENANT, severity="medium")
        assert all(m["severity"] == "high" for m in results_high)
        assert all(m["severity"] == "medium" for m in results_med)

    def test_playbook_id_filter(self, ice):
        pid = self._fire_match(ice, subject="filter@x.com")
        results = ice.get_matches(TENANT, playbook_id=pid)
        assert all(m["playbook_id"] == pid for m in results)

    def test_matches_empty_for_new_tenant(self, ice):
        assert ice.get_matches("brand-new-tenant-ice") == []

    def test_match_has_required_fields(self, ice):
        self._fire_match(ice, subject="fields@x.com")
        matches = ice.get_matches(TENANT)
        m = matches[0]
        for key in ("match_id", "playbook_id", "playbook_name", "severity",
                    "confidence", "detected_at", "matched_events", "detail"):
            assert key in m


# ─────────────────────────────────────────────────────────────────────────────
# uis_store integration
# ─────────────────────────────────────────────────────────────────────────────

class TestUISStoreIntegration:
    def test_correlate_called_on_insert(self, ice, tmp_db, monkeypatch):
        """correlate_event is invoked when an event is inserted via uis_store."""
        import importlib
        import modules.identity.uis_store as store
        importlib.reload(store)
        store.init_db()

        calls = []
        original = ice.correlate_event

        def mock_correlate(tid, ev):
            calls.append((tid, ev.get("event_id")))
            return []

        import modules.identity.intent_correlation as icm
        monkeypatch.setattr(icm, "correlate_event", mock_correlate)

        ev = {
            "event_id": "integ-ice-001",
            "event_timestamp": "2026-04-16T00:00:00+00:00",
            "identity": {"subject": "u@x", "entity_type": "human",
                         "tenant_id": TENANT, "tenant_name": "T",
                         "machine_classification": "user", "agent_id": None},
            "auth": {"method": "password", "mfa_asserted": True,
                     "protocol": "oidc", "credential_strength": "standard"},
            "token": {"type": "bearer", "issuer": "auth", "audience": "api",
                      "claims_hash": "x", "dpop_bound": False, "expires_at": None,
                      "issued_at": None, "rotation_history": [], "jti": "j"},
            "session": {"id": "s", "request_id": "r", "ip": "1.2.3.4", "country": "US",
                        "asn": "AS1", "device_fingerprint": None, "user_agent": "t",
                        "impossible_travel": False, "graph_position": None},
            "behavior": {"dna_fingerprint": None, "pattern_deviation_score": 0.0,
                         "velocity_anomaly": False},
            "lifecycle": {"state": "active", "provisioned_at": None,
                          "revoked_at": None, "dormant": False},
            "threat": {"risk_score": 10, "risk_tier": "low", "indicators": [],
                       "lateral_movement": False},
            "binding": {"dpop_jkt": None, "mtls_subject": None, "spiffe_id": None,
                        "attestation_id": None, "supply_chain_hash": None},
        }
        store.insert_event(TENANT, ev)
        assert any(eid == "integ-ice-001" for _, eid in calls)

    def test_correlate_failure_does_not_block_insert(self, ice, tmp_db, monkeypatch):
        import importlib
        import modules.identity.uis_store as store
        importlib.reload(store)
        store.init_db()

        import modules.identity.intent_correlation as icm
        monkeypatch.setattr(icm, "correlate_event", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))

        ev = {
            "event_id": "ice-failsafe-001",
            "event_timestamp": "2026-04-16T00:00:00+00:00",
            "identity": {"subject": "u@x", "entity_type": "human",
                         "tenant_id": TENANT, "tenant_name": "T",
                         "machine_classification": "user", "agent_id": None},
            "auth": {"method": "password", "mfa_asserted": True,
                     "protocol": "oidc", "credential_strength": "standard"},
            "token": {"type": "bearer", "issuer": "auth", "audience": "api",
                      "claims_hash": "x", "dpop_bound": False, "expires_at": None,
                      "issued_at": None, "rotation_history": [], "jti": "j"},
            "session": {"id": "s", "request_id": "r", "ip": "1.2.3.4", "country": "US",
                        "asn": "AS1", "device_fingerprint": None, "user_agent": "t",
                        "impossible_travel": False, "graph_position": None},
            "behavior": {"dna_fingerprint": None, "pattern_deviation_score": 0.0,
                         "velocity_anomaly": False},
            "lifecycle": {"state": "active", "provisioned_at": None,
                          "revoked_at": None, "dormant": False},
            "threat": {"risk_score": 10, "risk_tier": "low", "indicators": [],
                       "lateral_movement": False},
            "binding": {"dpop_jkt": None, "mtls_subject": None, "spiffe_id": None,
                        "attestation_id": None, "supply_chain_hash": None},
        }
        store.insert_event(TENANT, ev)  # Must NOT raise
        assert store.get_event(TENANT, "ice-failsafe-001") is not None
