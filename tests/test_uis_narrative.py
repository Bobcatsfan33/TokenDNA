"""
Tests for UIS Exploit Narrative Layer (Sprint 1-1).

Coverage:
  - NarrativeBlock inference (all HIGH / MEDIUM / LOW rules)
  - attach_narrative / backfill_narrative API
  - uis_version bump 1.0 → 1.1
  - MITRE ATT&CK mapping attachment
  - normalize_identity_event produces narrative block
  - uis_store: narrative_json persisted and round-trips
  - SDK wrapper: narrative override fields
  - Migration: existing tables get narrative_json column without data loss
  - Downstream POC: reconstruct attack story from chained events
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile

import pytest


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _base_event(overrides: dict | None = None) -> dict:
    """Minimal valid UIS event for testing."""
    ev = {
        "uis_version": "1.0",
        "event_id": "test-evt-001",
        "event_timestamp": "2026-04-15T00:00:00+00:00",
        "identity": {
            "entity_type": "human",
            "subject": "user@example.com",
            "tenant_id": "tenant-1",
            "tenant_name": "Test Tenant",
            "machine_classification": "user",
            "agent_id": None,
        },
        "auth": {
            "method": "password",
            "mfa_asserted": True,
            "protocol": "oidc",
            "credential_strength": "standard",
        },
        "token": {
            "type": "bearer",
            "issuer": "https://auth.example.com",
            "audience": "api.example.com",
            "claims_hash": "abc123",
            "dpop_bound": False,
            "expires_at": None,
            "issued_at": None,
            "rotation_history": [],
            "jti": "jti-1",
        },
        "session": {
            "id": "sess-1",
            "request_id": "req-1",
            "ip": "1.2.3.4",
            "country": "US",
            "asn": "AS12345",
            "device_fingerprint": None,
            "user_agent": "pytest",
            "impossible_travel": False,
            "graph_position": None,
        },
        "behavior": {
            "dna_fingerprint": None,
            "pattern_deviation_score": 0.0,
            "velocity_anomaly": False,
        },
        "lifecycle": {
            "state": "active",
            "provisioned_at": None,
            "revoked_at": None,
            "dormant": False,
        },
        "threat": {
            "risk_score": 10,
            "risk_tier": "low",
            "indicators": [],
            "lateral_movement": False,
        },
        "binding": {
            "dpop_jkt": None,
            "mtls_subject": None,
            "spiffe_id": None,
            "attestation_id": None,
            "supply_chain_hash": None,
        },
    }
    if overrides:
        for k, v in overrides.items():
            if isinstance(v, dict) and k in ev:
                ev[k].update(v)
            else:
                ev[k] = v
    return ev


# ────────────────────────────────────────────────────────────────────────────
# Unit tests — NarrativeBlock / inference engine
# ────────────────────────────────────────────────────────────────────────────

class TestNarrativeInference:
    def test_clean_event_produces_no_pivot(self):
        from modules.identity.uis_narrative import infer_narrative
        nb = infer_narrative(_base_event())
        # Low-risk clean event → no HIGH/MEDIUM pivot
        assert nb.confidence in (None, "LOW")

    def test_impossible_travel_r01(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"session": {"impossible_travel": True}})
        nb = infer_narrative(ev)
        assert nb.pivot == "impossible_travel"
        assert nb.confidence == "HIGH"
        assert any(r.startswith("R-01") for r in (nb.inference_rules or []))
        assert nb.precondition is not None

    def test_lateral_movement_flag_r02(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"threat": {"lateral_movement": True, "risk_score": 10, "risk_tier": "low", "indicators": []}})
        nb = infer_narrative(ev)
        assert nb.pivot == "lateral_movement"
        assert nb.confidence == "HIGH"
        assert any(r.startswith("R-02") for r in nb.inference_rules)

    def test_revoked_identity_reauth_r03(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"lifecycle": {"revoked_at": "2026-04-14T00:00:00Z", "state": "revoked", "dormant": False, "provisioned_at": None}})
        nb = infer_narrative(ev)
        assert nb.pivot == "token_replay"
        assert nb.confidence == "HIGH"
        assert nb.precondition == "identity_previously_revoked"

    def test_high_risk_no_mfa_r04(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "threat": {"risk_score": 90, "risk_tier": "high", "indicators": [], "lateral_movement": False},
            "auth": {"method": "password", "mfa_asserted": False, "protocol": "oidc", "credential_strength": "standard"},
        })
        nb = infer_narrative(ev)
        assert nb.pivot == "mfa_bypass"
        assert nb.confidence == "HIGH"
        assert any(r.startswith("R-04") for r in nb.inference_rules)

    def test_supply_chain_indicator_r05(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "binding": {"supply_chain_hash": "sha256:abc", "dpop_jkt": None, "mtls_subject": None, "spiffe_id": None, "attestation_id": None},
            "threat": {"risk_score": 50, "risk_tier": "medium", "indicators": ["supply_chain_integrity_check_failed"], "lateral_movement": False},
        })
        nb = infer_narrative(ev)
        assert nb.pivot == "supply_chain_compromise"
        assert nb.confidence == "HIGH"

    def test_velocity_anomaly_medium_r06(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "behavior": {"velocity_anomaly": True, "pattern_deviation_score": 0.2, "dna_fingerprint": None},
            "threat": {"risk_score": 60, "risk_tier": "medium", "indicators": [], "lateral_movement": False},
        })
        nb = infer_narrative(ev)
        assert nb.pivot == "credential_access"
        assert nb.confidence == "MEDIUM"

    def test_pattern_deviation_medium_r07(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"behavior": {"pattern_deviation_score": 0.8, "velocity_anomaly": False, "dna_fingerprint": None}})
        nb = infer_narrative(ev)
        assert nb.pivot == "context_switch"
        assert nb.confidence == "MEDIUM"

    def test_scope_indicator_r08(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"threat": {"risk_score": 30, "risk_tier": "low", "indicators": ["scope_escalation_detected"], "lateral_movement": False}})
        nb = infer_narrative(ev)
        assert nb.pivot == "scope_escalation"
        assert nb.confidence == "MEDIUM"

    def test_unbound_machine_identity_r09(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "identity": {"entity_type": "machine", "subject": "svc@agents", "tenant_id": "t-1", "tenant_name": "T", "machine_classification": "agent", "agent_id": "agt-1"},
            "token": {"type": "bearer", "issuer": "auth", "audience": "api", "claims_hash": "x", "dpop_bound": False, "expires_at": None, "issued_at": None, "rotation_history": [], "jti": "j"},
            "binding": {"dpop_jkt": None, "mtls_subject": None, "spiffe_id": None, "attestation_id": None, "supply_chain_hash": None},
        })
        nb = infer_narrative(ev)
        assert nb.pivot == "identity_compromise"
        assert nb.confidence == "MEDIUM"

    def test_agent_delegation_r10(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "identity": {"entity_type": "machine", "subject": "agt", "tenant_id": "t-1", "tenant_name": "T", "machine_classification": "agent", "agent_id": "agt-99"},
            # Provide DPoP binding so R-09 (unbound machine) does NOT fire first
            "token": {"type": "bearer", "issuer": "auth", "audience": "api", "claims_hash": "x", "dpop_bound": True, "expires_at": None, "issued_at": None, "rotation_history": [], "jti": "j"},
            "binding": {"dpop_jkt": "jkt-bound", "mtls_subject": None, "spiffe_id": None, "attestation_id": None, "supply_chain_hash": None},
            "threat": {"risk_score": 20, "risk_tier": "low", "indicators": ["delegation_chain_suspicious"], "lateral_movement": False},
        })
        nb = infer_narrative(ev)
        assert nb.pivot == "delegation_abuse"
        assert nb.confidence == "MEDIUM"

    def test_elevated_risk_low_r11(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"threat": {"risk_score": 55, "risk_tier": "medium", "indicators": [], "lateral_movement": False}})
        nb = infer_narrative(ev)
        # No high/medium signals → falls to R-11
        assert nb.pivot == "reconnaissance"
        assert nb.confidence == "LOW"

    def test_dormant_identity_r12(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"lifecycle": {"dormant": True, "state": "active", "provisioned_at": None, "revoked_at": None}})
        nb = infer_narrative(ev)
        assert nb.pivot == "persistence"
        assert nb.confidence == "LOW"

    def test_no_pivot_for_clean_low_risk(self):
        from modules.identity.uis_narrative import infer_narrative
        nb = infer_narrative(_base_event())
        # No rules fire except maybe R-11 if risk_score > 50; base event has 10
        assert nb.pivot is None or nb.confidence == "LOW"
        assert nb.pivot is None  # risk_score=10 → no rule fires

    def test_mitre_attached_when_pivot_set(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({"session": {"impossible_travel": True}})
        nb = infer_narrative(ev)
        assert nb.mitre is not None
        assert "tactic" in nb.mitre
        assert "technique_id" in nb.mitre
        assert nb.mitre["technique_id"].startswith("T")

    def test_payload_inference(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "auth": {"method": "mfa", "mfa_asserted": True, "protocol": "oidc", "credential_strength": "high"},
            "binding": {"dpop_jkt": "jkt-abc", "mtls_subject": None, "spiffe_id": None, "attestation_id": "att-1", "supply_chain_hash": None},
            "token": {"type": "bearer", "issuer": "auth", "audience": "api", "claims_hash": "x", "dpop_bound": True, "expires_at": None, "issued_at": None, "rotation_history": [], "jti": "j"},
        })
        nb = infer_narrative(ev)
        assert nb.payload is not None
        assert "auth:mfa" in nb.payload

    def test_objective_fallback_category(self):
        from modules.identity.uis_narrative import infer_narrative
        # Clean event with no overriding signals → falls to category-based objective
        nb = infer_narrative(_base_event())
        assert nb.objective == "establish_session"  # auth_success category

    def test_inference_rules_list_populated(self):
        from modules.identity.uis_narrative import infer_narrative
        ev = _base_event({
            "session": {"impossible_travel": True},
            "threat": {"lateral_movement": True, "risk_score": 80, "risk_tier": "high", "indicators": []},
        })
        nb = infer_narrative(ev)
        assert len(nb.inference_rules) >= 2


# ────────────────────────────────────────────────────────────────────────────
# attach_narrative / backfill_narrative API
# ────────────────────────────────────────────────────────────────────────────

class TestAttachNarrative:
    def test_attach_narrative_returns_copy(self):
        from modules.identity.uis_narrative import attach_narrative
        original = _base_event()
        result = attach_narrative(original)
        assert result is not original

    def test_attach_narrative_bumps_version(self):
        from modules.identity.uis_narrative import attach_narrative
        result = attach_narrative(_base_event())
        assert result["uis_version"] == "1.1"

    def test_attach_narrative_adds_block(self):
        from modules.identity.uis_narrative import attach_narrative
        result = attach_narrative(_base_event())
        assert "narrative" in result
        nb = result["narrative"]
        assert set(nb.keys()) >= {"precondition", "pivot", "payload", "objective", "confidence", "mitre", "inference_rules"}

    def test_backfill_narrative_sets_flag(self):
        from modules.identity.uis_narrative import backfill_narrative
        result = backfill_narrative(_base_event())
        assert result["narrative"]["backfill"] is True

    def test_attach_narrative_preserves_all_fields(self):
        from modules.identity.uis_narrative import attach_narrative
        ev = _base_event()
        result = attach_narrative(ev)
        for field in ("event_id", "event_timestamp", "identity", "auth", "threat", "binding"):
            assert result[field] == ev[field]

    def test_narrative_block_is_serializable(self):
        from modules.identity.uis_narrative import attach_narrative
        result = attach_narrative(_base_event())
        # Must round-trip through JSON without error
        dumped = json.dumps(result["narrative"])
        loaded = json.loads(dumped)
        assert isinstance(loaded, dict)

    def test_high_confidence_event_narrative(self):
        from modules.identity.uis_narrative import attach_narrative
        ev = _base_event({"session": {"impossible_travel": True}})
        result = attach_narrative(ev)
        assert result["narrative"]["confidence"] == "HIGH"
        assert result["narrative"]["pivot"] == "impossible_travel"
        assert result["narrative"]["mitre"] is not None


# ────────────────────────────────────────────────────────────────────────────
# normalize_identity_event → narrative attached end-to-end
# ────────────────────────────────────────────────────────────────────────────

class TestNormalizeWithNarrative:
    def test_normalize_produces_narrative_via_attach(self):
        """normalize_from_protocol returns v1.0; attach_narrative wraps it to v1.1."""
        from modules.identity.uis import normalize_from_protocol
        from modules.identity.uis_narrative import attach_narrative
        base = normalize_from_protocol(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="Tenant",
            subject="user@example.com",
            claims={"iss": "https://auth", "aud": "api", "jti": "jti-1"},
        )
        # Base event is v1.0 (backward compat)
        assert base["uis_version"] == "1.0"
        assert "narrative" not in base
        # Attaching narrative upgrades to v1.1
        event = attach_narrative(base)
        assert event["uis_version"] == "1.1"
        assert "narrative" in event
        assert isinstance(event["narrative"], dict)

    def test_sdk_normalize_produces_v11_event(self):
        """SDK wrapper always attaches narrative (v1.1)."""
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="Tenant",
            payload={"sub": "user@example.com", "iss": "https://auth"},
        )
        assert event["uis_version"] == "1.1"
        assert "narrative" in event

    def test_normalize_high_risk_has_narrative(self):
        from modules.identity.uis import normalize_from_protocol
        from modules.identity.uis_narrative import attach_narrative
        base = normalize_from_protocol(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="Tenant",
            subject="agent@svc",
            claims={"entity_type": "machine", "agent_id": "agt-1"},
            request_context={"impossible_travel": True, "ip": "1.2.3.4", "country": "US", "asn": "AS1"},
            risk_context={"impossible_travel": True, "risk_score": 85, "risk_tier": "high"},
        )
        event = attach_narrative(base)
        assert event["narrative"]["confidence"] == "HIGH"
        assert event["narrative"]["pivot"] == "impossible_travel"


# ────────────────────────────────────────────────────────────────────────────
# UIS store — narrative_json persistence
# ────────────────────────────────────────────────────────────────────────────

class TestUISStoreNarrative:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        os.environ["DATA_DB_PATH"] = self.tmp.name

    def teardown_method(self):
        os.environ.pop("DATA_DB_PATH", None)
        import os as _os
        try:
            _os.unlink(self.tmp.name)
        except Exception:
            pass

    def _store(self):
        # Re-import to pick up new DATA_DB_PATH
        import importlib
        import modules.identity.uis_store as m
        importlib.reload(m)
        return m

    def test_init_creates_narrative_column(self):
        store = self._store()
        store.init_db()
        conn = sqlite3.connect(self.tmp.name)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(uis_events)").fetchall()}
        conn.close()
        assert "narrative_json" in cols

    def test_insert_persists_narrative(self):
        from modules.identity.uis_narrative import attach_narrative
        store = self._store()
        store.init_db()
        ev = attach_narrative(_base_event())
        ev["event_id"] = "persist-test-001"
        store.insert_event("tenant-1", ev)
        conn = sqlite3.connect(self.tmp.name)
        row = conn.execute("SELECT narrative_json FROM uis_events WHERE event_id=?", ("persist-test-001",)).fetchone()
        conn.close()
        assert row is not None
        narrative = json.loads(row[0])
        assert isinstance(narrative, dict)
        assert "pivot" in narrative

    def test_insert_null_narrative_allowed(self):
        """Events without a narrative field still insert cleanly."""
        store = self._store()
        store.init_db()
        ev = _base_event()
        ev["event_id"] = "no-narrative-001"
        # Remove narrative key entirely (simulates a v1.0 event)
        ev.pop("narrative", None)
        store.insert_event("tenant-1", ev)
        conn = sqlite3.connect(self.tmp.name)
        row = conn.execute("SELECT narrative_json FROM uis_events WHERE event_id=?", ("no-narrative-001",)).fetchone()
        conn.close()
        assert row is not None
        assert row[0] is None

    def test_roundtrip_get_event_includes_narrative(self):
        from modules.identity.uis_narrative import attach_narrative
        store = self._store()
        store.init_db()
        ev = attach_narrative(_base_event())
        ev["event_id"] = "rt-test-001"
        store.insert_event("tenant-1", ev)
        retrieved = store.get_event("tenant-1", "rt-test-001")
        assert retrieved is not None
        assert "narrative" in retrieved
        assert isinstance(retrieved["narrative"], dict)
        # narrative block has the expected keys
        assert "pivot" in retrieved["narrative"]

    def test_migration_adds_column_to_existing_table(self):
        """
        Simulate a pre-v1.1 database that has uis_events without narrative_json.
        init_db() must add the column without dropping data.
        """
        store = self._store()
        # Create old-style table
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            """
            CREATE TABLE uis_events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO uis_events VALUES (?,?,?,?,?,?,?)",
            ("legacy-001", "tenant-1", "user@x", "2026-01-01T00:00:00Z", "oidc", "low", json.dumps({"event_id": "legacy-001"})),
        )
        conn.commit()
        conn.close()

        # Now run init_db — must add column without losing legacy row
        store.init_db()

        conn = sqlite3.connect(self.tmp.name)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(uis_events)").fetchall()}
        row = conn.execute("SELECT event_id, narrative_json FROM uis_events WHERE event_id='legacy-001'").fetchone()
        conn.close()

        assert "narrative_json" in cols
        assert row is not None
        assert row[0] == "legacy-001"
        assert row[1] is None  # NULL for legacy rows — expected


# ────────────────────────────────────────────────────────────────────────────
# SDK wrapper — narrative override fields
# ────────────────────────────────────────────────────────────────────────────

class TestSDKNarrativeOverrides:
    def test_no_override_returns_inferred_narrative(self):
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="T",
            payload={"sub": "user@x", "iss": "https://auth"},
        )
        assert "narrative" in event
        assert event["uis_version"] == "1.1"

    def test_pivot_override_takes_precedence(self):
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="T",
            payload={"sub": "user@x"},
            narrative_pivot="data_exfiltration",
        )
        assert event["narrative"]["pivot"] == "data_exfiltration"
        assert event["narrative"]["confidence"] == "HIGH"

    def test_pivot_override_attaches_mitre(self):
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        from modules.identity.uis_narrative import MITRE_PIVOT_MAP
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="T",
            payload={"sub": "user@x"},
            narrative_pivot="data_exfiltration",
        )
        expected_mitre = MITRE_PIVOT_MAP["data_exfiltration"]
        assert event["narrative"]["mitre"] == expected_mitre

    def test_all_four_overrides(self):
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="T",
            payload={"sub": "user@x"},
            narrative_precondition="admin_access_granted",
            narrative_pivot="privilege_escalation",
            narrative_payload="sudo:ALL",
            narrative_objective="achieve_full_control",
        )
        nb = event["narrative"]
        assert nb["precondition"] == "admin_access_granted"
        assert nb["pivot"] == "privilege_escalation"
        assert nb["payload"] == "sudo:ALL"
        assert nb["objective"] == "achieve_full_control"

    def test_partial_override_preserves_inferred_fields(self):
        from modules.integrations.sdk_wrappers import sdk_normalize_uis_event
        event = sdk_normalize_uis_event(
            protocol="oidc",
            tenant_id="t-1",
            tenant_name="T",
            payload={"sub": "user@x"},
            narrative_objective="steal_data",
        )
        nb = event["narrative"]
        assert nb["objective"] == "steal_data"
        # Other fields come from auto-inference (not None checks)
        assert "pivot" in nb
        assert "inference_rules" in nb


# ────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping completeness
# ────────────────────────────────────────────────────────────────────────────

class TestMITREMappings:
    def test_all_pivot_types_have_mitre(self):
        from modules.identity.uis_narrative import MITRE_PIVOT_MAP
        for pivot, mapping in MITRE_PIVOT_MAP.items():
            assert "tactic" in mapping, f"Missing tactic for {pivot}"
            assert "technique_id" in mapping, f"Missing technique_id for {pivot}"
            assert "technique_name" in mapping, f"Missing technique_name for {pivot}"
            assert mapping["technique_id"].startswith("T"), f"Bad technique_id for {pivot}"

    def test_all_five_categories_have_objectives(self):
        from modules.identity.uis_narrative import CATEGORY_OBJECTIVE_MAP
        expected_categories = {"auth_success", "auth_failure", "scope_change", "lifecycle_event", "threat_detected"}
        assert set(CATEGORY_OBJECTIVE_MAP.keys()) == expected_categories


# ────────────────────────────────────────────────────────────────────────────
# Downstream POC — reconstruct attack story from chained events
# Validates Sprint 1-1 gate: "at least one downstream consumer POC confirms
# the schema is sufficient to reconstruct an attack story"
# ────────────────────────────────────────────────────────────────────────────

class TestAttackStoryReconstruction:
    """
    Simulate a three-event attack chain and verify a simple story reconstructor
    can produce a coherent narrative from the chained events.
    """

    def _make_chain(self) -> list[dict]:
        from modules.identity.uis_narrative import attach_narrative

        # Event 1: Initial credential probe
        e1 = attach_narrative(_base_event({
            "event_id": "chain-001",
            "threat": {"risk_score": 30, "risk_tier": "low", "indicators": ["scope_escalation_detected"], "lateral_movement": False},
        }))

        # Event 2: Successful auth from impossible location
        e2 = attach_narrative(_base_event({
            "event_id": "chain-002",
            "session": {
                "impossible_travel": True, "ip": "9.9.9.9", "country": "XX",
                "asn": "AS9999", "id": "s-2", "request_id": "r-2",
                "device_fingerprint": None, "user_agent": "bot", "graph_position": None
            },
            "threat": {"risk_score": 80, "risk_tier": "high", "indicators": [], "lateral_movement": False},
        }))

        # Event 3: Lateral movement to new resource
        e3 = attach_narrative(_base_event({
            "event_id": "chain-003",
            "threat": {"risk_score": 90, "risk_tier": "critical", "indicators": [], "lateral_movement": True},
            "auth": {"method": "token_reuse", "mfa_asserted": False, "protocol": "oidc", "credential_strength": "standard"},
        }))

        return [e1, e2, e3]

    def _reconstruct_story(self, chain: list[dict]) -> str:
        """Simple story reconstructor — the downstream consumer POC."""
        lines: list[str] = ["=== Attack Story ==="]
        for i, event in enumerate(chain, 1):
            nb = event.get("narrative") or {}
            pivot = nb.get("pivot") or "unknown"
            objective = nb.get("objective") or "unknown"
            confidence = nb.get("confidence") or "?"
            mitre = nb.get("mitre") or {}
            technique = mitre.get("technique_id", "—")
            lines.append(
                f"Step {i}: [{confidence}] pivot={pivot} objective={objective} "
                f"mitre={technique}"
            )
        lines.append("=== End ===")
        return "\n".join(lines)

    def test_chain_produces_three_events_with_narrative(self):
        chain = self._make_chain()
        assert len(chain) == 3
        for ev in chain:
            assert "narrative" in ev
            assert ev["uis_version"] == "1.1"

    def test_chain_escalates_from_low_to_critical(self):
        chain = self._make_chain()
        confidences = [ev["narrative"]["confidence"] for ev in chain]
        # Expect at least one HIGH in the chain
        assert "HIGH" in confidences

    def test_story_reconstructor_produces_readable_output(self):
        chain = self._make_chain()
        story = self._reconstruct_story(chain)
        assert "Attack Story" in story
        assert "Step 1" in story
        assert "Step 2" in story
        assert "Step 3" in story
        # At least one MITRE technique referenced
        assert "T1" in story

    def test_story_contains_impossible_travel_pivot(self):
        chain = self._make_chain()
        story = self._reconstruct_story(chain)
        assert "impossible_travel" in story

    def test_story_contains_lateral_movement_pivot(self):
        chain = self._make_chain()
        story = self._reconstruct_story(chain)
        assert "lateral_movement" in story
