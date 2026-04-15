"""
Tests for UIS Exploit Narrative Layer (Sprint 1-1).

Covers:
- Event classification from scoring reasons
- MITRE ATT&CK mapping selection
- Narrative field inference for all 5 categories
- Confidence computation
- Narrative template rendering
- Full enrichment pipeline (enrich_event)
- Migration from UIS v1.0 → v1.1
- Backward compatibility with existing scoring
- Edge cases (empty reasons, unknown signals)
"""
from __future__ import annotations

import pytest

from modules.identity.uis_narrative import (
    NarrativeFields,
    UISEventCategory,
    UISNarrativeEvent,
    UIS_SCHEMA_VERSION,
    MITRE_MAPPINGS,
    NARRATIVE_TEMPLATES,
    classify_event,
    compute_confidence,
    enrich_event,
    infer_narrative_fields,
    migrate_event_v1_to_v1_1,
    render_narrative,
    select_mitre_mapping,
)
from modules.identity.scoring import ScoreBreakdown, RiskTier


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_dna():
    return {
        "version": 2,
        "device": "abc123",
        "ip": "def456",
        "country": "US",
        "asn": "AS15169",
        "ua_os": "macOS",
        "ua_browser": "Chrome",
        "is_mobile": False,
    }


@pytest.fixture
def sample_breakdown_allow():
    return ScoreBreakdown(
        ml_score=85,
        threat_penalty=0,
        graph_penalty=0,
        final_score=85,
        tier=RiskTier.ALLOW,
        reasons=[],
    )


@pytest.fixture
def sample_breakdown_tor():
    return ScoreBreakdown(
        ml_score=80,
        threat_penalty=40,
        graph_penalty=0,
        final_score=40,
        tier=RiskTier.STEP_UP,
        reasons=["tor_exit_node"],
    )


@pytest.fixture
def sample_breakdown_lateral():
    return ScoreBreakdown(
        ml_score=70,
        threat_penalty=0,
        graph_penalty=50,
        final_score=20,
        tier=RiskTier.BLOCK,
        reasons=["impossible_travel"],
    )


@pytest.fixture
def sample_breakdown_credential():
    return ScoreBreakdown(
        ml_score=75,
        threat_penalty=0,
        graph_penalty=30,
        final_score=45,
        tier=RiskTier.STEP_UP,
        reasons=["session_branching"],
    )


@pytest.fixture
def sample_breakdown_revoke():
    return ScoreBreakdown(
        ml_score=60,
        threat_penalty=40,
        graph_penalty=50,
        final_score=0,
        tier=RiskTier.REVOKE,
        reasons=["tor_exit_node", "impossible_travel", "revoke_threshold_breached"],
    )


@pytest.fixture
def sample_breakdown_abuse():
    return ScoreBreakdown(
        ml_score=70,
        threat_penalty=30,
        graph_penalty=0,
        final_score=40,
        tier=RiskTier.STEP_UP,
        reasons=["abuseipdb:85"],
    )


# ── Event Classification ─────────────────────────────────────────────────────

class TestClassifyEvent:
    def test_empty_reasons_default_auth_anomaly(self):
        assert classify_event([]) == UISEventCategory.AUTH_ANOMALY

    def test_tor_maps_to_auth_anomaly(self):
        assert classify_event(["tor_exit_node"]) == UISEventCategory.AUTH_ANOMALY

    def test_vpn_maps_to_auth_anomaly(self):
        assert classify_event(["vpn_or_proxy"]) == UISEventCategory.AUTH_ANOMALY

    def test_datacenter_maps_to_auth_anomaly(self):
        assert classify_event(["datacenter_ip"]) == UISEventCategory.AUTH_ANOMALY

    def test_branching_maps_to_credential_abuse(self):
        assert classify_event(["session_branching"]) == UISEventCategory.CREDENTIAL_ABUSE

    def test_impossible_travel_maps_to_lateral_movement(self):
        assert classify_event(["impossible_travel"]) == UISEventCategory.LATERAL_MOVEMENT

    def test_revoke_maps_to_privilege_escalation(self):
        assert classify_event(["revoke_threshold_breached"]) == UISEventCategory.PRIVILEGE_ESCALATION

    def test_abuseipdb_maps_to_credential_abuse(self):
        assert classify_event(["abuseipdb:90"]) == UISEventCategory.CREDENTIAL_ABUSE

    def test_lateral_beats_credential_in_priority(self):
        """Lateral movement has higher priority than credential abuse."""
        result = classify_event(["impossible_travel", "session_branching"])
        assert result == UISEventCategory.LATERAL_MOVEMENT

    def test_credential_beats_auth_anomaly(self):
        result = classify_event(["session_branching", "tor_exit_node"])
        assert result == UISEventCategory.CREDENTIAL_ABUSE

    def test_multi_signal_priority(self):
        """With all signals, lateral movement wins."""
        result = classify_event([
            "tor_exit_node", "impossible_travel",
            "session_branching", "revoke_threshold_breached",
        ])
        assert result == UISEventCategory.LATERAL_MOVEMENT

    def test_unknown_reason_defaults_to_auth_anomaly(self):
        assert classify_event(["some_unknown_signal"]) == UISEventCategory.AUTH_ANOMALY


# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

class TestMITREMapping:
    def test_all_categories_have_mappings(self):
        for cat in UISEventCategory:
            assert cat in MITRE_MAPPINGS
            assert len(MITRE_MAPPINGS[cat]) >= 1

    def test_impossible_travel_specific_mapping(self):
        m = select_mitre_mapping(UISEventCategory.LATERAL_MOVEMENT, ["impossible_travel"])
        assert m.technique_id == "T1550.001"
        assert m.tactic_id == "TA0008"

    def test_session_branching_specific_mapping(self):
        m = select_mitre_mapping(UISEventCategory.CREDENTIAL_ABUSE, ["session_branching"])
        assert m.technique_id == "T1528"

    def test_tor_specific_mapping(self):
        m = select_mitre_mapping(UISEventCategory.AUTH_ANOMALY, ["tor_exit_node"])
        assert m.technique_id == "T1090.003"

    def test_default_mapping_for_category(self):
        m = select_mitre_mapping(UISEventCategory.AUTH_ANOMALY, [])
        assert m.tactic_id.startswith("TA")
        assert m.technique_id.startswith("T")

    def test_mapping_fields_non_empty(self):
        for cat in UISEventCategory:
            for m in MITRE_MAPPINGS[cat]:
                assert m.tactic_id
                assert m.tactic_name
                assert m.technique_id
                assert m.technique_name


# ── Narrative Field Inference ─────────────────────────────────────────────────

class TestInferNarrativeFields:
    def test_auth_anomaly_tor(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.AUTH_ANOMALY, ["tor_exit_node"], sample_dna,
        )
        assert fields.precondition is not None
        assert "Tor" in fields.pivot
        assert fields.objective is not None
        assert fields.is_populated

    def test_auth_anomaly_vpn(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.AUTH_ANOMALY, ["vpn_or_proxy"], sample_dna,
        )
        assert "VPN" in fields.pivot

    def test_auth_anomaly_datacenter(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.AUTH_ANOMALY, ["datacenter_ip"], sample_dna,
        )
        assert "datacenter" in fields.pivot.lower()

    def test_auth_anomaly_generic(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.AUTH_ANOMALY, [], sample_dna,
        )
        assert fields.is_populated

    def test_credential_abuse_branching(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.CREDENTIAL_ABUSE, ["session_branching"], sample_dna,
        )
        assert "multiple devices" in fields.pivot.lower() or "simultaneously" in fields.pivot.lower()

    def test_credential_abuse_generic(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.CREDENTIAL_ABUSE, [], sample_dna,
        )
        assert fields.is_populated

    def test_lateral_movement_impossible_travel(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.LATERAL_MOVEMENT, ["impossible_travel"], sample_dna,
        )
        assert "US" in fields.pivot  # country from sample_dna

    def test_privilege_escalation(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.PRIVILEGE_ESCALATION, ["revoke_threshold_breached"], sample_dna,
        )
        assert fields.precondition is not None
        assert fields.objective is not None

    def test_exfiltration(self, sample_dna):
        fields = infer_narrative_fields(
            UISEventCategory.EXFILTRATION, [], sample_dna,
        )
        assert "data" in fields.objective.lower() or "extract" in fields.objective.lower()

    def test_all_categories_produce_populated_fields(self, sample_dna):
        for cat in UISEventCategory:
            fields = infer_narrative_fields(cat, [], sample_dna)
            assert fields.is_populated, f"{cat} should produce populated fields"


# ── Confidence Computation ────────────────────────────────────────────────────

class TestComputeConfidence:
    def test_empty_reasons_gives_base_confidence(self):
        c = compute_confidence(UISEventCategory.AUTH_ANOMALY, [])
        assert c == pytest.approx(0.3)

    def test_tor_boosts_confidence(self):
        c = compute_confidence(UISEventCategory.AUTH_ANOMALY, ["tor_exit_node"])
        assert c > 0.5

    def test_impossible_travel_high_confidence(self):
        c = compute_confidence(UISEventCategory.LATERAL_MOVEMENT, ["impossible_travel"])
        assert c >= 0.7

    def test_multiple_signals_boost(self):
        c_single = compute_confidence(UISEventCategory.AUTH_ANOMALY, ["tor_exit_node"])
        c_multi = compute_confidence(
            UISEventCategory.AUTH_ANOMALY,
            ["tor_exit_node", "vpn_or_proxy", "datacenter_ip"],
        )
        assert c_multi > c_single

    def test_abuseipdb_high_score_high_confidence(self):
        c = compute_confidence(UISEventCategory.CREDENTIAL_ABUSE, ["abuseipdb:95"])
        assert c > 0.6

    def test_abuseipdb_low_score_lower_confidence(self):
        c_low = compute_confidence(UISEventCategory.CREDENTIAL_ABUSE, ["abuseipdb:20"])
        c_high = compute_confidence(UISEventCategory.CREDENTIAL_ABUSE, ["abuseipdb:95"])
        assert c_high > c_low

    def test_confidence_never_exceeds_1(self):
        c = compute_confidence(
            UISEventCategory.LATERAL_MOVEMENT,
            ["impossible_travel", "session_branching", "tor_exit_node", "abuseipdb:100"],
        )
        assert c <= 1.0

    def test_confidence_at_least_base(self):
        for cat in UISEventCategory:
            c = compute_confidence(cat, [])
            assert c >= 0.3


# ── Narrative Rendering ──────────────────────────────────────────────────────

class TestRenderNarrative:
    def test_all_categories_have_templates(self):
        for cat in UISEventCategory:
            assert cat in NARRATIVE_TEMPLATES

    def test_render_includes_user_id(self, sample_dna):
        text = render_narrative(
            UISEventCategory.AUTH_ANOMALY, "user123", sample_dna, ["tor_exit_node"], 40,
        )
        assert "user123" in text

    def test_render_includes_country(self, sample_dna):
        text = render_narrative(
            UISEventCategory.AUTH_ANOMALY, "user123", sample_dna, [], 85,
        )
        assert "US" in text

    def test_render_includes_score(self, sample_dna):
        text = render_narrative(
            UISEventCategory.AUTH_ANOMALY, "user123", sample_dna, [], 42,
        )
        assert "42" in text

    def test_render_includes_reasons(self, sample_dna):
        text = render_narrative(
            UISEventCategory.CREDENTIAL_ABUSE, "user123", sample_dna,
            ["session_branching"], 45,
        )
        assert "session_branching" in text

    def test_render_each_category_non_empty(self, sample_dna):
        for cat in UISEventCategory:
            text = render_narrative(cat, "u", sample_dna, [], 50)
            assert len(text) > 50


# ── Full Enrichment Pipeline ─────────────────────────────────────────────────

class TestEnrichEvent:
    def test_enrich_returns_narrative_event(self, sample_dna, sample_breakdown_tor):
        result = enrich_event("user1", sample_dna, sample_breakdown_tor)
        assert isinstance(result, UISNarrativeEvent)
        assert result.schema_version == UIS_SCHEMA_VERSION

    def test_enrich_tor_event(self, sample_dna, sample_breakdown_tor):
        result = enrich_event("user1", sample_dna, sample_breakdown_tor)
        assert result.category == UISEventCategory.AUTH_ANOMALY
        assert result.mitre_tactic is not None
        assert result.mitre_technique is not None
        assert result.narrative is not None
        assert result.confidence > 0.3
        assert result.narrative_fields.is_populated

    def test_enrich_lateral_event(self, sample_dna, sample_breakdown_lateral):
        result = enrich_event("user1", sample_dna, sample_breakdown_lateral)
        assert result.category == UISEventCategory.LATERAL_MOVEMENT
        assert result.mitre_technique == "T1550.001"

    def test_enrich_credential_event(self, sample_dna, sample_breakdown_credential):
        result = enrich_event("user1", sample_dna, sample_breakdown_credential)
        assert result.category == UISEventCategory.CREDENTIAL_ABUSE

    def test_enrich_revoke_event(self, sample_dna, sample_breakdown_revoke):
        result = enrich_event("user1", sample_dna, sample_breakdown_revoke)
        # With impossible_travel present, lateral_movement wins priority
        assert result.category == UISEventCategory.LATERAL_MOVEMENT
        assert result.confidence > 0.5  # multiple signals = higher confidence

    def test_enrich_clean_event(self, sample_dna, sample_breakdown_allow):
        result = enrich_event("user1", sample_dna, sample_breakdown_allow)
        assert result.category == UISEventCategory.AUTH_ANOMALY
        assert result.confidence == pytest.approx(0.3)

    def test_enrich_abuse_event(self, sample_dna, sample_breakdown_abuse):
        result = enrich_event("user1", sample_dna, sample_breakdown_abuse)
        assert result.category == UISEventCategory.CREDENTIAL_ABUSE

    def test_enrich_to_dict_roundtrip(self, sample_dna, sample_breakdown_tor):
        result = enrich_event("user1", sample_dna, sample_breakdown_tor)
        d = result.to_dict()
        assert d["schema_version"] == UIS_SCHEMA_VERSION
        assert d["category"] == "auth_anomaly"
        assert d["mitre_tactic"] is not None
        assert d["mitre_technique"] is not None
        assert d["narrative"] is not None
        assert d["confidence"] > 0
        # All four narrative fields present
        assert "precondition" in d
        assert "pivot" in d
        assert "payload" in d
        assert "objective" in d

    def test_enrich_from_dict_roundtrip(self, sample_dna, sample_breakdown_tor):
        original = enrich_event("user1", sample_dna, sample_breakdown_tor)
        d = original.to_dict()
        restored = UISNarrativeEvent.from_dict(d)
        assert restored.category == original.category
        assert restored.mitre_tactic == original.mitre_tactic
        assert restored.confidence == pytest.approx(original.confidence)

    def test_enrich_with_dict_breakdown(self, sample_dna):
        """Ensure enrich_event works with dict score_breakdown (API flexibility)."""
        bd = {"reasons": ["tor_exit_node"], "final_score": 40}
        result = enrich_event("user1", sample_dna, bd)
        assert result.category == UISEventCategory.AUTH_ANOMALY
        assert result.narrative is not None


# ── Narrative Fields Dataclass ────────────────────────────────────────────────

class TestNarrativeFields:
    def test_empty_fields_not_populated(self):
        f = NarrativeFields()
        assert not f.is_populated

    def test_single_field_is_populated(self):
        f = NarrativeFields(precondition="something")
        assert f.is_populated

    def test_to_dict(self):
        f = NarrativeFields(precondition="a", pivot="b", payload="c", objective="d")
        d = f.to_dict()
        assert d == {"precondition": "a", "pivot": "b", "payload": "c", "objective": "d"}

    def test_from_dict(self):
        d = {"precondition": "x", "pivot": "y"}
        f = NarrativeFields.from_dict(d)
        assert f.precondition == "x"
        assert f.pivot == "y"
        assert f.payload is None

    def test_from_dict_empty(self):
        f = NarrativeFields.from_dict({})
        assert not f.is_populated


# ── Migration v1.0 → v1.1 ────────────────────────────────────────────────────

class TestMigration:
    def test_migrate_adds_narrative_fields(self):
        v1 = {
            "request_id": "req1",
            "user_id": "user1",
            "tier": "block",
            "final_score": 25,
        }
        v11 = migrate_event_v1_to_v1_1(v1)
        assert v11["schema_version"] == UIS_SCHEMA_VERSION
        assert v11["precondition"] is None
        assert v11["pivot"] is None
        assert v11["payload"] is None
        assert v11["objective"] is None
        assert v11["mitre_tactic"] is None
        assert v11["mitre_technique"] is None
        assert v11["narrative"] is None
        assert v11["confidence"] == 0.0

    def test_migrate_preserves_existing_fields(self):
        v1 = {"request_id": "req1", "user_id": "user1", "tier": "allow", "final_score": 85}
        v11 = migrate_event_v1_to_v1_1(v1)
        assert v11["request_id"] == "req1"
        assert v11["user_id"] == "user1"
        assert v11["tier"] == "allow"
        assert v11["final_score"] == 85

    def test_migrate_already_v11_is_noop(self):
        v11 = {
            "schema_version": UIS_SCHEMA_VERSION,
            "precondition": "test",
            "pivot": "test",
        }
        result = migrate_event_v1_to_v1_1(v11)
        assert result is v11  # same object, not a copy

    def test_migrate_does_not_overwrite_existing_narrative_fields(self):
        """If a v1 event somehow already has a narrative field, preserve it."""
        v1 = {"precondition": "pre-existing"}
        v11 = migrate_event_v1_to_v1_1(v1)
        assert v11["precondition"] == "pre-existing"


# ── UIS Event Category Enum ──────────────────────────────────────────────────

class TestUISEventCategory:
    def test_all_five_categories_exist(self):
        assert len(UISEventCategory) == 5

    def test_category_values_are_snake_case(self):
        for cat in UISEventCategory:
            assert cat.value == cat.value.lower()
            assert "_" in cat.value or cat.value.isalpha()

    def test_category_string_roundtrip(self):
        for cat in UISEventCategory:
            assert UISEventCategory(cat.value) == cat


# ── Backward Compatibility ────────────────────────────────────────────────────

class TestBackwardCompatibility:
    """Ensure existing scoring/DNA functionality is unaffected."""

    def test_scoring_imports_unchanged(self):
        from modules.identity.scoring import compute, ScoreBreakdown, RiskTier
        bd = compute(85)
        assert bd.tier == RiskTier.ALLOW
        assert bd.final_score == 85

    def test_scoring_with_threat_unchanged(self):
        from modules.identity.scoring import compute
        bd = compute(80)
        assert bd.final_score == 80

    def test_dna_generation_unchanged(self):
        from modules.identity.token_dna import generate_dna
        dna = generate_dna("Mozilla/5.0", "1.2.3.4", "US", "AS15169")
        assert dna["version"] == 2
        assert dna["country"] == "US"

    def test_dna_migration_unchanged(self):
        from modules.identity.token_dna import migrate_dna
        v1 = {"version": 1, "d": "dev", "i": "ip", "c": "GB", "a": "AS1"}
        v2 = migrate_dna(v1)
        assert v2["version"] == 2
        assert v2["device"] == "dev"


# ── POC: Attack Story Reconstruction ─────────────────────────────────────────
# Gate requirement: "at least one downstream POC script reconstructs an
# attack story from chained events with narrative fields populated"

class TestAttackStoryReconstruction:
    """
    Simulates a multi-event attack chain and reconstructs the story
    from narrative fields — the Sprint 1-1 gate requirement.
    """

    def test_reconstruct_credential_theft_to_lateral_movement(self, sample_dna):
        """
        Scenario: Attacker steals credentials, uses them from multiple
        devices (branching), then replays from a distant location
        (impossible travel).
        """
        # Event 1: Credential abuse via session branching
        bd1 = ScoreBreakdown(
            ml_score=75, threat_penalty=0, graph_penalty=30,
            final_score=45, tier=RiskTier.STEP_UP,
            reasons=["session_branching"],
        )
        evt1 = enrich_event("victim", sample_dna, bd1)

        # Event 2: Lateral movement via impossible travel
        bd2 = ScoreBreakdown(
            ml_score=70, threat_penalty=0, graph_penalty=50,
            final_score=20, tier=RiskTier.BLOCK,
            reasons=["impossible_travel"],
        )
        evt2 = enrich_event("victim", sample_dna, bd2)

        # Event 3: Tor-based access + revocation
        bd3 = ScoreBreakdown(
            ml_score=60, threat_penalty=40, graph_penalty=50,
            final_score=0, tier=RiskTier.REVOKE,
            reasons=["tor_exit_node", "impossible_travel", "revoke_threshold_breached"],
        )
        evt3 = enrich_event("victim", sample_dna, bd3)

        # Reconstruct the attack story
        chain = [evt1, evt2, evt3]

        # Verify: each event has a populated narrative
        for i, evt in enumerate(chain):
            assert evt.narrative is not None, f"Event {i} missing narrative"
            assert evt.narrative_fields.is_populated, f"Event {i} missing narrative fields"
            assert evt.mitre_tactic is not None, f"Event {i} missing MITRE tactic"
            assert evt.mitre_technique is not None, f"Event {i} missing MITRE technique"

        # Verify: the chain tells a coherent escalation story
        assert chain[0].category == UISEventCategory.CREDENTIAL_ABUSE
        assert chain[1].category == UISEventCategory.LATERAL_MOVEMENT
        assert chain[2].category == UISEventCategory.LATERAL_MOVEMENT  # impossible_travel wins

        # Verify: confidence increases with signal severity
        assert chain[2].confidence >= chain[0].confidence

        # Verify: narrative can be serialized for downstream consumption
        story = [evt.to_dict() for evt in chain]
        assert len(story) == 3
        assert all(s["schema_version"] == UIS_SCHEMA_VERSION for s in story)

        # Reconstruct human-readable story
        full_narrative = "\n".join(
            f"[{evt.category.value}] {evt.narrative}" for evt in chain
        )
        assert "victim" in full_narrative
        assert len(full_narrative) > 100
