"""
Tests for modules/product/shadow_mode.py — observe-only trial framework.

Coverage:
  - is_active() resolves env var → global override → per-tenant override
  - set_shadow_active / clear_shadow_state
  - FileTailJSONLConnector ingests, skips, errors
  - Connector marks events with shadow_observed metadata when active
  - generate_trial_report against a fresh DB returns sensible defaults
  - generate_trial_report aggregates real anomalies and violations
  - Top findings logic includes / excludes severity classes
"""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture(autouse=True)
def reset_shadow():
    from modules.product import shadow_mode
    shadow_mode.clear_shadow_state()
    yield
    shadow_mode.clear_shadow_state()


# ── Activation ────────────────────────────────────────────────────────────────


class TestActivation:
    def test_default_inactive(self, monkeypatch):
        monkeypatch.delenv("TOKENDNA_SHADOW_MODE", raising=False)
        from modules.product import shadow_mode
        assert shadow_mode.is_active() is False
        assert shadow_mode.is_active("any-tenant") is False

    def test_env_var_activates(self, monkeypatch):
        from modules.product import shadow_mode
        for value in ("true", "1", "yes", "on", "TRUE"):
            monkeypatch.setenv("TOKENDNA_SHADOW_MODE", value)
            assert shadow_mode.is_active() is True

    def test_global_override_beats_env(self, monkeypatch):
        monkeypatch.setenv("TOKENDNA_SHADOW_MODE", "true")
        from modules.product import shadow_mode
        shadow_mode.set_shadow_active(False)
        assert shadow_mode.is_active() is False

    def test_per_tenant_override(self):
        from modules.product import shadow_mode
        shadow_mode.set_shadow_active(True, "tenant-A")
        shadow_mode.set_shadow_active(False, "tenant-B")
        assert shadow_mode.is_active("tenant-A") is True
        assert shadow_mode.is_active("tenant-B") is False
        # Global default falls through.
        assert shadow_mode.is_active("tenant-C") is False


# ── FileTailJSONLConnector ────────────────────────────────────────────────────


class TestFileTailConnector:
    def _make_jsonl(self, tmp_path, events):
        p = tmp_path / "audit.jsonl"
        with p.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        return p

    def test_ingests_mapped_events(self, tmp_path):
        from modules.product import shadow_mode
        src = self._make_jsonl(tmp_path, [
            {"id": 1, "actor": "alice", "action": "read"},
            {"id": 2, "actor": "bob",   "action": "write"},
        ])
        ingested: list[dict] = []
        connector = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1",
            source_path=src,
            mapping=lambda r: {"event_id": str(r["id"]), "actor": r["actor"]},
            ingest_fn=ingested.append,
        )
        report = connector.run()
        assert report.events_seen == 2
        assert report.events_ingested == 2
        assert report.events_skipped == 0
        assert len(ingested) == 2
        # Connector metadata stamped.
        assert all(e["metadata"]["connector"].startswith("file-tail:") for e in ingested)

    def test_skips_when_mapping_returns_none(self, tmp_path):
        from modules.product import shadow_mode
        src = self._make_jsonl(tmp_path, [
            {"id": 1, "type": "keep"},
            {"id": 2, "type": "drop"},
            {"id": 3, "type": "keep"},
        ])
        ingested: list[dict] = []
        connector = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1",
            source_path=src,
            mapping=lambda r: r if r["type"] == "keep" else None,
            ingest_fn=ingested.append,
        )
        report = connector.run()
        assert report.events_seen == 3
        assert report.events_ingested == 2
        assert report.events_skipped == 1

    def test_marks_shadow_observed_when_active(self, tmp_path):
        from modules.product import shadow_mode
        shadow_mode.set_shadow_active(True, "t-shadow")
        src = self._make_jsonl(tmp_path, [{"id": 1}])
        ingested: list[dict] = []
        connector = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-shadow",
            source_path=src,
            mapping=lambda r: {"event_id": str(r["id"])},
            ingest_fn=ingested.append,
        )
        connector.run()
        assert ingested[0]["metadata"]["shadow_observed"] is True

    def test_handles_invalid_json_lines(self, tmp_path):
        from modules.product import shadow_mode
        src = tmp_path / "bad.jsonl"
        src.write_text("{\"id\": 1}\nnot-json\n{\"id\": 2}\n")
        ingested: list[dict] = []
        report = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1", source_path=src,
            mapping=lambda r: r, ingest_fn=ingested.append,
        ).run()
        assert report.events_ingested == 2
        assert report.events_skipped == 1
        assert any("invalid JSON" in e for e in report.errors)

    def test_handles_mapping_exception(self, tmp_path):
        from modules.product import shadow_mode
        src = tmp_path / "x.jsonl"
        src.write_text("{}\n")
        def boom(_): raise RuntimeError("mapping broken")
        report = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1", source_path=src,
            mapping=boom, ingest_fn=lambda _: None,
        ).run()
        assert report.events_ingested == 0
        assert report.events_skipped == 1

    def test_missing_source_returns_error(self, tmp_path):
        from modules.product import shadow_mode
        report = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1",
            source_path=tmp_path / "does-not-exist.jsonl",
            mapping=lambda r: r,
            ingest_fn=lambda _: None,
        ).run()
        assert report.events_seen == 0
        assert any("not found" in e for e in report.errors)

    def test_max_events_caps_intake(self, tmp_path):
        from modules.product import shadow_mode
        src = tmp_path / "many.jsonl"
        src.write_text("\n".join(json.dumps({"id": i}) for i in range(20)))
        ingested: list[dict] = []
        report = shadow_mode.FileTailJSONLConnector(
            tenant_id="t-1", source_path=src,
            mapping=lambda r: {"event_id": str(r["id"])},
            ingest_fn=ingested.append, max_events=5,
        ).run()
        assert report.events_ingested == 5


# ── Trial report ──────────────────────────────────────────────────────────────


class TestTrialReport:
    def test_empty_db_returns_zero_findings(self, tmp_path):
        from modules.product import shadow_mode
        report = shadow_mode.generate_trial_report(
            tenant_id="prospect", db_path=str(tmp_path / "empty.db"),
        )
        assert report.events_observed == 0
        assert report.unique_agents_observed == 0
        assert report.policy_violations_blocked == 0
        # Top findings always has at least the "no findings" entry.
        assert len(report.top_findings) >= 1

    def test_aggregates_seeded_anomalies(self, tmp_path, monkeypatch):
        # Run the demo seeder against an isolated DB so the report has
        # something to count.  Use a small days_back to keep it quick.
        db = str(tmp_path / "seeded.db")
        monkeypatch.setenv("DATA_DB_PATH", db)
        # Reload modules so they pick up the env-scoped DB path.
        from modules.identity import (
            permission_drift, policy_advisor, policy_guard, trust_graph,
            uis_store, honeypot_mesh, intent_correlation, mcp_inspector,
            federation,
        )
        for m in (uis_store, trust_graph, policy_guard, policy_advisor,
                  permission_drift, honeypot_mesh, intent_correlation,
                  mcp_inspector, federation):
            importlib.reload(m)
            m.init_db()
        # Drive a self-modification via the trust graph so the report
        # has at least one POLICY_SCOPE_MODIFICATION row.
        anomalies = trust_graph.record_policy_modification(
            tenant_id="prospect",
            target_agent="agt-X", modified_by="agt-X",
            policy_id="pol-1",
        )
        for a in anomalies:
            trust_graph.store_anomaly(a)

        from modules.product import shadow_mode
        importlib.reload(shadow_mode)
        report = shadow_mode.generate_trial_report(
            tenant_id="prospect", db_path=db,
        )
        assert report.anomalies_by_type.get("POLICY_SCOPE_MODIFICATION", 0) >= 1
        critical_finding = [
            f for f in report.top_findings
            if f["severity"] == "critical"
            and "self-modification" in f["title"].lower()
        ]
        assert critical_finding, "self-modification should appear as a critical finding"

    def test_serializes_to_dict(self, tmp_path):
        from modules.product import shadow_mode
        report = shadow_mode.generate_trial_report(
            tenant_id="x", db_path=str(tmp_path / "ser.db"),
        )
        d = report.as_dict()
        for key in (
            "tenant_id", "generated_at", "window_days",
            "events_observed", "anomalies_by_type",
            "policy_violations_blocked", "drift_alerts_total",
            "top_findings", "high_blast_radius_agents",
            "federation_trusts_active",
        ):
            assert key in d


# ── Top findings logic ────────────────────────────────────────────────────────


class TestTopFindings:
    def test_no_findings_emits_info_baseline(self):
        from modules.product import shadow_mode
        findings = shadow_mode._build_top_findings(
            anomalies_by_type={}, drift_critical=0,
            mcp_chain_matches=0, violations_blocked=0,
            cross_org_blocks=0,
        )
        assert len(findings) == 1
        assert findings[0]["severity"] == "info"

    def test_self_modification_yields_critical(self):
        from modules.product import shadow_mode
        findings = shadow_mode._build_top_findings(
            anomalies_by_type={"POLICY_SCOPE_MODIFICATION": 3},
            drift_critical=0, mcp_chain_matches=0,
            violations_blocked=0, cross_org_blocks=0,
        )
        assert findings[0]["severity"] == "critical"
        assert findings[0]["count"] == 3

    def test_multiple_signals_listed_in_order(self):
        from modules.product import shadow_mode
        findings = shadow_mode._build_top_findings(
            anomalies_by_type={"POLICY_SCOPE_MODIFICATION": 1},
            drift_critical=4,
            mcp_chain_matches=2,
            violations_blocked=8,
            cross_org_blocks=5,
        )
        titles = [f["title"] for f in findings]
        assert "Agent self-modification detected" in titles
        assert "Critical permission drift" in titles
        assert "MCP attack-chain matches" in titles
        assert "Policy violations blocked" in titles
        assert "Cross-org actions without federation" in titles
