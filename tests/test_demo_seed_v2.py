"""
Smoke tests for scripts/demo_seed_v2.py.

Validates the seeder runs in --dry-run mode without errors and produces a
sensible summary. Does NOT exercise the live writes — those would require
spinning up every module's schema in a temp DB which the integration test
in test_rsa_narrative_e2e.py covers indirectly.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys


_SEED = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "demo_seed_v2.py"
_FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "data" / "demo_fixtures"


def test_seeder_script_exists():
    assert _SEED.is_file(), f"missing {_SEED}"


def test_fixtures_present():
    expected = (
        "mitre_techniques.json",
        "geo_samples.json",
        "agent_archetypes.json",
        "attack_chains.json",
    )
    for name in expected:
        path = _FIXTURES / name
        assert path.is_file(), f"missing fixture: {name}"
        # Must parse as JSON.
        json.loads(path.read_text())


def test_dry_run_completes_cleanly():
    result = subprocess.run(
        [sys.executable, str(_SEED), "--dry-run"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for marker in (
        "Stage 1 — Agents + 30-day UIS history",
        "Stage 2 — Drift baselines",
        "Stage 3 — Pre-existing policy_guard violations",
        "Stage 4 — Honeytoken decoys",
        "Stage 5 — Federation: Acme ↔ Beta mutual trust",
        "Stage 6 — Historical attack chain traces",
        "Demo Seed v2 — complete",
        "(dry-run — nothing was written)",
    ):
        assert marker in out, f"missing marker: {marker}"


def test_seeder_module_imports_cleanly():
    spec = importlib.util.spec_from_file_location("demo_seed_v2", _SEED)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert callable(getattr(mod, "seed_agents_and_history"))
    summary = mod.seed_agents_and_history(days_back=5, rng_seed=1, dry_run=True)
    assert summary["dry_run"] is True
    assert summary["tenants"] == ["acme", "beta"]
    # Realistic agent counts from the fixture archetypes.
    assert summary["agents"]["acme"] >= 30
    assert summary["agents"]["beta"] >= 15


def test_fixtures_have_expected_shape():
    techniques = json.loads((_FIXTURES / "mitre_techniques.json").read_text())
    assert len(techniques["techniques"]) >= 10
    assert all("id" in t and "name" in t for t in techniques["techniques"])

    geo = json.loads((_FIXTURES / "geo_samples.json").read_text())
    assert len(geo["samples"]) >= 8
    for s in geo["samples"]:
        assert s["category"] in {"cloud_egress", "office_network", "high_risk_geo"}

    archetypes = json.loads((_FIXTURES / "agent_archetypes.json").read_text())
    assert "archetypes" in archetypes
    assert "remote_org_archetypes" in archetypes
    for arch in archetypes["archetypes"] + archetypes["remote_org_archetypes"]:
        for key in ("key", "name_pattern", "tier", "baseline_scope",
                    "auth_method", "protocol", "count"):
            assert key in arch, f"archetype missing {key}: {arch.get('key')}"

    chains = json.loads((_FIXTURES / "attack_chains.json").read_text())
    assert len(chains["chains"]) >= 5
    for c in chains["chains"]:
        assert c["severity"] in {"low", "medium", "high", "critical"}
        assert isinstance(c["stages"], list) and len(c["stages"]) >= 1


def test_shadow_trial_report_cli_runs(tmp_path):
    """End-to-end: the CLI can render against an empty DB without crashing."""
    cli = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "shadow_trial_report.py"
    db = tmp_path / "trial.db"
    result = subprocess.run(
        [sys.executable, str(cli), "--tenant", "fresh-prospect",
         "--db-path", str(db)],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "TokenDNA Shadow Mode Trial Report" in result.stdout
    assert "Tenant:   fresh-prospect" in result.stdout

    # JSON mode must produce valid JSON.
    result_json = subprocess.run(
        [sys.executable, str(cli), "--tenant", "fresh-prospect",
         "--db-path", str(db), "--json"],
        capture_output=True, text=True, timeout=20,
    )
    assert result_json.returncode == 0
    data = json.loads(result_json.stdout)
    assert data["tenant_id"] == "fresh-prospect"
    assert data["window_days"] == 14
