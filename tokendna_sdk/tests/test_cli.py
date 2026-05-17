"""Tests for the v0.2 CLI commands."""

from __future__ import annotations

import json
import sys

import pytest

from tokendna_sdk.cli import main


def _run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else None


def test_config_show(capsys):
    code, data = _run(capsys, "config", "show")
    assert code == 0
    assert data["mode"] == "local"
    assert "api_key_present" in data


def test_status_local_mode(capsys, tmp_tokendna_root):
    code, data = _run(capsys, "status")
    assert code == 0
    assert data["health"]["mode"] == "local"
    assert data["recent_events"] == 0


def test_demo_runs_end_to_end_in_local_mode(capsys, tmp_tokendna_root):
    code, data = _run(capsys, "demo", "--agent-id", "demo-1")
    assert code == 0
    assert data["mode"] == "local"
    assert data["agent_id"] == "demo-1"
    assert data["attestation"]["agent_id"] == "demo-1"
    assert len(data["tool_calls"]) == 4


def test_status_lists_baselines_after_demo(capsys, tmp_tokendna_root):
    main(["demo", "--agent-id", "demo-bl"])
    capsys.readouterr()
    code, data = _run(capsys, "status")
    assert code == 0
    assert "demo-bl" in data["baselines"]


def test_baseline_show(capsys, tmp_tokendna_root):
    main(["demo", "--agent-id", "agent-base"])
    capsys.readouterr()
    code, data = _run(capsys, "baseline", "show", "agent-base")
    assert code == 0
    assert data["agent_id"] == "agent-base"
    assert data["sessions_observed"] >= 1


def test_baseline_show_unknown_agent(capsys, tmp_tokendna_root):
    code, data = _run(capsys, "baseline", "show", "ghost")
    assert code == 0
    assert data["sessions_observed"] == 0
    assert data["is_warm"] is False


def test_verify_in_local_mode_returns_allow(capsys, tmp_tokendna_root):
    code, data = _run(capsys, "verify", "a1", "search", "--scope", "x")
    assert code == 0
    assert data["decision"] == "allow"
    assert data["reason"] == "local_mode"
