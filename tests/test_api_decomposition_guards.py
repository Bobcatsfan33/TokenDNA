"""T-1: tests for the monolith ratchet + route-surface guard CI scripts.

These guards are the safety net that makes the api.py decomposition mechanical
and regression-proof, so they themselves must be tested.
"""
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(script_rel: str):
    path = ROOT / script_rel
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── ratchet ───────────────────────────────────────────────────────────────────

def _run_ratchet(tmp_path, monkeypatch, budget: int, api_lines: int):
    ratchet = _load("scripts/ci/api_monolith_ratchet.py")
    budget_file = tmp_path / "budget.txt"
    api_file = tmp_path / "api.py"
    budget_file.write_text(str(budget))
    api_file.write_text("\n".join("x" for _ in range(api_lines)))
    monkeypatch.setattr(ratchet, "BUDGET_FILE", budget_file)
    monkeypatch.setattr(ratchet, "TARGET", api_file)
    return ratchet.main()


def test_ratchet_passes_when_equal(tmp_path, monkeypatch):
    assert _run_ratchet(tmp_path, monkeypatch, budget=100, api_lines=100) == 0


def test_ratchet_fails_when_grown(tmp_path, monkeypatch):
    assert _run_ratchet(tmp_path, monkeypatch, budget=100, api_lines=101) == 1


def test_ratchet_fails_when_shrunk_without_budget_update(tmp_path, monkeypatch):
    # Shrinking is good, but the budget must be lowered in the same PR.
    assert _run_ratchet(tmp_path, monkeypatch, budget=100, api_lines=90) == 1


def test_committed_budget_matches_api_py():
    budget = int((ROOT / "scripts/ci/api_line_budget.txt").read_text().strip())
    actual = len((ROOT / "api.py").read_text(encoding="utf-8").splitlines())
    assert actual == budget, f"api.py is {actual} lines but budget says {budget}"


# ── route-surface guard ───────────────────────────────────────────────────────

def test_route_snapshot_exists_and_nonempty():
    snap = json.loads((ROOT / "scripts/ci/openapi_routes.json").read_text())
    assert isinstance(snap, list)
    assert len(snap) > 250  # the live surface is ~305 routes
    # signatures are "METHOD /path"
    assert all(" /" in sig for sig in snap)


def test_guard_detects_added_and_removed(tmp_path, monkeypatch):
    guard = _load("scripts/ci/openapi_route_guard.py")
    snap = tmp_path / "routes.json"
    snap.write_text(json.dumps(["GET /a", "POST /b"]))
    monkeypatch.setattr(guard, "SNAPSHOT", snap)
    monkeypatch.setattr(guard, "current_surface", lambda: ["GET /a", "GET /c"])
    # /b removed, /c added -> non-zero
    assert guard.main([]) == 1


def test_guard_passes_when_unchanged(tmp_path, monkeypatch):
    guard = _load("scripts/ci/openapi_route_guard.py")
    snap = tmp_path / "routes.json"
    snap.write_text(json.dumps(["GET /a", "POST /b"]))
    monkeypatch.setattr(guard, "SNAPSHOT", snap)
    monkeypatch.setattr(guard, "current_surface", lambda: ["GET /a", "POST /b"])
    assert guard.main([]) == 0


def test_guard_update_writes_snapshot(tmp_path, monkeypatch):
    guard = _load("scripts/ci/openapi_route_guard.py")
    snap = tmp_path / "routes.json"
    monkeypatch.setattr(guard, "SNAPSHOT", snap)
    monkeypatch.setattr(guard, "current_surface", lambda: ["GET /a"])
    assert guard.main(["--update"]) == 0
    assert json.loads(snap.read_text()) == ["GET /a"]


# ── registry scaffold ─────────────────────────────────────────────────────────

def test_mount_all_is_noop_safe():
    import api_routers
    from fastapi import FastAPI

    app = FastAPI()
    before = len(app.routes)
    api_routers.mount_all(app)  # empty registry -> no change
    assert len(app.routes) == before
    assert isinstance(api_routers.ALL_ROUTERS, tuple)
