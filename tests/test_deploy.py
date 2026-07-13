"""Tests for the Railway deployment scaffolding (serve.py + config + gate)."""
from __future__ import annotations

import pathlib

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ── files + config ─────────────────────────────────────────────────────────────

def test_serve_entrypoint_defaults_and_helpers():
    src = (ROOT / "serve.py").read_text()
    assert 'os.getenv("HOST", "127.0.0.1")' in src   # local default host
    assert 'os.getenv("PORT", "8000")' in src        # local default port
    assert 'uvicorn.run("api:app"' in src
    assert "_seed_if_needed" in src and "SEED_ON_START" in src
    assert "_apply_local_defaults" in src


def test_railway_config_present():
    toml = (ROOT / "railway.toml").read_text()
    assert 'healthcheckPath = "/healthz"' in toml
    assert "python serve.py" in toml
    assert (ROOT / "Dockerfile.railway").read_text().count("serve.py") >= 1
    assert "python:3.12-slim" in (ROOT / "Dockerfile.railway").read_text()
    assert (ROOT / "DEPLOY.md").exists()


def test_serve_helpers_import_and_work(monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("serve_mod", ROOT / "serve.py")
    serve = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(serve)
    assert serve._truthy("1") and serve._truthy("true") and not serve._truthy("")
    # local defaults only fill unset vars
    monkeypatch.delenv("DATA_DB_PATH", raising=False)
    monkeypatch.delenv("AUDIT_LOG_PATH", raising=False)
    serve._apply_local_defaults()
    import os
    assert os.environ["DATA_DB_PATH"].endswith(".tokendna/tokendna.db")
    assert os.environ["AUDIT_LOG_PATH"].endswith(".tokendna/audit.jsonl")


# ── demo password gate (DemoAuthMiddleware) ────────────────────────────────────

def _gated_app(password):
    from api_routers import DemoAuthMiddleware
    app = FastAPI()

    @app.get("/healthz")
    def hz():
        return {"status": "ok"}

    @app.get("/dashboard", response_class=HTMLResponse)
    def dash():
        return "<html>dash</html>"

    @app.get("/api/graph/stats")
    def stats():
        return {"node_count": 1}

    app.add_middleware(DemoAuthMiddleware, password=password)
    return app


def test_demo_gate_blocks_without_cookie_but_health_open():
    c = TestClient(_gated_app("s3cret"))
    assert c.get("/healthz").status_code == 200          # probe always open
    # fresh client (no cookie) is blocked
    fresh = TestClient(_gated_app("s3cret"))
    assert fresh.get("/dashboard").status_code == 401
    assert fresh.get("/api/graph/stats").status_code == 401


def test_demo_gate_login_then_access():
    c = TestClient(_gated_app("s3cret"))
    bad = c.post("/__demo_login", data={"password": "nope"})
    assert bad.status_code == 401
    ok = c.post("/__demo_login", data={"password": "s3cret"}, follow_redirects=False)
    assert ok.status_code == 303 and "tdna_demo" in ok.headers.get("set-cookie", "")
    # client keeps the cookie → now allowed
    assert c.get("/dashboard").status_code == 200
    assert c.get("/api/graph/stats").status_code == 200


# ── static cache policy (_CachingStatic) ───────────────────────────────────────

def test_static_cache_policy_env_driven(tmp_path, monkeypatch):
    from api_routers import _CachingStatic
    (tmp_path / "x.js").write_text("console.log(1)")
    app = FastAPI()
    app.mount("/s", _CachingStatic(directory=str(tmp_path)), name="s")
    c = TestClient(app)
    monkeypatch.delenv("ASSET_CACHE_SECONDS", raising=False)
    assert "no-store" in c.get("/s/x.js").headers.get("cache-control", "")
    monkeypatch.setenv("ASSET_CACHE_SECONDS", "86400")
    cc = c.get("/s/x.js").headers.get("cache-control", "")
    assert "max-age=86400" in cc and "no-store" not in cc
