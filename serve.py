#!/usr/bin/env python3
"""Process entry point for TokenDNA — local dev AND production (Railway).

Why this exists: ``api.py`` is frozen by the monolith ratchet, so the host/port
binding and optional boot-seed live here instead. Behaviour:

* Local dev (no env vars):   ``python serve.py``  → serves http://127.0.0.1:8000
  exactly as before (HOST defaults to 127.0.0.1, PORT to 8000, no seeding).
* Production (Railway):       set ``HOST=0.0.0.0`` and ``SEED_ON_START=1``; Railway
  injects ``$PORT``. The app then listens on 0.0.0.0:$PORT (required, or Railway
  returns 502) and self-seeds the demo on first boot if the graph is empty.

Env vars read here:
  HOST           bind host         (default 127.0.0.1)
  PORT           bind port         (default 8000)
  SEED_ON_START  "1"/"true" to seed the demo if the DB has no graph data
  DEV_TENANT_ID  tenant to seed    (default "acme")
"""
from __future__ import annotations

import os
import pathlib
import sys


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


def _apply_local_defaults() -> None:
    """Make zero-config ``python serve.py`` work locally.

    The app's built-in default DB path is ``/data/tokendna.db`` (the production
    volume), which is read-only/absent on a dev box. When these aren't set we
    fall back to a writable ``~/.tokendna`` location so the server starts with no
    env. Production (Railway) sets them explicitly to the mounted volume, so this
    is a no-op there.
    """
    home = pathlib.Path(os.path.expanduser("~/.tokendna"))
    defaults = {
        "DATA_DB_PATH": str(home / "tokendna.db"),
        "AUDIT_LOG_PATH": str(home / "audit.jsonl"),
    }
    for key, val in defaults.items():
        if not os.getenv(key):
            os.environ[key] = val


def _ensure_db_dirs() -> None:
    """Create parent dirs for every configured SQLite DB path (Railway volume)."""
    candidates = [
        os.getenv("DATA_DB_PATH"),
        os.getenv("TOKENDNA_BEHAVIORAL_DB"),
        os.getenv("TOKENDNA_ENFORCEMENT_DB"),
        os.getenv("TOKENDNA_DISCOVERY_DB"),
        os.getenv("TOKENDNA_MCP_GATEWAY_DB"),
        os.getenv("TOKENDNA_COMPLIANCE_DB"),
        os.getenv("AUDIT_LOG_PATH"),
    ]
    for path in candidates:
        if path:
            try:
                pathlib.Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
            except Exception as exc:  # pragma: no cover - best effort
                print(f"[serve] could not create dir for {path}: {exc}", file=sys.stderr)


def _graph_is_empty(tenant: str) -> bool:
    try:
        from modules.identity import trust_graph
        stats = trust_graph.get_stats(tenant)
        return int(stats.get("node_count", 0)) == 0
    except Exception as exc:  # pragma: no cover - if we can't tell, seed
        print(f"[serve] graph stat check failed ({exc!r}); will attempt seed", file=sys.stderr)
        return True


def _seed_if_needed() -> None:
    """Idempotent demo seed: only runs when SEED_ON_START is set and the graph
    is empty, so redeploys against a persistent volume never duplicate data."""
    if not _truthy(os.getenv("SEED_ON_START")):
        return
    tenant = os.getenv("DEV_TENANT_ID", "acme")
    _ensure_db_dirs()
    if not _graph_is_empty(tenant):
        print(f"[serve] graph already populated for tenant '{tenant}' — skipping seed")
        return
    print(f"[serve] SEED_ON_START set and graph empty — seeding demo for '{tenant}'…")
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "scripts"))
    # Rich population (agents, trust graph, anomalies, intent, honeypots, …)
    try:
        import demo_seed_v2  # noqa: PLC0415
        argv_backup = sys.argv
        sys.argv = ["demo_seed_v2.py"]
        try:
            demo_seed_v2.main()
        finally:
            sys.argv = argv_backup
    except SystemExit:
        pass
    except Exception as exc:  # pragma: no cover - boot seed is best effort
        print(f"[serve] demo_seed_v2 failed: {exc!r}", file=sys.stderr)
    # Gap-roadmap features (kill planes, asset scans, campaigns, SIEM, retrieval)
    try:
        import demo_seed_gap  # noqa: PLC0415
        demo_seed_gap.seed_gap(tenant)
    except Exception as exc:  # pragma: no cover - boot seed is best effort
        print(f"[serve] demo_seed_gap failed: {exc!r}", file=sys.stderr)
    print("[serve] seed complete")


def main() -> None:
    _apply_local_defaults()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    _seed_if_needed()
    import uvicorn  # noqa: PLC0415
    print(f"[serve] starting uvicorn on {host}:{port}")
    uvicorn.run("api:app", host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
