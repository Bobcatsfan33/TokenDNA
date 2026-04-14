# AGENTS.md

## Cursor Cloud specific instructions

### Product overview

TokenDNA / Aegis Security Platform — a zero-trust token integrity and session behavioral analytics FastAPI backend. See `README.md` for full architecture and API reference.

### Required services

| Service | How to start | Notes |
|---------|-------------|-------|
| **Redis** | `redis-server --daemonize yes` | Hard dependency. Must be running before the app starts. |
| **TokenDNA API** | `DEV_MODE=true uvicorn api:app --host 0.0.0.0 --port 8000 --reload` | `DEV_MODE=true` bypasses OIDC/JWT auth; uses a synthetic dev-user. |

ClickHouse is optional for local dev — the app starts without it (reports `clickhouse: false` in health check). Slack/SIEM webhooks and OIDC providers are also optional.

### Environment setup caveats

- The `/data` directory must exist and be writable (used for SQLite tenant DB). Run `sudo mkdir -p /data && sudo chmod 777 /data` if it doesn't exist.
- Copy `.env.example` to `.env` and set `DEV_MODE=true`, `REDIS_HOST=localhost`, `CLICKHOUSE_HOST=localhost`.
- `starlette` must be pinned to `<1.0.0` (e.g. `starlette>=0.46.0,<1.0.0`) to avoid `MutableHeaders.pop()` incompatibility. The update script handles this.

### Running commands

- **Lint:** `ruff check .` (config in `pyproject.toml`)
- **Tests:** `pytest tests/ -v` (155 unit tests, no external services needed)
- **Dev server:** `DEV_MODE=true uvicorn api:app --host 0.0.0.0 --port 8000 --reload`
- **Health check:** `curl http://localhost:8000/`
- **Token integrity check (dev):** `curl http://localhost:8000/secure` (uses synthetic dev-user in DEV_MODE)
