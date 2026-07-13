# Deploying the TokenDNA demo to Railway

This deploys the FastAPI app (`api:app`) to a stable public URL on Railway
without changing local `127.0.0.1:8000` development.

## TL;DR

* **Entry point:** `serve.py` (reads `HOST`/`PORT`, optional boot-seed, then runs
  `uvicorn api:app`). `api.py` is unchanged (it's frozen by a CI ratchet).
* **Builder:** `railway.toml` → `Dockerfile.railway` (python:3.12-slim).
* **Start command:** `python serve.py`
* **Health check:** `GET /healthz` (already existed; returns `{"status":"ok"}`).
* **Local dev is unchanged:** `python serve.py` with no env vars still serves
  `http://127.0.0.1:8000`.

## Files added/changed for deployment

| File | Purpose |
|------|---------|
| `serve.py` | **new** — process entry point. Reads `HOST` (default `127.0.0.1`) and `PORT` (default `8000`); binds `0.0.0.0:$PORT` in prod. Optional idempotent boot-seed. Defaults DB/audit paths to `~/.tokendna/` locally so zero-env startup works. |
| `railway.toml` | **new** — Railway build (Dockerfile) + start command + `/healthz` health check + restart policy. |
| `Dockerfile.railway` | **new** — python:3.12-slim, `pip install -r requirements.txt`, `CMD python serve.py`, image default `HOST=0.0.0.0`. (The existing distroless `./Dockerfile` is left untouched.) |
| `api_routers/__init__.py` | static mount now `_CachingStatic` (env-driven cache); optional `DemoAuthMiddleware` (password gate). |
| `requirements.txt` | pinned deps (already complete; verified in a clean venv). |

**Final start command:** `python serve.py` (with `HOST=0.0.0.0`, baked into the image; `PORT` injected by Railway).

## Railway steps

1. **Create project → Deploy from GitHub repo** → pick this repo. Railway reads
   `railway.toml` and builds `Dockerfile.railway`.
2. **Add a Volume** (Service → Settings → Volumes): mount path **`/data`**.
3. **Set environment variables** (Service → Variables):

   | Variable | Value | Why |
   |----------|-------|-----|
   | `HOST` | `0.0.0.0` | Already set in the image; set here too if you override the start cmd. |
   | `SEED_ON_START` | `1` | Self-seed the demo on first boot (idempotent — skipped once data exists). |
   | `DEV_MODE` | `true` | Demo runs without JWT auth so the dashboard's API calls work. Gate it with `DEMO_PASSWORD` below. |
   | `DEV_TENANT_ID` | `acme` | Tenant the seeder/dashboard use. |
   | `ATTESTATION_CA_SECRET` | *(32+ char secret)* | Required for attestation signing. |
   | `DATA_DB_PATH` | `/data/tokendna.db` | Main SQLite on the volume. |
   | `TOKENDNA_BEHAVIORAL_DB` | `/data/tokendna.db` | Behavioral DNA store. |
   | `TOKENDNA_ENFORCEMENT_DB` | `/data/tokendna.db` | Enforcement plane store. |
   | `TOKENDNA_DISCOVERY_DB` | `/data/tokendna.db` | Asset discovery store. |
   | `TOKENDNA_MCP_GATEWAY_DB` | `/data/tokendna.db` | MCP inspector store. |
   | `TOKENDNA_COMPLIANCE_DB` | `/data/tokendna.db` | Compliance store. |
   | `AUDIT_LOG_PATH` | `/data/audit.jsonl` | Audit log (default `/var/log/aegis` is not writable on Railway). |
   | `ASSET_CACHE_SECONDS` | `86400` | Cache `/static/*` in prod (URLs are version-busted, so this is safe). Omit/`0` = no-store. |
   | `DEMO_PASSWORD` | *(your shared password)* | **Optional.** Puts a one-page login in front of every route except `/healthz`. Unset = open. |
   | `CORS_ORIGINS` | *(optional)* | Only needed if a separate frontend origin calls the API; the dashboard is same-origin. |

4. **Deploy.** Railway builds, starts `python serve.py`, waits for `/healthz` to
   return 200, then routes traffic to the generated `*.up.railway.app` domain
   (Settings → Networking → Generate Domain). Add a custom domain
   (e.g. `demo.tokendna.com`) there when ready.

## Notes

* **Persistence:** all SQLite files live on the `/data` volume, so data survives
  redeploys. If you'd rather the demo reseed fresh each deploy, skip the volume
  and keep `SEED_ON_START=1` — the container's ephemeral disk is empty on each
  boot, so it reseeds automatically (the in-image default DB path is `/data`,
  which is ephemeral without a volume).
* **Offline / no CDN:** all front-end assets (React, the trust-graph engine,
  fixtures) are vendored under `dashboard/static/` and served from the app —
  there are zero third-party CDN requests in any environment.
* **Health check is always open:** the `DEMO_PASSWORD` gate never blocks
  `/healthz`, `/readyz`, `/`, or `/metrics`, so Railway's probe passes even with
  the password set.

## Local development (unchanged)

```bash
# zero-config: serves http://127.0.0.1:8000 (DB under ~/.tokendna/)
python serve.py

# full demo locally (auth off + seeded), same as before:
DEV_MODE=true DEV_TENANT_ID=acme SEED_ON_START=1 \
  DATA_DB_PATH=/tmp/tokendna-demo.db ATTESTATION_CA_SECRET=demo-secret-32-bytes-xxxxxxxx \
  python serve.py
```
