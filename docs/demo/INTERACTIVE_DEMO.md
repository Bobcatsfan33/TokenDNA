# TokenDNA — Interactive Demo (exact working prototype)

One command brings up the **real** TokenDNA app (real endpoints, real logic) with
fake imported data and auth bypassed, so every feature is testable in the browser.

```bash
./scripts/demo.sh
```

Then open:

| URL | What |
|-----|------|
| **http://127.0.0.1:8000/demo** | Interactive console — every feature as a live API card (edit body → Run → see the real response) |
| **http://127.0.0.1:8000/console** | Kill-switch workflow graph — Cytoscape DAG; click an agent → rip its credentials across every plane |
| **http://127.0.0.1:8000/dashboard** | Legacy operator dashboard |

`Ctrl-C` to stop. Options: `--port 8088`, `--db /tmp/x.db`, `--no-seed`.

## What's real vs. faked

- **Real**: the FastAPI app, every route, every detection/enforcement/kill module,
  the hash-chained audit log, the SQLite stores. Nothing is mocked.
- **Faked**: the *data*. `scripts/demo.sh` seeds it:
  - `demo_seed_v2.py` — 70 agents, ~72k UIS events, drift, policy violations,
    honeytokens, federation, blast-radius sims, MCP inspections (tenant `acme`).
  - `demo_seed_gap.py` — the gap-roadmap features as an **airline-agent-demo**:
    an asset scan (agents/tools/MCP/vulnerabilities), kill-switch planes (IdP +
    MCP credentials + live sessions) for `triage-agent` / `booking-agent` /
    `payment-agent`, governed-retrieval allow-lists, a multi-session campaign,
    MCP gateway enforcements (SIEM feed), and a certificate fleet.
- **Auth**: `DEV_MODE=true` injects a synthetic **ENTERPRISE** tenant (`acme`,
  role `owner`), so all `ent.*` tier-gated features are enabled and no API key is
  needed. The startup guard refuses `DEV_MODE` in any production `ENVIRONMENT`.

## Try the headline flow (the differentiator)

1. Open `/console`. The airline-agent-demo workflow renders as a left→right DAG;
   the header strip shows Agents / Tools / MCP Servers / Vulnerabilities.
2. Click **payment-agent** → the side panel shows a kill preview (all planes
   connected: decision, edge JWT, Okta, Entra, MCP, live sessions).
3. Click **⚡ Rip Credentials** → watch per-plane status chips return `killed`;
   the node flips to a revoked style. **⚡ Cascade Rip** (OWNER) also rips the
   blast-radius reachable agents. **Restore** reverses the reversible planes.
4. Every action is in `/api/audit` (hash-chained).

## Config notes

The launcher points all three DB env vars at one SQLite file so the seeder and
server share state:
`DATA_DB_PATH`, `TOKENDNA_MCP_GATEWAY_DB`, `TOKENDNA_BEHAVIORAL_DB`. It also sets
`TOKENDNA_DEMO=acme` so the running server registers the in-memory demo IdP config
(the kill-switch Okta/Entra planes show connected without real OAuth creds — the
rip is a clean no-op for those two; the other four planes act for real).

## Re-seed without restarting the server process

```bash
DATA_DB_PATH=/tmp/tokendna-demo.db TOKENDNA_MCP_GATEWAY_DB=/tmp/tokendna-demo.db \
TOKENDNA_BEHAVIORAL_DB=/tmp/tokendna-demo.db \
  .venv/bin/python scripts/demo_seed_gap.py --with-base
```
