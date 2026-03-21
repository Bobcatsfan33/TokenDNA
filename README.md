# TokenDNA

**Zero-Trust token integrity and session behavioral analytics**

TokenDNA detects stolen JWT/Bearer tokens in real time by building a behavioral "DNA" fingerprint for each user — device, IP, geolocation, ASN, browser, OS — and flagging anomalies like impossible travel, session branching, Tor/VPN usage, and known-malicious IPs. Every request is scored and responded to adaptively: allow, step-up MFA, block, or auto-revoke.

---

## Architecture

```
Client
  │  Authorization: Bearer <jwt>
  │  DPoP: <dpop-proof>
  ▼
Cloudflare Worker  (edge/index.js)
  ├─ RS256 JWT verification  (JWKS endpoint)
  ├─ JWT revocation check    (KV)
  ├─ Full RFC 9449 DPoP validation
  └─ ML risk pre-check       → auto-revoke if score says so
          │
          ▼ (proxied)
TokenDNA API  (FastAPI / Python)
  ├─ GeoIP lookup            (ip-api or MaxMind)
  ├─ Threat intel            (Tor, datacenter ASN, VPN, AbuseIPDB)
  ├─ DNA fingerprint         (SHA-256 device + IP hash)
  ├─ Adaptive ML model       (per-user Redis profile)
  ├─ Session graph           (impossible travel, branching)
  ├─ Unified scoring         (ALLOW / STEP_UP / BLOCK / REVOKE)
  ├─ Risk-adaptive responses (200 / 202 / 403 / 401)
  └─ Async event logging     → ClickHouse
          │
          ├─ Redis           (baselines, profiles, graph, revocation list, rate limits)
          └─ ClickHouse      (immutable event log, 90-day TTL)
```

---

## Risk Tiers

| Tier | HTTP | Meaning | Action |
|------|------|---------|--------|
| ALLOW | 200 | Normal session | Pass through |
| STEP_UP | 202 | Elevated risk | Dispatch MFA challenge |
| BLOCK | 403 | High risk | Reject + alert |
| REVOKE | 401 | Critical risk | Revoke token + alert |

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — set OIDC_ISSUER, OIDC_AUDIENCE, and any webhook URLs

# 2. Start full stack
docker compose up -d

# 3. Check health
curl http://localhost:8000/
```

For local development without an OIDC provider:
```bash
DEV_MODE=true docker compose up -d
# All JWT verification is bypassed; a synthetic dev-user payload is used
```

---

## Configuration

All settings are read from environment variables (see `.env.example`).

| Variable | Default | Description |
|----------|---------|-------------|
| `DEV_MODE` | `false` | Disable JWT verification (dev only) |
| `OIDC_ISSUER` | — | OIDC provider base URL |
| `OIDC_AUDIENCE` | — | Expected `aud` claim in JWTs |
| `REDIS_HOST` | `redis` | Redis hostname |
| `CLICKHOUSE_HOST` | `clickhouse` | ClickHouse hostname |
| `GEOIP_PROVIDER` | `ip-api` | `ip-api` or `maxmind` |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB lookup key (optional) |
| `SCORE_THRESHOLD_ALLOW` | `70` | Score above → ALLOW |
| `SCORE_THRESHOLD_STEP_UP` | `50` | Score above → STEP_UP |
| `SCORE_THRESHOLD_BLOCK` | `30` | Score above → BLOCK |
| `SCORE_THRESHOLD_REVOKE` | `15` | Score at/below → REVOKE |
| `IMPOSSIBLE_TRAVEL_SPEED_KMH` | `900` | km/h threshold |
| `BRANCHING_THRESHOLD` | `3` | Distinct devices before flagging |
| `SIEM_WEBHOOK_URL` | — | HTTPS webhook for SIEM events |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook |

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | None | Health check |
| `GET` | `/secure` | Bearer JWT | Main integrity check |
| `GET` | `/profile/{uid}` | Bearer JWT | Inspect user profile |
| `DELETE` | `/profile/{uid}` | Bearer JWT | Reset user profile |
| `POST` | `/revoke` | Bearer JWT | Manually revoke token by jti |

---

## Cloudflare Edge Worker

The edge worker (`edge/`) runs at the CDN layer and handles DPoP proof-of-possession (RFC 9449) before any request reaches the backend.

```bash
cd edge
npm install -g wrangler
wrangler login

# Create KV namespace
wrangler kv:namespace create TOKEN_CACHE

# Set secrets (never in wrangler.toml)
wrangler secret put JWKS_URL
wrangler secret put BACKEND_API

# Deploy
wrangler deploy
```

Edit `edge/wrangler.toml` to replace placeholder KV namespace IDs and domain routes.

---

## ML Scoring Model

Each user has a Redis-backed profile of their known behavioral characteristics. The ML scorer computes a 0–100 match score against that profile:

| Signal | Weight |
|--------|--------|
| Device fingerprint | 30 pts |
| Country match | 25 pts |
| IP match | 15 pts |
| ASN match | 15 pts |
| OS family | 5 pts |
| Browser family | 5 pts |
| Mobile/desktop flip | 5 pts |

Penalties are then applied for threat signals (Tor exit = −40, impossible travel = −50, etc.) to produce the final score.

---

## Event Schema (ClickHouse)

All session events are stored in `tokendna.sessions` with a 90-day TTL:

```sql
SELECT user_id, country, tier, final_score, is_tor, impossible_travel, timestamp
FROM tokendna.sessions
WHERE user_id = 'abc123'
ORDER BY timestamp DESC
LIMIT 20;
```
