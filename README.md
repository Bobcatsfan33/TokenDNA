# TokenDNA · Aegis Security

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![CI](https://github.com/Bobcatsfan33/TokenDNA/actions/workflows/ci.yml/badge.svg)](https://github.com/Bobcatsfan33/TokenDNA/actions/workflows/ci.yml)
[![Security: FedRAMP-aligned](https://img.shields.io/badge/Security-FedRAMP%20High%20%7C%20IL6%20aligned-red)](SECURITY.md)
[![PRs: owner approval required](https://img.shields.io/badge/PRs-owner%20approval%20required-yellow)](CONTRIBUTING.md)

> **v2.2.0** — Security hardening release: RBAC, immutable audit log, security headers middleware, HMAC-SHA256 IP fingerprinting, secrets manager backend, CIS Docker hardening.

**Zero-Trust token integrity and session behavioral analytics.**

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

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/` | None | Health check |
| `GET` | `/secure` | READONLY+ | Main integrity check — validate token DNA |
| `GET` | `/profile/{uid}` | ANALYST+ | Inspect user behavioral profile |
| `DELETE` | `/profile/{uid}` | ANALYST+ | Reset user profile baseline |
| `POST` | `/revoke` | ANALYST+ | Manually revoke token by `jti` |
| `GET` | `/api/sessions` | ANALYST+ | Active session risk profiles |
| `GET` | `/api/cloud-findings` | ANALYST+ | Cloud scan findings with severity summary |
| `GET` | `/api/audit` | OWNER only | Tail the immutable audit log |
| `GET` | `/admin/tenants` | ADMIN+ | List tenants |
| `POST` | `/admin/tenants` | OWNER only | Create a new tenant |
| `GET` | `/docs` | Dev only | Swagger UI (disabled in production) |

---

## OSS Schema & SDK Onboarding

TokenDNA now publishes machine-readable identity artifacts to speed ecosystem adoption:

- `GET /api/schema/bundle` — consolidated UIS + attestation schema bundle.
- `GET /api/schema/uis.json` — UIS JSON schema artifact.
- `GET /api/schema/attestation.json` — attestation JSON schema artifact.
- `GET /api/schema/artifacts` — catalog of all schema artifacts.
- `GET /api/schema/artifacts/{name}` — fetch a specific artifact by name.
- `POST /api/schema/publish` — generate and return publish-ready schema artifacts.

Wrapper endpoints for SDK-style integrations:

- `POST /api/oss/sdk/normalize` — request/response wrapped UIS normalization.
- `POST /api/oss/sdk/attest` — request/response wrapped attestation creation.

These wrappers intentionally return stable metadata fields (`sdk_version`,
`schema_version`, `generated_at`) so third-party SDKs can map them directly.

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

---

## Security & Compliance

TokenDNA is built toward **FedRAMP High** and **DoD IL6** alignment. Key controls in v2.2.0:

| Control Family | Implementation |
|---|---|
| **AU-2 / AU-3 / AU-9** — Audit | Immutable hash-chained JSONL audit log; HMAC-SHA256 tamper detection; `os.fsync()` write hardening |
| **AC-3 / AC-6** — Access Control | 4-tier RBAC (OWNER / ADMIN / ANALYST / READONLY); `require_role()` FastAPI dependency |
| **SC-8 / SC-28** — Transmission / Data | HMAC-SHA256 IP/UA fingerprinting prevents rainbow-table reversal; HSTS + full security headers middleware |
| **IA-5** — Credential Management | AWS Secrets Manager and HashiCorp Vault backend; FIPS 140-2 endpoint support |
| **CM-7** — Least Functionality | CIS Docker Benchmark hardening; seccomp syscall allowlist; non-root container user (UID 10001) |
| **SI-2** — Flaw Remediation | GitHub Actions CI: CodeQL, pip-audit, TruffleHog, Trivy on every PR; Dependabot weekly scans |
| **SC-5** — Denial of Service Protection | Per-tenant rate limiting via Redis; 1MB body size hard limit; header size enforcement |

Open gaps being tracked toward full accreditation: mTLS service mesh, database encryption at rest, CAC/PIV authentication, full ABAC. See [SECURITY.md](SECURITY.md) for the complete posture.

---

## Contributing

All community contributions are welcome. Every PR must be approved by the repository owner before merge. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the security checklist and responsible disclosure process.

---

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](LICENSE).
Free for non-competing use; converts to Apache 2.0 four years from first public release.
