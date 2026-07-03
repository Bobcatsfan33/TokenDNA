"""
TokenDNA — Central configuration loaded from environment variables.
Copy .env.example to .env and fill in values before running.
"""

import os
import sys
from dotenv import load_dotenv

if not any("pytest" in arg for arg in sys.argv):
    load_dotenv()

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
REDIS_TLS: bool = os.getenv("REDIS_TLS", "false").lower() == "true"
REDIS_BASELINE_TTL: int = int(os.getenv("REDIS_BASELINE_TTL", "86400"))   # 24h
REDIS_GEO_TTL: int = int(os.getenv("REDIS_GEO_TTL", "3600"))              # 1h
REDIS_PROFILE_TTL: int = int(os.getenv("REDIS_PROFILE_TTL", "604800"))    # 7d
REDIS_TIMEOUT: int = int(os.getenv("REDIS_TIMEOUT", "2"))

# ── ClickHouse ────────────────────────────────────────────────────────────────
CLICKHOUSE_HOST: str = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT: int = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER: str = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD: str = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DB: str = os.getenv("CLICKHOUSE_DB", "tokendna")
CLICKHOUSE_SECURE: bool = os.getenv("CLICKHOUSE_SECURE", "false").lower() == "true"

# ── Auth / OIDC ───────────────────────────────────────────────────────────────
OIDC_ISSUER: str = os.getenv("OIDC_ISSUER", "")
OIDC_AUDIENCE: str = os.getenv("OIDC_AUDIENCE", "tokendna")
DEV_MODE: bool = os.getenv("DEV_MODE", "false").lower() == "true"

# ── GeoIP ─────────────────────────────────────────────────────────────────────
# ip-api.com (free, no key required for non-commercial use)
# Set GEOIP_PROVIDER=maxmind and MAXMIND_DB_PATH to use offline MaxMind GeoLite2
GEOIP_PROVIDER: str = os.getenv("GEOIP_PROVIDER", "ipapi")  # ipapi | maxmind
MAXMIND_DB_PATH: str = os.getenv("MAXMIND_DB_PATH", "/etc/geoip/GeoLite2-City.mmdb")
GEOIP_TIMEOUT: int = int(os.getenv("GEOIP_TIMEOUT", "3"))

# ── Threat Intelligence ───────────────────────────────────────────────────────
# AbuseIPDB (optional — get free key at abuseipdb.com)
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_MIN_CONFIDENCE: int = int(os.getenv("ABUSEIPDB_MIN_CONFIDENCE", "50"))

# Tor exit node list refresh interval (seconds)
TOR_REFRESH_INTERVAL: int = int(os.getenv("TOR_REFRESH_INTERVAL", "3600"))

# ── Scoring & Risk ────────────────────────────────────────────────────────────
# Risk tier thresholds (0–100 scale)
SCORE_ALLOW_THRESHOLD: int = int(os.getenv("SCORE_ALLOW_THRESHOLD", "70"))
SCORE_STEPUP_THRESHOLD: int = int(os.getenv("SCORE_STEPUP_THRESHOLD", "50"))
SCORE_BLOCK_THRESHOLD: int = int(os.getenv("SCORE_BLOCK_THRESHOLD", "30"))
# Below SCORE_BLOCK_THRESHOLD → block. Below 30 → also revoke token.
SCORE_REVOKE_THRESHOLD: int = int(os.getenv("SCORE_REVOKE_THRESHOLD", "15"))

# Impossible travel: max speed in km/h before flagging (commercial aircraft ~900 km/h)
MAX_TRAVEL_SPEED_KMH: float = float(os.getenv("MAX_TRAVEL_SPEED_KMH", "900"))

# Session branching: max distinct devices before flagging
BRANCHING_DEVICE_THRESHOLD: int = int(os.getenv("BRANCHING_DEVICE_THRESHOLD", "3"))

# ── Alerting ──────────────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
SIEM_WEBHOOK_URL: str = os.getenv("SIEM_WEBHOOK_URL", "")
SIEM_WEBHOOK_SECRET: str = os.getenv("SIEM_WEBHOOK_SECRET", "")  # HMAC signing key

# Step-up MFA webhook — POST here to trigger an MFA challenge for a user
MFA_CHALLENGE_URL: str = os.getenv("MFA_CHALLENGE_URL", "")

# Token revocation endpoint — POST here to revoke a token
TOKEN_REVOKE_URL: str = os.getenv("TOKEN_REVOKE_URL", "")
TOKEN_REVOKE_SECRET: str = os.getenv("TOKEN_REVOKE_SECRET", "")

# ── Rate Limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_BURST: int = int(os.getenv("RATE_LIMIT_BURST", "10"))
# Stricter limit for open (unauthenticated) endpoints — no tenant context
RATE_LIMIT_OPEN_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_OPEN_PER_MINUTE", "30"))
# ── Production Safety Guard ────────────────────────────────────────────────────
# IL5 / FedRAMP: DEV_MODE must NEVER be active in production.
# DEV_MODE bypasses ALL authentication, so this guard is DENY-BY-DEFAULT:
# DEV_MODE=true is permitted ONLY when the resolved environment is explicitly
# one of the known development contexts. An unset/unknown environment with
# DEV_MODE=true is treated as unsafe and terminates the process.
#
# Environment resolution mirrors the rest of the codebase (secret_gate.py,
# mtls.py, tenants/middleware.py), which key off TOKENDNA_ENV first, then
# ENVIRONMENT. The prior guard read only ENVIRONMENT, so
# `TOKENDNA_ENV=production DEV_MODE=true` booted with auth bypassed.
_ENVIRONMENT = (os.getenv("TOKENDNA_ENV") or os.getenv("ENVIRONMENT") or "").strip().lower()
_DEV_ENVIRONMENTS = {"dev", "development", "test", "testing", "local", "ci"}

if DEV_MODE and _ENVIRONMENT not in _DEV_ENVIRONMENTS:
    # SystemExit prints the message to stderr and exits with status 1.
    raise SystemExit(
        f"FATAL: DEV_MODE=true is set but the resolved environment is "
        f"{_ENVIRONMENT!r} (from TOKENDNA_ENV/ENVIRONMENT), which is not a "
        f"recognized development context {sorted(_DEV_ENVIRONMENTS)}. "
        "DEV_MODE bypasses all authentication and is prohibited outside "
        "development. Unset DEV_MODE, or set TOKENDNA_ENV/ENVIRONMENT to a "
        "development value to proceed."
    )
