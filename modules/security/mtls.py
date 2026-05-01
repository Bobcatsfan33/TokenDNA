"""
TokenDNA — internal mTLS configuration helpers.

Centralises the path-resolution + validation logic so every service-to-service
client (Redis, ClickHouse, Postgres) and the FastAPI server itself derive
their TLS material from the same env-var contract:

    TLS_CA_CERT_PATH        Trusted root CA (also used for client verification)
    TLS_API_CERT_PATH       Server certificate for the FastAPI process
    TLS_API_KEY_PATH        Matching private key
    TLS_REDIS_CERT_PATH     Client cert presented to Redis
    TLS_REDIS_KEY_PATH      Matching private key
    TLS_CLICKHOUSE_CERT_PATH/KEY_PATH    Same for ClickHouse
    TLS_POSTGRES_CERT_PATH/KEY_PATH      Same for Postgres

Provisioned by scripts/issue_internal_certs.sh; rotated by re-running with
``--renew --service <name>``. The helpers here are read-only — they never
write to disk.

Design choices:
  * Fail-closed in production:  when TOKENDNA_ENV ∈ {production, il5, il6}
    and any expected file is missing, ``MTLSConfig.load_or_raise`` raises
    ``MTLSConfigError`` so the process refuses to start.
  * Fail-soft in dev:  missing files yield a config object with
    ``is_active=False`` so the dev `docker compose up` flow still works.
  * No mutation of process state at import time — call ``load_or_raise``
    explicitly from your service entry point.
"""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


_PROD_ENVS = frozenset({"production", "prod", "il4", "il5", "il6"})


class MTLSConfigError(Exception):
    """Raised when required mTLS material is missing in a non-dev environment."""


@dataclass(frozen=True)
class MTLSPair:
    """A cert + key pair on disk."""
    cert_path: Path
    key_path: Path

    @property
    def exists(self) -> bool:
        return self.cert_path.is_file() and self.key_path.is_file()


@dataclass(frozen=True)
class MTLSConfig:
    """Resolved mTLS file paths for the current process."""
    ca_cert: Optional[Path]
    api: Optional[MTLSPair]
    redis: Optional[MTLSPair]
    clickhouse: Optional[MTLSPair]
    postgres: Optional[MTLSPair]
    environment: str

    @property
    def is_active(self) -> bool:
        """True when at least the CA + the API server pair are loadable."""
        return bool(self.ca_cert and self.ca_cert.is_file() and self.api and self.api.exists)

    # ── Convenience accessors ────────────────────────────────────────────
    def uvicorn_kwargs(self) -> dict[str, object]:
        """
        Returns the dict to splat into ``uvicorn.run(..., **kwargs)``.
        Empty dict if API TLS isn't configured (the server runs plain HTTP).
        """
        if not (self.api and self.api.exists):
            return {}
        kwargs: dict[str, object] = {
            "ssl_certfile": str(self.api.cert_path),
            "ssl_keyfile": str(self.api.key_path),
        }
        if self.ca_cert and self.ca_cert.is_file():
            kwargs["ssl_ca_certs"] = str(self.ca_cert)
            kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED  # mTLS — clients must present a cert
        return kwargs

    def redis_kwargs(self) -> dict[str, object]:
        """Dict to merge into ``redis.Redis(...)`` constructor kwargs."""
        if not self.is_active:
            return {}
        out: dict[str, object] = {"ssl": True}
        if self.ca_cert:
            out["ssl_ca_certs"] = str(self.ca_cert)
        if self.redis and self.redis.exists:
            out["ssl_certfile"] = str(self.redis.cert_path)
            out["ssl_keyfile"] = str(self.redis.key_path)
            out["ssl_cert_reqs"] = "required"
        return out

    def clickhouse_kwargs(self) -> dict[str, object]:
        """Dict for ``clickhouse_connect.get_client(...)``."""
        if not self.is_active:
            return {}
        out: dict[str, object] = {"secure": True}
        if self.ca_cert:
            out["ca_cert"] = str(self.ca_cert)
        if self.clickhouse and self.clickhouse.exists:
            out["client_cert"] = str(self.clickhouse.cert_path)
            out["client_cert_key"] = str(self.clickhouse.key_path)
        return out

    def postgres_dsn_params(self) -> dict[str, str]:
        """Extra connection params for libpq / psycopg."""
        if not self.is_active:
            return {}
        out: dict[str, str] = {"sslmode": "verify-full"}
        if self.ca_cert:
            out["sslrootcert"] = str(self.ca_cert)
        if self.postgres and self.postgres.exists:
            out["sslcert"] = str(self.postgres.cert_path)
            out["sslkey"] = str(self.postgres.key_path)
        return out


def _maybe_path(env_var: str) -> Optional[Path]:
    raw = os.getenv(env_var, "").strip()
    return Path(raw) if raw else None


def _maybe_pair(cert_var: str, key_var: str) -> Optional[MTLSPair]:
    cert = _maybe_path(cert_var)
    key = _maybe_path(key_var)
    if cert and key:
        return MTLSPair(cert_path=cert, key_path=key)
    return None


def load(environment: Optional[str] = None) -> MTLSConfig:
    """
    Best-effort load. Returns whatever's resolvable from env; missing pieces
    appear as ``None``. Use ``load_or_raise`` for production startup.
    """
    env = (environment or os.getenv("TOKENDNA_ENV") or os.getenv("ENVIRONMENT") or "dev").lower()
    return MTLSConfig(
        ca_cert=_maybe_path("TLS_CA_CERT_PATH"),
        api=_maybe_pair("TLS_API_CERT_PATH", "TLS_API_KEY_PATH"),
        redis=_maybe_pair("TLS_REDIS_CERT_PATH", "TLS_REDIS_KEY_PATH"),
        clickhouse=_maybe_pair("TLS_CLICKHOUSE_CERT_PATH", "TLS_CLICKHOUSE_KEY_PATH"),
        postgres=_maybe_pair("TLS_POSTGRES_CERT_PATH", "TLS_POSTGRES_KEY_PATH"),
        environment=env,
    )


def load_or_raise(environment: Optional[str] = None) -> MTLSConfig:
    """
    Production-grade loader. Raises ``MTLSConfigError`` if the resolved
    config is incomplete in a production-class environment.
    """
    cfg = load(environment)
    if cfg.environment not in _PROD_ENVS:
        if not cfg.is_active:
            logger.info(
                "mTLS not configured (env=%s); services will use plain TCP "
                "(set TLS_CA_CERT_PATH + TLS_API_CERT_PATH + TLS_API_KEY_PATH "
                "to enable).", cfg.environment,
            )
        return cfg

    missing: list[str] = []
    if not (cfg.ca_cert and cfg.ca_cert.is_file()):
        missing.append("TLS_CA_CERT_PATH")
    if not (cfg.api and cfg.api.exists):
        missing.append("TLS_API_CERT_PATH/TLS_API_KEY_PATH")
    if missing:
        raise MTLSConfigError(
            f"mTLS material missing for env={cfg.environment}: "
            f"{', '.join(missing)}. Run scripts/issue_internal_certs.sh."
        )
    logger.info("mTLS active (env=%s, ca=%s)", cfg.environment, cfg.ca_cert)
    return cfg
