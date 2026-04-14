"""
TokenDNA -- Shared database backend helpers.

Provides a lightweight abstraction for selecting SQLite (default) or PostgreSQL
stores and optional dual-write behavior for migration rollouts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BackendConfig:
    backend: str
    dual_write: bool
    postgres_dsn: str | None


def get_backend_config() -> BackendConfig:
    backend = str(os.getenv("TOKENDNA_DB_BACKEND", "sqlite")).strip().lower()
    if backend not in {"sqlite", "postgres"}:
        backend = "sqlite"
    dual_raw = str(os.getenv("TOKENDNA_DB_DUAL_WRITE", "false")).strip().lower()
    dual_write = dual_raw in {"1", "true", "yes", "on"}
    dsn = str(os.getenv("TOKENDNA_PG_DSN", "")).strip() or None
    return BackendConfig(backend=backend, dual_write=dual_write, postgres_dsn=dsn)


def should_use_postgres() -> bool:
    cfg = get_backend_config()
    return cfg.backend == "postgres" and bool(cfg.postgres_dsn)


def should_dual_write() -> bool:
    cfg = get_backend_config()
    return cfg.dual_write and bool(cfg.postgres_dsn)


def _safe_json(value: Any) -> str:
    try:
        import json

        return json.dumps(value)
    except Exception:
        return "{}"


def record_backend_fallback(reason: str, *, context: dict[str, Any] | None = None) -> None:
    """
    Emit a warning about backend fallback.

    We intentionally avoid hard dependency on the audit module to keep this
    helper import-safe for early startup paths.
    """

    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event

        log_event(
            AuditEventType.CONFIG_CHANGED,
            AuditOutcome.UNKNOWN,
            tenant_id="_global_",
            subject="db-backend",
            resource="storage.backend",
            detail={
                "reason": reason,
                "context": context or {},
                "backend_config": _safe_json(get_backend_config().__dict__),
            },
        )
    except Exception:
        # Fallback path should never fail caller execution.
        pass
