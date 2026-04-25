"""SDK-wide configuration — reads env vars, exposes a setter."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any


_lock = threading.Lock()


@dataclass(frozen=True)
class SdkConfig:
    api_base: str = ""
    api_key: str = ""
    tenant_id: str = ""
    timeout_seconds: float = 5.0
    offline_buffer_path: str = ""    # empty => in-memory only
    enabled: bool = True

    def is_online(self) -> bool:
        return bool(self.api_base) and self.enabled

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_base": self.api_base,
            "tenant_id": self.tenant_id,
            "timeout_seconds": self.timeout_seconds,
            "offline_buffer_path": self.offline_buffer_path,
            "enabled": self.enabled,
            # Never echo the key in to_dict — debug logs would catch it.
        }


def _from_env() -> SdkConfig:
    return SdkConfig(
        api_base=os.getenv("TOKENDNA_API_BASE", "").rstrip("/"),
        api_key=os.getenv("TOKENDNA_API_KEY", ""),
        tenant_id=os.getenv("TOKENDNA_TENANT_ID", ""),
        timeout_seconds=float(os.getenv("TOKENDNA_TIMEOUT_SECONDS", "5.0") or "5.0"),
        offline_buffer_path=os.getenv("TOKENDNA_OFFLINE_BUFFER", ""),
        enabled=os.getenv("TOKENDNA_ENABLED", "true").lower() != "false",
    )


_active: SdkConfig | None = None


def configure(
    *,
    api_base: str | None = None,
    api_key: str | None = None,
    tenant_id: str | None = None,
    timeout_seconds: float | None = None,
    offline_buffer_path: str | None = None,
    enabled: bool | None = None,
) -> SdkConfig:
    """Set or update the active config. Any field left as ``None`` is
    inherited from the existing active config (or from env on first call)."""
    global _active
    with _lock:
        base = _active if _active is not None else _from_env()
        new = SdkConfig(
            api_base=(api_base if api_base is not None else base.api_base).rstrip("/"),
            api_key=api_key if api_key is not None else base.api_key,
            tenant_id=tenant_id if tenant_id is not None else base.tenant_id,
            timeout_seconds=(
                float(timeout_seconds) if timeout_seconds is not None
                else base.timeout_seconds
            ),
            offline_buffer_path=(
                offline_buffer_path if offline_buffer_path is not None
                else base.offline_buffer_path
            ),
            enabled=enabled if enabled is not None else base.enabled,
        )
        _active = new
        return new


def current_config() -> SdkConfig:
    global _active
    with _lock:
        if _active is None:
            _active = _from_env()
        return _active


def reset_config() -> None:
    """Reset to env-derived defaults. Primarily for tests."""
    global _active
    with _lock:
        _active = _from_env()
