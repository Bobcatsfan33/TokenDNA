"""
SDK-wide configuration — reads env vars, exposes a setter.

Env var precedence (first non-empty wins for each field):

* ``TOKENDNA_URL``       — preferred (v0.2+)
* ``TOKENDNA_API_BASE``  — legacy alias (v0.1.x), still respected

That ordering matters: ``TOKENDNA_URL`` is the documented name, but
shipping users may already have ``TOKENDNA_API_BASE`` in their .env so
we keep it working. If both are set, ``TOKENDNA_URL`` wins.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
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
    local_root: str = ""             # empty => ~/.tokendna

    def is_online(self) -> bool:
        return bool(self.api_base) and self.enabled

    def is_local(self) -> bool:
        """True when no remote endpoint is configured. The SDK is still
        usable — it just records to a local JSONL via
        :class:`tokendna_sdk.local.TokenDNALocalClient`."""
        return not bool(self.api_base)

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_base": self.api_base,
            "tenant_id": self.tenant_id,
            "timeout_seconds": self.timeout_seconds,
            "offline_buffer_path": self.offline_buffer_path,
            "enabled": self.enabled,
            "local_root": self.local_root,
            "mode": "remote" if self.is_online() else "local",
            # Never echo the key in to_dict — debug logs would catch it.
        }


def _first_env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n, "")
        if v:
            return v
    return default


def _from_env() -> SdkConfig:
    return SdkConfig(
        api_base=_first_env("TOKENDNA_URL", "TOKENDNA_API_BASE").rstrip("/"),
        api_key=_first_env("TOKENDNA_API_KEY"),
        tenant_id=_first_env("TOKENDNA_TENANT_ID"),
        timeout_seconds=float(_first_env("TOKENDNA_TIMEOUT_SECONDS",
                                         default="5.0") or "5.0"),
        offline_buffer_path=_first_env("TOKENDNA_OFFLINE_BUFFER"),
        enabled=_first_env("TOKENDNA_ENABLED", default="true").lower() != "false",
        local_root=_first_env("TOKENDNA_LOCAL_ROOT"),
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
    local_root: str | None = None,
    url: str | None = None,        # alias for api_base
) -> SdkConfig:
    """Set or update the active config. Any field left as ``None`` is
    inherited from the existing active config (or from env on first call).

    ``url`` is accepted as a friendlier alias for ``api_base``.
    """
    global _active
    with _lock:
        base = _active if _active is not None else _from_env()
        effective_base = url if url is not None else api_base
        new = SdkConfig(
            api_base=(effective_base if effective_base is not None
                      else base.api_base).rstrip("/"),
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
            local_root=local_root if local_root is not None else base.local_root,
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
