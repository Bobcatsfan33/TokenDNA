"""IdP OAuth revocation connectors for the kill switch (Gap roadmap, Epic 2.1b).

Severing external app access is what actually stops a rogue agent — the agent's
OAuth/refresh tokens at the IdP outlive any internal block. These connectors
plug into ``revocation_bus`` and, on kill:

  * Okta   — RFC 7009 token revocation + deactivate the service account/app.
  * Entra  — Microsoft Graph revokeSignInSessions + disable the account.

Config is per-tenant (wired from your secret manager via ``set_idp_config``).
HTTP is injectable (``http=`` transport) so tests run with no network. Without
config for a tenant, ``is_connected()`` is False and the bus marks the plane
``not_connected`` (skipped) — never a hard failure.

An ``IdPConfig`` maps the TokenDNA agent_id to the provider's principal id and,
optionally, the live token ids to revoke.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from modules.identity import revocation_bus

logger = logging.getLogger(__name__)

# http transport signature: (method, url, headers, body) -> (status_code, text)
HttpFn = Callable[[str, str, dict[str, str], Optional[bytes]], "tuple[int, str]"]


def _default_http(method: str, url: str, headers: dict[str, str],
                  body: Optional[bytes]) -> "tuple[int, str]":
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


@dataclass
class IdPConfig:
    provider: str                       # "okta" | "entra"
    base_url: str                       # https://acme.okta.com or https://graph.microsoft.com/v1.0
    api_token: str                      # bearer for the management API
    # agent_id -> {"principal_id": str (okta user/app id or entra object id),
    #              "tokens": [str] (optional token ids / jti to revoke),
    #              "client_id": str, "client_secret": str (okta RFC 7009 auth)}
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)


# Per-tenant config store (ops wires this from secrets; tests set it directly).
_configs: dict[tuple[str, str], IdPConfig] = {}


def set_idp_config(tenant_id: str, config: IdPConfig) -> None:
    _configs[(tenant_id, config.provider)] = config


def clear_idp_configs() -> None:
    _configs.clear()


def get_idp_config(tenant_id: str, provider: str) -> Optional[IdPConfig]:
    return _configs.get((tenant_id, provider))


# ── Base connector ────────────────────────────────────────────────────────────

class _IdPConnector:
    provider = ""
    plane = ""
    reversible = False  # revoked tokens are dead; the agent must re-auth

    def __init__(self, http: Optional[HttpFn] = None):
        self._http = http or _default_http

    def is_connected(self, tenant_id: str) -> bool:
        return get_idp_config(tenant_id, self.provider) is not None

    def _agent(self, tenant_id: str, agent_id: str) -> tuple[IdPConfig, dict[str, Any]]:
        cfg = get_idp_config(tenant_id, self.provider)
        if cfg is None:
            raise RuntimeError(f"{self.provider} not configured for tenant")
        return cfg, cfg.agents.get(agent_id, {})

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        return f"{self.provider} OAuth revocation is irreversible — agent must re-authenticate"


class OktaConnector(_IdPConnector):
    provider = "okta"
    plane = "idp_okta"

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        cfg, agent = self._agent(tenant_id, agent_id)
        actions: list[str] = []

        # 1) RFC 7009 token revocation for each known token.
        tokens = list(agent.get("tokens") or [])
        client_id = agent.get("client_id", "")
        client_secret = agent.get("client_secret", "")
        for tok in tokens:
            form = f"token={tok}&token_type_hint=access_token&client_id={client_id}&client_secret={client_secret}"
            status, _ = self._http(
                "POST", f"{cfg.base_url}/oauth2/v1/revoke",
                {"Content-Type": "application/x-www-form-urlencoded"},
                form.encode("utf-8"),
            )
            if status >= 400:
                raise RuntimeError(f"okta token revoke failed (HTTP {status})")
            actions.append("token revoked")

        # 2) Deactivate the service account / app principal (kills future auth).
        principal = agent.get("principal_id")
        if principal:
            status, _ = self._http(
                "POST", f"{cfg.base_url}/api/v1/users/{principal}/lifecycle/deactivate",
                {"Authorization": f"SSWS {cfg.api_token}", "Accept": "application/json"},
                None,
            )
            if status >= 400:
                raise RuntimeError(f"okta deactivate failed (HTTP {status})")
            actions.append("principal deactivated")

        if not actions:
            return "okta connected but no tokens/principal mapped for agent"
        return "okta: " + ", ".join(actions)


class EntraConnector(_IdPConnector):
    provider = "entra"
    plane = "idp_entra"

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        cfg, agent = self._agent(tenant_id, agent_id)
        principal = agent.get("principal_id")
        if not principal:
            return "entra connected but no principal mapped for agent"
        hdr = {"Authorization": f"Bearer {cfg.api_token}", "Content-Type": "application/json"}
        actions: list[str] = []

        # 1) Revoke all refresh tokens / active sessions.
        status, _ = self._http(
            "POST", f"{cfg.base_url}/users/{principal}/revokeSignInSessions", hdr, b"{}",
        )
        if status >= 400:
            raise RuntimeError(f"entra revokeSignInSessions failed (HTTP {status})")
        actions.append("sign-in sessions revoked")

        # 2) Disable the account so it cannot re-acquire tokens.
        status, _ = self._http(
            "PATCH", f"{cfg.base_url}/users/{principal}", hdr,
            json.dumps({"accountEnabled": False}).encode("utf-8"),
        )
        if status >= 400:
            raise RuntimeError(f"entra disable account failed (HTTP {status})")
        actions.append("account disabled")
        return "entra: " + ", ".join(actions)


# Self-register so the planes appear (gated by is_connected) after reset.
revocation_bus.register_default_factory(OktaConnector)
revocation_bus.register_default_factory(EntraConnector)
