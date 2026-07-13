"""
TokenDNA -- IdP adapter helpers for common identity provider event formats.
"""

from __future__ import annotations

from typing import Any


def from_okta_system_log(event: dict[str, Any]) -> dict[str, Any]:
    actor = event.get("actor", {}) or {}
    client = event.get("client", {}) or {}
    outcome = event.get("outcome", {}) or {}
    transaction = event.get("transaction", {}) or {}
    security_context = event.get("securityContext", {}) or {}
    return {
        "sub": actor.get("id") or actor.get("alternateId"),
        "name": actor.get("displayName"),
        "iss": "okta",
        "aud": "tokendna",
        "jti": transaction.get("id"),
        "scope": [],
        "token_type": "event",
        "auth_method": "idp-event",
        "amr": [],
        "mfa": outcome.get("result") == "SUCCESS",
        "entity_type": "human",
        "event_type": event.get("eventType"),
        "client_ip": client.get("ipAddress"),
        "user_agent": client.get("userAgent", {}).get("rawUserAgent"),
        "country": security_context.get("asOrg"),
    }


def from_entra_signin_log(event: dict[str, Any]) -> dict[str, Any]:
    device = event.get("deviceDetail", {}) or {}
    location = event.get("location", {}) or {}
    auth = event.get("authenticationDetails", []) or []
    return {
        "sub": event.get("userId") or event.get("userPrincipalName"),
        "name": event.get("userDisplayName") or event.get("userPrincipalName"),
        "iss": "entra",
        "aud": "tokendna",
        "jti": event.get("id"),
        "scope": [],
        "token_type": "event",
        "auth_method": "idp-event",
        "amr": [item.get("authenticationMethod") for item in auth if item.get("authenticationMethod")],
        "mfa": bool(event.get("mfaDetail")),
        "entity_type": "human",
        "event_type": "signin",
        "client_ip": event.get("ipAddress"),
        "user_agent": device.get("operatingSystem"),
        "country": location.get("countryOrRegion"),
    }


def adapt_idp_event(provider: str, event: dict[str, Any]) -> dict[str, Any]:
    p = (provider or "").lower()
    if p in {"okta", "okta_system_log"}:
        return from_okta_system_log(event)
    if p in {"entra", "azuread", "microsoft_entra"}:
        return from_entra_signin_log(event)
    return event

