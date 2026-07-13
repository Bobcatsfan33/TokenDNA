"""
TokenDNA — Sentry error reporting (optional).

Activates only when ``SENTRY_DSN`` is set and the ``sentry-sdk`` package is
installed; otherwise this is a no-op so tests and dev environments do not
need the dependency.

Configuration (env vars):

* ``SENTRY_DSN`` — Sentry project DSN. Required to enable.
* ``SENTRY_ENVIRONMENT`` — defaults to ``ENVIRONMENT`` or ``dev``.
* ``SENTRY_TRACES_SAMPLE_RATE`` — float ``[0,1]``, default ``0.1``.
* ``SENTRY_RELEASE`` — defaults to ``APP_VERSION`` or ``dev``.

PII / secret hygiene
--------------------
The integration registers a ``before_send`` hook that scrubs:

* All HTTP headers named like ``authorization``, ``cookie``, ``x-api-key``.
* All known TokenDNA secret env names (delegation, workflow, honeypot,
  posture, attestation CA, audit HMAC, DNA HMAC).
* Any string that pattern-matches an obvious bearer token shape.

The hook never sees raw bodies because we configure ``send_default_pii=False``.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger("tokendna.errors")

_INITIALIZED = False

# Headers and env-var-style keys that must never leave the host.
_REDACT_KEYS: frozenset[str] = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key",
    "tokendna_delegation_secret", "tokendna_workflow_secret",
    "tokendna_honeypot_secret", "tokendna_posture_secret",
    "attestation_ca_secret", "attestation_ca_private_key_pem",
    "audit_hmac_key", "dna_hmac_key", "vault_token",
    "redis_password", "clickhouse_password", "postgres_password",
    "github_token", "aws_secret_access_key",
})

_BEARER_PATTERN = re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE)


def is_enabled() -> bool:
    return _INITIALIZED


def init_error_reporting() -> bool:
    """Initialize Sentry. Returns ``True`` when active, ``False`` otherwise."""
    global _INITIALIZED

    dsn = os.getenv("SENTRY_DSN", "").strip()
    if not dsn:
        return False

    try:
        import sentry_sdk  # type: ignore[import-not-found]
    except Exception as exc:
        logger.warning("sentry-sdk not installed; error reporting disabled (%s)", exc)
        return False

    sentry_sdk.init(
        dsn=dsn,
        environment=os.getenv("SENTRY_ENVIRONMENT", os.getenv("ENVIRONMENT", "dev")),
        release=os.getenv("SENTRY_RELEASE", os.getenv("APP_VERSION", "dev")),
        traces_sample_rate=_safe_float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1"), default=0.1),
        send_default_pii=False,
        max_breadcrumbs=20,
        before_send=_before_send,
    )
    _INITIALIZED = True
    logger.info("Sentry error reporting enabled")
    return True


def _before_send(event: dict[str, Any], _hint: dict[str, Any]) -> dict[str, Any] | None:
    """Scrub headers, env, and bearer-shaped strings out of every event."""
    try:
        request = event.get("request") or {}
        headers = request.get("headers")
        if isinstance(headers, dict):
            for key in list(headers.keys()):
                if key.lower() in _REDACT_KEYS:
                    headers[key] = "[redacted]"
        env = (event.get("contexts") or {}).get("env") or {}
        for key in list(env.keys()):
            if key.lower() in _REDACT_KEYS:
                env[key] = "[redacted]"
        # Walk message + breadcrumbs for bearer-shaped strings.
        if isinstance(event.get("message"), str):
            event["message"] = _BEARER_PATTERN.sub("Bearer [redacted]", event["message"])
        for bc in event.get("breadcrumbs", {}).get("values", []) or []:
            msg = bc.get("message")
            if isinstance(msg, str):
                bc["message"] = _BEARER_PATTERN.sub("Bearer [redacted]", msg)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("before_send scrub failed: %s", exc)
    return event


def _safe_float(raw: str, *, default: float) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default
