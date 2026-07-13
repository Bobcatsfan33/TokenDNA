"""
TokenDNA — Production Secret Gate
=================================

Hardens the four module-local HMAC keys (delegation, workflow, honeypot,
posture) against the most common production-readiness failure: shipping with
the dev fallback secret because no operator remembered to set the env var.

When ``TOKENDNA_ENV`` is ``production`` (or ``prod``), every entry in
``REQUIRED_PRODUCTION_SECRETS`` must

    1. Be present in the environment.
    2. NOT match a known published dev default.
    3. Be at least ``MIN_SECRET_BYTES`` bytes long when UTF-8 encoded.

Failures raise :class:`ConfigurationError` at startup so the process never
serves traffic with a known-weak key.

In non-prod environments the gate is permissive: a warning is logged the first
time a known dev default is read, but the module still works for tests and
local development.

Public API:

* ``REQUIRED_PRODUCTION_SECRETS`` — the canonical list of HMAC env vars.
* ``KNOWN_DEV_DEFAULTS`` — the dev fallback strings shipped in source.
* ``secret_value(env_var, dev_default)`` — read-and-validate replacement for
  ``os.getenv(env_var, dev_default)``.
* ``assert_production_secrets()`` — call once during application startup;
  raises :class:`ConfigurationError` on the first invalid secret.
* ``is_production()`` — convenience helper for callers that want to branch.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Mapping

logger = logging.getLogger("tokendna.secret_gate")


class ConfigurationError(RuntimeError):
    """Raised when a required production secret is missing or unsafe."""


MIN_SECRET_BYTES: int = 16

# Canonical list of env vars that MUST be operator-supplied in production.
# Add new entries here as additional HMAC-keyed modules are built.
REQUIRED_PRODUCTION_SECRETS: tuple[str, ...] = (
    "TOKENDNA_DELEGATION_SECRET",
    "TOKENDNA_WORKFLOW_SECRET",
    "TOKENDNA_HONEYPOT_SECRET",
    "TOKENDNA_POSTURE_SECRET",
)

# Dev defaults that have been published in this repository's source tree.
# Anything matching these values in a production environment is treated as
# unset, because an attacker reading the public source can forge signatures.
KNOWN_DEV_DEFAULTS: Mapping[str, str] = {
    "TOKENDNA_DELEGATION_SECRET": "dev-delegation-secret-do-not-use-in-prod",
    "TOKENDNA_WORKFLOW_SECRET": "dev-workflow-secret-do-not-use-in-prod",
    "TOKENDNA_HONEYPOT_SECRET": "dev-honeypot-secret-do-not-use-in-prod",
    "TOKENDNA_POSTURE_SECRET": "dev-posture-secret-do-not-use-in-prod",
}

_PROD_VALUES = frozenset({"production", "prod"})

# Track which dev defaults we've already warned about to avoid log spam.
_warned_defaults: set[str] = set()


def is_production() -> bool:
    """Return True when ``TOKENDNA_ENV`` indicates a production deployment."""
    return os.getenv("TOKENDNA_ENV", "").strip().lower() in _PROD_VALUES


def secret_value(env_var: str, dev_default: str) -> str:
    """
    Resolve a secret env var with environment-aware validation.

    In production: missing values, dev-default values, and short values raise
    :class:`ConfigurationError`. In non-prod: missing values fall back to the
    dev default and a warning is logged on first read.
    """
    raw = os.getenv(env_var)
    if is_production():
        _enforce_prod_secret(env_var, raw)
        return raw  # type: ignore[return-value]

    if raw is None or raw == "":
        if env_var not in _warned_defaults:
            logger.warning(
                "%s not set; using dev default. Set this env var before deploying.",
                env_var,
            )
            _warned_defaults.add(env_var)
        return dev_default

    return raw


def assert_production_secrets() -> None:
    """
    Validate that every entry in ``REQUIRED_PRODUCTION_SECRETS`` is fit to
    serve production traffic. Safe to call in non-prod environments — it
    is a no-op there.

    Call this once during application startup, before any HMAC-signed object
    is read or written.
    """
    if not is_production():
        return

    failures: list[str] = []
    for env_var in REQUIRED_PRODUCTION_SECRETS:
        try:
            _enforce_prod_secret(env_var, os.getenv(env_var))
        except ConfigurationError as exc:
            failures.append(str(exc))

    if failures:
        joined = "\n  - ".join(failures)
        raise ConfigurationError(
            "Production secret gate failed. Refusing to start.\n  - " + joined
        )


def _enforce_prod_secret(env_var: str, raw: str | None) -> None:
    if raw is None or raw == "":
        raise ConfigurationError(
            f"{env_var} is not set. Production deployments must supply this."
        )
    if raw == KNOWN_DEV_DEFAULTS.get(env_var):
        raise ConfigurationError(
            f"{env_var} is set to the published dev default. "
            "Generate a fresh 32+ byte random key (e.g. `openssl rand -hex 32`)."
        )
    if len(raw.encode("utf-8")) < MIN_SECRET_BYTES:
        raise ConfigurationError(
            f"{env_var} is shorter than {MIN_SECRET_BYTES} bytes. "
            "Use `openssl rand -hex 32` to generate one."
        )


@dataclass(frozen=True)
class SecretReport:
    env_var: str
    present: bool
    is_dev_default: bool
    length_bytes: int


def report() -> list[SecretReport]:
    """Return a non-sensitive audit summary suitable for preflight scripts."""
    out: list[SecretReport] = []
    for env_var in REQUIRED_PRODUCTION_SECRETS:
        raw = os.getenv(env_var, "")
        out.append(
            SecretReport(
                env_var=env_var,
                present=bool(raw),
                is_dev_default=raw == KNOWN_DEV_DEFAULTS.get(env_var),
                length_bytes=len(raw.encode("utf-8")),
            )
        )
    return out
