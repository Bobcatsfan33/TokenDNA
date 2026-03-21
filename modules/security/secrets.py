"""
Aegis Security Platform — Secrets Management
=============================================
FedRAMP High / IL6 compliance: NIST 800-53 Rev5 IA-5, SC-12, SC-28

Centralizes all secret retrieval.  Supports three backends:

  env        — plain environment variables (dev/CI only)
  aws_sm     — AWS Secrets Manager (production recommended; FIPS endpoints available)
  vault      — HashiCorp Vault (with AppRole or Kubernetes auth)

Priority: aws_sm > vault > env
Configure with SECRETS_BACKEND=aws_sm|vault|env

IL6 requirement: Secrets must be stored in a FIPS 140-2 Level 2+ validated
HSM. AWS Secrets Manager with KMS CMK satisfies this requirement.
Use the FIPS endpoint: secretsmanager.us-east-1.amazonaws.com (FIPS 140-2).
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("aegis.secrets")

SECRETS_BACKEND: str = os.getenv("SECRETS_BACKEND", "env")
AWS_REGION:      str = os.getenv("AWS_REGION", "us-east-1")
AWS_SM_PREFIX:   str = os.getenv("AWS_SM_PREFIX", "aegis/")       # e.g. aegis/redis-password
VAULT_ADDR:      str = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN:     str = os.getenv("VAULT_TOKEN", "")
VAULT_PATH:      str = os.getenv("VAULT_SECRET_PATH", "secret/aegis")
USE_FIPS:        bool = os.getenv("FIPS_MODE", "false").lower() == "true"


@lru_cache(maxsize=256)
def get_secret(name: str, default: str = "") -> str:
    """
    Retrieve a secret by logical name.

    Usage:
        redis_password = get_secret("redis-password")
        db_password    = get_secret("clickhouse-password")
        jwt_hmac_key   = get_secret("jwt-hmac-key")

    Secret names map to:
      env        → env var AEGIS_<NAME_UPPER_UNDERSCORED>
      aws_sm     → AWS SM secret  <AWS_SM_PREFIX><name>
      vault      → Vault path     <VAULT_PATH>/<name>
    """
    backend = SECRETS_BACKEND.lower()

    if backend == "aws_sm":
        value = _from_aws_sm(name)
    elif backend == "vault":
        value = _from_vault(name)
    else:
        value = _from_env(name)

    if not value:
        if default:
            return default
        logger.warning("Secret '%s' not found in backend '%s'", name, backend)
        return ""
    return value


def _from_env(name: str) -> Optional[str]:
    env_name = "AEGIS_" + name.upper().replace("-", "_")
    # Also check the plain name for backward compat with existing env files
    return os.getenv(env_name) or os.getenv(name.upper().replace("-", "_")) or ""


def _from_aws_sm(name: str) -> Optional[str]:
    """Fetch from AWS Secrets Manager.  Uses FIPS endpoint when FIPS_MODE=true."""
    try:
        import boto3
        endpoint = (
            f"https://secretsmanager-fips.{AWS_REGION}.amazonaws.com"
            if USE_FIPS else None
        )
        kwargs = {"region_name": AWS_REGION}
        if endpoint:
            kwargs["endpoint_url"] = endpoint

        client = boto3.client("secretsmanager", **kwargs)
        response = client.get_secret_value(SecretId=f"{AWS_SM_PREFIX}{name}")
        # Secrets Manager returns either SecretString or SecretBinary
        secret = response.get("SecretString") or response.get("SecretBinary", b"").decode()
        logger.debug("Secret '%s' retrieved from AWS Secrets Manager", name)
        return secret
    except Exception as e:  # noqa: BLE001
        logger.error("AWS SM fetch failed for '%s': %s", name, e)
        return None


def _from_vault(name: str) -> Optional[str]:
    """Fetch from HashiCorp Vault KV v2."""
    try:
        import requests
        token = VAULT_TOKEN or os.getenv("VAULT_TOKEN", "")
        headers = {"X-Vault-Token": token}
        # KV v2 path format: /v1/<mount>/data/<path>
        url = f"{VAULT_ADDR}/v1/{VAULT_PATH}/data/{name}"
        resp = requests.get(url, headers=headers, timeout=3)
        resp.raise_for_status()
        data = resp.json()
        value = data.get("data", {}).get("data", {}).get("value", "")
        logger.debug("Secret '%s' retrieved from Vault", name)
        return value
    except Exception as e:  # noqa: BLE001
        logger.error("Vault fetch failed for '%s': %s", name, e)
        return None


def invalidate_cache() -> None:
    """Force re-fetch of all secrets (call after rotation event)."""
    get_secret.cache_clear()
    logger.info("Secrets cache invalidated — will re-fetch on next access")


def audit_secret_access(name: str, accessor: str) -> None:
    """
    Log every secret access for AU-2 compliance.
    Call this alongside get_secret() for sensitive secrets.
    """
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.CONFIG_CHANGED,
            AuditOutcome.SUCCESS,
            subject=accessor,
            resource=f"secret:{name}",
            detail={"action": "read", "backend": SECRETS_BACKEND},
        )
    except Exception:  # noqa: BLE001
        pass
