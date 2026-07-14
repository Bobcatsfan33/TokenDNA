from __future__ import annotations

"""
TokenDNA production preflight validator.

Validates critical runtime env configuration before deploy or startup.
Exit code 0 means pass; non-zero means one or more required checks failed.
"""

import argparse
import importlib.util
import json
import os
import sys
from typing import Any
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


PROD_ENVS = {"production", "il5", "il6"}
KNOWN_COMPLIANCE_PROFILES = {"", "commercial", "cmmc_l2", "fedramp_high", "dod_il4", "dod_il5", "dod_il6"}
DOD_HARDENED_PROFILES = {"fedramp_high", "dod_il4", "dod_il5", "dod_il6"}
DIRECT_SQLITE_ALLOWED = {
    "modules/storage/pg_connection.py",
}


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _has(value: str | None) -> bool:
    return bool(str(value or "").strip())


def _scan_direct_sqlite_connects() -> list[str]:
    """Return production modules that still bypass the shared DB factory."""
    offenders: list[str] = []
    for base in ("modules",):
        root = _ROOT / base
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            rel = path.relative_to(_ROOT).as_posix()
            if rel in DIRECT_SQLITE_ALLOWED:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if "sqlite3.connect" in text:
                offenders.append(rel)
    return sorted(offenders)


# Minimum acceptable length for any HMAC key in production.
_MIN_KEY_BYTES = 16

# Known dev-default HMAC values that ship in source. Anything matching these
# in a prod deploy is treated as unset.
_KNOWN_DEV_DEFAULTS: dict[str, str] = {
    "TOKENDNA_DELEGATION_SECRET": "dev-delegation-secret-do-not-use-in-prod",
    "TOKENDNA_WORKFLOW_SECRET": "dev-workflow-secret-do-not-use-in-prod",
    "TOKENDNA_HONEYPOT_SECRET": "dev-honeypot-secret-do-not-use-in-prod",
    "TOKENDNA_POSTURE_SECRET": "dev-posture-secret-do-not-use-in-prod",
}


def _is_strong_secret(env_var: str) -> tuple[bool, str]:
    """Return (ok, detail) for an HMAC env var."""
    raw = os.getenv(env_var, "")
    if not raw:
        return False, f"{env_var} not set"
    if "change-me" in raw.lower():
        return False, f"{env_var} still contains a placeholder value"
    if raw == _KNOWN_DEV_DEFAULTS.get(env_var):
        return False, f"{env_var} matches published dev default"
    if len(raw.encode("utf-8")) < _MIN_KEY_BYTES:
        return False, f"{env_var} shorter than {_MIN_KEY_BYTES} bytes"
    return True, "ok"


def _valid_json_object(env_var: str) -> tuple[bool, str]:
    raw = os.getenv(env_var, "").strip()
    if not raw:
        return True, "not configured"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, f"{env_var} is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return False, f"{env_var} must be a JSON object"
    return True, "ok"


def _python_module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _is_https_url(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith("https://")


def _saml_configured() -> bool:
    return any(
        _has(os.getenv(key))
        for key in (
            "SAML_IDP_SSO_URL",
            "SAML_IDP_X509_CERT",
            "SAML_IDP_METADATA_URL",
        )
    )


def run_preflight(environment: str | None = None) -> dict[str, Any]:
    env = (environment or os.getenv("ENVIRONMENT", "dev")).strip().lower()
    compliance_profile = os.getenv("TOKENDNA_COMPLIANCE_PROFILE", "").strip().lower()
    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add_check(
        "compliance_profile_known",
        compliance_profile in KNOWN_COMPLIANCE_PROFILES,
        "TOKENDNA_COMPLIANCE_PROFILE must be one of: " + ", ".join(sorted(p for p in KNOWN_COMPLIANCE_PROFILES if p)),
    )

    dev_mode = _is_truthy(os.getenv("DEV_MODE"))
    add_check("dev_mode_disabled", not dev_mode, "DEV_MODE must be false in production")
    add_check("tokendna_env_production", os.getenv("TOKENDNA_ENV", "").strip().lower() in {"production", "prod"}, "TOKENDNA_ENV=production required")

    add_check("oidc_issuer_set", _has(os.getenv("OIDC_ISSUER")), "OIDC_ISSUER required")
    add_check("oidc_audience_set", _has(os.getenv("OIDC_AUDIENCE")), "OIDC_AUDIENCE required")
    tenant_claim = os.getenv("TOKENDNA_OIDC_TENANT_CLAIM", "").strip()
    add_check(
        "oidc_tenant_claim_set",
        _has(tenant_claim),
        "TOKENDNA_OIDC_TENANT_CLAIM required in production (for example: org_id)",
    )
    fallback_enabled = _is_truthy(os.getenv("TOKENDNA_OIDC_ALLOW_SUB_TENANT_FALLBACK"))
    add_check(
        "oidc_sub_tenant_fallback_disabled",
        not fallback_enabled,
        "Do not use sub/client_id as tenant id in production",
    )
    for env_var in ("TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON", "TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON"):
        ok, detail = _valid_json_object(env_var)
        add_check(env_var.lower() + "_valid", ok, detail)
    dna_ok, dna_detail = _is_strong_secret("DNA_HMAC_KEY")
    audit_ok, audit_detail = _is_strong_secret("AUDIT_HMAC_KEY")
    add_check("dna_hmac_key_strong", dna_ok, dna_detail)
    add_check("audit_hmac_key_strong", audit_ok, audit_detail)
    audit_backend = os.getenv("AUDIT_BACKEND") or os.getenv("AUDIT_BACKENDS") or ""
    audit_log_path = os.getenv("AUDIT_LOG_PATH") or os.getenv("AUDIT_LOG_FILE") or ""
    add_check("audit_backend_set", _has(audit_backend), "AUDIT_BACKEND required")
    add_check("audit_log_path_set", _has(audit_log_path), "AUDIT_LOG_PATH required for file audit backend")
    audit_backends = {p.strip().lower() for p in audit_backend.split(",") if p.strip()}
    if "siem" in audit_backends:
        add_check("audit_siem_webhook_set", _has(os.getenv("SIEM_WEBHOOK_URL")), "SIEM_WEBHOOK_URL required when AUDIT_BACKEND includes siem")

    from modules.storage.db_backend import get_backend_config

    storage = get_backend_config()
    add_check("storage_backend_postgres", storage.backend == "postgres", "TOKENDNA_DB_BACKEND=postgres required; SQLite is dev-only")
    add_check("storage_postgres_dsn_set", _has(storage.postgres_dsn), "TOKENDNA_PG_DSN or DATABASE_URL required")
    add_check(
        "storage_postgres_dsn_not_placeholder",
        not _has(storage.postgres_dsn) or "change-me" not in str(storage.postgres_dsn).lower(),
        "Postgres DSN still contains a placeholder value",
    )
    explicit_dsn = os.getenv("TOKENDNA_PG_DSN", "").strip()
    alias_dsn = os.getenv("DATABASE_URL", "").strip()
    add_check(
        "storage_dsn_aliases_consistent",
        not (explicit_dsn and alias_dsn and explicit_dsn != alias_dsn),
        "TOKENDNA_PG_DSN and DATABASE_URL differ",
    )
    direct_sqlite = _scan_direct_sqlite_connects()
    add_check(
        "storage_modules_use_shared_backend",
        not direct_sqlite,
        (
            "all product modules use the shared storage backend"
            if not direct_sqlite
            else "direct sqlite3.connect usage remains: " + ", ".join(direct_sqlite[:8]) + ("..." if len(direct_sqlite) > 8 else "")
        ),
    )

    # Production HMAC secret gate — value-level checks, not just presence.
    for env_var in (
        "TOKENDNA_DELEGATION_SECRET",
        "TOKENDNA_WORKFLOW_SECRET",
        "TOKENDNA_HONEYPOT_SECRET",
        "TOKENDNA_POSTURE_SECRET",
    ):
        ok, detail = _is_strong_secret(env_var)
        add_check(env_var.lower() + "_strong", ok, detail)

    ca_alg = (os.getenv("ATTESTATION_CA_ALG", "HS256") or "HS256").upper()
    ca_backend = (os.getenv("ATTESTATION_KEY_BACKEND", "software") or "software").lower()
    add_check("attestation_ca_alg_supported", ca_alg in {"HS256", "RS256"}, "ATTESTATION_CA_ALG must be HS256 or RS256")
    add_check(
        "attestation_ca_key_id_set",
        _has(os.getenv("ATTESTATION_CA_KEY_ID")),
        "ATTESTATION_CA_KEY_ID required",
    )

    if ca_backend == "aws_kms":
        add_check("aws_region_set", _has(os.getenv("AWS_REGION")), "AWS_REGION required for aws_kms backend")
        add_check(
            "attestation_kms_key_set",
            _has(os.getenv("ATTESTATION_KMS_KEY_ID")),
            "ATTESTATION_KMS_KEY_ID required for aws_kms backend",
        )
    elif ca_alg == "RS256":
        add_check(
            "rsa_key_material_set",
            _has(os.getenv("ATTESTATION_CA_PRIVATE_KEY_PEM")) or _has(os.getenv("ATTESTATION_CA_PUBLIC_KEY_PEM")),
            "RSA key material required when ATTESTATION_CA_ALG=RS256",
        )
    else:
        ca_secret_ok, ca_secret_detail = _is_strong_secret("ATTESTATION_CA_SECRET")
        add_check(
            "attestation_ca_secret_strong",
            ca_secret_ok,
            ca_secret_detail,
        )

    hardened_env = env in {"il5", "il6"} or compliance_profile in DOD_HARDENED_PROFILES
    if hardened_env:
        fips_enabled = _is_truthy(os.getenv("USE_FIPS")) or _is_truthy(os.getenv("FIPS_MODE"))
        add_check("fips_enabled", fips_enabled, "USE_FIPS=true or FIPS_MODE=true required for DoD/FedRAMP High profiles")

    if compliance_profile in DOD_HARDENED_PROFILES or compliance_profile == "cmmc_l2":
        secrets_backend = (os.getenv("SECRETS_BACKEND", "env") or "env").strip().lower()
        add_check(
            "managed_secrets_backend",
            secrets_backend in {"aws_sm", "vault"},
            "SECRETS_BACKEND must be aws_sm or vault for DoD/CMMC profiles",
        )
        add_check(
            "audit_siem_enabled",
            "siem" in audit_backends,
            "AUDIT_BACKEND must include siem for DoD/CMMC profiles",
        )
        if "siem" not in audit_backends:
            add_check(
                "audit_siem_webhook_set",
                _has(os.getenv("SIEM_WEBHOOK_URL")),
                "SIEM_WEBHOOK_URL required for DoD/CMMC profiles",
            )

    if compliance_profile in DOD_HARDENED_PROFILES:
        add_check(
            "attestation_managed_key_backend",
            ca_backend in {"aws_kms", "cloudhsm", "hsm"},
            "ATTESTATION_KEY_BACKEND must be aws_kms, cloudhsm, or hsm for DoD/FedRAMP High profiles",
        )
        add_check(
            "mtls_api_material_set",
            all(_has(os.getenv(name)) for name in ("TLS_CA_CERT_PATH", "TLS_API_CERT_PATH", "TLS_API_KEY_PATH")),
            "TLS_CA_CERT_PATH, TLS_API_CERT_PATH, and TLS_API_KEY_PATH required for DoD/FedRAMP High profiles",
        )
        add_check(
            "redis_tls_enabled",
            _is_truthy(os.getenv("REDIS_TLS")),
            "REDIS_TLS=true required for DoD/FedRAMP High profiles",
        )
        add_check(
            "clickhouse_tls_enabled",
            _is_truthy(os.getenv("CLICKHOUSE_SECURE")),
            "CLICKHOUSE_SECURE=true required for DoD/FedRAMP High profiles",
        )
        add_check(
            "postgres_mtls_material_set",
            all(_has(os.getenv(name)) for name in ("TLS_POSTGRES_CERT_PATH", "TLS_POSTGRES_KEY_PATH")),
            "TLS_POSTGRES_CERT_PATH and TLS_POSTGRES_KEY_PATH required for DoD/FedRAMP High profiles",
        )

    saml_enabled = _saml_configured()
    if saml_enabled:
        add_check("saml_sp_entity_id_https", _is_https_url(os.getenv("SAML_SP_ENTITY_ID")), "SAML_SP_ENTITY_ID must be an https URL")
        add_check("saml_sp_acs_url_https", _is_https_url(os.getenv("SAML_SP_ACS_URL")), "SAML_SP_ACS_URL must be an https URL")
        add_check("saml_idp_sso_url_set", _has(os.getenv("SAML_IDP_SSO_URL")), "SAML_IDP_SSO_URL required when SAML is enabled")
        add_check("saml_idp_x509_cert_set", _has(os.getenv("SAML_IDP_X509_CERT")), "SAML_IDP_X509_CERT required when SAML is enabled")
        add_check(
            "saml_runtime_dependency_available",
            _python_module_available("onelogin.saml2.response"),
            "python3-saml runtime dependency required when SAML is enabled",
        )
        add_check(
            "saml_xml_defusedxml_available",
            _python_module_available("defusedxml"),
            "defusedxml runtime dependency required for safe SAML XML parsing",
        )
        add_check(
            "saml_relay_state_allowlist_set",
            _has(os.getenv("SAML_ALLOWED_RELAY_STATE_HOSTS")),
            "SAML_ALLOWED_RELAY_STATE_HOSTS required for enterprise return URL control",
        )
        add_check(
            "saml_idp_initiated_disabled_by_default",
            not _is_truthy(os.getenv("SAML_ALLOW_IDP_INITIATED")),
            "IdP-initiated SAML must remain disabled unless explicitly approved per customer",
        )
    else:
        add_check("saml_config_not_enabled", True, "SAML not configured in this environment")

    required_for_env = env in PROD_ENVS
    if not required_for_env:
        # For non-prod environments, degrade failing checks to informational only.
        for item in checks:
            if not item["ok"]:
                item["detail"] = f"[non-prod warning] {item['detail']}"

    failed = [c for c in checks if not c["ok"]]
    return {
        "environment": env,
        "compliance_profile": compliance_profile or "commercial",
        "required_for_env": required_for_env,
        "passed": required_for_env is False or not failed,
        "failed_count": len(failed),
        "storage": {
            "backend": storage.backend,
            "dual_write": storage.dual_write,
            "postgres_dsn_present": bool(storage.postgres_dsn),
            "direct_sqlite_module_count": len(direct_sqlite),
            "direct_sqlite_modules": direct_sqlite,
        },
        "saml": {
            "configured": saml_enabled,
            "idp_initiated": _is_truthy(os.getenv("SAML_ALLOW_IDP_INITIATED")),
            "relay_state_allowlist_present": _has(os.getenv("SAML_ALLOWED_RELAY_STATE_HOSTS")),
        },
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA production preflight validator")
    parser.add_argument("--environment", default=None, help="Override ENVIRONMENT")
    parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Fail even when non-production checks fail",
    )
    parser.add_argument(
        "--require-kms-backend",
        action="store_true",
        help="Require ATTESTATION_KEY_BACKEND=aws_kms",
    )
    args = parser.parse_args()

    report = run_preflight(args.environment)
    if args.require_kms_backend:
        backend = (os.getenv("ATTESTATION_KEY_BACKEND", "software") or "software").lower()
        report["checks"].append(
            {
                "name": "kms_backend_required",
                "ok": backend == "aws_kms",
                "detail": "ATTESTATION_KEY_BACKEND must be aws_kms",
            }
        )
        report["failed_count"] = len([c for c in report["checks"] if not c["ok"]])
        report["passed"] = report["failed_count"] == 0
    print(json.dumps(report, sort_keys=True, indent=2))

    should_fail = (report["required_for_env"] or args.fail_on_warn or args.require_kms_backend) and not report["passed"]
    if should_fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
