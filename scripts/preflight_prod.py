from __future__ import annotations

"""
TokenDNA production preflight validator.

Validates critical runtime env configuration before deploy or startup.
Exit code 0 means pass; non-zero means one or more required checks failed.
"""

import argparse
import json
import os
import sys
from typing import Any
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


PROD_ENVS = {"production", "il5", "il6"}


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _has(value: str | None) -> bool:
    return bool(str(value or "").strip())


def run_preflight(environment: str | None = None) -> dict[str, Any]:
    env = (environment or os.getenv("ENVIRONMENT", "dev")).strip().lower()
    checks: list[dict[str, Any]] = []

    def add_check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    dev_mode = _is_truthy(os.getenv("DEV_MODE"))
    add_check("dev_mode_disabled", not dev_mode, "DEV_MODE must be false in production")

    add_check("oidc_issuer_set", _has(os.getenv("OIDC_ISSUER")), "OIDC_ISSUER required")
    add_check("oidc_audience_set", _has(os.getenv("OIDC_AUDIENCE")), "OIDC_AUDIENCE required")
    add_check("dna_hmac_key_set", _has(os.getenv("DNA_HMAC_KEY")), "DNA_HMAC_KEY required")
    add_check("audit_hmac_key_set", _has(os.getenv("AUDIT_HMAC_KEY")), "AUDIT_HMAC_KEY required")

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
        add_check(
            "attestation_ca_secret_set",
            _has(os.getenv("ATTESTATION_CA_SECRET")),
            "ATTESTATION_CA_SECRET required for HS256 mode",
        )

    if env in {"il5", "il6"}:
        add_check("fips_enabled", _is_truthy(os.getenv("USE_FIPS")), "USE_FIPS=true required for IL5/IL6")

    required_for_env = env in PROD_ENVS
    if not required_for_env:
        # For non-prod environments, degrade failing checks to informational only.
        for item in checks:
            if not item["ok"]:
                item["detail"] = f"[non-prod warning] {item['detail']}"

    failed = [c for c in checks if not c["ok"]]
    return {
        "environment": env,
        "required_for_env": required_for_env,
        "passed": required_for_env is False or not failed,
        "failed_count": len(failed),
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

