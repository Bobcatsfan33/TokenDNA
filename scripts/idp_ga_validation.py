from __future__ import annotations

"""
Live IdP GA validation harness for TokenDNA SAML/SCIM integrations.

This script verifies the TokenDNA-side contract that every Okta, Entra, and
OneLogin rollout depends on. A human still completes the browser SAML login
inside the customer's IdP tenant, but this produces a repeatable JSON report
for the deploy gate and customer evidence packet.
"""

import argparse
import json
import secrets
import sys
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class Step:
    name: str
    ok: bool
    detail: str


def _headers(api_key: str | None, bearer: str | None) -> dict[str, str]:
    headers = {"Accept": "application/scim+json"}
    if api_key:
        headers["X-API-Key"] = api_key
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    return headers


def _request(method: str, url: str, *, headers: dict[str, str] | None = None, json_body: dict[str, Any] | None = None) -> requests.Response:
    return requests.request(method, url, headers=headers, json=json_body, timeout=20)


def _record(steps: list[Step], name: str, ok: bool, detail: str) -> None:
    steps.append(Step(name=name, ok=ok, detail=detail))


def run_validation(base_url: str, *, provider: str, api_key: str | None, bearer: str | None) -> dict[str, Any]:
    base = base_url.rstrip("/")
    scim_headers = _headers(api_key, bearer)
    steps: list[Step] = []
    suffix = secrets.token_hex(4)
    user_id = ""
    group_id = ""

    try:
        metadata = _request("GET", f"{base}/saml/metadata")
        _record(
            steps,
            "saml_metadata_available",
            metadata.status_code == 200 and "EntityDescriptor" in metadata.text and "WantAssertionsSigned" in metadata.text,
            f"status={metadata.status_code}",
        )
    except Exception as exc:  # noqa: BLE001
        _record(steps, "saml_metadata_available", False, str(exc))

    try:
        login = _request("GET", f"{base}/saml/login?relay_state=/dashboard")
        body = login.json() if login.headers.get("content-type", "").startswith("application/json") else {}
        redirect_url = str(body.get("redirect_url") or "")
        _record(
            steps,
            "saml_sp_initiated_login_contract",
            login.status_code == 200 and "SAMLRequest=" in redirect_url and "RelayState=" in redirect_url,
            f"status={login.status_code}",
        )
    except Exception as exc:  # noqa: BLE001
        _record(steps, "saml_sp_initiated_login_contract", False, str(exc))

    try:
        spc = _request("GET", f"{base}/scim/v2/ServiceProviderConfig", headers=scim_headers)
        body = spc.json()
        _record(
            steps,
            "scim_service_provider_config",
            spc.status_code == 200 and body.get("patch", {}).get("supported") is True and body.get("etag", {}).get("supported") is True,
            f"status={spc.status_code}",
        )
    except Exception as exc:  # noqa: BLE001
        _record(steps, "scim_service_provider_config", False, str(exc))

    try:
        create = _request(
            "POST",
            f"{base}/scim/v2/Users",
            headers=scim_headers,
            json_body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": f"tokendna-ga-{suffix}@example.invalid",
                "active": True,
                "name": {"givenName": "TokenDNA", "familyName": "GA"},
            },
        )
        body = create.json()
        user_id = str(body.get("id") or "")
        _record(steps, "scim_user_create", create.status_code == 201 and bool(user_id), f"status={create.status_code}")
    except Exception as exc:  # noqa: BLE001
        _record(steps, "scim_user_create", False, str(exc))

    if user_id:
        try:
            patch = _request(
                "PATCH",
                f"{base}/scim/v2/Users/{user_id}",
                headers=scim_headers,
                json_body={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                },
            )
            body = patch.json()
            _record(steps, "scim_user_deactivate_patch", patch.status_code == 200 and body.get("active") is False, f"status={patch.status_code}")
        except Exception as exc:  # noqa: BLE001
            _record(steps, "scim_user_deactivate_patch", False, str(exc))

    try:
        group = _request(
            "POST",
            f"{base}/scim/v2/Groups",
            headers=scim_headers,
            json_body={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": f"tokendna-ga-{suffix}",
            },
        )
        body = group.json()
        group_id = str(body.get("id") or "")
        _record(steps, "scim_group_create", group.status_code == 201 and bool(group_id), f"status={group.status_code}")
    except Exception as exc:  # noqa: BLE001
        _record(steps, "scim_group_create", False, str(exc))

    if user_id and group_id:
        try:
            patch_group = _request(
                "PATCH",
                f"{base}/scim/v2/Groups/{group_id}",
                headers=scim_headers,
                json_body={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "path": "members", "value": [{"value": user_id}]}],
                },
            )
            body = patch_group.json()
            _record(steps, "scim_group_membership_patch", patch_group.status_code == 200 and body.get("members") == [{"value": user_id}], f"status={patch_group.status_code}")
        except Exception as exc:  # noqa: BLE001
            _record(steps, "scim_group_membership_patch", False, str(exc))

    if group_id:
        try:
            delete_group = _request("DELETE", f"{base}/scim/v2/Groups/{group_id}", headers=scim_headers)
            _record(steps, "scim_group_delete", delete_group.status_code == 204, f"status={delete_group.status_code}")
        except Exception as exc:  # noqa: BLE001
            _record(steps, "scim_group_delete", False, str(exc))

    if user_id:
        try:
            delete_user = _request("DELETE", f"{base}/scim/v2/Users/{user_id}", headers=scim_headers)
            _record(steps, "scim_user_delete", delete_user.status_code == 204, f"status={delete_user.status_code}")
        except Exception as exc:  # noqa: BLE001
            _record(steps, "scim_user_delete", False, str(exc))

    return {
        "provider": provider,
        "base_url": base,
        "passed": all(step.ok for step in steps),
        "steps": [step.__dict__ for step in steps],
        "manual_evidence_required": [
            "browser_login_completed_in_customer_idp",
            "assertion_signature_verified_by_audit_log",
            "assertion_replay_rejected",
            "idp_certificate_fingerprint_recorded",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TokenDNA IdP GA validation checks")
    parser.add_argument("--base-url", required=True, help="TokenDNA base URL, for example https://tokendna.customer.example")
    parser.add_argument("--provider", required=True, choices=["okta", "entra", "onelogin", "other"])
    parser.add_argument("--api-key", default=None, help="Tenant API key for SCIM validation")
    parser.add_argument("--bearer", default=None, help="Tenant bearer token for SCIM validation")
    args = parser.parse_args()

    if not args.api_key and not args.bearer:
        parser.error("--api-key or --bearer is required for SCIM validation")

    report = run_validation(args.base_url, provider=args.provider, api_key=args.api_key, bearer=args.bearer)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
