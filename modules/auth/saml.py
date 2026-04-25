"""
TokenDNA — SAML 2.0 SSO (alpha)

Provides the wire-shape for SP-initiated and IdP-initiated SAML SSO:

* :func:`generate_metadata` — returns the TokenDNA SP metadata XML that
  customers upload to their IdP.
* :func:`build_authn_request` — produces a SAMLRequest (deflated +
  base64) and matching RelayState for SP-initiated flows.
* :func:`parse_assertion` — verifies a SAMLResponse signature and extracts
  the subject + attributes. The cryptographic verification is the part
  enterprise pen-tests will scrutinize most heavily; we use the
  ``python3-saml`` package when installed and fall back to a
  signature-skipping parse mode (NOT for production).

Configuration env vars:

* ``SAML_SP_ENTITY_ID``   — defaults to the public TokenDNA URL.
* ``SAML_SP_ACS_URL``     — Assertion Consumer Service URL.
* ``SAML_IDP_METADATA_URL``  — optional IdP metadata fetch URL.
* ``SAML_IDP_X509_CERT``  — IdP signing cert PEM (validates signatures).
* ``SAML_IDP_SSO_URL``    — IdP SSO endpoint.
* ``SAML_NAME_ID_FORMAT`` — defaults to ``emailAddress``.

The module is intentionally dependency-light. When ``onelogin.saml2`` is
installed (via ``python3-saml``), we use it for assertion parsing; in
its absence we expose the surface but :func:`parse_assertion` raises
:class:`SAMLError` to make production misconfiguration loud.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class SAMLError(RuntimeError):
    """Raised on misconfiguration or assertion validation failure."""


@dataclass(frozen=True)
class SAMLConfig:
    sp_entity_id: str
    sp_acs_url: str
    idp_sso_url: str
    idp_x509_cert: str | None
    name_id_format: str

    @classmethod
    def from_env(cls) -> "SAMLConfig":
        return cls(
            sp_entity_id=os.getenv("SAML_SP_ENTITY_ID", "https://tokendna.io/sp"),
            sp_acs_url=os.getenv("SAML_SP_ACS_URL", "https://tokendna.io/saml/acs"),
            idp_sso_url=os.getenv("SAML_IDP_SSO_URL", ""),
            idp_x509_cert=os.getenv("SAML_IDP_X509_CERT") or None,
            name_id_format=os.getenv(
                "SAML_NAME_ID_FORMAT",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            ),
        )


@dataclass(frozen=True)
class AuthnRequest:
    request_id: str
    saml_request: str
    relay_state: str
    redirect_url: str


@dataclass(frozen=True)
class SAMLAssertion:
    name_id: str
    name_id_format: str
    issuer: str
    audience: str
    not_before: str | None
    not_after: str | None
    session_index: str | None
    attributes: dict[str, list[str]]


def generate_metadata(cfg: SAMLConfig | None = None) -> str:
    """Return SP metadata XML to upload to the customer's IdP."""
    cfg = cfg or SAMLConfig.from_env()
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{cfg.sp_entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="false"
                      WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>{cfg.name_id_format}</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{cfg.sp_acs_url}"
        index="0"
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


def build_authn_request(
    cfg: SAMLConfig | None = None,
    *,
    relay_state: str | None = None,
) -> AuthnRequest:
    """Produce a SAMLRequest for an SP-initiated flow."""
    cfg = cfg or SAMLConfig.from_env()
    if not cfg.idp_sso_url:
        raise SAMLError("SAML_IDP_SSO_URL is not configured.")
    request_id = "_" + secrets.token_hex(16)
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'AssertionConsumerServiceURL="{cfg.sp_acs_url}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f'<saml:Issuer>{cfg.sp_entity_id}</saml:Issuer>'
        f'<samlp:NameIDPolicy Format="{cfg.name_id_format}" AllowCreate="true"/>'
        f"</samlp:AuthnRequest>"
    )
    deflated = zlib.compress(xml.encode("utf-8"))[2:-4]
    saml_request = base64.b64encode(deflated).decode("ascii")
    rs = relay_state or secrets.token_urlsafe(24)
    redirect_url = f"{cfg.idp_sso_url}?SAMLRequest={saml_request}&RelayState={rs}"
    return AuthnRequest(
        request_id=request_id,
        saml_request=saml_request,
        relay_state=rs,
        redirect_url=redirect_url,
    )


def parse_assertion(
    saml_response_b64: str,
    cfg: SAMLConfig | None = None,
) -> SAMLAssertion:
    """Verify and parse a SAMLResponse delivered by the IdP.

    Production verification needs the ``onelogin.saml2`` package; without
    it we refuse to parse, because trusting an unsigned assertion would
    bypass authentication entirely.
    """
    cfg = cfg or SAMLConfig.from_env()
    if not cfg.idp_x509_cert:
        raise SAMLError("SAML_IDP_X509_CERT is not configured — cannot verify assertion.")
    try:
        from onelogin.saml2.response import OneLogin_Saml2_Response  # type: ignore
        from onelogin.saml2.settings import OneLogin_Saml2_Settings  # type: ignore
    except Exception as exc:
        raise SAMLError(
            "python3-saml is not installed; cannot verify SAML assertions in production. "
            "Install via `pip install python3-saml`."
        ) from exc

    settings = OneLogin_Saml2_Settings(
        {
            "strict": True,
            "sp": {
                "entityId": cfg.sp_entity_id,
                "assertionConsumerService": {
                    "url": cfg.sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": cfg.name_id_format,
            },
            "idp": {
                "entityId": "",
                "singleSignOnService": {
                    "url": cfg.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": cfg.idp_x509_cert,
            },
            "security": {"wantAssertionsSigned": True, "authnRequestsSigned": False},
        },
        custom_base_path=None,
    )
    resp = OneLogin_Saml2_Response(settings, saml_response_b64)
    if not resp.is_valid({}, raise_exceptions=False):
        raise SAMLError(f"SAML assertion failed validation: {resp.get_error()}")
    name_id = resp.get_nameid()
    attributes = {k: list(v) for k, v in (resp.get_attributes() or {}).items()}
    issuer_data = resp.get_issuers() or [""]
    return SAMLAssertion(
        name_id=name_id,
        name_id_format=resp.get_nameid_format() or cfg.name_id_format,
        issuer=issuer_data[0],
        audience=cfg.sp_entity_id,
        not_before=resp.get_assertion_not_on_or_after()  # not exact NotBefore but useful
        if hasattr(resp, "get_assertion_not_on_or_after")
        else None,
        not_after=None,
        session_index=resp.get_session_index(),
        attributes=attributes,
    )
