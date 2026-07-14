"""
TokenDNA -- SAML 2.0 SSO.

Provides the wire-shape for SP-initiated and IdP-initiated SAML SSO:

* :func:`generate_metadata` — returns the TokenDNA SP metadata XML that
  customers upload to their IdP.
* :func:`build_authn_request` — produces a SAMLRequest (deflated +
  base64) and matching RelayState for SP-initiated flows.
* :func:`parse_assertion` — verifies a signed SAMLResponse and extracts
  the subject + attributes. The cryptographic verification is delegated to
  ``python3-saml``; if that dependency is unavailable, assertions are refused.

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
import hashlib
import logging
import os
import secrets
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

# SECURITY: SAML responses are attacker-controlled XML. We parse them ONLY
# with defusedxml (XXE / entity-expansion / DTD hardening). We deliberately do
# NOT fall back to the stdlib xml.etree parser on untrusted input -- if
# defusedxml is unavailable we refuse to extract state rather than expose an
# XXE / billion-laughs sink. defusedxml is a hard runtime dependency in
# production (see requirements.txt).
try:
    from defusedxml import ElementTree as SafeElementTree  # type: ignore
except Exception:  # pragma: no cover - dependency is shipped in production image
    SafeElementTree = None  # type: ignore[assignment]

from modules.storage.pg_connection import AdaptedCursor, ensure_sqlite_dir, get_db_conn

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
    allowed_relay_state_hosts: tuple[str, ...]
    request_ttl_seconds: int
    clock_skew_seconds: int
    allow_idp_initiated: bool

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
            allowed_relay_state_hosts=tuple(
                h.strip().lower()
                for h in os.getenv("SAML_ALLOWED_RELAY_STATE_HOSTS", "").split(",")
                if h.strip()
            ),
            request_ttl_seconds=int(os.getenv("SAML_REQUEST_TTL_SECONDS", "300")),
            clock_skew_seconds=int(os.getenv("SAML_CLOCK_SKEW_SECONDS", "180")),
            allow_idp_initiated=str(os.getenv("SAML_ALLOW_IDP_INITIATED", "false")).lower()
            in {"1", "true", "yes", "on"},
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
    in_response_to: str | None = None
    assertion_id: str | None = None


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _cursor():
    return get_db_conn(db_path=_db_path())


def init_db() -> None:
    """Create SAML request/replay state tables."""
    ensure_sqlite_dir(_db_path())
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS saml_request_state (
                request_id       TEXT PRIMARY KEY,
                relay_state_hash TEXT NOT NULL,
                relay_state      TEXT NOT NULL,
                created_at       TEXT NOT NULL,
                expires_at       TEXT NOT NULL,
                consumed_at      TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS saml_assertion_replay (
                assertion_id TEXT PRIMARY KEY,
                issuer       TEXT NOT NULL,
                name_id      TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                consumed_at  TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_saml_request_expiry ON saml_request_state(expires_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_saml_assertion_expiry ON saml_assertion_replay(expires_at)")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _hash_relay_state(relay_state: str) -> str:
    return hashlib.sha256(relay_state.encode("utf-8")).hexdigest()


def validate_relay_state(relay_state: str | None, cfg: SAMLConfig | None = None) -> str:
    """Allow relative RelayState and explicitly configured return hosts only."""
    cfg = cfg or SAMLConfig.from_env()
    value = str(relay_state or "").strip()
    if not value:
        return value
    parsed = urlparse(value)
    if not parsed.scheme and not parsed.netloc:
        if not value.startswith("/"):
            raise SAMLError("RelayState must be a relative path or an allowed absolute URL.")
        return value
    if parsed.scheme not in {"https"}:
        raise SAMLError("RelayState absolute URLs must use https.")
    host = (parsed.hostname or "").lower()
    if host not in cfg.allowed_relay_state_hosts:
        raise SAMLError("RelayState host is not allowlisted.")
    return value


def store_authn_request(request_id: str, relay_state: str, cfg: SAMLConfig | None = None) -> None:
    cfg = cfg or SAMLConfig.from_env()
    init_db()
    now = datetime.now(timezone.utc)
    with _cursor() as conn:
        AdaptedCursor(conn.cursor()).execute(
            """
            INSERT INTO saml_request_state(request_id, relay_state_hash, relay_state, created_at, expires_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, NULL)
            """,
            (
                request_id,
                _hash_relay_state(relay_state),
                relay_state,
                _iso(now),
                _iso(now + timedelta(seconds=cfg.request_ttl_seconds)),
            ),
        )


def consume_authn_request(request_id: str, relay_state: str, cfg: SAMLConfig | None = None) -> None:
    cfg = cfg or SAMLConfig.from_env()
    init_db()
    now = datetime.now(timezone.utc)
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        row = cur.execute(
            "SELECT * FROM saml_request_state WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if not row:
            raise SAMLError("SAML response references an unknown AuthnRequest.")
        if row["consumed_at"]:
            raise SAMLError("SAML AuthnRequest has already been consumed.")
        expires_at = _parse_iso(row["expires_at"])
        if expires_at and now > expires_at + timedelta(seconds=cfg.clock_skew_seconds):
            raise SAMLError("SAML AuthnRequest has expired.")
        if row["relay_state_hash"] != _hash_relay_state(relay_state or ""):
            raise SAMLError("SAML RelayState does not match the AuthnRequest.")
        cur.execute(
            "UPDATE saml_request_state SET consumed_at=? WHERE request_id=?",
            (_iso(now), request_id),
        )


def record_assertion_replay(assertion_id: str, issuer: str, name_id: str, not_after: str | None, cfg: SAMLConfig | None = None) -> None:
    cfg = cfg or SAMLConfig.from_env()
    if not assertion_id:
        raise SAMLError("SAML assertion is missing an ID.")
    init_db()
    now = datetime.now(timezone.utc)
    expires_at = _parse_iso(not_after) or now + timedelta(seconds=cfg.request_ttl_seconds)
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        row = cur.execute(
            "SELECT assertion_id FROM saml_assertion_replay WHERE assertion_id=?",
            (assertion_id,),
        ).fetchone()
        if row:
            raise SAMLError("SAML assertion replay detected.")
        cur.execute(
            """
            INSERT INTO saml_assertion_replay(assertion_id, issuer, name_id, expires_at, consumed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (assertion_id, issuer, name_id, _iso(expires_at), _iso(now)),
        )


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
    validated_relay_state = validate_relay_state(relay_state, cfg) if relay_state else secrets.token_urlsafe(24)
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
    rs = validated_relay_state
    store_authn_request(request_id, rs, cfg)
    redirect_url = f"{cfg.idp_sso_url}?{urlencode({'SAMLRequest': saml_request, 'RelayState': rs})}"
    return AuthnRequest(
        request_id=request_id,
        saml_request=saml_request,
        relay_state=rs,
        redirect_url=redirect_url,
    )


def parse_assertion(
    saml_response_b64: str,
    cfg: SAMLConfig | None = None,
    *,
    relay_state: str | None = None,
) -> SAMLAssertion:
    """Verify and parse a SAMLResponse delivered by the IdP.

    Production verification needs the ``onelogin.saml2`` package; without
    it we refuse to parse, because trusting an unsigned assertion would
    bypass authentication entirely.
    """
    cfg = cfg or SAMLConfig.from_env()
    validate_relay_state(relay_state, cfg)
    if not cfg.idp_x509_cert:
        raise SAMLError("SAML_IDP_X509_CERT is not configured — cannot verify assertion.")
    extracted = _extract_response_state(saml_response_b64)
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
    destination = extracted.get("destination")
    recipient = extracted.get("recipient")
    if destination and destination != cfg.sp_acs_url:
        raise SAMLError("SAML response Destination does not match ACS URL.")
    if recipient and recipient != cfg.sp_acs_url:
        raise SAMLError("SAML SubjectConfirmation recipient does not match ACS URL.")
    name_id = resp.get_nameid()
    attributes = {k: list(v) for k, v in (resp.get_attributes() or {}).items()}
    issuer_data = resp.get_issuers() or [""]
    in_response_to = _call_optional(resp, "get_in_response_to") or extracted.get("in_response_to")
    assertion_id = _call_optional(resp, "get_assertion_id") or extracted.get("assertion_id")
    not_after = _call_optional(resp, "get_assertion_not_on_or_after") or extracted.get("not_after")
    if in_response_to:
        consume_authn_request(in_response_to, relay_state or "", cfg)
    elif not cfg.allow_idp_initiated:
        raise SAMLError("IdP-initiated SAML responses are disabled.")
    record_assertion_replay(assertion_id or "", issuer_data[0], name_id, not_after, cfg)
    return SAMLAssertion(
        name_id=name_id,
        name_id_format=resp.get_nameid_format() or cfg.name_id_format,
        issuer=issuer_data[0],
        audience=cfg.sp_entity_id,
        not_before=extracted.get("not_before"),
        not_after=not_after,
        session_index=resp.get_session_index(),
        attributes=attributes,
        in_response_to=in_response_to,
        assertion_id=assertion_id,
    )


def _call_optional(obj: Any, method: str) -> Any:
    fn = getattr(obj, method, None)
    if callable(fn):
        try:
            return fn()
        except Exception:
            return None
    return None


def _extract_response_state(saml_response_b64: str) -> dict[str, str | None]:
    """Extract non-trusted SAML IDs/timestamps after base64 decoding.

    Cryptographic trust is still delegated to python3-saml; these values are
    used only for replay/request-state bookkeeping after signature validation.
    """
    if SafeElementTree is None:  # defusedxml missing -> refuse to parse untrusted XML
        logger.error("defusedxml is not installed; refusing to parse SAML response state")
        return {}
    try:
        raw = base64.b64decode(saml_response_b64, validate=True)
        root = SafeElementTree.fromstring(raw)
    except Exception:
        return {}
    ns = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    }
    assertion = root.find(".//saml:Assertion", ns)
    conditions = root.find(".//saml:Conditions", ns)
    subject_confirmation = root.find(".//saml:SubjectConfirmationData", ns)
    return {
        "response_id": root.attrib.get("ID"),
        "in_response_to": root.attrib.get("InResponseTo") or (subject_confirmation.attrib.get("InResponseTo") if subject_confirmation is not None else None),
        "assertion_id": assertion.attrib.get("ID") if assertion is not None else None,
        "not_before": conditions.attrib.get("NotBefore") if conditions is not None else None,
        "not_after": conditions.attrib.get("NotOnOrAfter") if conditions is not None else None,
        "destination": root.attrib.get("Destination"),
        "recipient": subject_confirmation.attrib.get("Recipient") if subject_confirmation is not None else None,
    }


def _reset_for_tests() -> None:
    init_db()
    with _cursor() as conn:
        cur = AdaptedCursor(conn.cursor())
        cur.execute("DELETE FROM saml_assertion_replay")
        cur.execute("DELETE FROM saml_request_state")
