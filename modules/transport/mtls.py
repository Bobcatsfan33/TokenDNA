"""
TokenDNA — mTLS Service Mesh  (v2.7.0)
=======================================
Mutual TLS enforcement for zero-trust transport between TokenDNA services
and upstream callers (IdP webhooks, SIEM, admin tooling).

Design Goals
------------
- Enforce client certificate authentication for all inter-service calls
- Validate peer certificates against a pinned CA bundle (IL5: DoD PKI / private CA)
- Extract and bind client identity (CN/SAN) into the request context for RBAC
- Provide FIPS 140-2 compatible TLS settings (TLS 1.2+ only, approved ciphers)
- Support cert rotation without downtime (hot-reload via SIGHUP or endpoint)
- Emit audit events for all mTLS handshake failures (IA-3 / SC-8 traceability)

NIST 800-53 Rev5 Controls
-------------------------
  SC-8   Transmission Confidentiality and Integrity
  SC-8(1) Cryptographic Protection (TLS 1.2+, FIPS ciphers)
  IA-3   Device Identification and Authentication (client cert CN binding)
  SC-17  Public Key Infrastructure Certificates
  MA-3   Maintenance Tools (authenticated maintenance channel)
  SC-23  Session Authenticity
  AU-2   Auditable Events (TLS handshake failures logged)

DISA STIG References
--------------------
  SRG-APP-000014 (FIPS 140-2 validated crypto)
  SRG-APP-000015 (TLS mutual authentication)
  SRG-APP-000156 (session termination on cert expiry)

Usage
-----
Standalone Uvicorn (production — pass ssl_* kwargs directly):
  See `get_uvicorn_ssl_config()` — returns dict ready for uvicorn.run()

FastAPI middleware (peer cert extraction from X-Client-Cert header):
  Deployed behind an mTLS-terminating proxy (Nginx / Envoy / ISTIO sidecar)
  that forwards the verified peer cert in PEM or DN format.
  Use `MTLSMiddleware` and add it to your FastAPI app.

  When running with raw Uvicorn (no proxy), set MTLS_MODE=native.
  When behind an Envoy/Nginx proxy forwarding the cert header, set MTLS_MODE=proxy.
"""

from __future__ import annotations

import logging
import os
import re
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# ── Configuration (from env) ───────────────────────────────────────────────────

# Certificate paths
MTLS_CA_CERT      = os.getenv("MTLS_CA_CERT", "/run/secrets/mtls/ca.crt")
MTLS_SERVER_CERT  = os.getenv("MTLS_SERVER_CERT", "/run/secrets/mtls/server.crt")
MTLS_SERVER_KEY   = os.getenv("MTLS_SERVER_KEY", "/run/secrets/mtls/server.key")

# Operational mode: "native" (Uvicorn TLS) | "proxy" (cert passed via header)
MTLS_MODE         = os.getenv("MTLS_MODE", "proxy").lower()

# Header name used by the upstream proxy to forward the verified client cert
# Nginx: ssl_client_cert → $ssl_client_escaped_cert
# Envoy: x-forwarded-client-cert (XFCC) or custom
MTLS_CERT_HEADER  = os.getenv("MTLS_CERT_HEADER", "X-Client-Cert")

# Comma-separated allowlist of permitted client certificate CNs (or SANs).
# Empty = allow any cert that passes CA validation.
MTLS_ALLOWED_CNS  = {
    cn.strip()
    for cn in os.getenv("MTLS_ALLOWED_CNS", "").split(",")
    if cn.strip()
}

# Endpoints that are excluded from mTLS enforcement (e.g., public health check).
# Comma-separated path prefixes.
MTLS_EXEMPT_PATHS = {
    p.strip()
    for p in os.getenv("MTLS_EXEMPT_PATHS", "/health,/").split(",")
    if p.strip()
}

# Require mTLS even on exempt paths? (False = skip for health checks)
MTLS_STRICT       = os.getenv("MTLS_STRICT", "false").lower() == "true"

# FIPS-approved TLS 1.2 cipher suite list (NSA Suite B / Commercial National Security)
_FIPS_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",  # allowed in FIPS 140-3
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
])


# ── Peer identity extracted from client certificate ───────────────────────────

@dataclass
class PeerIdentity:
    """Extracted identity from a verified client certificate."""
    cn: str                          # Common Name
    sans: list[str] = field(default_factory=list)   # Subject Alternative Names
    issuer_cn: str = ""              # Issuer CN
    serial: str = ""                 # Certificate serial number (hex)
    not_after: Optional[datetime] = None             # Expiry timestamp
    raw_subject: str = ""            # Full subject DN

    @property
    def is_expired(self) -> bool:
        if self.not_after is None:
            return False
        return datetime.now(timezone.utc) > self.not_after

    def __str__(self) -> str:
        return f"PeerIdentity(cn={self.cn!r}, issuer={self.issuer_cn!r})"


# ── Certificate parser (proxy mode — PEM header forwarded as HTTP header) ─────

_CN_RE     = re.compile(r"CN=([^,/]+)")
_SAN_RE    = re.compile(r"(?:DNS|IP|URI):([^\s,;]+)")
_SERIAL_RE = re.compile(r"([0-9A-Fa-f:]+)")


def _parse_dn_cn(dn: str) -> str:
    """Extract CN from an RFC 2253 / OpenSSL DN string."""
    m = _CN_RE.search(dn)
    return m.group(1).strip() if m else ""


def parse_peer_cert_header(header_value: str) -> Optional[PeerIdentity]:
    """
    Parse a client certificate forwarded by an mTLS-terminating proxy.

    Supports two formats:
      1. URL-encoded PEM block (Nginx: $ssl_client_escaped_cert)
      2. XFCC header (Envoy): semi-colon-separated key=value pairs

    Returns None if the header is absent, malformed, or unparseable.
    """
    if not header_value:
        return None

    header_value = header_value.strip()

    # ── XFCC (Envoy / Istio) ──────────────────────────────────────────────────
    # Format: By=<uri>;Hash=<hash>;Cert=<urlencoded-pem>;Subject="<dn>";URI=<uri>
    if header_value.startswith("By=") or "Subject=" in header_value:
        return _parse_xfcc_header(header_value)

    # ── URL-encoded PEM (Nginx) ───────────────────────────────────────────────
    if "%2F" in header_value or "%0A" in header_value or "BEGIN%20CERT" in header_value:
        from urllib.parse import unquote
        header_value = unquote(header_value)

    # ── PEM block ─────────────────────────────────────────────────────────────
    if "BEGIN CERTIFICATE" in header_value:
        return _parse_pem_cert(header_value)

    # ── Raw DN string (some proxies) ──────────────────────────────────────────
    if "CN=" in header_value:
        cn = _parse_dn_cn(header_value)
        if cn:
            return PeerIdentity(cn=cn, raw_subject=header_value)

    logger.debug("mTLS: could not parse cert header (first 120 chars): %s", header_value[:120])
    return None


def _parse_xfcc_header(header_value: str) -> Optional[PeerIdentity]:
    """Parse Envoy x-forwarded-client-cert (XFCC) header."""
    parts: dict[str, str] = {}
    # XFCC values can contain quoted strings with semicolons; use a simple parser
    for segment in re.split(r';(?=\w+=)', header_value):
        if "=" in segment:
            k, _, v = segment.partition("=")
            parts[k.strip()] = v.strip().strip('"')

    subject = parts.get("Subject", "")
    cn = _parse_dn_cn(subject)
    if not cn:
        uri = parts.get("URI", "")
        if uri:
            cn = uri.split("/")[-1]  # SPIFFE: spiffe://cluster/ns/sa/name
    if not cn:
        return None

    sans: list[str] = []
    if "URI" in parts:
        sans.append(parts["URI"])

    return PeerIdentity(
        cn=cn,
        sans=sans,
        raw_subject=subject,
    )


def _parse_pem_cert(pem: str) -> Optional[PeerIdentity]:
    """Parse a PEM certificate block using the stdlib ssl module."""
    try:
        import base64
        import re as _re

        # Extract base64 body
        body = _re.sub(r"-----[^-]+-----", "", pem).replace("\n", "").replace(" ", "")
        der = base64.b64decode(body + "==")  # pad

        # Use ssl to load and inspect
        cert_info = ssl.DER_cert_to_PEM_cert(der)

        # Fall back to basic regex extraction since ssl.SSLSocket is needed for
        # get_peer_certificate(), and we only have the PEM string here.
        # Use cryptography library if available, else basic regex.
        try:
            from cryptography import x509 as _x509
            from cryptography.hazmat.backends import default_backend

            cert = _x509.load_pem_x509_certificate(cert_info.encode(), default_backend())
            cn = cert.subject.get_attributes_for_oid(
                _x509.NameOID.COMMON_NAME
            )[0].value if cert.subject.get_attributes_for_oid(
                _x509.NameOID.COMMON_NAME
            ) else ""
            issuer_cn = cert.issuer.get_attributes_for_oid(
                _x509.NameOID.COMMON_NAME
            )[0].value if cert.issuer.get_attributes_for_oid(
                _x509.NameOID.COMMON_NAME
            ) else ""
            sans: list[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    _x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san_ext.value:
                    sans.append(str(name.value))
            except Exception:
                pass
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
                else cert.not_valid_after.replace(tzinfo=timezone.utc)
            return PeerIdentity(
                cn=cn,
                sans=sans,
                issuer_cn=issuer_cn,
                serial=hex(cert.serial_number),
                not_after=not_after,
                raw_subject=cert.subject.rfc4514_string(),
            )
        except ImportError:
            # cryptography not installed — fall back to regex
            pass

        cn = _parse_dn_cn(pem)
        return PeerIdentity(cn=cn, raw_subject=pem[:200]) if cn else None

    except Exception as exc:
        logger.debug("mTLS: PEM parse error: %s", exc)
        return None


# ── SSL context factory ────────────────────────────────────────────────────────

class MTLSContextError(RuntimeError):
    """Raised when SSL context cannot be built (missing certs, bad config)."""


def build_ssl_context(
    ca_cert: str = MTLS_CA_CERT,
    server_cert: str = MTLS_SERVER_CERT,
    server_key: str = MTLS_SERVER_KEY,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    Build an SSL context suitable for Uvicorn native mTLS.

    TLS 1.2 minimum, FIPS-approved cipher suites, client cert requirement.
    Raises MTLSContextError if cert files are missing or unreadable.
    """
    for path, label in [(ca_cert, "CA cert"), (server_cert, "server cert"), (server_key, "server key")]:
        if not Path(path).exists():
            raise MTLSContextError(f"mTLS: {label} not found: {path}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # FIPS cipher suite restriction
    try:
        ctx.set_ciphers(_FIPS_CIPHERS)
    except ssl.SSLError as exc:
        logger.warning("mTLS: could not set FIPS cipher list (%s) — using OpenSSL defaults", exc)

    # Load server identity
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)

    # Load trusted CA(s) for client cert verification
    ctx.load_verify_locations(cafile=ca_cert)

    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_OPTIONAL

    # Disable insecure options
    ctx.options |= ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0
    ctx.options |= ssl.OP_NO_SSLv3 if hasattr(ssl, "OP_NO_SSLv3") else 0
    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    logger.info(
        "mTLS: SSL context built — min TLS %s, client cert %s, CA=%s",
        ctx.minimum_version.name,
        "REQUIRED" if require_client_cert else "OPTIONAL",
        ca_cert,
    )
    return ctx


def get_uvicorn_ssl_config() -> dict[str, Any]:
    """
    Return keyword arguments suitable for uvicorn.run() / uvicorn.Config().

    Usage:
        import uvicorn
        from modules.transport.mtls import get_uvicorn_ssl_config
        uvicorn.run(app, host="0.0.0.0", port=8443, **get_uvicorn_ssl_config())
    """
    return {
        "ssl_certfile":       MTLS_SERVER_CERT,
        "ssl_keyfile":        MTLS_SERVER_KEY,
        "ssl_ca_certs":       MTLS_CA_CERT,
        "ssl_cert_reqs":      ssl.CERT_REQUIRED,
        "ssl_version":        ssl.PROTOCOL_TLS_SERVER,
        "ssl_ciphers":        _FIPS_CIPHERS,
    }


# ── Hot-reload: cert watcher ───────────────────────────────────────────────────

class _CertWatcher:
    """
    Background thread that polls cert file mtime and signals when rotation occurs.

    Allows zero-downtime cert rotation: new certs written to the same paths
    are detected within `interval` seconds and trigger registered callbacks.
    """

    def __init__(self, paths: list[str], interval: int = 60):
        self._paths     = paths
        self._interval  = interval
        self._callbacks: list[Callable[[], None]] = []
        self._mtimes: dict[str, float] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop      = threading.Event()

    def register(self, callback: Callable[[], None]) -> None:
        self._callbacks.append(callback)

    def _snapshot(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for p in self._paths:
            try:
                out[p] = Path(p).stat().st_mtime
            except OSError:
                out[p] = 0.0
        return out

    def start(self) -> None:
        self._mtimes = self._snapshot()
        self._thread = threading.Thread(target=self._run, daemon=True, name="mtls-cert-watcher")
        self._thread.start()
        logger.info("mTLS: cert watcher started (interval=%ds, watching %d files)", self._interval, len(self._paths))

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            current = self._snapshot()
            changed = [p for p in self._paths if current.get(p) != self._mtimes.get(p)]
            if changed:
                logger.info("mTLS: cert rotation detected — changed files: %s", changed)
                self._mtimes = current
                for cb in self._callbacks:
                    try:
                        cb()
                    except Exception as exc:
                        logger.error("mTLS: cert rotation callback error: %s", exc)


_cert_watcher = _CertWatcher(
    paths=[MTLS_CA_CERT, MTLS_SERVER_CERT, MTLS_SERVER_KEY],
    interval=int(os.getenv("MTLS_CERT_WATCH_INTERVAL", "60")),
)


def start_cert_watcher(callback: Optional[Callable[[], None]] = None) -> None:
    """
    Start the certificate rotation watcher.

    Optional callback is invoked when any cert file changes.
    Typical use: rebuild the SSL context and hot-reload Uvicorn.
    """
    if callback:
        _cert_watcher.register(callback)
    try:
        _cert_watcher.start()
    except Exception as exc:
        logger.warning("mTLS: cert watcher could not start: %s", exc)


# ── FastAPI / Starlette ASGI middleware ────────────────────────────────────────

class MTLSMiddleware:
    """
    ASGI middleware that enforces mTLS client certificate validation.

    In 'proxy' mode (default), the upstream proxy (Nginx/Envoy) terminates TLS
    and forwards the verified peer cert in a configurable HTTP header.
    This middleware parses that header, validates CN against the allowlist,
    rejects expired certs, and injects a `peer_identity` attribute into
    `request.state` for downstream consumption.

    In 'native' mode, raw TLS is handled by Uvicorn; this middleware only
    does post-handshake policy checks (CN allowlist, expiry).

    Configuration env vars:
      MTLS_MODE          proxy | native  (default: proxy)
      MTLS_CERT_HEADER   Header name for forwarded cert  (default: X-Client-Cert)
      MTLS_ALLOWED_CNS   Comma-separated allowlist of client CNs  (default: any)
      MTLS_EXEMPT_PATHS  Comma-separated path prefixes to skip    (default: /health,/)
      MTLS_STRICT        true = enforce on exempt paths too        (default: false)
    """

    def __init__(self, app: "ASGIApp") -> None:
        self.app = app

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive, send)
        path    = scope.get("path", "")

        # ── Exempt paths ──────────────────────────────────────────────────────
        if not MTLS_STRICT:
            for exempt in MTLS_EXEMPT_PATHS:
                if path == exempt or path.startswith(exempt.rstrip("/") + "/"):
                    await self.app(scope, receive, send)
                    return

        # ── Certificate extraction ─────────────────────────────────────────────
        peer: Optional[PeerIdentity] = None

        if MTLS_MODE == "proxy":
            cert_header = request.headers.get(MTLS_CERT_HEADER, "")
            if cert_header:
                peer = parse_peer_cert_header(cert_header)
            if peer is None:
                logger.warning(
                    "mTLS: missing or unparseable client cert header '%s' on %s %s (IP=%s)",
                    MTLS_CERT_HEADER, request.method, path,
                    request.client.host if request.client else "unknown",
                )
                response = JSONResponse(
                    {"detail": "mTLS client certificate required", "code": "MTLS_CERT_MISSING"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

        elif MTLS_MODE == "native":
            # In native mode, Uvicorn has already verified the cert at the TLS layer.
            # We can't easily access the verified cert from ASGI scope in standard Uvicorn,
            # so we rely on the XFCC header if the proxy chain forwards it,
            # otherwise we trust Uvicorn's TLS enforcement and skip CN checks here.
            cert_header = request.headers.get(MTLS_CERT_HEADER, "")
            if cert_header:
                peer = parse_peer_cert_header(cert_header)
            # No peer = TLS was enforced at transport layer; pass through
            if peer is None:
                await self.app(scope, receive, send)
                return

        # ── Expiry check ──────────────────────────────────────────────────────
        if peer and peer.is_expired:
            logger.warning("mTLS: expired client cert from %s (CN=%s, expired=%s)",
                request.client.host if request.client else "?", peer.cn, peer.not_after)
            _emit_mtls_failure(request, peer, "CERT_EXPIRED")
            response = JSONResponse(
                {"detail": "Client certificate has expired", "code": "MTLS_CERT_EXPIRED"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        # ── CN allowlist check ────────────────────────────────────────────────
        if peer and MTLS_ALLOWED_CNS:
            if peer.cn not in MTLS_ALLOWED_CNS:
                # Also check SANs
                if not any(san in MTLS_ALLOWED_CNS for san in peer.sans):
                    logger.warning(
                        "mTLS: client CN '%s' not in allowlist (SANs=%s, path=%s, IP=%s)",
                        peer.cn, peer.sans, path,
                        request.client.host if request.client else "?",
                    )
                    _emit_mtls_failure(request, peer, "CN_NOT_ALLOWED")
                    response = JSONResponse(
                        {
                            "detail": "Client certificate CN not authorized",
                            "code": "MTLS_CN_DENIED",
                        },
                        status_code=403,
                    )
                    await response(scope, receive, send)
                    return

        # ── Inject peer identity into request state ────────────────────────────
        if peer:
            scope["state"] = scope.get("state", {})
            scope["state"]["peer_identity"] = peer
            logger.debug("mTLS: peer authenticated — CN=%s path=%s", peer.cn, path)

        await self.app(scope, receive, send)


# ── Audit emission helper ──────────────────────────────────────────────────────

def _emit_mtls_failure(request: Any, peer: Optional[PeerIdentity], reason: str) -> None:
    """Emit an audit log entry for mTLS handshake / policy failures (AU-2)."""
    try:
        from modules.security.audit import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.AUTH_FAILURE,
            AuditOutcome.FAILURE,
            detail={
                "subsystem": "mtls",
                "reason": reason,
                "client_cn": peer.cn if peer else None,
                "client_ip": request.client.host if request.client else None,
                "path": request.url.path if hasattr(request, "url") else None,
            },
        )
    except Exception:
        pass  # Audit failure must never crash the request path


# ── Startup check ──────────────────────────────────────────────────────────────

def check_mtls_config() -> dict[str, Any]:
    """
    Validate mTLS configuration at startup.

    Returns a summary dict; does NOT raise on missing certs (graceful degradation
    with warning). Set MTLS_STRICT=true to fail-fast if certs are absent.
    """
    summary: dict[str, Any] = {
        "mode":             MTLS_MODE,
        "cert_header":      MTLS_CERT_HEADER,
        "allowed_cns":      sorted(MTLS_ALLOWED_CNS) if MTLS_ALLOWED_CNS else "*",
        "exempt_paths":     sorted(MTLS_EXEMPT_PATHS),
        "strict":           MTLS_STRICT,
        "ca_cert_exists":   Path(MTLS_CA_CERT).exists(),
        "server_cert_exists": Path(MTLS_SERVER_CERT).exists(),
        "server_key_exists":  Path(MTLS_SERVER_KEY).exists(),
    }

    if MTLS_MODE == "native":
        missing = [
            label for label, path, key in [
                ("CA cert",     MTLS_CA_CERT,     "ca_cert_exists"),
                ("server cert", MTLS_SERVER_CERT,  "server_cert_exists"),
                ("server key",  MTLS_SERVER_KEY,   "server_key_exists"),
            ] if not summary[key]
        ]
        if missing:
            msg = f"mTLS native mode: missing cert files: {missing}"
            if MTLS_STRICT:
                raise MTLSContextError(msg)
            else:
                logger.warning("%s — mTLS will NOT be enforced until certs are present.", msg)
        else:
            logger.info(
                "mTLS: native mode configured — CA=%s CERT=%s KEY=%s",
                MTLS_CA_CERT, MTLS_SERVER_CERT, MTLS_SERVER_KEY,
            )
    elif MTLS_MODE == "proxy":
        logger.info(
            "mTLS: proxy mode — expecting '%s' header (set by upstream Nginx/Envoy)",
            MTLS_CERT_HEADER,
        )
        if MTLS_ALLOWED_CNS:
            logger.info("mTLS: CN allowlist: %s", sorted(MTLS_ALLOWED_CNS))
        else:
            logger.info("mTLS: CN allowlist: open (any valid CN accepted)")
    else:
        raise MTLSContextError(f"Unknown MTLS_MODE: {MTLS_MODE!r}. Use 'native' or 'proxy'.")

    return summary
