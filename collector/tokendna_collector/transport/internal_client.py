"""T-2: collector-side mTLS client for the internal :8443 plane.

Stdlib-only (consistent with stream.py and the collector's Apache-2.0,
minimal-dependency design). Builds an mTLS ``ssl.SSLContext`` that presents the
collector's client certificate (SPIFFE id ``spiffe://tokendna/collector``) and
verifies the API server against the internal CA, then a urllib opener bound to
that context.

    from tokendna_collector.transport.internal_client import internal_opener

    opener, base_url = internal_opener(
        cert_path="/etc/tokendna/tls/tls.crt",
        key_path="/etc/tokendna/tls/tls.key",
        ca_path="/etc/tokendna/tls/ca.crt",
        host="tokendna-internal",
    )
    req = urllib.request.Request(f"{base_url}/internal/health")
    with opener.open(req, timeout=10) as resp:
        ...
"""
from __future__ import annotations

import ssl
import urllib.request

INTERNAL_PORT = 8443


def build_client_context(cert_path: str, key_path: str, ca_path: str) -> ssl.SSLContext:
    """TLS 1.3-only client context presenting the collector cert + verifying CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(ca_path)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def internal_opener(
    cert_path: str,
    key_path: str,
    ca_path: str,
    host: str = "tokendna-internal",
    port: int = INTERNAL_PORT,
) -> tuple[urllib.request.OpenerDirector, str]:
    """Return ``(opener, base_url)`` for the internal mTLS plane."""
    ctx = build_client_context(cert_path, key_path, ca_path)
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(handler)
    base_url = f"https://{host}:{port}"
    return opener, base_url
