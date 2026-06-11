"""T-2: authorize the mTLS peer, not just authenticate it.

The internal plane (collector, edge worker, batch jobs) reaches the API over
mutual TLS on :8443. uvicorn verifies the certificate *chain*; this module
checks the peer certificate's SAN URI against an allowlist (SPIFFE-style
identities), so a valid cert from the internal CA still cannot call planes it
is not entitled to (SC-8 / IA-3, defence in depth).

Usage in a router:

    from modules.security.mtls_peer import require_internal_peer

    router = APIRouter(
        prefix="/internal",
        dependencies=[Depends(require_internal_peer)],
    )

The allowlist defaults to the three internal services and can be overridden
with ``TLS_INTERNAL_PEER_ALLOWLIST`` (comma/space separated SPIFFE URIs).
"""
from __future__ import annotations

import os
from typing import Iterable, Optional

from fastapi import HTTPException, Request

_DEFAULT_ALLOWED_INTERNAL_PEERS = frozenset({
    "spiffe://tokendna/collector",
    "spiffe://tokendna/edge-worker",
    "spiffe://tokendna/migration-job",
})


def allowed_internal_peers() -> frozenset[str]:
    """Resolve the SPIFFE allowlist (env override or the default set)."""
    raw = os.getenv("TLS_INTERNAL_PEER_ALLOWLIST", "").strip()
    if not raw:
        return _DEFAULT_ALLOWED_INTERNAL_PEERS
    parts = [p.strip() for p in raw.replace(",", " ").split()]
    return frozenset(p for p in parts if p)


def _peer_san_uris(ssl_object) -> set[str]:
    """Extract SAN URI entries from a verified peer certificate.

    ``ssl_object.getpeercert()`` returns the decoded cert dict only when the
    peer presented one and the chain verified (CERT_REQUIRED). SAN entries are
    ``(type, value)`` tuples; we keep the ``URI`` ones (SPIFFE IDs).
    """
    if ssl_object is None:
        return set()
    cert = ssl_object.getpeercert()
    if not cert:
        return set()
    return {value for key, value in cert.get("subjectAltName", ()) if key == "URI"}


def _ssl_object_from_request(request: Request):
    transport = request.scope.get("transport")
    if transport is None:
        return None
    try:
        return transport.get_extra_info("ssl_object")
    except Exception:  # pragma: no cover - defensive
        return None


def authorize_peer(
    ssl_object,
    allowlist: Optional[Iterable[str]] = None,
) -> str:
    """Return the matched SPIFFE identity or raise HTTPException(403).

    Separated from the FastAPI dependency so it is unit-testable without a
    live TLS socket.
    """
    if ssl_object is None:
        raise HTTPException(status_code=403, detail="internal plane requires mTLS")
    allowed = frozenset(allowlist) if allowlist is not None else allowed_internal_peers()
    sans = _peer_san_uris(ssl_object)
    matched = sans & allowed
    if not matched:
        raise HTTPException(status_code=403, detail="peer identity not allowed")
    return sorted(matched)[0]


def require_internal_peer(request: Request) -> str:
    """FastAPI dependency: authorize the mTLS peer for the internal plane."""
    ssl_object = _ssl_object_from_request(request)
    return authorize_peer(ssl_object)
