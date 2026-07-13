"""T-2: internal mTLS listener (:8443).

TokenDNA exposes two listeners in the federal/enterprise profile:

  :8000  — external API (TLS terminated by ingress; OIDC bearer auth)
  :8443  — internal plane (collector, edge worker, batch jobs) — mutual TLS,
           client certificates REQUIRED and pinned to the internal CA, with
           SPIFFE peer authorization via modules.security.mtls_peer.

Run as a second uvicorn process in the same image (entrypoint starts both) or
as a dedicated Deployment; both are wired in deploy/helm. TLS material is
resolved through the existing modules.security.mtls.MTLSConfig env contract,
falling back to the conventional cert-manager mount paths below.
"""
from __future__ import annotations

import ssl

from modules.security import mtls

INTERNAL_PORT = 8443

# Conventional cert-manager mount paths (see internal-pki.yaml); used only when
# the TLS_* env contract is not set.
_DEFAULT_SERVER_CERT = "/etc/tokendna/tls/tls.crt"
_DEFAULT_SERVER_KEY = "/etc/tokendna/tls/tls.key"
_DEFAULT_CLIENT_CA = "/etc/tokendna/tls/ca.crt"


def _resolved_paths() -> tuple[str, str, str]:
    cfg = mtls.load()
    server_cert = str(cfg.api.cert_path) if (cfg.api and cfg.api.cert_path) else _DEFAULT_SERVER_CERT
    server_key = str(cfg.api.key_path) if (cfg.api and cfg.api.key_path) else _DEFAULT_SERVER_KEY
    client_ca = str(cfg.ca_cert) if cfg.ca_cert else _DEFAULT_CLIENT_CA
    return server_cert, server_key, client_ca


def build_internal_ssl_context(
    server_cert: str | None = None,
    server_key: str | None = None,
    client_ca: str | None = None,
) -> ssl.SSLContext:
    """TLS 1.3-only, client-cert-REQUIRED context for the internal plane."""
    rc, rk, rca = _resolved_paths()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3       # SC-8: TLS 1.3 only internally
    ctx.load_cert_chain(server_cert or rc, server_key or rk)
    ctx.load_verify_locations(client_ca or rca)
    ctx.verify_mode = ssl.CERT_REQUIRED                # mutual TLS: no cert, no socket
    return ctx


def uvicorn_kwargs() -> dict[str, object]:
    """ssl_* kwargs for ``uvicorn.run(...)`` on the internal listener."""
    server_cert, server_key, client_ca = _resolved_paths()
    return {
        "host": "0.0.0.0",
        "port": INTERNAL_PORT,
        "ssl_keyfile": server_key,
        "ssl_certfile": server_cert,
        "ssl_ca_certs": client_ca,
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
    }


def run_internal_listener() -> None:  # pragma: no cover - process entry point
    import uvicorn

    uvicorn.run("api:app", **uvicorn_kwargs())


if __name__ == "__main__":  # pragma: no cover
    run_internal_listener()
