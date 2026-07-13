"""T-2: tests for internal-plane mTLS peer authorization + listener context.

Covers the SC-8/IA-3 contract:
  * no client cert (no ssl_object)            -> 403 (mTLS required)
  * valid cert, SPIFFE URI not in allowlist   -> 403 (peer not allowed)
  * valid cert, SPIFFE URI in allowlist        -> matched identity returned
  * internal listener context is TLS 1.3-only + CERT_REQUIRED
"""
import datetime
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from modules.security import mtls_peer, mtls_server


# ── fakes ─────────────────────────────────────────────────────────────────────

class _FakeSSL:
    def __init__(self, cert: dict | None):
        self._cert = cert

    def getpeercert(self):
        return self._cert


class _FakeTransport:
    def __init__(self, ssl_object):
        self._ssl = ssl_object

    def get_extra_info(self, key):
        return self._ssl if key == "ssl_object" else None


class _FakeRequest:
    def __init__(self, ssl_object):
        self.scope = {"transport": _FakeTransport(ssl_object)}


def _cert_with_uri(uri: str) -> dict:
    return {"subjectAltName": (("URI", uri),)}


# ── authorize_peer ────────────────────────────────────────────────────────────

def test_no_ssl_object_is_403():
    with pytest.raises(HTTPException) as exc:
        mtls_peer.authorize_peer(None)
    assert exc.value.status_code == 403
    assert "mTLS" in exc.value.detail


def test_unlisted_spiffe_uri_is_403():
    ssl_obj = _FakeSSL(_cert_with_uri("spiffe://tokendna/attacker"))
    with pytest.raises(HTTPException) as exc:
        mtls_peer.authorize_peer(ssl_obj)
    assert exc.value.status_code == 403
    assert "not allowed" in exc.value.detail


def test_allowed_spiffe_uri_returns_identity():
    ssl_obj = _FakeSSL(_cert_with_uri("spiffe://tokendna/collector"))
    assert mtls_peer.authorize_peer(ssl_obj) == "spiffe://tokendna/collector"


def test_cert_without_san_is_403():
    ssl_obj = _FakeSSL({"subject": ((("commonName", "x"),),)})
    with pytest.raises(HTTPException) as exc:
        mtls_peer.authorize_peer(ssl_obj)
    assert exc.value.status_code == 403


def test_custom_allowlist_argument():
    ssl_obj = _FakeSSL(_cert_with_uri("spiffe://tokendna/custom"))
    assert (
        mtls_peer.authorize_peer(ssl_obj, allowlist={"spiffe://tokendna/custom"})
        == "spiffe://tokendna/custom"
    )


def test_env_allowlist_override(monkeypatch):
    monkeypatch.setenv("TLS_INTERNAL_PEER_ALLOWLIST", "spiffe://tokendna/a, spiffe://tokendna/b")
    assert mtls_peer.allowed_internal_peers() == frozenset(
        {"spiffe://tokendna/a", "spiffe://tokendna/b"}
    )


def test_default_allowlist_when_env_unset(monkeypatch):
    monkeypatch.delenv("TLS_INTERNAL_PEER_ALLOWLIST", raising=False)
    allowed = mtls_peer.allowed_internal_peers()
    assert "spiffe://tokendna/collector" in allowed
    assert "spiffe://tokendna/edge-worker" in allowed


# ── require_internal_peer (dependency) ────────────────────────────────────────

def test_dependency_rejects_missing_transport():
    req = _FakeRequest(None)
    with pytest.raises(HTTPException) as exc:
        mtls_peer.require_internal_peer(req)
    assert exc.value.status_code == 403


def test_dependency_allows_known_peer():
    req = _FakeRequest(_FakeSSL(_cert_with_uri("spiffe://tokendna/migration-job")))
    assert mtls_peer.require_internal_peer(req) == "spiffe://tokendna/migration-job"


# ── internal listener TLS context ─────────────────────────────────────────────

def _write_self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tokendna-internal")])
    now = datetime.datetime(2026, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier("spiffe://tokendna/api")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "tls.crt"
    key_path = tmp_path / "tls.key"
    ca_path = tmp_path / "ca.crt"
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_pem)
    ca_path.write_bytes(cert_pem)  # self-signed acts as its own CA for the test
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path), str(ca_path)


def test_internal_context_is_tls13_and_mutual(tmp_path):
    cert, key, ca = _write_self_signed(tmp_path)
    ctx = mtls_server.build_internal_ssl_context(cert, key, ca)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_internal_uvicorn_kwargs_demand_client_cert():
    kwargs = mtls_server.uvicorn_kwargs()
    assert kwargs["port"] == 8443
    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
