"""T-2: collector-side internal mTLS client (stdlib)."""
import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tokendna_collector.transport import internal_client


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "collector")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://tokendna/collector")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path = tmp_path / "tls.crt"
    key_path = tmp_path / "tls.key"
    ca_path = tmp_path / "ca.crt"
    cert_path.write_bytes(pem)
    ca_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path), str(ca_path)


def test_client_context_is_tls13_mutual_verified(tmp_path):
    cert, key, ca = _self_signed(tmp_path)
    ctx = internal_client.build_client_context(cert, key, ca)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_internal_opener_targets_8443(tmp_path):
    cert, key, ca = _self_signed(tmp_path)
    opener, base_url = internal_client.internal_opener(cert, key, ca, host="tokendna-internal")
    assert base_url == "https://tokendna-internal:8443"
    assert opener is not None
