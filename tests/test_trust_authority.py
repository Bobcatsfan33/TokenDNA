from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.trust_authority import (
    AWSKMSTrustSigner,
    CloudHSMTrustSigner,
    HMACTrustSigner,
    TrustSignerError,
    build_signer,
    build_signer_for_key,
    list_key_configs,
    rotate_active_key,
)


def test_hmac_signer_sign_and_verify_roundtrip():
    signer = HMACTrustSigner(secret="test-secret", key_id="k1")
    payload = {"a": 1, "b": "two"}
    signed = signer.sign(payload)
    assert signed.algorithm == "HS256"
    assert signed.key_id == "k1"
    assert signer.verify(payload, signed.signature) is True


def test_hmac_signer_rejects_tampered_payload():
    signer = HMACTrustSigner(secret="test-secret", key_id="k1")
    payload = {"a": 1}
    signed = signer.sign(payload)
    assert signer.verify({"a": 2}, signed.signature) is False


def test_build_signer_defaults_to_hmac():
    os.environ.pop("ATTESTATION_CA_ALG", None)
    signer = build_signer()
    payload = {"hello": "world"}
    signed = signer.sign(payload)
    assert signed.algorithm in {"HS256", "RS256"}


def test_build_signer_for_key_uses_keyring_hmac():
    keyring = [
        {"key_id": "k-legacy", "algorithm": "HS256", "backend": "software"},
        {"key_id": "k-rotated", "algorithm": "HS256", "backend": "software"},
    ]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)
    try:
        signer = build_signer_for_key("k-rotated", "HS256", secret_override="rotated-secret")
        payload = {"k": "v"}
        signed = signer.sign(payload)
        assert signed.key_id == "k-rotated"
        assert signer.verify(payload, signed.signature) is True
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)


def test_build_signer_respects_active_key_id():
    keyring = [{"key_id": "k-active", "algorithm": "HS256", "backend": "software"}]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)
    os.environ["ATTESTATION_ACTIVE_KEY_ID"] = "k-active"
    try:
        signer = build_signer(secret_override="active-secret")
        signed = signer.sign({"hello": "active"})
        assert signed.key_id == "k-active"
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)
        os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)


def test_list_key_configs_uses_keyring_when_available():
    keyring = [
        {"key_id": "k1", "algorithm": "HS256", "backend": "software"},
        {"key_id": "k2", "algorithm": "RS256", "backend": "aws_kms", "kms_key_id": "arn:aws:kms:region:acct:key/1"},
    ]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)
    try:
        configs = list_key_configs()
        ids = {row["key_id"] for row in configs}
        assert ids == {"k1", "k2"}
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)


# ── KMS / CloudHSM signer tests ──────────────────────────────────────────────
#
# These tests inject a stub KMS client so they exercise the full
# AWSKMSTrustSigner / CloudHSMTrustSigner code path without touching boto3
# or the network.  The stub records every call so we can assert the
# correct API parameters were sent.


class _StubKMSClient:
    """Records sign/verify calls; signs by reflecting the message bytes."""
    def __init__(self):
        self.sign_calls: list[dict] = []
        self.verify_calls: list[dict] = []

    def sign(self, **kwargs):
        self.sign_calls.append(dict(kwargs))
        # Simulated signature = sha256(KeyId || Message); verify reproduces it.
        import hashlib as _h
        sig = _h.sha256(kwargs["KeyId"].encode() + kwargs["Message"]).digest()
        return {"Signature": sig, "KeyId": kwargs["KeyId"], "SigningAlgorithm": kwargs["SigningAlgorithm"]}

    def verify(self, **kwargs):
        self.verify_calls.append(dict(kwargs))
        import hashlib as _h
        expected = _h.sha256(kwargs["KeyId"].encode() + kwargs["Message"]).digest()
        ok = expected == kwargs["Signature"]
        if not ok:
            class KMSInvalidSignature(Exception):
                pass
            raise KMSInvalidSignature("KMSInvalidSignatureException")
        return {"SignatureValid": True, "KeyId": kwargs["KeyId"]}


def test_aws_kms_signer_sign_uses_pkcs1_v1_5_sha_256():
    stub = _StubKMSClient()
    signer = AWSKMSTrustSigner(
        kms_key_id="alias/tokendna-ca",
        key_id="ca-prod-2026",
        client_factory=lambda: stub,
    )
    payload = {"hello": "kms"}
    res = signer.sign(payload)

    assert len(stub.sign_calls) == 1
    call = stub.sign_calls[0]
    assert call["KeyId"] == "alias/tokendna-ca"
    assert call["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    assert call["MessageType"] == "RAW"
    assert res.algorithm == "RS256"
    assert res.key_id == "ca-prod-2026"
    assert signer.verify(payload, res.signature) is True


def test_aws_kms_signer_verify_returns_false_on_tampered_payload():
    stub = _StubKMSClient()
    signer = AWSKMSTrustSigner(
        kms_key_id="alias/tokendna-ca",
        key_id="ca-prod-2026",
        client_factory=lambda: stub,
    )
    res = signer.sign({"hello": "kms"})
    assert signer.verify({"hello": "tampered"}, res.signature) is False


def test_aws_kms_signer_caches_client_across_calls():
    """One call to client_factory regardless of how many sign/verify calls."""
    factory_calls = {"n": 0}
    stub = _StubKMSClient()
    def factory():
        factory_calls["n"] += 1
        return stub
    signer = AWSKMSTrustSigner("alias/x", "k1", client_factory=factory)
    for _ in range(5):
        res = signer.sign({"i": _})
        signer.verify({"i": _}, res.signature)
    assert factory_calls["n"] == 1


def test_aws_kms_signer_raises_trust_signer_error_on_kms_failure():
    class FailingClient:
        def sign(self, **kwargs):
            raise RuntimeError("kms api transient failure")
    signer = AWSKMSTrustSigner("alias/x", "k1", client_factory=lambda: FailingClient())
    with pytest.raises(TrustSignerError):
        signer.sign({"x": 1})


def test_cloudhsm_signer_marks_algorithm_with_chsm_suffix():
    stub = _StubKMSClient()
    signer = CloudHSMTrustSigner(
        kms_key_id="alias/tokendna-ca-fips3",
        key_id="ca-il5-2026",
        client_factory=lambda: stub,
    )
    res = signer.sign({"il5": True})
    assert res.algorithm == "RS256+CHSM"
    assert res.key_id == "ca-il5-2026"
    assert signer.verify({"il5": True}, res.signature) is True


def test_build_signer_for_key_routes_aws_kms_backend():
    """Keyring entry with backend=aws_kms should produce an AWSKMSTrustSigner."""
    keyring = [
        {"key_id": "ca-prod", "algorithm": "RS256", "backend": "aws_kms",
         "kms_key_id": "alias/tokendna-ca", "region_name": "us-east-1"},
    ]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)
    try:
        signer = build_signer_for_key("ca-prod", "RS256")
        assert isinstance(signer, AWSKMSTrustSigner)
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)


def test_build_signer_for_key_routes_cloudhsm_backend():
    keyring = [
        {"key_id": "ca-il5", "algorithm": "RS256", "backend": "cloudhsm",
         "kms_key_id": "alias/tokendna-ca-fips3"},
    ]
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps(keyring)
    try:
        signer = build_signer_for_key("ca-il5", "RS256")
        assert isinstance(signer, CloudHSMTrustSigner)
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)


def test_build_signer_aws_kms_falls_back_to_software_when_no_kms_key_id():
    """Mis-configured backend (no kms_key_id anywhere) should not crash issuance."""
    os.environ["ATTESTATION_KEY_BACKEND"] = "aws_kms"
    os.environ.pop("ATTESTATION_KMS_KEY_ID", None)
    os.environ.pop("AWS_KMS_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    try:
        signer = build_signer(secret_override="fallback-secret")
        assert isinstance(signer, HMACTrustSigner)
        signed = signer.sign({"x": 1})
        assert signer.verify({"x": 1}, signed.signature) is True
    finally:
        os.environ.pop("ATTESTATION_KEY_BACKEND", None)


def test_aws_kms_key_id_env_var_resolves():
    """AWS-standard env var name AWS_KMS_KEY_ID should be honored."""
    os.environ["ATTESTATION_KEY_BACKEND"] = "aws_kms"
    os.environ["AWS_KMS_KEY_ID"] = "alias/tokendna-ca"
    os.environ.pop("ATTESTATION_KMS_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    try:
        signer = build_signer()
        assert isinstance(signer, AWSKMSTrustSigner)
    finally:
        os.environ.pop("ATTESTATION_KEY_BACKEND", None)
        os.environ.pop("AWS_KMS_KEY_ID", None)


# ── Key rotation tests ──────────────────────────────────────────────────────


def test_rotate_active_key_appends_to_keyring_and_sets_active():
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps([
        {"key_id": "ca-2025", "algorithm": "RS256", "backend": "aws_kms",
         "kms_key_id": "alias/tokendna-ca-2025"},
    ])
    os.environ["ATTESTATION_ACTIVE_KEY_ID"] = "ca-2025"
    try:
        result = rotate_active_key(
            "ca-2026",
            algorithm="RS256",
            backend="aws_kms",
            kms_key_id="alias/tokendna-ca-2026",
        )
        assert result["previous_active_key_id"] == "ca-2025"
        assert result["new_active_key_id"] == "ca-2026"
        assert os.environ["ATTESTATION_ACTIVE_KEY_ID"] == "ca-2026"
        configs = {r["key_id"] for r in list_key_configs()}
        assert configs == {"ca-2025", "ca-2026"}
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)
        os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)


def test_rotate_active_key_dry_run_does_not_mutate_environ():
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    try:
        result = rotate_active_key(
            "ca-2026", algorithm="RS256", backend="aws_kms",
            kms_key_id="alias/tokendna-ca-2026", apply=False,
        )
        assert result["applied"] == "false"
        assert result["new_active_key_id"] == "ca-2026"
        # Did NOT touch env
        assert "ATTESTATION_KEYRING_JSON" not in os.environ
        assert "ATTESTATION_ACTIVE_KEY_ID" not in os.environ
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)
        os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)


def test_rotate_active_key_rejects_existing_id():
    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps([
        {"key_id": "ca-2025", "algorithm": "RS256", "backend": "aws_kms",
         "kms_key_id": "alias/tokendna-ca-2025"},
    ])
    try:
        with pytest.raises(TrustSignerError):
            rotate_active_key("ca-2025", algorithm="RS256", backend="aws_kms",
                              kms_key_id="alias/tokendna-ca-2025")
    finally:
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)


def test_full_rotation_flow_old_certs_still_validate():
    """
    The plan's explicit acceptance criterion:
      issue cert with KMS key → rotate key → verify old cert still validates →
      issue new cert with new key → verify new cert validates.

    Uses the stub KMS client so this runs without boto3 / network.
    """
    from modules.identity import attestation_certificates as ac
    from modules.identity import trust_authority as ta

    # Map each KMS KeyId to its own stub so rotation actually changes the keyset
    stubs: dict[str, _StubKMSClient] = {}
    def factory_for(kms_key_id):
        stubs.setdefault(kms_key_id, _StubKMSClient())
        return lambda: stubs[kms_key_id]

    # Monkey-patch _build_from_key_config so it injects our client_factory.
    # Cleaner than threading client_factory through the public API.
    real_build = ta._build_from_key_config
    def patched_build(cfg, *, secret_override=None):
        if cfg.backend in ("aws_kms", "cloudhsm") and cfg.kms_key_id:
            cls = ta.CloudHSMTrustSigner if cfg.backend == "cloudhsm" else ta.AWSKMSTrustSigner
            return cls(kms_key_id=cfg.kms_key_id, key_id=cfg.key_id,
                       client_factory=factory_for(cfg.kms_key_id))
        return real_build(cfg, secret_override=secret_override)

    os.environ["ATTESTATION_KEYRING_JSON"] = json.dumps([
        {"key_id": "ca-2025", "algorithm": "RS256", "backend": "aws_kms",
         "kms_key_id": "alias/tokendna-ca-2025"},
    ])
    os.environ["ATTESTATION_ACTIVE_KEY_ID"] = "ca-2025"
    ta._build_from_key_config = patched_build
    try:
        # 1. Issue cert with the original key
        old_cert = ac.issue_certificate_with_key(
            tenant_id="t1", attestation_id="att-1",
            subject="agent-A", issuer="trust-authority",
            claims={"role": "worker"}, key_id="ca-2025", algorithm="RS256",
        )
        assert old_cert["ca_key_id"] == "ca-2025"
        first_check = ac.verify_certificate(old_cert)
        assert first_check["valid"] is True

        # 2. Rotate to ca-2026
        ta.rotate_active_key("ca-2026", algorithm="RS256", backend="aws_kms",
                             kms_key_id="alias/tokendna-ca-2026")

        # 3. Old cert STILL validates (uses ca-2025 entry from keyring)
        post_rotation_check = ac.verify_certificate(old_cert)
        assert post_rotation_check["valid"] is True, post_rotation_check

        # 4. Issue new cert under the rotated active key
        new_cert = ac.issue_certificate_with_key(
            tenant_id="t1", attestation_id="att-2",
            subject="agent-B", issuer="trust-authority",
            claims={"role": "worker"}, key_id="ca-2026", algorithm="RS256",
        )
        assert new_cert["ca_key_id"] == "ca-2026"

        # 5. New cert validates against its own key
        new_check = ac.verify_certificate(new_cert)
        assert new_check["valid"] is True

        # 6. Cross-key forgery attempt: take the new cert's signature, claim
        #    it was issued by the old key — should fail.
        forged = dict(new_cert)
        forged["ca_key_id"] = "ca-2025"
        forged_check = ac.verify_certificate(forged)
        assert forged_check["valid"] is False
    finally:
        ta._build_from_key_config = real_build
        os.environ.pop("ATTESTATION_KEYRING_JSON", None)
        os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
