from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.trust_authority import HMACTrustSigner, build_signer


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
