from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.trust_authority import (
    HMACTrustSigner,
    build_signer,
    build_signer_for_key,
    list_key_configs,
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
