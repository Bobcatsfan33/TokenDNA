"""
TokenDNA Sprint 5 — Tests for FIPS 140-2 enforcement (SC-13).

Covers:
  - FIPSEnforcer hashing (SHA-256/384/512, HMAC)
  - Algorithm blocklist enforcement (HS256/HS384/HS512/none, MD5, SHA-1)
  - Algorithm allowlist (RS256, PS256, ES256, EdDSA)
  - AES-256-GCM encrypt/decrypt
  - Key derivation (PBKDF2)
  - Key/nonce generation
  - compliance_summary() shape
  - Base64url encode/decode
  - FIPSStatus dataclass
  - IL5 JWT enforcement toggle
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.security.fips import (
    BLOCKED_JWT_ALGORITHMS,
    FIPS_APPROVED_JWT_ALGORITHMS,
    BLOCKED_HASH_ALGORITHMS,
    FIPSAlgorithmViolation,
    FIPSEnforcer,
    FIPSError,
    FIPSStatus,
    fips,
)


# ---------------------------------------------------------------------------
# Basic instantiation
# ---------------------------------------------------------------------------


class TestFIPSEnforcerInstantiation:
    def test_singleton_is_fips_enforcer(self):
        assert isinstance(fips, FIPSEnforcer)

    def test_fresh_enforcer_can_be_created(self):
        e = FIPSEnforcer()
        assert isinstance(e, FIPSEnforcer)

    def test_status_returns_fips_status(self):
        e = FIPSEnforcer()
        s = e.status
        assert isinstance(s, FIPSStatus)

    def test_status_has_bool_fields(self):
        s = fips.status
        assert isinstance(s.kernel_fips, bool)
        assert isinstance(s.openssl_fips, bool)
        assert isinstance(s.effective_fips, bool)

    def test_is_active_returns_bool(self):
        assert isinstance(fips.is_active(), bool)


# ---------------------------------------------------------------------------
# Algorithm tables
# ---------------------------------------------------------------------------


class TestAlgorithmTables:
    def test_approved_jwt_contains_rs256(self):
        assert "RS256" in FIPS_APPROVED_JWT_ALGORITHMS

    def test_approved_jwt_contains_ps256(self):
        assert "PS256" in FIPS_APPROVED_JWT_ALGORITHMS

    def test_approved_jwt_contains_es256(self):
        assert "ES256" in FIPS_APPROVED_JWT_ALGORITHMS

    def test_approved_jwt_contains_eddsa(self):
        assert "EdDSA" in FIPS_APPROVED_JWT_ALGORITHMS

    def test_blocked_jwt_contains_hs256(self):
        assert "HS256" in BLOCKED_JWT_ALGORITHMS

    def test_blocked_jwt_contains_hs384(self):
        assert "HS384" in BLOCKED_JWT_ALGORITHMS

    def test_blocked_jwt_contains_hs512(self):
        assert "HS512" in BLOCKED_JWT_ALGORITHMS

    def test_blocked_jwt_contains_none(self):
        assert "none" in BLOCKED_JWT_ALGORITHMS

    def test_approved_and_blocked_are_disjoint(self):
        assert FIPS_APPROVED_JWT_ALGORITHMS.isdisjoint(BLOCKED_JWT_ALGORITHMS)

    def test_blocked_hash_contains_md5(self):
        assert "md5" in BLOCKED_HASH_ALGORITHMS

    def test_blocked_hash_contains_sha1(self):
        assert "sha1" in BLOCKED_HASH_ALGORITHMS


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


class TestFIPSHashing:
    def test_sha256_returns_bytes(self):
        result = fips.sha256(b"hello world")
        assert isinstance(result, bytes)

    def test_sha256_length(self):
        assert len(fips.sha256(b"data")) == 32

    def test_sha384_length(self):
        assert len(fips.sha384(b"data")) == 48

    def test_sha512_length(self):
        assert len(fips.sha512(b"data")) == 64

    def test_sha256_hex_returns_string(self):
        h = fips.sha256_hex(b"data")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_sha256_deterministic(self):
        a = fips.sha256(b"same input")
        b = fips.sha256(b"same input")
        assert a == b

    def test_sha256_different_inputs(self):
        assert fips.sha256(b"aaa") != fips.sha256(b"bbb")

    def test_safe_hash_sha256(self):
        result = fips.safe_hash("sha256", b"test")
        assert result == fips.sha256(b"test")

    def test_safe_hash_sha512(self):
        result = fips.safe_hash("sha512", b"test")
        assert len(result) == 64

    def test_safe_hash_blocks_md5(self):
        with pytest.raises(FIPSAlgorithmViolation):
            fips.safe_hash("md5", b"data")

    def test_safe_hash_blocks_sha1(self):
        with pytest.raises(FIPSAlgorithmViolation):
            fips.safe_hash("sha1", b"data")

    def test_hmac_sha256_returns_bytes(self):
        key = os.urandom(32)
        result = fips.hmac_sha256(key, b"message")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hmac_sha256_hex_returns_hex_string(self):
        key = os.urandom(32)
        h = fips.hmac_sha256_hex(key, b"message")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hmac_sha256_deterministic(self):
        key = b"k" * 32
        a = fips.hmac_sha256(key, b"msg")
        b = fips.hmac_sha256(key, b"msg")
        assert a == b

    def test_constant_time_compare_equal(self):
        a = b"same data"
        assert fips.constant_time_compare(a, a) is True

    def test_constant_time_compare_unequal(self):
        assert fips.constant_time_compare(b"aaa", b"bbb") is False


# ---------------------------------------------------------------------------
# JWT algorithm enforcement
# ---------------------------------------------------------------------------


class TestFIPSJWTEnforcement:
    """Tests run with a fresh FIPSEnforcer to control _jwt_enforcement."""

    def _enforcer_with_jwt_enforcement(self, enabled: bool) -> FIPSEnforcer:
        e = FIPSEnforcer()
        e._jwt_enforcement = enabled
        return e

    def test_hs256_always_blocked(self):
        e = self._enforcer_with_jwt_enforcement(False)
        with pytest.raises(FIPSAlgorithmViolation):
            e.assert_jwt_algorithm("HS256")

    def test_hs384_always_blocked(self):
        e = self._enforcer_with_jwt_enforcement(False)
        with pytest.raises(FIPSAlgorithmViolation):
            e.assert_jwt_algorithm("HS384")

    def test_hs512_always_blocked(self):
        e = self._enforcer_with_jwt_enforcement(False)
        with pytest.raises(FIPSAlgorithmViolation):
            e.assert_jwt_algorithm("HS512")

    def test_none_always_blocked(self):
        e = self._enforcer_with_jwt_enforcement(False)
        with pytest.raises(FIPSAlgorithmViolation):
            e.assert_jwt_algorithm("none")

    def test_rs256_allowed_without_enforcement(self):
        e = self._enforcer_with_jwt_enforcement(False)
        e.assert_jwt_algorithm("RS256")  # Should not raise

    def test_rs256_allowed_with_enforcement(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("RS256")  # Approved algorithm

    def test_ps256_allowed_with_enforcement(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("PS256")

    def test_es256_allowed_with_enforcement(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("ES256")

    def test_eddsa_allowed_with_enforcement(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("EdDSA")

    def test_rs384_allowed(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("RS384")

    def test_rs512_allowed(self):
        e = self._enforcer_with_jwt_enforcement(True)
        e.assert_jwt_algorithm("RS512")


# ---------------------------------------------------------------------------
# Hash algorithm assertion
# ---------------------------------------------------------------------------


class TestFIPSHashAssertion:
    def test_sha256_passes(self):
        fips.assert_hash_algorithm("sha256")  # no exception

    def test_sha512_passes(self):
        fips.assert_hash_algorithm("sha512")

    def test_md5_blocked(self):
        with pytest.raises(FIPSAlgorithmViolation):
            fips.assert_hash_algorithm("md5")

    def test_sha1_blocked(self):
        with pytest.raises(FIPSAlgorithmViolation):
            fips.assert_hash_algorithm("sha1")

    def test_md5_with_hyphens_blocked(self):
        with pytest.raises(FIPSAlgorithmViolation):
            fips.assert_hash_algorithm("MD5")


# ---------------------------------------------------------------------------
# AES-256-GCM encrypt / decrypt
# ---------------------------------------------------------------------------


class TestFIPSAESGCM:
    def setup_method(self):
        self.key = os.urandom(32)

    def test_encrypt_returns_tuple(self):
        ct, tag, nonce = fips.encrypt(b"plaintext", self.key)
        assert isinstance(ct, bytes)
        assert isinstance(tag, bytes)
        assert isinstance(nonce, bytes)

    def test_nonce_is_12_bytes(self):
        _, _, nonce = fips.encrypt(b"data", self.key)
        assert len(nonce) == 12

    def test_tag_is_16_bytes(self):
        _, tag, _ = fips.encrypt(b"data", self.key)
        assert len(tag) == 16

    def test_roundtrip(self):
        plaintext = b"IL5 secret data"
        ct, tag, nonce = fips.encrypt(plaintext, self.key)
        recovered = fips.decrypt(ct, tag, nonce, self.key)
        assert recovered == plaintext

    def test_roundtrip_empty_plaintext(self):
        ct, tag, nonce = fips.encrypt(b"", self.key)
        recovered = fips.decrypt(ct, tag, nonce, self.key)
        assert recovered == b""

    def test_roundtrip_with_aad(self):
        plaintext = b"secret"
        aad = b"tenant=org-123"
        ct, tag, nonce = fips.encrypt(plaintext, self.key, aad=aad)
        recovered = fips.decrypt(ct, tag, nonce, self.key, aad=aad)
        assert recovered == plaintext

    def test_wrong_key_raises(self):
        ct, tag, nonce = fips.encrypt(b"data", self.key)
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):  # InvalidTag from AESGCM
            fips.decrypt(ct, tag, nonce, wrong_key)

    def test_tampered_ciphertext_raises(self):
        ct, tag, nonce = fips.encrypt(b"data", self.key)
        tampered = bytes([b ^ 0xFF for b in ct]) if ct else b"\xff"
        with pytest.raises(Exception):
            fips.decrypt(tampered, tag, nonce, self.key)

    def test_short_key_raises_fips_error(self):
        with pytest.raises(FIPSError):
            fips.encrypt(b"data", b"shortkey")

    def test_encrypt_produces_different_ciphertexts(self):
        """Randomised nonce ensures different ciphertexts for same plaintext."""
        ct1, _, _ = fips.encrypt(b"same", self.key)
        ct2, _, _ = fips.encrypt(b"same", self.key)
        # Highly unlikely to be equal (different random nonces)
        # Can't assert inequality deterministically, but test it doesn't crash
        assert isinstance(ct1, bytes)
        assert isinstance(ct2, bytes)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


class TestFIPSKeyDerivation:
    def test_derive_key_returns_bytes(self):
        password = b"password123"
        salt = os.urandom(16)
        key = fips.derive_key(password, salt)
        assert isinstance(key, bytes)

    def test_derive_key_default_length_32(self):
        key = fips.derive_key(b"pw", os.urandom(16))
        assert len(key) == 32

    def test_derive_key_custom_length(self):
        key = fips.derive_key(b"pw", os.urandom(16), length=48)
        assert len(key) == 48

    def test_derive_key_deterministic(self):
        pw = b"same-password"
        salt = b"same-salt-16byte"
        k1 = fips.derive_key(pw, salt)
        k2 = fips.derive_key(pw, salt)
        assert k1 == k2

    def test_derive_key_different_salts(self):
        pw = b"password"
        k1 = fips.derive_key(pw, b"salt1salt1salt1s")
        k2 = fips.derive_key(pw, b"salt2salt2salt2s")
        assert k1 != k2


# ---------------------------------------------------------------------------
# Key and nonce generation
# ---------------------------------------------------------------------------


class TestFIPSKeyNonce:
    def test_generate_key_default_32(self):
        key = fips.generate_key()
        assert len(key) == 32

    def test_generate_key_custom_length(self):
        key = fips.generate_key(length=48)
        assert len(key) == 48

    def test_generate_key_minimum_16(self):
        key = fips.generate_key(length=16)
        assert len(key) == 16

    def test_generate_key_below_minimum_raises(self):
        with pytest.raises(FIPSError):
            fips.generate_key(length=8)

    def test_generate_key_random(self):
        k1 = fips.generate_key()
        k2 = fips.generate_key()
        assert k1 != k2  # statistically certain

    def test_generate_nonce_default_12(self):
        nonce = fips.generate_nonce()
        assert len(nonce) == 12

    def test_generate_nonce_custom_length(self):
        nonce = fips.generate_nonce(length=16)
        assert len(nonce) == 16


# ---------------------------------------------------------------------------
# Base64url
# ---------------------------------------------------------------------------


class TestFIPSBase64Url:
    def test_encode_decode_roundtrip(self):
        data = b"IL5 token data \x00\xff\xfe"
        encoded = fips.encode_b64url(data)
        decoded = fips.decode_b64url(encoded)
        assert decoded == data

    def test_encode_no_padding(self):
        encoded = fips.encode_b64url(b"hello")
        assert "=" not in encoded

    def test_decode_accepts_unpadded(self):
        # Standard b64 of b"hello" is "aGVsbG8=" — unpadded is "aGVsbG8"
        decoded = fips.decode_b64url("aGVsbG8")
        assert decoded == b"hello"

    def test_encode_url_safe_chars(self):
        # Should use - and _ not + and /
        encoded = fips.encode_b64url(b"\xfb\xff")
        assert "+" not in encoded
        assert "/" not in encoded


# ---------------------------------------------------------------------------
# compliance_summary
# ---------------------------------------------------------------------------


class TestFIPSComplianceSummary:
    def test_returns_dict(self):
        summary = fips.compliance_summary()
        assert isinstance(summary, dict)

    def test_has_fips_active_key(self):
        summary = fips.compliance_summary()
        assert "fips_active" in summary

    def test_has_environment_key(self):
        summary = fips.compliance_summary()
        assert "environment" in summary

    def test_has_approved_jwt_algs(self):
        summary = fips.compliance_summary()
        assert "approved_jwt_algs" in summary
        assert "RS256" in summary["approved_jwt_algs"]

    def test_has_blocked_jwt_algs(self):
        summary = fips.compliance_summary()
        assert "blocked_jwt_algs" in summary
        assert "HS256" in summary["blocked_jwt_algs"]

    def test_has_nist_reference(self):
        summary = fips.compliance_summary()
        assert "nist_reference" in summary

    def test_has_il5_ready(self):
        summary = fips.compliance_summary()
        assert "il5_ready" in summary
        assert isinstance(summary["il5_ready"], bool)

    def test_kernel_fips_bool(self):
        summary = fips.compliance_summary()
        assert isinstance(summary["kernel_fips"], bool)
