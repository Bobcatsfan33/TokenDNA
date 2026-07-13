"""
TokenDNA Sprint 5 — Tests for RFC 9449 DPoP Proof-of-Possession.

Covers:
  - DPoPVerifier.verify() — happy path, malformed proofs, algorithm enforcement
  - Claim validation: typ, alg, jwk, jti, htm, htu, iat, ath
  - Clock skew enforcement
  - Redis JTI replay detection (mocked)
  - Nonce enforcement
  - verify_dpop_proof() convenience function
  - DPoPError hierarchy (DPoPReplayError, DPoPAlgorithmError)
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from base64 import urlsafe_b64encode
from typing import Optional
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.dpop import (
    DPOP_ALLOWED_ALGORITHMS,
    DPOP_MAX_AGE_SECONDS,
    DPoPAlgorithmError,
    DPoPError,
    DPoPProof,
    DPoPReplayError,
    DPoPVerifier,
    verify_dpop_proof,
)


# ---------------------------------------------------------------------------
# Helpers — build minimal DPoP proof JWTs for testing
# The DPoP proof JWT format:
#   Header: {"typ": "dpop+jwt", "alg": "ES256", "jwk": {...}}
#   Payload: {"jti": ..., "htm": "GET", "htu": "https://...", "iat": ...}
#   Signature: (mocked / ignored in tests that skip sig verification)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_proof(
    typ: str = "dpop+jwt",
    alg: str = "ES256",
    jwk: Optional[dict] = None,
    jti: Optional[str] = None,
    htm: str = "GET",
    htu: str = "https://api.example.com/token",
    iat: Optional[int] = None,
    ath: Optional[str] = None,
    nonce: Optional[str] = None,
) -> str:
    """Build a fake DPoP JWT (unsigned — signature bytes are zeroed)."""
    if iat is None:
        iat = int(time.time())
    if jti is None:
        jti = uuid.uuid4().hex
    if jwk is None:
        jwk = {"kty": "EC", "crv": "P-256", "x": "fake_x", "y": "fake_y"}

    header = {"typ": typ, "alg": alg, "jwk": jwk}
    payload = {"jti": jti, "htm": htm, "htu": htu, "iat": iat}
    if ath is not None:
        payload["ath"] = ath
    if nonce is not None:
        payload["nonce"] = nonce

    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    # Fake signature — sig verification is skipped when python-jose isn't available
    sig_b64 = _b64url(b"\x00" * 64)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _make_verifier(redis=None, require_nonce: bool = False) -> DPoPVerifier:
    v = DPoPVerifier(redis_client=redis, require_nonce=require_nonce)
    # Patch signature verification so tests work without real EC keys.
    # The signature check is separate from claim validation — we test
    # claim validation logic; signature crypto is covered by python-jose tests.
    from unittest.mock import patch as _patch
    _patcher = _patch.object(v, "_verify_signature", return_value=None)
    _patcher.start()
    # Store patcher so it can be stopped (no teardown needed in test process)
    v._test_sig_patcher = _patcher  # type: ignore[attr-defined]
    return v


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------


class TestDPoPAlgorithmTable:
    def test_es256_allowed(self):
        assert "ES256" in DPOP_ALLOWED_ALGORITHMS

    def test_rs256_allowed(self):
        assert "RS256" in DPOP_ALLOWED_ALGORITHMS

    def test_ps256_allowed(self):
        assert "PS256" in DPOP_ALLOWED_ALGORITHMS

    def test_eddsa_allowed(self):
        assert "EdDSA" in DPOP_ALLOWED_ALGORITHMS

    def test_hs256_not_allowed(self):
        assert "HS256" not in DPOP_ALLOWED_ALGORITHMS

    def test_none_not_allowed(self):
        assert "none" not in DPOP_ALLOWED_ALGORITHMS


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestDPoPVerifierHappyPath:
    def test_verify_returns_dpop_proof(self):
        v = _make_verifier()
        proof = _make_proof()
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert isinstance(result, DPoPProof)

    def test_verify_proof_alg(self):
        v = _make_verifier()
        proof = _make_proof(alg="ES256")
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert result.alg == "ES256"

    def test_verify_proof_htm(self):
        v = _make_verifier()
        proof = _make_proof(htm="POST")
        result = v.verify(proof, "POST", "https://api.example.com/token")
        assert result.htm == "POST"

    def test_verify_proof_htu(self):
        v = _make_verifier()
        uri = "https://api.example.com/resource"
        proof = _make_proof(htu=uri)
        result = v.verify(proof, "GET", uri)
        assert result.htu == uri

    def test_verify_proof_jti_populated(self):
        v = _make_verifier()
        jti = uuid.uuid4().hex
        proof = _make_proof(jti=jti)
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert result.jti == jti

    def test_verify_proof_iat_populated(self):
        v = _make_verifier()
        now = int(time.time())
        proof = _make_proof(iat=now)
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert result.iat == now

    def test_verify_case_insensitive_method(self):
        v = _make_verifier()
        proof = _make_proof(htm="GET")
        # Should accept case-insensitive match
        result = v.verify(proof, "get", "https://api.example.com/token")
        assert result is not None


# ---------------------------------------------------------------------------
# Claim validation failures
# ---------------------------------------------------------------------------


class TestDPoPVerifierClaimValidation:
    def test_wrong_typ_raises(self):
        v = _make_verifier()
        proof = _make_proof(typ="JWT")
        with pytest.raises(DPoPError, match="typ"):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_disallowed_alg_raises(self):
        v = _make_verifier()
        proof = _make_proof(alg="HS256")
        with pytest.raises(DPoPAlgorithmError):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_missing_jwk_raises(self):
        v = _make_verifier()
        # Build proof without jwk in header
        header = {"typ": "dpop+jwt", "alg": "ES256"}  # no jwk
        payload = {"jti": uuid.uuid4().hex, "htm": "GET",
                   "htu": "https://api.example.com/token", "iat": int(time.time())}
        h = _b64url(json.dumps(header).encode())
        p = _b64url(json.dumps(payload).encode())
        s = _b64url(b"\x00" * 64)
        proof = f"{h}.{p}.{s}"
        with pytest.raises(DPoPError, match="jwk"):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_missing_jti_raises(self):
        v = _make_verifier()
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {"kty": "EC"}}
        payload = {"htm": "GET", "htu": "https://api.example.com/token",
                   "iat": int(time.time())}
        h = _b64url(json.dumps(header).encode())
        p = _b64url(json.dumps(payload).encode())
        s = _b64url(b"\x00" * 64)
        with pytest.raises(DPoPError, match="jti"):
            v.verify(f"{h}.{p}.{s}", "GET", "https://api.example.com/token")

    def test_htm_mismatch_raises(self):
        v = _make_verifier()
        proof = _make_proof(htm="POST")
        with pytest.raises(DPoPError, match="htm"):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_htu_mismatch_raises(self):
        v = _make_verifier()
        proof = _make_proof(htu="https://api.example.com/token")
        with pytest.raises(DPoPError, match="htu"):
            v.verify(proof, "GET", "https://other.example.com/token")

    def test_expired_iat_raises(self):
        v = _make_verifier()
        old_iat = int(time.time()) - DPOP_MAX_AGE_SECONDS - 10
        proof = _make_proof(iat=old_iat)
        with pytest.raises(DPoPError, match="iat"):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_future_iat_raises(self):
        v = _make_verifier()
        future_iat = int(time.time()) + DPOP_MAX_AGE_SECONDS + 10
        proof = _make_proof(iat=future_iat)
        with pytest.raises(DPoPError, match="iat"):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_not_a_jwt_raises(self):
        v = _make_verifier()
        with pytest.raises(DPoPError):
            v.verify("not.a.valid.jwt.with.too.many.parts", "GET", "https://example.com")


# ---------------------------------------------------------------------------
# Access token hash (ath)
# ---------------------------------------------------------------------------


class TestDPoPAth:
    def _make_ath(self, access_token: str) -> str:
        digest = hashlib.sha256(access_token.encode()).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode()

    def test_valid_ath_passes(self):
        v = _make_verifier()
        access_token = "eyJhbGciOiJFUzI1NiJ9.fakepayload.fakesig"
        ath = self._make_ath(access_token)
        proof = _make_proof(ath=ath)
        result = v.verify(proof, "GET", "https://api.example.com/token",
                          access_token=access_token)
        assert result.ath == ath

    def test_missing_ath_when_token_provided_raises(self):
        v = _make_verifier()
        proof = _make_proof()  # no ath
        with pytest.raises(DPoPError, match="ath"):
            v.verify(proof, "GET", "https://api.example.com/token",
                     access_token="some_access_token")

    def test_wrong_ath_raises(self):
        v = _make_verifier()
        proof = _make_proof(ath="wrong_ath_value")
        with pytest.raises(DPoPError, match="ath"):
            v.verify(proof, "GET", "https://api.example.com/token",
                     access_token="the_actual_access_token")


# ---------------------------------------------------------------------------
# Redis JTI replay detection
# ---------------------------------------------------------------------------


class TestDPoPReplayDetection:
    def _fresh_redis_mock(self, already_seen: bool = False):
        r = MagicMock()
        # Redis SET NX: returns True on first set, None/False on subsequent
        r.set.return_value = None if already_seen else True
        return r

    def test_first_jti_allowed(self):
        r = self._fresh_redis_mock(already_seen=False)
        v = _make_verifier(redis=r)
        proof = _make_proof()
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert isinstance(result, DPoPProof)
        r.set.assert_called_once()

    def test_replayed_jti_raises(self):
        r = self._fresh_redis_mock(already_seen=True)
        v = _make_verifier(redis=r)
        proof = _make_proof()
        with pytest.raises(DPoPReplayError):
            v.verify(proof, "GET", "https://api.example.com/token")

    def test_no_redis_does_not_raise(self):
        """Without Redis, replay protection is skipped (dev mode)."""
        v = _make_verifier(redis=None)
        proof = _make_proof()
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert isinstance(result, DPoPProof)

    def test_redis_error_does_not_crash(self):
        """If Redis throws (not DPoPReplayError), it should be caught gracefully."""
        r = MagicMock()
        r.set.side_effect = ConnectionError("Redis down")
        v = _make_verifier(redis=r)
        proof = _make_proof()
        # Should not raise (Redis errors are logged as warnings)
        result = v.verify(proof, "GET", "https://api.example.com/token")
        assert isinstance(result, DPoPProof)


# ---------------------------------------------------------------------------
# Nonce enforcement
# ---------------------------------------------------------------------------


class TestDPoPNonce:
    def test_nonce_accepted_when_valid(self):
        v = _make_verifier(require_nonce=True)
        nonce = uuid.uuid4().hex
        proof = _make_proof(nonce=nonce)
        result = v.verify(proof, "GET", "https://api.example.com/token",
                          expected_nonce=nonce)
        assert isinstance(result, DPoPProof)

    def test_nonce_mismatch_raises(self):
        v = _make_verifier(require_nonce=True)
        proof = _make_proof(nonce="correct-nonce")
        with pytest.raises(DPoPError, match="nonce"):
            v.verify(proof, "GET", "https://api.example.com/token",
                     expected_nonce="different-nonce")

    def test_missing_nonce_raises(self):
        v = _make_verifier(require_nonce=True)
        proof = _make_proof()  # no nonce
        with pytest.raises(DPoPError, match="nonce"):
            v.verify(proof, "GET", "https://api.example.com/token",
                     expected_nonce="some-nonce")

    def test_nonce_not_required_without_flag(self):
        v = _make_verifier(require_nonce=False)
        proof = _make_proof()  # no nonce
        result = v.verify(proof, "GET", "https://api.example.com/token",
                          expected_nonce="some-nonce")
        assert isinstance(result, DPoPProof)

    def test_issue_nonce_returns_string(self):
        v = _make_verifier()
        nonce = v.issue_nonce()
        assert isinstance(nonce, str)
        assert len(nonce) > 0

    def test_issue_nonce_unique(self):
        v = _make_verifier()
        n1 = v.issue_nonce()
        n2 = v.issue_nonce()
        assert n1 != n2

    def test_issue_nonce_stores_in_redis(self):
        r = MagicMock()
        v = _make_verifier(redis=r)
        nonce = v.issue_nonce()
        r.set.assert_called_once()
        call_args = r.set.call_args
        assert nonce in call_args[0][0]  # key contains nonce


# ---------------------------------------------------------------------------
# verify_dpop_proof convenience function
# ---------------------------------------------------------------------------


class TestVerifyDPoPProofFunction:
    def test_returns_dpop_proof(self):
        from unittest.mock import patch
        proof = _make_proof()
        with patch.object(DPoPVerifier, "_verify_signature", return_value=None):
            result = verify_dpop_proof(proof, "GET", "https://api.example.com/token")
        assert isinstance(result, DPoPProof)

    def test_invalid_proof_raises(self):
        # A JWT with wrong number of parts should raise DPoPError
        with pytest.raises((DPoPError, Exception)):
            verify_dpop_proof("only.two", "GET", "https://example.com")
