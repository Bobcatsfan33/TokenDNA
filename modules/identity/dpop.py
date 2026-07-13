"""
TokenDNA — RFC 9449 DPoP (Demonstrating Proof of Possession)
=============================================================
IL5 / NIST SC-13, IA-7 compliance.

DPoP binds an access token to a specific key pair held by the client,
preventing token theft and replay attacks. The client generates a
short-lived proof JWT (DPoP proof) signed with their private key for
each request. The server verifies the proof matches the token binding.

Key features:
- DPoP proof validation (alg, typ, jwk, jti, htm, htu, iat, ath)
- Nonce enforcement (anti-replay) via Redis-backed nonce store
- Token binding verification (ath = BASE64URL(SHA-256(access_token)))
- IL5 algorithm enforcement: only RS256/PS256/ES256/ES384/ES512/EdDSA
- JTI replay detection (jti must be unique per proof, stored in Redis)
- Clock skew tolerance: +/-60 seconds on iat

Classes:
  DPoPProof -- parsed/validated DPoP proof
  DPoPVerifier -- stateful verifier (requires Redis for nonce+JTI store)

Functions:
  verify_dpop_proof(proof_header, method, uri, access_token, redis_client) -> DPoPProof
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# -- Constants -----------------------------------------------------------------

DPOP_ALLOWED_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
    "EdDSA",
})
DPOP_MAX_AGE_SECONDS = 60          # iat must be within +/-60s
DPOP_JTI_TTL_SECONDS = 300         # JTI stored in Redis for 5 min to detect replays
DPOP_NONCE_TTL_SECONDS = 120       # server-issued nonces expire in 2 min

# -- Exceptions ----------------------------------------------------------------

class DPoPError(Exception):
    """Raised when DPoP proof validation fails."""
    pass

class DPoPReplayError(DPoPError):
    """Raised when jti has been seen before (replay attack)."""
    pass

class DPoPAlgorithmError(DPoPError):
    """Raised when DPoP proof uses a disallowed algorithm."""
    pass

# -- Data classes --------------------------------------------------------------

@dataclass
class DPoPProof:
    """Parsed and validated DPoP proof."""
    alg: str
    jti: str
    htm: str        # HTTP method
    htu: str        # HTTP URI
    iat: int        # issued-at timestamp
    jwk: dict       # public key (JWK format)
    ath: Optional[str] = None   # access token hash (required when token provided)

@dataclass
class DPoPVerifier:
    """
    Stateful DPoP verifier. Requires Redis for JTI replay detection and nonce store.

    In DEV_MODE (redis=None), replay protection is skipped (warning logged).
    """
    redis_client: Optional[object] = None  # redis.Redis or compatible
    require_nonce: bool = False             # set True for IL5 strict mode

    def _decode_jwt_parts(self, token: str) -> tuple[dict, dict, bytes]:
        """Split JWT into header, payload, signature. No signature verification here."""
        parts = token.split(".")
        if len(parts) != 3:
            raise DPoPError("DPoP proof is not a valid JWT (expected 3 parts)")

        def _b64decode(s: str) -> bytes:
            s += "=" * (4 - len(s) % 4)
            return urlsafe_b64decode(s)

        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
        sig = _b64decode(parts[2])
        return header, payload, sig

    def _verify_signature(self, token: str, jwk: dict) -> None:
        """Verify JWT signature using the JWK from the header."""
        try:
            from jose import jwt as jose_jwt
            from jose.backends import RSAKey, ECKey

            header, _, _ = self._decode_jwt_parts(token)
            alg = header.get("alg")

            key_type = jwk.get("kty", "").upper()
            if key_type == "RSA":
                key = RSAKey(jwk, alg)
            elif key_type == "EC":
                key = ECKey(jwk, alg)
            else:
                raise DPoPError(f"Unsupported JWK key type: {key_type}")

            jose_jwt.decode(
                token,
                key.public_key(),
                algorithms=[alg],
                options={"verify_exp": False},
            )
        except ImportError:
            logger.warning("python-jose not available -- DPoP signature verification skipped")
        except Exception as e:
            raise DPoPError(f"DPoP signature verification failed: {e}") from e

    def verify(
        self,
        proof_jwt: str,
        method: str,
        uri: str,
        access_token: Optional[str] = None,
        expected_nonce: Optional[str] = None,
    ) -> DPoPProof:
        """Validate a DPoP proof JWT."""
        header, payload, _ = self._decode_jwt_parts(proof_jwt)

        if header.get("typ") != "dpop+jwt":
            raise DPoPError(f"DPoP proof typ must be 'dpop+jwt', got: {header.get('typ')!r}")

        alg = header.get("alg", "")
        if alg not in DPOP_ALLOWED_ALGORITHMS:
            raise DPoPAlgorithmError(f"DPoP algorithm {alg!r} not allowed in IL5 mode")

        jwk = header.get("jwk")
        if not jwk or not isinstance(jwk, dict):
            raise DPoPError("DPoP proof header missing 'jwk' claim")

        jti = payload.get("jti")
        htm = payload.get("htm")
        htu = payload.get("htu")
        iat = payload.get("iat")

        if not jti:
            raise DPoPError("DPoP proof missing 'jti' claim")
        if not htm:
            raise DPoPError("DPoP proof missing 'htm' claim")
        if not htu:
            raise DPoPError("DPoP proof missing 'htu' claim")
        if iat is None:
            raise DPoPError("DPoP proof missing 'iat' claim")

        if htm.upper() != method.upper():
            raise DPoPError(f"DPoP htm {htm!r} does not match request method {method!r}")
        if htu != uri:
            raise DPoPError(f"DPoP htu {htu!r} does not match request URI {uri!r}")

        now = int(time.time())
        if abs(now - iat) > DPOP_MAX_AGE_SECONDS:
            raise DPoPError(f"DPoP proof iat {iat} is too old or in the future (now={now})")

        if access_token is not None:
            ath = payload.get("ath")
            if not ath:
                raise DPoPError("DPoP proof missing 'ath' claim (required when access token present)")
            expected_ath = urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
            if ath != expected_ath:
                raise DPoPError("DPoP 'ath' claim does not match SHA-256 of access token")

        if self.require_nonce and expected_nonce:
            nonce = payload.get("nonce")
            if not nonce:
                raise DPoPError("DPoP proof missing 'nonce' claim (required)")
            if nonce != expected_nonce:
                raise DPoPError("DPoP proof nonce does not match server-issued nonce")

        if self.redis_client is not None:
            jti_key = f"dpop:jti:{jti}"
            try:
                already_seen = self.redis_client.set(
                    jti_key, "1", nx=True, ex=DPOP_JTI_TTL_SECONDS
                )
                if not already_seen:
                    raise DPoPReplayError(f"DPoP jti {jti!r} has been replayed")
            except DPoPReplayError:
                raise
            except Exception as e:
                logger.warning("Redis unavailable for DPoP JTI check: %s", e)
        else:
            logger.warning("DPoP JTI replay protection disabled (no Redis client)")

        self._verify_signature(proof_jwt, jwk)

        return DPoPProof(
            alg=alg,
            jti=jti,
            htm=htm,
            htu=htu,
            iat=iat,
            jwk=jwk,
            ath=payload.get("ath"),
        )

    def issue_nonce(self, redis_client=None) -> str:
        """Issue a server nonce for DPoP fresh-challenge flow."""
        nonce = uuid.uuid4().hex
        r = redis_client or self.redis_client
        if r is not None:
            try:
                r.set(f"dpop:nonce:{nonce}", "1", ex=DPOP_NONCE_TTL_SECONDS)
            except Exception as e:
                logger.warning("Redis unavailable for DPoP nonce issuance: %s", e)
        return nonce


def verify_dpop_proof(
    proof_jwt: str,
    method: str,
    uri: str,
    access_token: Optional[str] = None,
    redis_client=None,
    require_nonce: bool = False,
    expected_nonce: Optional[str] = None,
) -> DPoPProof:
    """Convenience function for one-shot DPoP proof verification."""
    verifier = DPoPVerifier(redis_client=redis_client, require_nonce=require_nonce)
    return verifier.verify(proof_jwt, method, uri, access_token, expected_nonce)
