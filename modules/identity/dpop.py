"""
Aegis Security — DPoP (Demonstrating Proof of Possession) Enforcement  (v2.4.0)
RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession at the Application Layer

IA-2(1) / IA-5 / SC-8: Binds access tokens to the client's private key.
A stolen bearer token is USELESS without the corresponding private key.
This is the single most effective control against token theft.

IL5 requirement: All ANALYST+ API access must present a valid DPoP proof
when DPOP_REQUIRED=true. Tokens not bound to a DPoP key are rejected.

How DPoP works:
  1. Client generates an ephemeral EC/RSA key pair (per session or per request)
  2. Client sends: Authorization: DPoP <access_token>
                   DPoP: <signed_proof_jwt>
  3. Server verifies the proof JWT:
     a. alg must be ES256 or PS256 (FIPS-approved asymmetric)
     b. typ must be "dpop+jwt"
     c. jwk header contains the public key
     d. htm claim matches HTTP method
     e. htu claim matches request URL (without query string)
     f. iat is within ±60 seconds (replay window)
     g. jti is unique (not seen before — anti-replay via Redis)
     h. ath claim (if present) = BASE64URL(SHA-256(access_token))
        — binds the DPoP proof to this specific access token
  4. Server extracts the public key thumbprint (JWK SHA-256) and stores it
     with the session. All future requests for this session must present
     a DPoP proof signed by the same private key.

Replay prevention:
  jti values are stored in Redis with TTL = max_age_seconds (default 300s).
  Any jti seen twice within the window is rejected immediately.

Key binding:
  On first successful DPoP validation, the JWK thumbprint is stored in Redis
  under the token's jti or sub claim. All subsequent requests validate that
  the DPoP proof is signed by the same key.
"""

import hashlib
import json
import logging
import os
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from modules.security.fips import FIPSAlgorithmViolation, fips

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_DPOP_REQUIRED: bool    = os.getenv("DPOP_REQUIRED", "false").lower() == "true"
_DPOP_MAX_AGE_SEC: int  = int(os.getenv("DPOP_MAX_AGE_SECONDS", "60"))
_DPOP_CLOCK_SKEW: int   = int(os.getenv("DPOP_CLOCK_SKEW_SECONDS", "5"))
_DPOP_JTI_TTL: int      = int(os.getenv("DPOP_JTI_TTL_SECONDS", "300"))

# Approved DPoP proof algorithms (FIPS-approved asymmetric only)
_DPOP_APPROVED_ALGS = frozenset({"ES256", "ES384", "ES512", "PS256", "PS384", "PS512"})

# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class DPoPProof:
    """Validated DPoP proof context attached to a request."""
    jti:           str            # Unique proof ID
    htm:           str            # HTTP method from proof
    htu:           str            # HTTP URI from proof
    iat:           int            # Issued-at timestamp
    jwk_thumbprint: str           # SHA-256 thumbprint of the binding public key
    algorithm:     str            # Signing algorithm
    ath:           Optional[str]  # Access token hash (if present)
    public_key_jwk: dict          # Raw JWK from proof header


@dataclass
class DPoPContext:
    """Full DPoP validation result returned to endpoint handlers."""
    proof:         DPoPProof
    token_hash:    Optional[str]  # SHA-256 of the presented access token
    key_bound:     bool           # True if key was already known for this token
    first_use:     bool           # True if this is the first DPoP proof for this token


# ── Exceptions ────────────────────────────────────────────────────────────────

class DPoPError(Exception):
    """Base class for all DPoP validation errors."""
    pass

class DPoPMissingError(DPoPError):
    """DPoP header missing when required."""
    pass

class DPoPReplayError(DPoPError):
    """jti has been seen before — replay attack detected."""
    pass

class DPoPKeyMismatchError(DPoPError):
    """DPoP proof signed with a different key than the bound key."""
    pass

class DPoPClockError(DPoPError):
    """iat is outside the acceptable window."""
    pass

class DPoPBindingError(DPoPError):
    """ath claim does not match the presented access token."""
    pass


# ── JWK utilities ─────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode, padding-tolerant."""
    return urlsafe_b64decode(s + "=" * (4 - len(s) % 4))

def _b64url_encode(b: bytes) -> str:
    return urlsafe_b64encode(b).rstrip(b"=").decode()

def _jwk_thumbprint(jwk: dict) -> str:
    """
    Compute RFC 7638 JWK SHA-256 thumbprint.
    Used to uniquely identify a key and bind tokens to it.
    Members are serialized in lexicographic order per RFC 7638 §3.
    """
    key_type = jwk.get("kty", "")
    if key_type == "EC":
        canonical = json.dumps({
            "crv": jwk["crv"],
            "kty": "EC",
            "x":   jwk["x"],
            "y":   jwk["y"],
        }, separators=(",", ":"), sort_keys=True)
    elif key_type == "RSA":
        canonical = json.dumps({
            "e":   jwk["e"],
            "kty": "RSA",
            "n":   jwk["n"],
        }, separators=(",", ":"), sort_keys=True)
    elif key_type == "OKP":
        canonical = json.dumps({
            "crv": jwk["crv"],
            "kty": "OKP",
            "x":   jwk["x"],
        }, separators=(",", ":"), sort_keys=True)
    else:
        raise DPoPError(f"Unsupported JWK key type: {key_type}")

    return _b64url_encode(hashlib.sha256(canonical.encode()).digest())


def _decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    """
    Decode a JWT without signature verification.
    Returns (header, payload, signing_input_bytes, signature_bytes).
    Used for DPoP proof parsing before cryptographic verification.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise DPoPError("DPoP proof JWT must have exactly 3 parts.")

    header    = json.loads(_b64url_decode(parts[0]))
    payload   = json.loads(_b64url_decode(parts[1]))
    sig       = _b64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode()

    return header, payload, signing_input, sig


def _verify_ec_signature(jwk: dict, signing_input: bytes, signature: bytes, alg: str) -> bool:
    """Verify ECDSA signature using the public key from a JWK."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDSA, EllipticCurvePublicNumbers, SECP256R1, SECP384R1, SECP521R1
        )
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.exceptions import InvalidSignature

        curve_map = {"P-256": SECP256R1(), "P-384": SECP384R1(), "P-521": SECP521R1()}
        curve = curve_map.get(jwk.get("crv", "P-256"))
        if curve is None:
            raise DPoPError(f"Unsupported EC curve: {jwk.get('crv')}")

        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
        public_key  = pub_numbers.public_key()

        hash_map = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
        hash_alg = hash_map.get(alg, hashes.SHA256())

        # JWS signatures are raw (r || s) for EC — convert to DER
        key_size  = (public_key.key_size + 7) // 8
        r = int.from_bytes(signature[:key_size], "big")
        s = int.from_bytes(signature[key_size:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, signing_input, ECDSA(hash_alg))
        return True
    except ImportError:
        raise DPoPError("[DPoP] cryptography package required for EC signature verification.")
    except Exception:
        return False


def _verify_rsa_pss_signature(jwk: dict, signing_input: bytes, signature: bytes, alg: str) -> bool:
    """Verify RSA-PSS signature using the public key from a JWK."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        pub_numbers = RSAPublicNumbers(e=e, n=n)
        public_key  = pub_numbers.public_key()

        hash_map = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}
        hash_alg = hash_map.get(alg, hashes.SHA256())

        public_key.verify(
            signature, signing_input,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg,
        )
        return True
    except ImportError:
        raise DPoPError("[DPoP] cryptography package required for RSA-PSS verification.")
    except Exception:
        return False


# ── Core validator ────────────────────────────────────────────────────────────

class DPoPValidator:
    """
    RFC 9449 DPoP proof validator.

    Validates DPoP proofs against the current HTTP request context and
    maintains anti-replay state in Redis.
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client  # Injected; lazy-imported if None on first use

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis as redis_lib
            host    = os.getenv("REDIS_HOST", "localhost")
            port    = int(os.getenv("REDIS_PORT", "6379"))
            password = os.getenv("REDIS_PASSWORD") or None
            tls     = os.getenv("REDIS_TLS", "false").lower() == "true"
            client  = redis_lib.Redis(
                host=host, port=port, password=password,
                ssl=tls, decode_responses=True, socket_timeout=2
            )
            client.ping()
            self._redis = client
            return client
        except Exception as e:
            logger.warning(f"[DPoP] Redis unavailable for anti-replay store: {e}. "
                           "jti uniqueness check disabled — not suitable for production.")
            return None

    def validate(
        self,
        dpop_header: str,
        method: str,
        uri: str,
        access_token: Optional[str] = None,
        expected_thumbprint: Optional[str] = None,
    ) -> DPoPProof:
        """
        Validate a DPoP proof JWT.

        Args:
            dpop_header:         Value of the DPoP HTTP header
            method:              HTTP method of the current request (GET, POST, etc.)
            uri:                 Full request URI (scheme + host + path, no query string)
            access_token:        The presented access token (for ath binding check)
            expected_thumbprint: Previously stored JWK thumbprint for this token

        Returns:
            DPoPProof with validated claims

        Raises:
            DPoPError subclass on any validation failure
        """
        # 1. Parse the proof JWT (3-part structure)
        try:
            header, payload, signing_input, signature = _decode_jwt_unverified(dpop_header)
        except Exception as e:
            raise DPoPError(f"[DPoP] Failed to parse proof JWT: {e}")

        # 2. typ must be "dpop+jwt"
        if header.get("typ") != "dpop+jwt":
            raise DPoPError(
                f"[DPoP] Invalid typ claim: '{header.get('typ')}'. Must be 'dpop+jwt'."
            )

        # 3. Algorithm check — FIPS approved asymmetric only
        alg = header.get("alg", "")
        try:
            fips.assert_jwt_algorithm(alg)
        except FIPSAlgorithmViolation as e:
            raise DPoPError(str(e))
        if alg not in _DPOP_APPROVED_ALGS:
            raise DPoPError(
                f"[DPoP] Algorithm '{alg}' not approved for DPoP. "
                f"Use: {_DPOP_APPROVED_ALGS}"
            )

        # 4. JWK must be present in header (no "kid" reference — key must be inline)
        jwk = header.get("jwk")
        if not jwk:
            raise DPoPError("[DPoP] Missing 'jwk' in proof header. "
                            "Public key must be embedded inline (not referenced by kid).")
        if "d" in jwk:
            raise DPoPError("[DPoP] Private key material found in DPoP jwk header. Rejected.")

        # 5. Compute JWK thumbprint for key binding
        try:
            thumbprint = _jwk_thumbprint(jwk)
        except Exception as e:
            raise DPoPError(f"[DPoP] Failed to compute JWK thumbprint: {e}")

        # 6. Key binding check — must match previously registered key
        if expected_thumbprint and thumbprint != expected_thumbprint:
            raise DPoPKeyMismatchError(
                f"[DPoP] Key mismatch: proof signed with key '{thumbprint}' "
                f"but token is bound to '{expected_thumbprint}'. "
                "Token theft or key rotation without re-authentication detected."
            )

        # 7. htm (HTTP method) claim
        htm = payload.get("htm", "")
        if htm.upper() != method.upper():
            raise DPoPError(
                f"[DPoP] htm claim '{htm}' does not match request method '{method}'."
            )

        # 8. htu (HTTP URI) claim — ignore query string per RFC 9449 §4.3
        htu = payload.get("htu", "")
        uri_no_query = uri.split("?")[0]
        if htu.rstrip("/") != uri_no_query.rstrip("/"):
            raise DPoPError(
                f"[DPoP] htu claim '{htu}' does not match request URI '{uri_no_query}'."
            )

        # 9. iat (issued-at) freshness check
        iat = payload.get("iat")
        if not isinstance(iat, (int, float)):
            raise DPoPError("[DPoP] Missing or invalid 'iat' claim.")
        now = int(time.time())
        delta = abs(now - int(iat))
        max_age = _DPOP_MAX_AGE_SEC + _DPOP_CLOCK_SKEW
        if delta > max_age:
            raise DPoPClockError(
                f"[DPoP] Proof is {'stale' if iat < now else 'from the future'}: "
                f"iat={iat} now={now} delta={delta}s max={max_age}s."
            )

        # 10. jti (JWT ID) uniqueness — anti-replay
        jti = payload.get("jti")
        if not jti:
            raise DPoPError("[DPoP] Missing 'jti' claim. All DPoP proofs must have a unique ID.")
        self._check_jti_replay(jti)

        # 11. ath (access token hash) binding check
        ath = payload.get("ath")
        if access_token and ath:
            expected_ath = _b64url_encode(
                hashlib.sha256(access_token.encode()).digest()
            )
            if ath != expected_ath:
                raise DPoPBindingError(
                    "[DPoP] ath claim does not match SHA-256 of presented access token. "
                    "The DPoP proof is not bound to this access token."
                )

        # 12. Cryptographic signature verification
        self._verify_signature(jwk, signing_input, signature, alg)

        return DPoPProof(
            jti=jti,
            htm=htm,
            htu=htu,
            iat=int(iat),
            jwk_thumbprint=thumbprint,
            algorithm=alg,
            ath=ath,
            public_key_jwk=jwk,
        )

    def _check_jti_replay(self, jti: str) -> None:
        """Store jti in Redis. Raise DPoPReplayError if already seen."""
        redis = self._get_redis()
        if redis is None:
            logger.warning(f"[DPoP] jti replay check skipped (no Redis): jti={jti}")
            return
        redis_key = f"dpop:jti:{jti}"
        was_set = redis.set(redis_key, "1", nx=True, ex=_DPOP_JTI_TTL)
        if not was_set:
            raise DPoPReplayError(
                f"[DPoP] jti '{jti}' has been seen before within the replay window. "
                "Possible replay attack detected. Request rejected."
            )

    def _verify_signature(
        self, jwk: dict, signing_input: bytes, signature: bytes, alg: str
    ) -> None:
        """Dispatch to the correct signature verification function."""
        key_type = jwk.get("kty", "")
        valid = False

        if key_type == "EC" and alg.startswith("ES"):
            valid = _verify_ec_signature(jwk, signing_input, signature, alg)
        elif key_type == "RSA" and alg.startswith("PS"):
            valid = _verify_rsa_pss_signature(jwk, signing_input, signature, alg)
        else:
            raise DPoPError(
                f"[DPoP] Cannot verify signature: kty='{key_type}' alg='{alg}' "
                "combination not supported."
            )

        if not valid:
            raise DPoPError("[DPoP] Signature verification failed. Proof is invalid.")


# ── FastAPI dependency ────────────────────────────────────────────────────────

# Module-level singleton validator
_validator = DPoPValidator()


async def require_dpop(request: Request) -> DPoPContext:
    """
    FastAPI dependency that enforces DPoP proof of possession.
    IA-2(1) / IA-5 / SC-8(1)

    When DPOP_REQUIRED=true: rejects any request without a valid DPoP proof.
    When DPOP_REQUIRED=false: validates DPoP if present; passes through if absent.

    Usage:
        @app.post("/secure-endpoint")
        async def endpoint(dpop: DPoPContext = Depends(require_dpop)):
            print(dpop.proof.jwk_thumbprint)
    """
    dpop_header = request.headers.get("DPoP")
    auth_header = request.headers.get("Authorization", "")

    # Extract bearer token (access_token) from Authorization header
    access_token: Optional[str] = None
    if auth_header.startswith("DPoP "):
        access_token = auth_header[5:]
    elif auth_header.startswith("Bearer "):
        access_token = auth_header[7:]

    if not dpop_header:
        if _DPOP_REQUIRED:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "dpop_required",
                    "error_description": (
                        "This endpoint requires DPoP proof of possession (RFC 9449). "
                        "Include a DPoP: <proof_jwt> header with your request. "
                        "IA-2(1): Hardware token or cryptographic proof required."
                    ),
                    "dpop_algs_supported": sorted(_DPOP_APPROVED_ALGS),
                },
                headers={"WWW-Authenticate": 'DPoP algs="ES256 ES384 PS256 PS384"'},
            )
        # DPoP not required and not present — pass through
        return DPoPContext(
            proof=None,  # type: ignore[arg-type]
            token_hash=None,
            key_bound=False,
            first_use=False,
        )

    # Build the full request URI for htu validation
    scheme = request.url.scheme
    host   = request.headers.get("host", request.url.netloc)
    path   = request.url.path
    uri    = f"{scheme}://{host}{path}"

    # Look up previously bound thumbprint (if any) from Redis
    expected_thumbprint: Optional[str] = None
    key_bound = False
    if access_token:
        redis = _validator._get_redis()
        if redis and access_token:
            token_hash = fips.sha256_hex(access_token.encode())
            stored_tp  = redis.get(f"dpop:bind:{token_hash}")
            if stored_tp:
                expected_thumbprint = stored_tp
                key_bound = True

    try:
        proof = _validator.validate(
            dpop_header=dpop_header,
            method=request.method,
            uri=uri,
            access_token=access_token,
            expected_thumbprint=expected_thumbprint,
        )
    except DPoPReplayError as e:
        logger.warning(f"[DPoP] Replay attack detected: {e} | ip={request.client.host}")
        raise HTTPException(status_code=401, detail={
            "error": "dpop_replay",
            "error_description": str(e),
        })
    except DPoPKeyMismatchError as e:
        logger.warning(f"[DPoP] Key mismatch: {e} | ip={request.client.host}")
        raise HTTPException(status_code=401, detail={
            "error": "dpop_key_mismatch",
            "error_description": str(e),
        })
    except DPoPError as e:
        logger.warning(f"[DPoP] Validation failed: {e} | ip={request.client.host}")
        raise HTTPException(status_code=401, detail={
            "error": "dpop_invalid",
            "error_description": str(e),
        }, headers={"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'})

    # On first use: bind the token to this DPoP key in Redis
    first_use = False
    token_hash: Optional[str] = None
    if access_token and not key_bound:
        redis = _validator._get_redis()
        token_hash = fips.sha256_hex(access_token.encode())
        if redis:
            redis.set(
                f"dpop:bind:{token_hash}",
                proof.jwk_thumbprint,
                ex=int(os.getenv("DPOP_BINDING_TTL_SECONDS", "86400")),  # 24h default
            )
        first_use = True
        logger.info(
            f"[DPoP] New key binding: token_hash={token_hash[:16]}... "
            f"thumbprint={proof.jwk_thumbprint[:16]}... alg={proof.algorithm}"
        )

    return DPoPContext(
        proof=proof,
        token_hash=token_hash,
        key_bound=key_bound,
        first_use=first_use,
    )


async def optional_dpop(request: Request) -> Optional[DPoPContext]:
    """
    Like require_dpop but returns None instead of raising if DPoP is absent.
    Use on endpoints that accept but don't require DPoP.
    """
    if not request.headers.get("DPoP"):
        return None
    return await require_dpop(request)
