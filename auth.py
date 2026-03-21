"""
TokenDNA — JWT / OIDC authentication with token revocation check.

Validates Bearer JWTs against an OIDC provider's JWKS endpoint.
Also checks Redis revocation list so that revoked tokens are rejected
immediately — before the JWT's natural expiry.

DEV_MODE=true bypasses all validation for local development.
"""

import logging
import threading
from typing import Optional

import requests
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from config import DEV_MODE, OIDC_AUDIENCE, OIDC_ISSUER
from modules.identity.cache_redis import is_token_revoked

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=not DEV_MODE)

# ── JWKS cache ────────────────────────────────────────────────────────────────

_jwks_cache: Optional[dict] = None
_jwks_lock = threading.Lock()


def _jwks_url() -> str:
    return f"{OIDC_ISSUER}/.well-known/jwks.json"


def _fetch_jwks(force_refresh: bool = False) -> dict:
    global _jwks_cache
    with _jwks_lock:
        if _jwks_cache is None or force_refresh:
            if not OIDC_ISSUER:
                raise RuntimeError("OIDC_ISSUER is not configured.")
            try:
                resp = requests.get(_jwks_url(), timeout=10)
                resp.raise_for_status()
                _jwks_cache = resp.json()
                logger.info("JWKS refreshed.")
            except Exception as e:
                logger.error(f"JWKS fetch failed: {e}")
                if _jwks_cache is None:
                    raise
        return _jwks_cache


def _find_key(kid: str, allow_refresh: bool = True) -> Optional[dict]:
    jwks = _fetch_jwks()
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None and allow_refresh:
        logger.info(f"Key '{kid}' not cached — refreshing JWKS.")
        jwks = _fetch_jwks(force_refresh=True)
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    return key


# ── Token verification ────────────────────────────────────────────────────────

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    FastAPI dependency. Validates a Bearer JWT and returns the decoded payload.

    In DEV_MODE the token is not verified — a synthetic payload is returned.
    """
    if DEV_MODE:
        logger.warning("DEV_MODE: JWT verification skipped.")
        return {"sub": "dev-user", "jti": "dev-jti", "dev_mode": True}

    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = credentials.credentials

    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Malformed token")

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Token missing 'kid' header")

    key = _find_key(kid)
    if key is None:
        raise HTTPException(status_code=401, detail="Signing key not found")

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
        )
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # ── Check Redis revocation list ───────────────────────────────────────────
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        logger.warning(f"Revoked token used: jti={jti} sub={payload.get('sub')}")
        raise HTTPException(status_code=401, detail="Token has been revoked")

    return payload
