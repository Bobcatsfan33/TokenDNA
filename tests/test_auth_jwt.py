"""Cryptographic regression tests for the OIDC bearer-token boundary."""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

import auth


@pytest.fixture
def oidc_material(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "test-key"
    monkeypatch.setattr(auth, "OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setattr(auth, "OIDC_AUDIENCE", "tokendna")
    monkeypatch.setattr(auth, "_find_key", lambda kid: public_jwk if kid == "test-key" else None)
    monkeypatch.setattr(auth, "is_token_revoked", lambda _jti: False)
    return private_key


def _token(private_key, **overrides):
    now = int(time.time())
    claims = {
        "sub": "agent-1",
        "jti": "token-1",
        "iss": "https://issuer.example",
        "aud": "tokendna",
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def test_verify_jwt_accepts_valid_rs256_token(oidc_material):
    payload = auth._verify_jwt(_token(oidc_material))
    assert payload["sub"] == "agent-1"


@pytest.mark.parametrize(
    ("claim", "value"),
    [("aud", "other-service"), ("iss", "https://attacker.example"), ("exp", 1)],
)
def test_verify_jwt_rejects_invalid_registered_claims(oidc_material, claim, value):
    with pytest.raises(HTTPException) as caught:
        auth._verify_jwt(_token(oidc_material, **{claim: value}))
    assert caught.value.status_code == 401


def test_verify_jwt_rejects_revoked_token(monkeypatch, oidc_material):
    monkeypatch.setattr(auth, "is_token_revoked", lambda jti: jti == "token-1")
    with pytest.raises(HTTPException, match="revoked") as caught:
        auth._verify_jwt(_token(oidc_material))
    assert caught.value.status_code == 401


def test_verify_jwt_rejects_token_without_key_id(oidc_material):
    token = jwt.encode(
        {"sub": "agent-1", "exp": int(time.time()) + 300},
        oidc_material,
        algorithm="RS256",
    )
    with pytest.raises(HTTPException, match="kid") as caught:
        auth._verify_jwt(token)
    assert caught.value.status_code == 401
