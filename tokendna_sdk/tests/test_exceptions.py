"""Tests for the exception hierarchy."""

from __future__ import annotations

import pytest

from tokendna_sdk.exceptions import (
    TokenDNAAttestationError,
    TokenDNAConfigError,
    TokenDNAError,
    TokenDNAUnavailableError,
    TokenDNAVerificationError,
)
from tokendna_sdk.models import PolicyVerdict


@pytest.mark.parametrize("cls", [
    TokenDNAConfigError,
    TokenDNAUnavailableError,
    TokenDNAVerificationError,
    TokenDNAAttestationError,
])
def test_all_inherit_from_base(cls):
    """Callers should be able to ``except TokenDNAError`` once and
    catch the entire family."""
    assert issubclass(cls, TokenDNAError)


def test_verification_error_carries_verdict():
    v = PolicyVerdict(decision="deny", reason="scope:missing")
    err = TokenDNAVerificationError("policy denied", verdict=v)
    assert err.verdict is v
    assert "policy denied" in str(err)


def test_verification_error_verdict_optional():
    err = TokenDNAVerificationError("no verdict carrier")
    assert err.verdict is None
