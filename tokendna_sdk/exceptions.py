"""
Public exception hierarchy for ``tokendna-sdk``.

Design contract
---------------
- The SDK never raises from the ``@identified`` / ``@tool`` wedge — that's
  load-bearing. These exceptions exist for *explicit* user-driven calls
  (``client.verify()``, ``client.attest()``) where surfacing a failure is
  expected behavior.
- All custom exceptions inherit from :class:`TokenDNAError` so callers can
  catch the whole family with one ``except`` clause.
"""

from __future__ import annotations


class TokenDNAError(Exception):
    """Base class for every exception raised by ``tokendna_sdk``."""


class TokenDNAConfigError(TokenDNAError):
    """Raised when SDK configuration is invalid or incomplete.

    Examples:
        - ``configure(api_base="")`` with no env fallback
        - missing ``TOKENDNA_API_KEY`` when remote mode is forced
    """


class TokenDNAUnavailableError(TokenDNAError):
    """The remote TokenDNA service is unreachable or unhealthy.

    Raised by ``TokenDNAClient.health()`` and explicit verification calls
    when the caller asked for the remote outcome and we cannot deliver it.
    Decorator-driven calls swallow this and buffer offline instead.
    """


class TokenDNAVerificationError(TokenDNAError):
    """An attestation or policy verification call returned a non-allow verdict.

    Carries the structured verdict so callers can branch on
    ``err.verdict.reason`` without re-parsing the message.
    """

    def __init__(self, message: str, verdict: object | None = None) -> None:
        super().__init__(message)
        self.verdict = verdict


class TokenDNAAttestationError(TokenDNAError):
    """Raised when an attestation cannot be produced or registered.

    Typical causes: bad signing material in local mode, server rejected
    the attestation payload (4xx), or the attested workflow trace is empty.
    """


__all__ = [
    "TokenDNAError",
    "TokenDNAConfigError",
    "TokenDNAUnavailableError",
    "TokenDNAVerificationError",
    "TokenDNAAttestationError",
]
