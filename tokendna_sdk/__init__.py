"""
tokendna_sdk — identity for AI agents in one decorator.

The shortest possible distance between ``pip install tokendna-sdk`` and
a fully-attested AI agent. Drop ``@tokendna_sdk.identified`` on a
LangChain / CrewAI / AutoGen / plain-Python agent class and every tool
call becomes a UIS event with workflow-attestation hops, delegation
receipts, and policy-guard wiring — without the developer thinking
about any of it.

Two surfaces
------------

**Classic (v0.1.x, still supported)** — the decorator wedge::

    from tokendna_sdk import identified, tool, configure

    configure(url="https://api.tokendna.io", api_key=os.environ["TOKENDNA_API_KEY"])

    @identified(agent_id="research-bot", scope=["docs:read"])
    class ResearchAgent:
        @tool("fetch_doc")
        def fetch_doc(self, url: str) -> str: ...

**Native framework middleware (v0.2+)** — see
``tokendna_sdk.integrations`` for LangChain ``TokenDNAMiddleware``,
CrewAI ``TokenDNACrewCallback``, AutoGen ``TokenDNAAutoGenMiddleware``,
and the MCP interceptor.

Local-first mode
----------------
If ``TOKENDNA_URL`` (or legacy ``TOKENDNA_API_BASE``) is unset,
``make_client()`` returns a :class:`TokenDNALocalClient` that writes a
signed JSONL audit trail to ``~/.tokendna/events.jsonl``. ``pip install
tokendna-sdk`` therefore works end-to-end without a server account —
the on-ramp for new users and for the test suite.
"""

from __future__ import annotations

from .client import Client, OfflineBufferClient, TokenDNAClient
from .config import (
    SdkConfig,
    configure,
    current_config,
    reset_config,
)
from .decorators import get_agent_metadata, identified, tool
from .events import EventEmitter
from .exceptions import (
    TokenDNAAttestationError,
    TokenDNAConfigError,
    TokenDNAError,
    TokenDNAUnavailableError,
    TokenDNAVerificationError,
)
from .local import TokenDNALocalClient
from .models import (
    AgentIdentity,
    Attestation,
    BehavioralBaseline,
    ModelCallEvent,
    PolicyVerdict,
    ToolCallEvent,
)

# Stamped at release time. Must stay in sync with [project].version in
# pyproject.toml and with bin/bump_sdk_version.py. The release-pypi
# workflow's guard step fails the build if these drift.
__version__ = "0.2.0"


def make_client(config: SdkConfig | None = None):
    """Return the appropriate client for the active configuration.

    * Remote mode (``TOKENDNA_URL`` set) → :class:`TokenDNAClient`
    * Local mode (no URL configured)    → :class:`TokenDNALocalClient`

    The returned object has the same duck-typed surface
    (``health()``, ``post()``, ``normalize()``, ``attest()``,
    ``verify()``) so framework adapters can call either without
    branching.
    """
    cfg = config or current_config()
    if cfg.is_local():
        return TokenDNALocalClient(root=cfg.local_root or None)
    return TokenDNAClient(config=cfg)


__all__ = [
    "__version__",
    # config
    "SdkConfig",
    "configure",
    "current_config",
    "reset_config",
    # clients
    "Client",
    "OfflineBufferClient",
    "TokenDNAClient",
    "TokenDNALocalClient",
    "make_client",
    # decorators (legacy v0.1 surface — still supported)
    "identified",
    "tool",
    "get_agent_metadata",
    # emitter
    "EventEmitter",
    # models
    "AgentIdentity",
    "ToolCallEvent",
    "ModelCallEvent",
    "PolicyVerdict",
    "Attestation",
    "BehavioralBaseline",
    # exceptions
    "TokenDNAError",
    "TokenDNAConfigError",
    "TokenDNAUnavailableError",
    "TokenDNAVerificationError",
    "TokenDNAAttestationError",
]
