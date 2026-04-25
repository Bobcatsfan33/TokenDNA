"""
tokendna_sdk — developer wedge for TokenDNA.

The shortest possible distance between ``pip install tokendna`` and a
fully-attested AI agent. Drop ``@tokendna.identified`` on a LangChain /
CrewAI / AutoGen / plain-Python agent class and every tool call it makes
becomes a UIS event with workflow-attestation hops, delegation receipts,
and policy-guard wiring — without the developer thinking about any of it.

Surface
-------

    from tokendna_sdk import identified, tool, configure

    configure(api_base="https://api.tokendna.io", api_key=os.environ["TDNA_KEY"])

    @identified(agent_id="research-bot", scope=["docs:read", "summarize"])
    class ResearchAgent:
        @tool("fetch_doc")
        def fetch_doc(self, url: str) -> str:
            ...

The decorators wire every method call through ``Client`` which posts UIS
events. The default Client is offline-safe — when no API base is configured
or the network is unreachable, events are buffered locally and the
decorators continue to work; nothing the developer wrote can fail because
of a TokenDNA outage. That property is the wedge.

Modules
-------
``tokendna_sdk.config``      module-level configuration singleton.
``tokendna_sdk.client``      thin HTTP client + offline buffer.
``tokendna_sdk.decorators``  ``identified`` and ``tool`` decorators.
``tokendna_sdk.cli``         ``tokendna policy plan / apply / replay`` CLI.
"""

from __future__ import annotations

from .config import (
    SdkConfig,
    configure,
    current_config,
    reset_config,
)
from .client import Client, OfflineBufferClient
from .decorators import identified, tool, get_agent_metadata

__all__ = [
    "SdkConfig",
    "Client",
    "OfflineBufferClient",
    "configure",
    "current_config",
    "reset_config",
    "identified",
    "tool",
    "get_agent_metadata",
]
