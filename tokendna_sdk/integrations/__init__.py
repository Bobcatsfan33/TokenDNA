"""
Native framework adapters for TokenDNA.

Each module here is **independently importable** — none of them import
each other and none of them require their target framework to be
installed at SDK import time. The framework dep is loaded lazily inside
the adapter so ``pip install tokendna-sdk`` stays zero-deps and you can
``from tokendna_sdk.integrations import langchain`` only when you
actually need it.

Sprint 1 ships the package scaffold; Sprint 2 fills in the actual
adapter classes (``TokenDNAMiddleware``, ``TokenDNACrewCallback``,
``TokenDNAAutoGenMiddleware``). Sprint 3 adds ``mcp.py``.
"""

from __future__ import annotations
