"""
Internal-only helpers shared between framework integrations.

Anything under ``_core`` is **not** part of the public API and may
change between minor releases. The split exists so the three middleware
adapters (``langchain.py``, ``crewai.py``, ``autogen.py``) can share
verification and behavioral-baseline logic without forming a circular
dependency through the package root.
"""

from __future__ import annotations
