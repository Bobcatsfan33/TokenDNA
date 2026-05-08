"""Stream-consuming intelligence engines.

Public surface for Sprint 5-6:

  * :class:`StreamEngine` — base contract.
  * :class:`TrustGraphEngine` — agent → resource edge accumulator.
  * :class:`BehavioralDNAEngine` — rolling-window action-frequency fingerprint.
  * :class:`PermissionDriftEngine` — resource-set growth detection.
  * :class:`MCPChainEngine` — multi-step MCP tool-call chain matcher.
  * :class:`PolicyGuardEngine` — detect-mode rule engine.

Each engine subscribes itself to an :class:`EventRouter` via
``register_with(router)``.  The engines do *not* import each other —
correlation between engines lives in a Sprint 9-10 finding-aggregator
that reads from each engine's published findings.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .base import StreamEngine
from .behavioral_dna import BehavioralDNAEngine
from .mcp_inspector import DEFAULT_CHAIN_PATTERNS, MCPChainEngine
from .permission_drift import DriftFinding, PermissionDriftEngine
from .policy_guard import GuardMode, PolicyFinding, PolicyGuardEngine, PolicyRule
from .trust_graph import GraphEdge, TrustGraphEngine

__all__ = [
    "BehavioralDNAEngine",
    "DEFAULT_CHAIN_PATTERNS",
    "DriftFinding",
    "GraphEdge",
    "GuardMode",
    "MCPChainEngine",
    "PermissionDriftEngine",
    "PolicyFinding",
    "PolicyGuardEngine",
    "PolicyRule",
    "StreamEngine",
    "TrustGraphEngine",
]
