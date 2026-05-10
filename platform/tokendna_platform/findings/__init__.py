"""Finding aggregator — unifies engine output into a single feed.

Each engine in ``tokendna_platform.engines`` produces its own
findings type.  This package normalises them into a single
``Finding`` shape that the alerts, SIEM forwarding, dashboard, and
compliance subsystems can all consume without knowing about
engine-specific data classes.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .finding import Finding, FindingSeverity, FindingStore, InMemoryFindingStore

__all__ = [
    "Finding",
    "FindingSeverity",
    "FindingStore",
    "InMemoryFindingStore",
]
