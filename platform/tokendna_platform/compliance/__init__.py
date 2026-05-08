"""Compliance evidence + framework mapping.

Generates auditor-ready reports against:

  * **EU AI Act**          — Article 9, 10, 13, 14 control evidence
  * **NIST AI RMF**        — Govern, Map, Measure, Manage functions
  * **SOC 2 (AI addendum)** — CC6, CC7, CC8 + AI-specific controls

Each report is a JSON-safe dict that downstream PDF generators
(``compliance.pdf``) or eMASS/OSCAL exporters render into the format
the auditor expects.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .reports import (
    ComplianceFramework,
    ComplianceReport,
    EUAIActReport,
    NISTAIRMFReport,
    SOC2AIReport,
)

__all__ = [
    "ComplianceFramework",
    "ComplianceReport",
    "EUAIActReport",
    "NISTAIRMFReport",
    "SOC2AIReport",
]
