"""Adapter framework — re-exports the public ``BaseAdapter`` contract.

Concrete adapters live under one of the four category subpackages:

  * ``tokendna_collector.adapters.idp``         (Okta, Azure AD, Google WS, generic SAML)
  * ``tokendna_collector.adapters.siem``        (Splunk, Datadog, Sentinel, Elastic)
  * ``tokendna_collector.adapters.cloud``       (AWS, Azure, GCP)
  * ``tokendna_collector.adapters.ai_workload`` (MCP mirror, Bedrock, OpenAI)

Each subpackage is currently empty — concrete adapters land per the
sprint plan in ``~/Desktop/tokendna/TOKENDNA-DEPLOYMENT-REDESIGN.md``.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from .base import BaseAdapter

__all__ = ["BaseAdapter"]
