"""SIEM adapters — read forwarded events from the customer's SIEM.

Planned concrete adapters:

  * ``splunk`` — Splunk REST + HEC          (P1)
  * ``datadog`` — Datadog events API        (P2)
  * ``sentinel`` — Azure Sentinel           (P1)
  * ``elastic`` — Elasticsearch / OpenSearch (P3)

The SIEM adapters consume the customer's existing telemetry pipeline
rather than installing yet-another agent on their hosts.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.
