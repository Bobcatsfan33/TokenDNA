"""SIEM forwarding — push findings back to the customer's SIEM.

The customer keeps their SIEM as the system of record for security
events.  TokenDNA enriches that picture by forwarding its own findings
back via the SIEM's HTTP-event-collector or REST ingestion API.

Built-in forwarders:

  * ``SplunkHECForwarder`` — Splunk HTTP Event Collector
  * ``DatadogForwarder``   — Datadog Logs Intake API
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .forwarder import SIEMForwarder, SplunkHECForwarder, DatadogForwarder

__all__ = ["DatadogForwarder", "SIEMForwarder", "SplunkHECForwarder"]
