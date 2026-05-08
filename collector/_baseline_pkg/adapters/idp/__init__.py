"""IDP adapters — read events from the customer's existing identity provider.

Planned concrete adapters (see the redesign doc's Step 4 priority table):

  * ``okta`` — Okta System Log API           (P0)
  * ``azure_ad`` — Azure AD audit + sign-in  (P1)
  * ``google_ws`` — Google Workspace reports (P2)
  * ``generic_saml`` — SAML assertion log     (P2)

Each adapter subclasses :class:`tokendna_collector.adapters.BaseAdapter`,
emits :class:`tokendna_collector.schema.NormalizedEvent` instances, and
ships zero secret material in this package — credentials come from
``AdapterConfig.options`` at runtime.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.
