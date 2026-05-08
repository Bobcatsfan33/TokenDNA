"""IDP adapters — read events from the customer's existing identity provider."""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from .okta import OktaAdapterError, OktaSystemLogAdapter

__all__ = ["OktaAdapterError", "OktaSystemLogAdapter"]
