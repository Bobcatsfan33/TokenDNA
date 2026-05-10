"""Response actions — webhook-driven enforcement at the customer's edge.

In *detect mode*, TokenDNA observes events and surfaces findings.
In *enforce mode*, the response subsystem additionally fires webhooks
to the customer's existing access-management plumbing — Okta to revoke
a session, an API gateway to add a deny rule, a K8s admission
controller to quarantine a workload, a ticket system to create an
emergency change record.

The webhook receivers live in customer-controlled systems.  TokenDNA
never mutates the customer's environment directly; it presents
evidence + recommended action, and the customer's webhook endpoint
chooses whether to act.

Public surface:

  * :class:`ResponseAction`  — the response contract.
  * :class:`ResponseRouter`  — finding → action dispatch.
  * Built-in actions: :class:`OktaRevokeSession`, :class:`AWSWAFBlockIP`,
    :class:`K8sIsolatePod`, :class:`PagerDutyEscalate`, :class:`JiraTicket`.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from .actions import (
    AWSWAFBlockIP,
    JiraTicket,
    K8sIsolatePod,
    OktaRevokeSession,
    PagerDutyEscalate,
    ResponseAction,
    ResponseActionError,
)
from .router import ResponseRouter, ResponseRule

__all__ = [
    "AWSWAFBlockIP",
    "JiraTicket",
    "K8sIsolatePod",
    "OktaRevokeSession",
    "PagerDutyEscalate",
    "ResponseAction",
    "ResponseActionError",
    "ResponseRouter",
    "ResponseRule",
]
