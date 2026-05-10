"""Single-tenant deployment validation.

For federal + IL5/IL6 customers, the platform deploys as a single-
tenant instance inside their boundary.  This module centralises the
*invariants* a single-tenant deployment must satisfy at startup —
shared state outside the customer boundary is a deployment bug, not
just a configuration warning.

Invariants:

  * `tenant_id` is set, non-empty, and matches the configured
    deployment id.
  * No multi-tenant tables / indexes are reachable from the runtime
    config (the SaaS path is disabled).
  * Outbound endpoints are restricted to an allow-list (no public
    internet egress unless explicitly enabled).
  * Encryption keys are sourced from the customer-managed KMS / HSM,
    not from the SaaS-mode env defaults.

The validator runs at platform startup and refuses to boot when any
invariant is violated.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SingleTenantConfig:
    """Configuration shape supplied at deployment time."""
    tenant_id: str
    deployment_id: str
    allowed_outbound_hosts: tuple[str, ...] = ()
    customer_kms_key_arn: str | None = None
    saas_mode_disabled: bool = True
    fips_mode: bool = True


class SingleTenantValidationError(Exception):
    """Raised when a single-tenant invariant is violated."""


class SingleTenantValidator:
    """Pure-function validator; no side effects, no I/O."""

    @staticmethod
    def validate(config: SingleTenantConfig) -> list[str]:
        """Return a list of reasons the deployment is invalid (empty if OK)."""
        problems: list[str] = []
        if not config.tenant_id.strip():
            problems.append("tenant_id must be non-empty")
        if not config.deployment_id.strip():
            problems.append("deployment_id must be non-empty")
        if config.tenant_id != config.deployment_id:
            problems.append(
                "tenant_id and deployment_id must match in single-tenant mode"
            )
        if not config.saas_mode_disabled:
            problems.append("saas_mode_disabled=False is forbidden in single-tenant mode")
        if not config.fips_mode:
            problems.append("fips_mode=False is forbidden for IL5/IL6 deployments")
        if config.customer_kms_key_arn is None:
            problems.append("customer_kms_key_arn must be set; SaaS-default keys are not allowed")
        if not config.allowed_outbound_hosts:
            problems.append("allowed_outbound_hosts must be non-empty (egress allow-list required)")
        return problems

    @staticmethod
    def assert_valid(config: SingleTenantConfig) -> None:
        problems = SingleTenantValidator.validate(config)
        if problems:
            raise SingleTenantValidationError(
                "single-tenant deployment invariants violated: " + "; ".join(problems)
            )
