"""
TokenDNA — Attribute-Based Access Control (ABAC) Engine  (Phase 2E)

Implements a standards-aligned ABAC policy engine inspired by XACML/NIST SP 800-162.

Architecture
────────────
  Policy        → A named rule with a target (attribute conditions) and an effect
  PolicySet     → A collection of policies with a combining algorithm
  AttributeSet  → User, resource, and environment attributes for evaluation
  Decision      → PERMIT | DENY | NOT_APPLICABLE | INDETERMINATE

Attribute sources (all optional, fail-open unless policy requires)
──────────────────────────────────────────────────────────────────
  user        → role, department, clearance_level, mfa_verified, …
  resource    → type, classification, owner_id, sensitivity, …
  environment → current_time (ISO-8601), location, device_trust_level, …

Combining algorithms
────────────────────
  deny-overrides      — any DENY wins; PERMIT only if all applicable rules PERMIT
  permit-overrides    — any PERMIT wins; DENY only if no rule permits
  first-applicable    — stop at the first PERMIT or DENY (rule order matters)

Integration with auth middleware
────────────────────────────────
  Call abac_evaluate(policy_set, user_attrs, resource_attrs, env_attrs) → Decision
  Middleware should treat PERMIT as pass-through and everything else as a block
  (or step-up for INDETERMINATE, depending on risk posture).

Policy admin API
─────────────────
  In-process registry backed by a dict (swap for DB/Redis in production):
    create_policy(policy)     → policy_id
    get_policy(policy_id)     → Policy | None
    update_policy(policy)     → bool
    delete_policy(policy_id)  → bool
    list_policies()           → list[Policy]
    create_policy_set(ps)     → policy_set_id
    get_policy_set(ps_id)     → PolicySet | None

NIST 800-53 Rev5: AC-3 (Access Enforcement), AC-16 (Security Attributes),
                  AC-24 (Access Control Decisions).
"""

from __future__ import annotations

import logging
import operator
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# ─── Decision ─────────────────────────────────────────────────────────────────

class Decision(str, Enum):
    PERMIT          = "permit"
    DENY            = "deny"
    NOT_APPLICABLE  = "not_applicable"   # No matching policy
    INDETERMINATE   = "indeterminate"    # Policy matched but evaluation error


# ─── Attribute condition operators ────────────────────────────────────────────

class ConditionOperator(str, Enum):
    EQ          = "eq"          # ==
    NEQ         = "neq"         # !=
    GT          = "gt"          # >
    GTE         = "gte"         # >=
    LT          = "lt"          # <
    LTE         = "lte"         # <=
    IN          = "in"          # value in list
    NOT_IN      = "not_in"      # value not in list
    CONTAINS    = "contains"    # list contains value  (or str substring)
    REGEX       = "regex"       # re.search match


_OP_FNS: Dict[ConditionOperator, Callable] = {
    ConditionOperator.EQ:       lambda v, p: v == p,
    ConditionOperator.NEQ:      lambda v, p: v != p,
    ConditionOperator.GT:       lambda v, p: v > p,
    ConditionOperator.GTE:      lambda v, p: v >= p,
    ConditionOperator.LT:       lambda v, p: v < p,
    ConditionOperator.LTE:      lambda v, p: v <= p,
    ConditionOperator.IN:       lambda v, p: v in p,
    ConditionOperator.NOT_IN:   lambda v, p: v not in p,
    ConditionOperator.CONTAINS: lambda v, p: p in v,
    ConditionOperator.REGEX:    lambda v, p: bool(re.search(p, str(v))),
}


# ─── Attribute condition ───────────────────────────────────────────────────────

@dataclass
class AttributeCondition:
    """
    A single attribute condition: ``<source>.<attribute> <operator> <param>``.

    source   : "user" | "resource" | "environment"
    attribute: attribute key (dot-separated for nested: "resource.owner.id")
    operator : ConditionOperator
    param    : the comparison value
    """
    source:    str               # "user" | "resource" | "environment"
    attribute: str
    operator:  ConditionOperator
    param:     Any

    def __post_init__(self):
        # Coerce string → ConditionOperator so callers can pass plain strings
        if isinstance(self.operator, str):
            object.__setattr__(self, "operator", ConditionOperator(self.operator))

    def evaluate(self, attrs: "AttributeSet") -> bool:
        """
        Evaluate this condition against the provided AttributeSet.
        Returns True (match), False (no match).
        Raises AttributeError if the attribute is not found (caller should
        treat as INDETERMINATE).
        """
        source_dict = attrs.get_source(self.source)
        value = _get_nested(source_dict, self.attribute)
        op_fn = _OP_FNS[self.operator]
        return bool(op_fn(value, self.param))

    def to_dict(self) -> dict:
        return {
            "source":    self.source,
            "attribute": self.attribute,
            "operator":  self.operator.value,
            "param":     self.param,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttributeCondition":
        return cls(
            source=d["source"],
            attribute=d["attribute"],
            operator=ConditionOperator(d["operator"]),
            param=d["param"],
        )


# ─── Policy ───────────────────────────────────────────────────────────────────

class PolicyEffect(str, Enum):
    PERMIT = "permit"
    DENY   = "deny"


@dataclass
class Policy:
    """
    A single ABAC policy rule.

    effect      : PERMIT or DENY when all target conditions match
    conditions  : list of AttributeCondition (all must match — AND semantics)
    description : human-readable summary
    policy_id   : auto-generated UUID if not provided
    """
    effect:      PolicyEffect
    conditions:  List[AttributeCondition] = field(default_factory=list)
    description: str = ""
    policy_id:   str = field(default_factory=lambda: str(uuid.uuid4()))

    def applies_to(self, attrs: "AttributeSet") -> Optional[bool]:
        """
        Check whether this policy applies to the given AttributeSet.

        Returns:
            True   — all conditions match → policy applies with its effect
            False  — at least one condition does not match → NOT_APPLICABLE
            None   — evaluation error → INDETERMINATE
        """
        if not self.conditions:
            return True  # No conditions = catch-all
        for cond in self.conditions:
            try:
                if not cond.evaluate(attrs):
                    return False
            except (KeyError, AttributeError, TypeError):
                return None  # Signal INDETERMINATE to caller
        return True

    def evaluate(self, attrs: "AttributeSet") -> Decision:
        match = self.applies_to(attrs)
        if match is None:
            return Decision.INDETERMINATE
        if not match:
            return Decision.NOT_APPLICABLE
        return Decision.PERMIT if self.effect == PolicyEffect.PERMIT else Decision.DENY

    def to_dict(self) -> dict:
        return {
            "policy_id":   self.policy_id,
            "effect":      self.effect.value,
            "description": self.description,
            "conditions":  [c.to_dict() for c in self.conditions],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(
            policy_id=d.get("policy_id", str(uuid.uuid4())),
            effect=PolicyEffect(d["effect"]),
            description=d.get("description", ""),
            conditions=[AttributeCondition.from_dict(c) for c in d.get("conditions", [])],
        )


# ─── Combining algorithms ──────────────────────────────────────────────────────

class CombiningAlgorithm(str, Enum):
    DENY_OVERRIDES    = "deny-overrides"
    PERMIT_OVERRIDES  = "permit-overrides"
    FIRST_APPLICABLE  = "first-applicable"


def _combine(decisions: List[Decision], algorithm: CombiningAlgorithm) -> Decision:
    """
    Combine a list of individual policy decisions using the given algorithm.
    """
    applicable = [d for d in decisions if d != Decision.NOT_APPLICABLE]

    if not applicable:
        return Decision.NOT_APPLICABLE

    if algorithm == CombiningAlgorithm.DENY_OVERRIDES:
        if Decision.DENY in applicable:
            return Decision.DENY
        if Decision.INDETERMINATE in applicable:
            return Decision.INDETERMINATE
        return Decision.PERMIT

    elif algorithm == CombiningAlgorithm.PERMIT_OVERRIDES:
        if Decision.PERMIT in applicable:
            return Decision.PERMIT
        if Decision.INDETERMINATE in applicable:
            return Decision.INDETERMINATE
        return Decision.DENY

    elif algorithm == CombiningAlgorithm.FIRST_APPLICABLE:
        # decisions list must be in policy order; return the first non-N/A result
        for d in decisions:
            if d != Decision.NOT_APPLICABLE:
                return d
        return Decision.NOT_APPLICABLE

    # Fallback (should not happen with enum-typed arg)
    return Decision.INDETERMINATE


# ─── PolicySet ────────────────────────────────────────────────────────────────

@dataclass
class PolicySet:
    """
    A named collection of policies with a combining algorithm.
    """
    name:       str
    algorithm:  CombiningAlgorithm
    policies:   List[Policy] = field(default_factory=list)
    policy_set_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""

    def evaluate(self, attrs: "AttributeSet") -> Decision:
        """Run all policies against attrs, combine, and return the final Decision."""
        decisions = [p.evaluate(attrs) for p in self.policies]
        return _combine(decisions, self.algorithm)

    def to_dict(self) -> dict:
        return {
            "policy_set_id": self.policy_set_id,
            "name":          self.name,
            "description":   self.description,
            "algorithm":     self.algorithm.value,
            "policies":      [p.to_dict() for p in self.policies],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PolicySet":
        return cls(
            policy_set_id=d.get("policy_set_id", str(uuid.uuid4())),
            name=d["name"],
            description=d.get("description", ""),
            algorithm=CombiningAlgorithm(d["algorithm"]),
            policies=[Policy.from_dict(p) for p in d.get("policies", [])],
        )


# ─── AttributeSet ─────────────────────────────────────────────────────────────

@dataclass
class AttributeSet:
    """
    Holds user, resource, and environment attributes for a single evaluation.

    user        : e.g. {"role": "admin", "department": "security", "mfa_verified": True}
    resource    : e.g. {"type": "report", "classification": "confidential"}
    environment : e.g. {"current_time": "14:30", "location": "US", "device_trust": "high"}
    """
    user:        Dict[str, Any] = field(default_factory=dict)
    resource:    Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)

    def get_source(self, source: str) -> Dict[str, Any]:
        source = source.lower()
        if source == "user":
            return self.user
        if source == "resource":
            return self.resource
        if source in ("environment", "env"):
            return self.environment
        raise ValueError(f"Unknown attribute source: {source!r}")


# ─── Top-level evaluate function ──────────────────────────────────────────────

def abac_evaluate(
    policy_set: PolicySet,
    user_attrs:  Dict[str, Any],
    resource_attrs: Dict[str, Any],
    env_attrs:   Dict[str, Any],
) -> Decision:
    """
    Convenience function: build an AttributeSet and evaluate the PolicySet.

    Returns a Decision. Middleware should:
      PERMIT          → allow the request
      DENY            → block the request (HTTP 403)
      NOT_APPLICABLE  → no matching policy; default deny (fail-closed) or allow (fail-open)
      INDETERMINATE   → evaluation error; treat as DENY or escalate to step-up
    """
    attrs = AttributeSet(
        user=user_attrs or {},
        resource=resource_attrs or {},
        environment=env_attrs or {},
    )
    return policy_set.evaluate(attrs)


# ─── In-process policy registry (Policy Admin API) ────────────────────────────

class PolicyRegistry:
    """
    Simple in-memory registry for policies and policy sets.
    Thread-safe for concurrent reads; writes use a plain dict (swap for DB/Redis in prod).
    """

    def __init__(self):
        self._policies: Dict[str, Policy] = {}
        self._policy_sets: Dict[str, PolicySet] = {}

    # ── Policy CRUD ─────────────────────────────────────────────────────────

    def create_policy(self, policy: Policy) -> str:
        """Register a policy and return its policy_id."""
        self._policies[policy.policy_id] = policy
        logger.info(f"[ABAC] Created policy {policy.policy_id!r}: {policy.description!r}")
        return policy.policy_id

    def get_policy(self, policy_id: str) -> Optional[Policy]:
        return self._policies.get(policy_id)

    def update_policy(self, policy: Policy) -> bool:
        """Replace an existing policy by policy_id. Returns False if not found."""
        if policy.policy_id not in self._policies:
            logger.warning(f"[ABAC] update_policy: {policy.policy_id!r} not found")
            return False
        self._policies[policy.policy_id] = policy
        logger.info(f"[ABAC] Updated policy {policy.policy_id!r}")
        return True

    def delete_policy(self, policy_id: str) -> bool:
        """Remove a policy. Returns False if not found."""
        if policy_id not in self._policies:
            return False
        del self._policies[policy_id]
        logger.info(f"[ABAC] Deleted policy {policy_id!r}")
        return True

    def list_policies(self) -> List[Policy]:
        return list(self._policies.values())

    # ── PolicySet CRUD ───────────────────────────────────────────────────────

    def create_policy_set(self, policy_set: PolicySet) -> str:
        self._policy_sets[policy_set.policy_set_id] = policy_set
        logger.info(f"[ABAC] Created policy set {policy_set.policy_set_id!r}: {policy_set.name!r}")
        return policy_set.policy_set_id

    def get_policy_set(self, policy_set_id: str) -> Optional[PolicySet]:
        return self._policy_sets.get(policy_set_id)

    def update_policy_set(self, policy_set: PolicySet) -> bool:
        if policy_set.policy_set_id not in self._policy_sets:
            return False
        self._policy_sets[policy_set.policy_set_id] = policy_set
        return True

    def delete_policy_set(self, policy_set_id: str) -> bool:
        if policy_set_id not in self._policy_sets:
            return False
        del self._policy_sets[policy_set_id]
        return True

    def list_policy_sets(self) -> List[PolicySet]:
        return list(self._policy_sets.values())


# ─── Module-level default registry ────────────────────────────────────────────

_default_registry = PolicyRegistry()

# Expose registry CRUD at module level for convenience
create_policy      = _default_registry.create_policy
get_policy         = _default_registry.get_policy
update_policy      = _default_registry.update_policy
delete_policy      = _default_registry.delete_policy
list_policies      = _default_registry.list_policies
create_policy_set  = _default_registry.create_policy_set
get_policy_set     = _default_registry.get_policy_set
update_policy_set  = _default_registry.update_policy_set
delete_policy_set  = _default_registry.delete_policy_set
list_policy_sets   = _default_registry.list_policy_sets


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_nested(d: dict, key: str) -> Any:
    """Traverse a dict with a dot-separated key path."""
    parts = key.split(".")
    val = d
    for part in parts:
        if not isinstance(val, dict):
            raise AttributeError(f"Cannot index into {type(val)} with key {part!r}")
        if part not in val:
            raise KeyError(f"Attribute not found: {part!r}")
        val = val[part]
    return val
