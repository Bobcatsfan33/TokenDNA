"""
Tests — ABAC Engine  (Phase 2E)

Coverage targets for modules/identity/abac.py:
  - AttributeCondition evaluation (all operators)
  - Policy evaluation (PERMIT / DENY / NOT_APPLICABLE / INDETERMINATE)
  - PolicySet evaluation with all three combining algorithms
  - AttributeSet construction and source resolution
  - abac_evaluate() end-to-end
  - PolicyRegistry CRUD (create / get / update / delete / list)
  - Serialization / deserialization (to_dict / from_dict)
  - Edge cases: missing attributes, conflicting policies, empty conditions
"""

import pytest
from modules.identity.abac import (
    AttributeCondition,
    AttributeSet,
    CombiningAlgorithm,
    Decision,
    Policy,
    PolicyEffect,
    PolicyRegistry,
    PolicySet,
    abac_evaluate,
    _get_nested,
    _combine,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _permit_policy(conditions=None, description="allow all"):
    return Policy(
        effect=PolicyEffect.PERMIT,
        conditions=conditions or [],
        description=description,
    )


def _deny_policy(conditions=None, description="deny all"):
    return Policy(
        effect=PolicyEffect.DENY,
        conditions=conditions or [],
        description=description,
    )


def _role_eq(role: str) -> AttributeCondition:
    return AttributeCondition(
        source="user", attribute="role",
        operator="eq", param=role
    )


def _std_attrs(role="user", resource_type="document", location="US"):
    return AttributeSet(
        user={"role": role, "mfa_verified": True, "clearance": 2},
        resource={"type": resource_type, "classification": "internal"},
        environment={"location": location, "device_trust": "high", "hour": 14},
    )


# ─── _get_nested ──────────────────────────────────────────────────────────────

class TestGetNested:

    def test_simple_key(self):
        assert _get_nested({"a": 1}, "a") == 1

    def test_nested_key(self):
        assert _get_nested({"a": {"b": 42}}, "a.b") == 42

    def test_deeply_nested(self):
        d = {"x": {"y": {"z": "deep"}}}
        assert _get_nested(d, "x.y.z") == "deep"

    def test_missing_key_raises(self):
        with pytest.raises(KeyError):
            _get_nested({"a": 1}, "b")

    def test_non_dict_midpath_raises(self):
        with pytest.raises(AttributeError):
            _get_nested({"a": "string"}, "a.b")


# ─── AttributeCondition operators ─────────────────────────────────────────────

class TestAttributeConditionOperators:

    def _make_attrs(self, **user_kw):
        return AttributeSet(user=user_kw)

    def test_eq_match(self):
        cond = AttributeCondition("user", "role", "eq", "admin")
        assert cond.evaluate(self._make_attrs(role="admin")) is True

    def test_eq_no_match(self):
        cond = AttributeCondition("user", "role", "eq", "admin")
        assert cond.evaluate(self._make_attrs(role="guest")) is False

    def test_neq_match(self):
        cond = AttributeCondition("user", "role", "neq", "guest")
        assert cond.evaluate(self._make_attrs(role="admin")) is True

    def test_gt_match(self):
        cond = AttributeCondition("user", "level", "gt", 2)
        assert cond.evaluate(self._make_attrs(level=3)) is True

    def test_gt_no_match(self):
        cond = AttributeCondition("user", "level", "gt", 2)
        assert cond.evaluate(self._make_attrs(level=2)) is False

    def test_gte_boundary(self):
        cond = AttributeCondition("user", "level", "gte", 2)
        assert cond.evaluate(self._make_attrs(level=2)) is True

    def test_lt_match(self):
        cond = AttributeCondition("user", "level", "lt", 5)
        assert cond.evaluate(self._make_attrs(level=3)) is True

    def test_lte_boundary(self):
        cond = AttributeCondition("user", "level", "lte", 3)
        assert cond.evaluate(self._make_attrs(level=3)) is True

    def test_in_match(self):
        cond = AttributeCondition("user", "role", "in", ["admin", "superuser"])
        assert cond.evaluate(self._make_attrs(role="admin")) is True

    def test_in_no_match(self):
        cond = AttributeCondition("user", "role", "in", ["admin"])
        assert cond.evaluate(self._make_attrs(role="guest")) is False

    def test_not_in_match(self):
        cond = AttributeCondition("user", "role", "not_in", ["banned"])
        assert cond.evaluate(self._make_attrs(role="admin")) is True

    def test_contains_match(self):
        cond = AttributeCondition("user", "tags", "contains", "security")
        attrs = AttributeSet(user={"tags": ["security", "devops"]})
        assert cond.evaluate(attrs) is True

    def test_contains_string_substring(self):
        cond = AttributeCondition("user", "email", "contains", "@corp.com")
        attrs = AttributeSet(user={"email": "alice@corp.com"})
        assert cond.evaluate(attrs) is True

    def test_regex_match(self):
        cond = AttributeCondition("user", "email", "regex", r"^[^@]+@corp\.com$")
        attrs = AttributeSet(user={"email": "bob@corp.com"})
        assert cond.evaluate(attrs) is True

    def test_regex_no_match(self):
        cond = AttributeCondition("user", "email", "regex", r"@corp\.com$")
        attrs = AttributeSet(user={"email": "bob@external.io"})
        assert cond.evaluate(attrs) is False

    def test_missing_attribute_raises(self):
        cond = AttributeCondition("user", "nonexistent", "eq", "x")
        with pytest.raises(KeyError):
            cond.evaluate(AttributeSet(user={}))

    def test_resource_source(self):
        cond = AttributeCondition("resource", "classification", "eq", "confidential")
        attrs = AttributeSet(resource={"classification": "confidential"})
        assert cond.evaluate(attrs) is True

    def test_environment_source(self):
        cond = AttributeCondition("environment", "location", "eq", "US")
        attrs = AttributeSet(environment={"location": "US"})
        assert cond.evaluate(attrs) is True


# ─── AttributeSet ─────────────────────────────────────────────────────────────

class TestAttributeSet:

    def test_get_user_source(self):
        attrs = AttributeSet(user={"role": "admin"})
        assert attrs.get_source("user") == {"role": "admin"}

    def test_get_resource_source(self):
        attrs = AttributeSet(resource={"type": "file"})
        assert attrs.get_source("resource") == {"type": "file"}

    def test_get_environment_source(self):
        attrs = AttributeSet(environment={"hour": 9})
        assert attrs.get_source("environment") == {"hour": 9}

    def test_env_alias(self):
        attrs = AttributeSet(environment={"loc": "UK"})
        assert attrs.get_source("env") == {"loc": "UK"}

    def test_unknown_source_raises(self):
        attrs = AttributeSet()
        with pytest.raises(ValueError):
            attrs.get_source("unknown")

    def test_defaults_to_empty_dicts(self):
        attrs = AttributeSet()
        assert attrs.user == {}
        assert attrs.resource == {}
        assert attrs.environment == {}


# ─── Policy evaluation ────────────────────────────────────────────────────────

class TestPolicyEvaluation:

    def test_permit_no_conditions_always_permits(self):
        p = _permit_policy()
        assert p.evaluate(_std_attrs()) == Decision.PERMIT

    def test_deny_no_conditions_always_denies(self):
        p = _deny_policy()
        assert p.evaluate(_std_attrs()) == Decision.DENY

    def test_permit_with_matching_condition(self):
        p = _permit_policy([_role_eq("admin")])
        assert p.evaluate(_std_attrs(role="admin")) == Decision.PERMIT

    def test_not_applicable_when_condition_unmet(self):
        p = _permit_policy([_role_eq("admin")])
        assert p.evaluate(_std_attrs(role="guest")) == Decision.NOT_APPLICABLE

    def test_deny_with_matching_condition(self):
        p = _deny_policy([_role_eq("banned")])
        assert p.evaluate(_std_attrs(role="banned")) == Decision.DENY

    def test_indeterminate_on_missing_attribute(self):
        cond = AttributeCondition("user", "nonexistent_attr", "eq", "x")
        p = _permit_policy([cond])
        assert p.evaluate(_std_attrs()) == Decision.INDETERMINATE

    def test_all_conditions_must_match(self):
        conds = [
            _role_eq("admin"),
            AttributeCondition("user", "mfa_verified", "eq", True),
        ]
        p = _permit_policy(conds)
        # Both match
        assert p.evaluate(_std_attrs(role="admin")) == Decision.PERMIT
        # Role doesn't match
        assert p.evaluate(_std_attrs(role="user")) == Decision.NOT_APPLICABLE

    def test_policy_id_is_unique(self):
        p1 = _permit_policy()
        p2 = _permit_policy()
        assert p1.policy_id != p2.policy_id


# ─── Combining algorithms ──────────────────────────────────────────────────────

class TestCombineFunction:

    def test_all_not_applicable_returns_not_applicable(self):
        decisions = [Decision.NOT_APPLICABLE, Decision.NOT_APPLICABLE]
        assert _combine(decisions, CombiningAlgorithm.DENY_OVERRIDES) == Decision.NOT_APPLICABLE

    # deny-overrides
    def test_deny_overrides_deny_wins(self):
        decisions = [Decision.PERMIT, Decision.DENY]
        assert _combine(decisions, CombiningAlgorithm.DENY_OVERRIDES) == Decision.DENY

    def test_deny_overrides_all_permit(self):
        decisions = [Decision.PERMIT, Decision.PERMIT]
        assert _combine(decisions, CombiningAlgorithm.DENY_OVERRIDES) == Decision.PERMIT

    def test_deny_overrides_indeterminate_without_deny(self):
        decisions = [Decision.PERMIT, Decision.INDETERMINATE]
        assert _combine(decisions, CombiningAlgorithm.DENY_OVERRIDES) == Decision.INDETERMINATE

    def test_deny_overrides_deny_beats_indeterminate(self):
        decisions = [Decision.INDETERMINATE, Decision.DENY]
        assert _combine(decisions, CombiningAlgorithm.DENY_OVERRIDES) == Decision.DENY

    # permit-overrides
    def test_permit_overrides_permit_wins(self):
        decisions = [Decision.PERMIT, Decision.DENY]
        assert _combine(decisions, CombiningAlgorithm.PERMIT_OVERRIDES) == Decision.PERMIT

    def test_permit_overrides_all_deny(self):
        decisions = [Decision.DENY, Decision.DENY]
        assert _combine(decisions, CombiningAlgorithm.PERMIT_OVERRIDES) == Decision.DENY

    def test_permit_overrides_indeterminate_without_permit(self):
        decisions = [Decision.DENY, Decision.INDETERMINATE]
        assert _combine(decisions, CombiningAlgorithm.PERMIT_OVERRIDES) == Decision.INDETERMINATE

    # first-applicable
    def test_first_applicable_returns_first_match(self):
        decisions = [Decision.NOT_APPLICABLE, Decision.PERMIT, Decision.DENY]
        assert _combine(decisions, CombiningAlgorithm.FIRST_APPLICABLE) == Decision.PERMIT

    def test_first_applicable_deny_first(self):
        decisions = [Decision.DENY, Decision.PERMIT]
        assert _combine(decisions, CombiningAlgorithm.FIRST_APPLICABLE) == Decision.DENY


# ─── PolicySet ────────────────────────────────────────────────────────────────

class TestPolicySet:

    def _make_ps(self, algo, *policies):
        return PolicySet(name="test-set", algorithm=algo, policies=list(policies))

    def test_empty_policyset_returns_not_applicable(self):
        ps = PolicySet(name="empty", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        assert ps.evaluate(_std_attrs()) == Decision.NOT_APPLICABLE

    def test_deny_overrides_set(self):
        ps = self._make_ps(
            CombiningAlgorithm.DENY_OVERRIDES,
            _permit_policy(),
            _deny_policy([_role_eq("banned")]),
        )
        # banned user → DENY wins
        assert ps.evaluate(_std_attrs(role="banned")) == Decision.DENY
        # normal user → PERMIT (deny not applicable)
        assert ps.evaluate(_std_attrs(role="user")) == Decision.PERMIT

    def test_permit_overrides_set(self):
        ps = self._make_ps(
            CombiningAlgorithm.PERMIT_OVERRIDES,
            _deny_policy(),
            _permit_policy([_role_eq("admin")]),
        )
        # admin → PERMIT overrides the blanket DENY
        assert ps.evaluate(_std_attrs(role="admin")) == Decision.PERMIT
        # regular user → only blanket DENY applies
        assert ps.evaluate(_std_attrs(role="user")) == Decision.DENY

    def test_first_applicable_set(self):
        ps = self._make_ps(
            CombiningAlgorithm.FIRST_APPLICABLE,
            _permit_policy([_role_eq("admin")]),  # first: admin only
            _deny_policy(),                        # second: catch-all deny
        )
        assert ps.evaluate(_std_attrs(role="admin")) == Decision.PERMIT
        assert ps.evaluate(_std_attrs(role="guest")) == Decision.DENY

    def test_policy_set_id_unique(self):
        ps1 = PolicySet(name="a", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        ps2 = PolicySet(name="b", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        assert ps1.policy_set_id != ps2.policy_set_id


# ─── abac_evaluate() ──────────────────────────────────────────────────────────

class TestAbacEvaluate:

    def _admin_policy_set(self, algo=CombiningAlgorithm.FIRST_APPLICABLE):
        """first-applicable: admin+MFA → PERMIT, else catch-all DENY."""
        return PolicySet(
            name="admin-only",
            algorithm=algo,
            policies=[
                _permit_policy([
                    AttributeCondition("user", "role", "eq", "admin"),
                    AttributeCondition("user", "mfa_verified", "eq", True),
                ]),
                _deny_policy(),
            ],
        )

    def test_admin_with_mfa_gets_permit(self):
        ps = self._admin_policy_set()
        result = abac_evaluate(
            ps,
            user_attrs={"role": "admin", "mfa_verified": True},
            resource_attrs={"type": "admin-panel"},
            env_attrs={"location": "US"},
        )
        assert result == Decision.PERMIT

    def test_non_admin_gets_deny(self):
        ps = self._admin_policy_set()
        result = abac_evaluate(
            ps,
            user_attrs={"role": "user", "mfa_verified": True},
            resource_attrs={},
            env_attrs={},
        )
        assert result == Decision.DENY

    def test_admin_without_mfa_gets_deny(self):
        ps = self._admin_policy_set()
        result = abac_evaluate(
            ps,
            user_attrs={"role": "admin", "mfa_verified": False},
            resource_attrs={},
            env_attrs={},
        )
        assert result == Decision.DENY

    def test_empty_attrs_accepted(self):
        ps = PolicySet(name="open", algorithm=CombiningAlgorithm.PERMIT_OVERRIDES,
                       policies=[_permit_policy()])
        result = abac_evaluate(ps, {}, {}, {})
        assert result == Decision.PERMIT

    def test_none_attrs_accepted(self):
        ps = PolicySet(name="open", algorithm=CombiningAlgorithm.PERMIT_OVERRIDES,
                       policies=[_permit_policy()])
        result = abac_evaluate(ps, None, None, None)
        assert result == Decision.PERMIT

    def test_environment_condition(self):
        cond = AttributeCondition("environment", "location", "in", ["US", "UK", "CA"])
        ps = PolicySet(
            name="geo-fence",
            algorithm=CombiningAlgorithm.FIRST_APPLICABLE,
            policies=[
                _permit_policy([cond]),
                _deny_policy(),
            ],
        )
        assert abac_evaluate(ps, {}, {}, {"location": "US"}) == Decision.PERMIT
        assert abac_evaluate(ps, {}, {}, {"location": "CN"}) == Decision.DENY

    def test_resource_condition(self):
        cond = AttributeCondition("resource", "classification", "neq", "top_secret")
        ps = PolicySet(
            name="classification-gate",
            algorithm=CombiningAlgorithm.FIRST_APPLICABLE,
            policies=[
                _permit_policy([cond]),
                _deny_policy(),
            ],
        )
        assert abac_evaluate(ps, {}, {"classification": "internal"}, {}) == Decision.PERMIT
        assert abac_evaluate(ps, {}, {"classification": "top_secret"}, {}) == Decision.DENY


# ─── Serialization ────────────────────────────────────────────────────────────

class TestSerialization:

    def test_condition_roundtrip(self):
        cond = AttributeCondition("user", "role", "in", ["admin", "superuser"])
        d = cond.to_dict()
        restored = AttributeCondition.from_dict(d)
        assert restored.source == cond.source
        assert restored.attribute == cond.attribute
        assert restored.operator == cond.operator
        assert restored.param == cond.param

    def test_policy_roundtrip(self):
        p = Policy(
            effect=PolicyEffect.PERMIT,
            description="test",
            conditions=[AttributeCondition("user", "role", "eq", "admin")],
        )
        d = p.to_dict()
        restored = Policy.from_dict(d)
        assert restored.effect == p.effect
        assert restored.description == p.description
        assert len(restored.conditions) == 1
        assert restored.conditions[0].attribute == "role"

    def test_policy_set_roundtrip(self):
        ps = PolicySet(
            name="my-set",
            algorithm=CombiningAlgorithm.DENY_OVERRIDES,
            policies=[_permit_policy(), _deny_policy([_role_eq("banned")])],
        )
        d = ps.to_dict()
        restored = PolicySet.from_dict(d)
        assert restored.name == ps.name
        assert restored.algorithm == ps.algorithm
        assert len(restored.policies) == 2

    def test_policy_set_evaluates_correctly_after_roundtrip(self):
        ps = PolicySet(
            name="set",
            algorithm=CombiningAlgorithm.FIRST_APPLICABLE,
            policies=[_permit_policy([_role_eq("admin")]), _deny_policy()],
        )
        restored = PolicySet.from_dict(ps.to_dict())
        assert restored.evaluate(_std_attrs(role="admin")) == Decision.PERMIT
        assert restored.evaluate(_std_attrs(role="user")) == Decision.DENY


# ─── PolicyRegistry (Admin API) ───────────────────────────────────────────────

class TestPolicyRegistry:

    def setup_method(self):
        self.registry = PolicyRegistry()

    def test_create_and_get_policy(self):
        p = _permit_policy(description="test policy")
        pid = self.registry.create_policy(p)
        assert self.registry.get_policy(pid) is p

    def test_get_nonexistent_policy_returns_none(self):
        assert self.registry.get_policy("does-not-exist") is None

    def test_update_policy(self):
        p = _permit_policy(description="original")
        self.registry.create_policy(p)
        p.description = "updated"
        assert self.registry.update_policy(p) is True
        assert self.registry.get_policy(p.policy_id).description == "updated"

    def test_update_nonexistent_returns_false(self):
        p = _permit_policy()
        assert self.registry.update_policy(p) is False

    def test_delete_policy(self):
        p = _permit_policy()
        self.registry.create_policy(p)
        assert self.registry.delete_policy(p.policy_id) is True
        assert self.registry.get_policy(p.policy_id) is None

    def test_delete_nonexistent_returns_false(self):
        assert self.registry.delete_policy("ghost-id") is False

    def test_list_policies(self):
        p1 = _permit_policy(description="p1")
        p2 = _deny_policy(description="p2")
        self.registry.create_policy(p1)
        self.registry.create_policy(p2)
        lst = self.registry.list_policies()
        assert len(lst) == 2
        ids = {p.policy_id for p in lst}
        assert p1.policy_id in ids
        assert p2.policy_id in ids

    def test_create_and_get_policy_set(self):
        ps = PolicySet(name="test-set", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        psid = self.registry.create_policy_set(ps)
        assert self.registry.get_policy_set(psid) is ps

    def test_get_nonexistent_policy_set_returns_none(self):
        assert self.registry.get_policy_set("nope") is None

    def test_delete_policy_set(self):
        ps = PolicySet(name="temp", algorithm=CombiningAlgorithm.PERMIT_OVERRIDES)
        self.registry.create_policy_set(ps)
        assert self.registry.delete_policy_set(ps.policy_set_id) is True
        assert self.registry.get_policy_set(ps.policy_set_id) is None

    def test_list_policy_sets(self):
        ps1 = PolicySet(name="a", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        ps2 = PolicySet(name="b", algorithm=CombiningAlgorithm.PERMIT_OVERRIDES)
        self.registry.create_policy_set(ps1)
        self.registry.create_policy_set(ps2)
        assert len(self.registry.list_policy_sets()) == 2

    def test_update_policy_set(self):
        ps = PolicySet(name="original", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        self.registry.create_policy_set(ps)
        ps.name = "updated"
        assert self.registry.update_policy_set(ps) is True
        assert self.registry.get_policy_set(ps.policy_set_id).name == "updated"

    def test_update_nonexistent_policy_set_returns_false(self):
        ps = PolicySet(name="ghost", algorithm=CombiningAlgorithm.DENY_OVERRIDES)
        assert self.registry.update_policy_set(ps) is False


# ─── Edge cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_conflicting_policies_deny_overrides_wins(self):
        """Both PERMIT and DENY apply — deny-overrides algorithm should return DENY."""
        # catch-all PERMIT and catch-all DENY — DENY wins
        ps = PolicySet(
            name="conflict",
            algorithm=CombiningAlgorithm.DENY_OVERRIDES,
            policies=[_permit_policy(), _deny_policy()],
        )
        assert ps.evaluate(_std_attrs()) == Decision.DENY

    def test_conflicting_policies_permit_overrides_wins(self):
        ps = PolicySet(
            name="conflict",
            algorithm=CombiningAlgorithm.PERMIT_OVERRIDES,
            policies=[_permit_policy(), _deny_policy()],
        )
        assert ps.evaluate(_std_attrs()) == Decision.PERMIT

    def test_empty_conditions_list_is_catch_all(self):
        p = _permit_policy(conditions=[])
        result = p.evaluate(AttributeSet())
        assert result == Decision.PERMIT

    def test_policy_with_multiple_indeterminate_conditions(self):
        cond1 = AttributeCondition("user", "missing1", "eq", "x")
        cond2 = AttributeCondition("user", "missing2", "eq", "y")
        p = _permit_policy([cond1, cond2])
        assert p.evaluate(AttributeSet(user={})) == Decision.INDETERMINATE

    def test_not_applicable_when_no_policies_match(self):
        p = _permit_policy([_role_eq("admin")])
        ps = PolicySet(name="single", algorithm=CombiningAlgorithm.DENY_OVERRIDES, policies=[p])
        assert ps.evaluate(_std_attrs(role="nobody")) == Decision.NOT_APPLICABLE

    def test_time_based_environment_condition(self):
        """Simulate a business-hours policy."""
        cond = AttributeCondition("environment", "hour", "gte", 9)
        cond2 = AttributeCondition("environment", "hour", "lte", 17)
        ps = PolicySet(
            name="business-hours",
            algorithm=CombiningAlgorithm.FIRST_APPLICABLE,
            policies=[
                _permit_policy([cond, cond2]),
                _deny_policy(),
            ],
        )
        assert ps.evaluate(AttributeSet(environment={"hour": 10})) == Decision.PERMIT
        assert ps.evaluate(AttributeSet(environment={"hour": 22})) == Decision.DENY

    def test_clearance_level_numeric_comparison(self):
        cond = AttributeCondition("user", "clearance", "gte", 3)
        ps = PolicySet(
            name="clearance-gate",
            algorithm=CombiningAlgorithm.FIRST_APPLICABLE,
            policies=[_permit_policy([cond]), _deny_policy()],
        )
        assert ps.evaluate(AttributeSet(user={"clearance": 5})) == Decision.PERMIT
        assert ps.evaluate(AttributeSet(user={"clearance": 2})) == Decision.DENY
