"""
TokenDNA Sprint 5 — Tests for HVIP (High-Value Identity Profile) hardening.

Covers:
  - HVIPProfile creation and serialisation (to_dict / from_dict)
  - HVIPEnforcer non-privileged pass-through
  - MFA enforcement (strict IL5 vs non-strict)
  - DPoP binding enforcement
  - First-time enrollment auto-create
  - Device DNA matching / mismatch
  - Geo policy enforcement
  - IL5 strict mode raises exceptions
  - Redis profile persistence (mocked)
  - HVIPCheckResult structure
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Optional
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.hvip import (
    HVIPAction,
    HVIPCheckResult,
    HVIPDeviceMismatch,
    HVIPDPoPRequired,
    HVIPEnforcer,
    HVIPError,
    HVIPMFARequired,
    HVIPProfile,
    HVIPRole,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redis_mock(profile: Optional[HVIPProfile] = None) -> MagicMock:
    """Return a mock Redis client that stores/returns one profile."""
    r = MagicMock()
    if profile is not None:
        r.get.return_value = json.dumps(profile.to_dict()).encode()
    else:
        r.get.return_value = None
    return r


def _make_profile(
    uid: str = "user-123",
    role: HVIPRole = HVIPRole.ADMIN,
    device_dna: str = "dna-abc123",
    country: str = "US",
) -> HVIPProfile:
    return HVIPProfile(
        uid=uid,
        role=role,
        enrolled_at=int(time.time()),
        enrolled_dna=device_dna,
        enrolled_country=country,
        enrolled_asn=None,
        mfa_method=None,
        dpop_jwk_thumbprint=None,
    )


def _make_enforcer(
    redis=None,
    il_environment: str = "dev",
    profile: Optional[HVIPProfile] = None,
) -> HVIPEnforcer:
    r = redis or _redis_mock(profile)
    return HVIPEnforcer(redis_client=r, il_environment=il_environment)


# ---------------------------------------------------------------------------
# HVIPProfile
# ---------------------------------------------------------------------------


class TestHVIPProfile:
    def test_to_dict_returns_dict(self):
        p = _make_profile()
        d = p.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_uid(self):
        p = _make_profile(uid="u-999")
        assert p.to_dict()["uid"] == "u-999"

    def test_to_dict_role(self):
        p = _make_profile(role=HVIPRole.OWNER)
        assert p.to_dict()["role"] == "owner"

    def test_to_dict_enrolled_dna(self):
        p = _make_profile(device_dna="dna-xyz")
        assert p.to_dict()["enrolled_dna"] == "dna-xyz"

    def test_from_dict_roundtrip(self):
        original = _make_profile()
        d = original.to_dict()
        restored = HVIPProfile.from_dict(d)
        assert restored.uid == original.uid
        assert restored.role == original.role
        assert restored.enrolled_dna == original.enrolled_dna

    def test_from_dict_country(self):
        p = _make_profile(country="DE")
        restored = HVIPProfile.from_dict(p.to_dict())
        assert restored.enrolled_country == "DE"

    def test_profile_has_enrolled_at(self):
        p = _make_profile()
        assert p.enrolled_at is not None
        assert p.enrolled_at > 0


# ---------------------------------------------------------------------------
# HVIPRole / HVIPAction enums
# ---------------------------------------------------------------------------


class TestHVIPEnums:
    def test_privileged_roles(self):
        assert HVIPRole.OWNER in HVIPEnforcer.PRIVILEGED_ROLES
        assert HVIPRole.ADMIN in HVIPEnforcer.PRIVILEGED_ROLES

    def test_non_privileged_roles(self):
        assert HVIPRole.ANALYST not in HVIPEnforcer.PRIVILEGED_ROLES
        assert HVIPRole.READONLY not in HVIPEnforcer.PRIVILEGED_ROLES

    def test_action_allow(self):
        assert HVIPAction.ALLOW == "allow"

    def test_action_step_up(self):
        assert HVIPAction.STEP_UP == "step_up"


# ---------------------------------------------------------------------------
# Non-privileged roles pass through
# ---------------------------------------------------------------------------


class TestHVIPNonPrivileged:
    def test_analyst_always_allowed(self):
        e = _make_enforcer()
        result = e.check(
            uid="u1",
            role=HVIPRole.ANALYST,
            device_dna="dna-xyz",
            mfa_asserted=False,
            dpop_bound=False,
        )
        assert result.action == HVIPAction.ALLOW

    def test_readonly_always_allowed(self):
        e = _make_enforcer()
        result = e.check(
            uid="u1",
            role=HVIPRole.READONLY,
            device_dna="dna-xyz",
            mfa_asserted=False,
            dpop_bound=False,
        )
        assert result.action == HVIPAction.ALLOW


# ---------------------------------------------------------------------------
# MFA enforcement
# ---------------------------------------------------------------------------


class TestHVIPMFAEnforcement:
    def test_no_mfa_returns_step_up_in_dev(self):
        e = _make_enforcer(il_environment="dev")
        result = e.check(
            uid="u1",
            role=HVIPRole.ADMIN,
            device_dna="dna",
            mfa_asserted=False,
            dpop_bound=False,
        )
        assert result.action == HVIPAction.STEP_UP

    def test_no_mfa_raises_in_il5(self):
        e = _make_enforcer(il_environment="il5")
        with pytest.raises(HVIPMFARequired):
            e.check(
                uid="u1",
                role=HVIPRole.ADMIN,
                device_dna="dna",
                mfa_asserted=False,
                dpop_bound=False,
            )

    def test_mfa_asserted_flag_accepted(self):
        profile = _make_profile(role=HVIPRole.ADMIN, device_dna="dna-123")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna-123",
            mfa_asserted=True,
            dpop_bound=True,
            country="US",
        )
        assert result.mfa_asserted is True

    def test_amr_mfa_accepted(self):
        profile = _make_profile(role=HVIPRole.ADMIN, device_dna="dna")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna",
            mfa_asserted=False,
            dpop_bound=True,
            amr_claims=["otp"],
            country="US",
        )
        assert result.mfa_asserted is True

    def test_amr_hwk_accepted(self):
        profile = _make_profile(role=HVIPRole.OWNER, device_dna="hw-dna")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.OWNER,
            device_dna="hw-dna",
            mfa_asserted=False,
            dpop_bound=True,
            amr_claims=["hwk"],
            country="US",
        )
        assert result.mfa_asserted is True


# ---------------------------------------------------------------------------
# DPoP binding enforcement
# ---------------------------------------------------------------------------


class TestHVIPDPoPEnforcement:
    def test_no_dpop_returns_warn_in_dev(self):
        e = _make_enforcer(il_environment="dev")
        result = e.check(
            uid="u1",
            role=HVIPRole.ADMIN,
            device_dna="dna",
            mfa_asserted=True,
            dpop_bound=False,
        )
        assert result.action == HVIPAction.WARN

    def test_no_dpop_raises_in_il5(self):
        e = _make_enforcer(il_environment="il5")
        with pytest.raises(HVIPDPoPRequired):
            e.check(
                uid="u1",
                role=HVIPRole.ADMIN,
                device_dna="dna",
                mfa_asserted=True,
                dpop_bound=False,
            )

    def test_dpop_bound_flag_recorded(self):
        profile = _make_profile(role=HVIPRole.ADMIN, device_dna="dna-123")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna-123",
            mfa_asserted=True,
            dpop_bound=True,
            country="US",
        )
        assert result.dpop_bound is True


# ---------------------------------------------------------------------------
# First-time enrollment
# ---------------------------------------------------------------------------


class TestHVIPFirstEnrollment:
    def test_no_profile_auto_enrolls(self):
        r = _redis_mock(profile=None)
        e = HVIPEnforcer(redis_client=r, il_environment="dev")
        result = e.check(
            uid="new-user",
            role=HVIPRole.ADMIN,
            device_dna="new-dna",
            mfa_asserted=True,
            dpop_bound=True,
        )
        assert result.action == HVIPAction.ALLOW
        assert "enrollment" in result.reason.lower()

    def test_auto_enroll_saves_to_redis(self):
        r = _redis_mock(profile=None)
        e = HVIPEnforcer(redis_client=r, il_environment="dev")
        e.check(
            uid="new-user",
            role=HVIPRole.ADMIN,
            device_dna="dna-777",
            mfa_asserted=True,
            dpop_bound=True,
        )
        # Redis.set should have been called to save the profile
        r.set.assert_called()


# ---------------------------------------------------------------------------
# Device DNA matching
# ---------------------------------------------------------------------------


class TestHVIPDeviceDNA:
    def test_matching_dna_allows(self):
        profile = _make_profile(device_dna="matching-dna", country="US")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="matching-dna",
            mfa_asserted=True,
            dpop_bound=True,
            country="US",
        )
        assert result.action == HVIPAction.ALLOW
        assert result.device_match is True

    def test_mismatched_dna_step_up_in_dev(self):
        profile = _make_profile(device_dna="original-dna", country="US")
        e = _make_enforcer(profile=profile, il_environment="dev")
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="different-dna",
            mfa_asserted=True,
            dpop_bound=True,
            country="US",
        )
        assert result.action == HVIPAction.STEP_UP
        assert result.device_match is False

    def test_mismatched_dna_raises_in_il5(self):
        profile = _make_profile(device_dna="original-dna", country="US")
        r = _redis_mock(profile=profile)
        e = HVIPEnforcer(redis_client=r, il_environment="il5")
        with pytest.raises(HVIPDeviceMismatch):
            e.check(
                uid="user-123",
                role=HVIPRole.ADMIN,
                device_dna="different-dna",
                mfa_asserted=True,
                dpop_bound=True,
                country="US",
            )


# ---------------------------------------------------------------------------
# Geo policy
# ---------------------------------------------------------------------------


class TestHVIPGeoPolicy:
    def test_matching_country_allows(self):
        profile = _make_profile(country="US")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna-abc123",
            mfa_asserted=True,
            dpop_bound=True,
            country="US",
        )
        assert result.action == HVIPAction.ALLOW
        assert result.geo_match is True

    def test_mismatched_country_applies_geo_policy(self):
        profile = _make_profile(country="US")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna-abc123",
            mfa_asserted=True,
            dpop_bound=True,
            country="RU",
        )
        # geo_match should be False; action depends on profile.geo_policy
        assert result.geo_match is False

    def test_no_country_skips_geo_check(self):
        profile = _make_profile(country="US")
        e = _make_enforcer(profile=profile)
        result = e.check(
            uid="user-123",
            role=HVIPRole.ADMIN,
            device_dna="dna-abc123",
            mfa_asserted=True,
            dpop_bound=True,
            country=None,
        )
        assert result.action == HVIPAction.ALLOW


# ---------------------------------------------------------------------------
# HVIPEnforcer.enroll() direct calls
# ---------------------------------------------------------------------------


class TestHVIPEnroll:
    def test_enroll_returns_profile(self):
        r = _redis_mock()
        e = HVIPEnforcer(redis_client=r, il_environment="dev")
        p = e.enroll(
            uid="u-enroll",
            role=HVIPRole.OWNER,
            device_dna="dna-enroll",
            country="US",
        )
        assert isinstance(p, HVIPProfile)
        assert p.uid == "u-enroll"

    def test_enroll_saves_to_redis(self):
        r = _redis_mock()
        e = HVIPEnforcer(redis_client=r, il_environment="dev")
        e.enroll(uid="u2", role=HVIPRole.ADMIN, device_dna="dna2")
        r.set.assert_called()

    def test_enroll_without_redis_does_not_crash(self):
        e = HVIPEnforcer(redis_client=None, il_environment="dev")
        p = e.enroll(uid="u3", role=HVIPRole.ADMIN, device_dna="dna3")
        assert p.uid == "u3"


# ---------------------------------------------------------------------------
# HVIPCheckResult structure
# ---------------------------------------------------------------------------


class TestHVIPCheckResult:
    def test_result_has_action(self):
        e = _make_enforcer()
        result = e.check(
            uid="u1",
            role=HVIPRole.ANALYST,
            device_dna="dna",
            mfa_asserted=False,
            dpop_bound=False,
        )
        assert hasattr(result, "action")

    def test_result_has_uid(self):
        e = _make_enforcer()
        result = e.check(
            uid="u-xyz",
            role=HVIPRole.ANALYST,
            device_dna="dna",
        )
        assert result.uid == "u-xyz"

    def test_result_has_reason(self):
        e = _make_enforcer()
        result = e.check(
            uid="u1",
            role=HVIPRole.ANALYST,
            device_dna="dna",
        )
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0
