"""Tests for enterprise hardening — single-tenant + SOC 2 observation log."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tokendna_platform.enterprise import (
    SOC2ObservationLog,
    SOC2ObservationWindow,
    SingleTenantConfig,
    SingleTenantValidator,
)
from tokendna_platform.enterprise.single_tenant import SingleTenantValidationError


def _valid_config(**overrides) -> SingleTenantConfig:
    base = dict(
        tenant_id="acme",
        deployment_id="acme",
        allowed_outbound_hosts=("logs.acme.internal",),
        customer_kms_key_arn="arn:aws:kms:us-east-1:111:key/abc",
        saas_mode_disabled=True,
        fips_mode=True,
    )
    base.update(overrides)
    return SingleTenantConfig(**base)


def test_valid_single_tenant_config_passes() -> None:
    assert SingleTenantValidator.validate(_valid_config()) == []


def test_mismatched_tenant_and_deployment_id_rejected() -> None:
    bad = _valid_config(deployment_id="other")
    problems = SingleTenantValidator.validate(bad)
    assert any("must match" in p for p in problems)


def test_saas_mode_disabled_required() -> None:
    bad = _valid_config(saas_mode_disabled=False)
    problems = SingleTenantValidator.validate(bad)
    assert any("saas_mode_disabled" in p for p in problems)


def test_fips_mode_required() -> None:
    bad = _valid_config(fips_mode=False)
    problems = SingleTenantValidator.validate(bad)
    assert any("fips_mode" in p for p in problems)


def test_customer_kms_required() -> None:
    bad = _valid_config(customer_kms_key_arn=None)
    problems = SingleTenantValidator.validate(bad)
    assert any("customer_kms_key_arn" in p for p in problems)


def test_outbound_allow_list_required() -> None:
    bad = _valid_config(allowed_outbound_hosts=())
    problems = SingleTenantValidator.validate(bad)
    assert any("allowed_outbound_hosts" in p for p in problems)


def test_assert_valid_raises_on_invalid() -> None:
    with pytest.raises(SingleTenantValidationError):
        SingleTenantValidator.assert_valid(_valid_config(fips_mode=False))


# ── SOC 2 observation log ─────────────────────────────────────────────────


def _window() -> SOC2ObservationWindow:
    now = datetime.now(timezone.utc)
    return SOC2ObservationWindow(
        tenant_id="acme",
        start=now - timedelta(days=1),
        end=now + timedelta(days=180),
        auditor="A-LIGN",
    )


def test_log_appends_in_sequence() -> None:
    log = SOC2ObservationLog(_window())
    e1 = log.record(control_id="CC6.1", event_type="control_activated", payload={"x": 1})
    e2 = log.record(control_id="CC7.2", event_type="finding_generated",  payload={"y": 2})
    assert e1.sequence == 1
    assert e2.sequence == 2
    assert e2.previous_hash == e1.entry_hash


def test_chain_verifies_when_intact() -> None:
    log = SOC2ObservationLog(_window())
    for i in range(10):
        log.record(control_id="CC6.1", event_type="t", payload={"i": i})
    assert log.verify() is True


def test_chain_detects_tampering() -> None:
    log = SOC2ObservationLog(_window())
    log.record(control_id="CC6.1", event_type="t", payload={"i": 1})
    log.record(control_id="CC6.1", event_type="t", payload={"i": 2})
    # Tamper directly with the internal list to mutate one entry.
    e0 = log._entries[0]
    log._entries[0] = type(e0)(
        sequence=e0.sequence, timestamp=e0.timestamp,
        control_id=e0.control_id, event_type="TAMPERED",
        payload=e0.payload, previous_hash=e0.previous_hash,
        entry_hash=e0.entry_hash,
    )
    assert log.verify() is False


def test_export_returns_json_safe_records() -> None:
    log = SOC2ObservationLog(_window())
    log.record(control_id="CC6.1", event_type="t", payload={"k": "v"})
    out = log.export()
    assert len(out) == 1
    assert isinstance(out[0]["timestamp"], str)
    assert out[0]["control_id"] == "CC6.1"


def test_window_is_open_during_window() -> None:
    w = _window()
    assert w.is_open is True
