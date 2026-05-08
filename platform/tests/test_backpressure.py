"""Tests for the bounded-queue backpressure gate."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import pytest

from tokendna_platform.ingestion.backpressure import (
    BackpressureGate,
    IngestQueueFull,
)


def test_admit_until_high_water_mark() -> None:
    g = BackpressureGate(capacity=10, high_water_mark=8)
    for _ in range(8):
        assert g.try_admit(1) is True
    # 9th would breach HWM.
    assert g.try_admit(1) is False


def test_admit_raises_when_full() -> None:
    g = BackpressureGate(capacity=4, high_water_mark=3)
    g.admit(3)
    with pytest.raises(IngestQueueFull):
        g.admit(1)


def test_release_frees_capacity() -> None:
    g = BackpressureGate(capacity=10, high_water_mark=8)
    g.admit(8)
    assert g.try_admit(1) is False
    g.release(3)
    assert g.try_admit(1) is True


def test_release_clamps_at_zero() -> None:
    g = BackpressureGate(capacity=10)
    g.release(100)
    assert g.status().pending == 0


def test_default_high_water_mark_is_90pct() -> None:
    g = BackpressureGate(capacity=100)
    assert g.status().high_water_mark == 90


def test_invalid_capacity_rejected() -> None:
    with pytest.raises(ValueError):
        BackpressureGate(capacity=0)


def test_admit_n_atomic() -> None:
    """Admitting a batch larger than free capacity refuses *all* of it."""
    g = BackpressureGate(capacity=10, high_water_mark=10)
    g.admit(8)
    assert g.try_admit(3) is False  # 8 + 3 > 10
    assert g.status().pending == 8  # not partially admitted


def test_status_reports_state() -> None:
    g = BackpressureGate(capacity=10, high_water_mark=8)
    g.admit(5)
    s = g.status()
    assert (s.pending, s.high_water_mark, s.capacity) == (5, 8, 10)
