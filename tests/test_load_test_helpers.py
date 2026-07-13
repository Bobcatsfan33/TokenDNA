"""
Smoke tests for the realistic load harness helpers — the parts that don't
need a running API.  The end-to-end run lives in scripts/load_test_realistic.py
and is exercised by the CI Stress Smoke job.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# Load by path because scripts/ isn't a package.
_SPEC = importlib.util.spec_from_file_location(
    "load_test_realistic",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "load_test_realistic.py"),
)
lt = importlib.util.module_from_spec(_SPEC)
# Register before exec so dataclass introspection can find the module.
sys.modules["load_test_realistic"] = lt
_SPEC.loader.exec_module(lt)


def test_percentile_basic():
    assert lt._percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50) in (5, 6)
    assert lt._percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 99) == 10
    assert lt._percentile([], 95) == 0.0


def test_percentile_handles_single_value():
    assert lt._percentile([42.0], 50) == 42.0
    assert lt._percentile([42.0], 99) == 42.0


def test_workload_picker_distribution_matches_spec():
    state = [123]
    buckets: dict[str, int] = {}
    n = 5000
    for _ in range(n):
        name, _ = lt._pick_workload(state)
        buckets[name] = buckets.get(name, 0) + 1
    # Allow ±5 absolute percent jitter from the configured weights.
    expected = {name: weight for name, weight, _ in lt.WORKLOAD_MIX}
    for name, got_count in buckets.items():
        observed_pct = (got_count / n) * 100.0
        spec_pct = expected[name] * 100.0
        assert abs(observed_pct - spec_pct) < 5.0, \
            f"{name}: observed {observed_pct:.1f}% vs spec {spec_pct:.1f}%"


def test_bucket_stats_records_and_summarises():
    b = lt.BucketStats(name="secure")
    for lat in (10, 20, 30, 40, 50):
        b.record(lat, 200)
    b.record(120, 503)
    s = b.summary()
    assert s["name"] == "secure"
    assert s["count"] == 6
    assert s["errors"] == 1
    assert s["5xx"] == 1
    assert s["max_ms"] == 120
    assert s["p50_ms"] in (30, 35)


def test_bucket_stats_summary_empty():
    b = lt.BucketStats(name="empty")
    s = b.summary()
    assert s == {"name": "empty", "count": 0}
