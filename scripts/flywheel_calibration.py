#!/usr/bin/env python3
"""
Flywheel calibration harness.

The threat-sharing flywheel scoring formula has three tunable parameters:

    BREADTH_SATURATION_TENANTS   how many distinct tenants saturate the
                                  breadth contribution (default 20)
    CONFIDENCE_HALF_LIFE_DAYS    half-life of a signal when no new hits
                                  arrive (default 180)
    confirmed_hit_curve          1 - 1/(1 + confirmed/3) — slope of the
                                  hit-volume contribution (hardcoded)

Picking *correct* values for these requires real false-positive rate data
from production intent-correlation matches. Until we have that, this
harness lets operators sanity-check the formula against synthetic
distributions: feed in plausible scenarios, see what scores fall out,
adjust env vars, re-run.

Usage
-----

    python scripts/flywheel_calibration.py                # default scenarios
    python scripts/flywheel_calibration.py --csv          # csv output
    python scripts/flywheel_calibration.py --tenants 50   # custom breadth sat

Output is a table per scenario showing how confidence evolves as a
function of (confirmed hits, distinct tenants, days-since-last-hit).
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from dataclasses import dataclass
from typing import Iterable


# Mirror the formula in modules/product/threat_sharing_flywheel.py so this
# harness can run standalone without booting the full app.

@dataclass
class Params:
    breadth_saturation_tenants: int = 20
    confidence_half_life_days: int = 180


def confidence(
    *,
    confirmed_hits: int,
    distinct_tenants: int,
    days_since_last_hit: float,
    params: Params,
) -> float:
    if confirmed_hits <= 0 and distinct_tenants <= 0:
        return 0.0
    hit_component = 1.0 - 1.0 / (1.0 + (confirmed_hits / 3.0)) if confirmed_hits else 0.0
    breadth = min(distinct_tenants, params.breadth_saturation_tenants)
    breadth_component = breadth / float(params.breadth_saturation_tenants)
    raw = 0.7 * hit_component + 0.3 * breadth_component
    decay_window = params.confidence_half_life_days * 2.0
    decay = max(0.0, 1.0 - (days_since_last_hit / decay_window))
    return round(raw * decay, 4)


# ── Synthetic scenarios ───────────────────────────────────────────────────────

@dataclass
class Scenario:
    name: str
    description: str
    confirmed_hits: int
    distinct_tenants: int
    days_since_last_hit: float


SCENARIOS: list[Scenario] = [
    Scenario(
        name="brand_new_signal",
        description="A playbook just published; nobody has confirmed yet.",
        confirmed_hits=0, distinct_tenants=0, days_since_last_hit=0,
    ),
    Scenario(
        name="single_tenant_one_hit",
        description="One tenant confirmed once. Lowest-confidence true signal.",
        confirmed_hits=1, distinct_tenants=1, days_since_last_hit=0,
    ),
    Scenario(
        name="single_tenant_repeated",
        description="Same tenant confirms 5 times — strong intra-tenant signal.",
        confirmed_hits=5, distinct_tenants=1, days_since_last_hit=0,
    ),
    Scenario(
        name="three_tenant_corroboration",
        description="Three different tenants each confirm once.",
        confirmed_hits=3, distinct_tenants=3, days_since_last_hit=0,
    ),
    Scenario(
        name="early_consensus",
        description="10 tenants × 2 confirmations each.",
        confirmed_hits=20, distinct_tenants=10, days_since_last_hit=0,
    ),
    Scenario(
        name="full_consensus",
        description="20 tenants (saturation) × 5 confirmations each.",
        confirmed_hits=100, distinct_tenants=20, days_since_last_hit=0,
    ),
    Scenario(
        name="oversaturated",
        description="40 tenants × 5 confirmations — beyond breadth saturation.",
        confirmed_hits=200, distinct_tenants=40, days_since_last_hit=0,
    ),
    Scenario(
        name="aged_30d",
        description="Strong signal but no hits in 30 days.",
        confirmed_hits=20, distinct_tenants=10, days_since_last_hit=30,
    ),
    Scenario(
        name="aged_180d",
        description="Half-life threshold — strong signal, no hits in 180 days.",
        confirmed_hits=20, distinct_tenants=10, days_since_last_hit=180,
    ),
    Scenario(
        name="aged_360d_zero",
        description="Past full decay window — confidence should be zero.",
        confirmed_hits=20, distinct_tenants=10, days_since_last_hit=400,
    ),
    Scenario(
        name="suspected_attacker_inflation",
        description="One tenant claims many confirms. Breadth saturation should keep this low-ish vs broad-but-shallow signal.",
        confirmed_hits=50, distinct_tenants=1, days_since_last_hit=0,
    ),
    Scenario(
        name="broad_but_shallow",
        description="20 tenants × 1 confirm each — should rank ABOVE the inflation case.",
        confirmed_hits=20, distinct_tenants=20, days_since_last_hit=0,
    ),
]


def evaluate(
    scenarios: Iterable[Scenario],
    params: Params,
) -> list[tuple[Scenario, float]]:
    return [
        (s, confidence(
            confirmed_hits=s.confirmed_hits,
            distinct_tenants=s.distinct_tenants,
            days_since_last_hit=s.days_since_last_hit,
            params=params,
        ))
        for s in scenarios
    ]


# ── CLI ──────────────────────────────────────────────────────────────────────

def _print_table(rows: list[tuple[Scenario, float]]) -> None:
    name_w = max(len(r[0].name) for r in rows) + 2
    print(f"{'scenario':<{name_w}} {'confirmed':>10} {'tenants':>8} "
          f"{'days_old':>10} {'confidence':>11}  description")
    print("-" * (name_w + 50))
    for s, c in sorted(rows, key=lambda kv: -kv[1]):
        bar = "█" * int(c * 40)
        print(f"{s.name:<{name_w}} {s.confirmed_hits:>10} {s.distinct_tenants:>8} "
              f"{s.days_since_last_hit:>10.1f} {c:>11.4f}  {bar} {s.description}")


def _print_csv(rows: list[tuple[Scenario, float]]) -> None:
    w = csv.writer(sys.stdout)
    w.writerow(["scenario", "confirmed_hits", "distinct_tenants",
                "days_since_last_hit", "confidence", "description"])
    for s, c in rows:
        w.writerow([s.name, s.confirmed_hits, s.distinct_tenants,
                    s.days_since_last_hit, c, s.description])


def _validate_invariants(rows: list[tuple[Scenario, float]]) -> list[str]:
    """Sanity checks the calibration MUST satisfy regardless of parameter choice."""
    by_name = {r[0].name: r[1] for r in rows}
    failures: list[str] = []
    if by_name.get("brand_new_signal", 0) > 0.001:
        failures.append("brand_new_signal should score ~0")
    if by_name.get("aged_360d_zero", 1) > 0.001:
        failures.append("aged_360d_zero should fully decay to 0")
    if by_name.get("suspected_attacker_inflation", 0) >= by_name.get("broad_but_shallow", 0):
        failures.append(
            "broad_but_shallow should rank ABOVE suspected_attacker_inflation — "
            "if not, breadth saturation is misconfigured"
        )
    if by_name.get("full_consensus", 0) <= by_name.get("single_tenant_one_hit", 1):
        failures.append("full_consensus should rank above single_tenant_one_hit")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Flywheel scoring calibration harness — synthetic-data simulator.",
    )
    parser.add_argument("--csv", action="store_true", help="Emit CSV instead of table.")
    parser.add_argument(
        "--tenants",
        type=int,
        default=int(os.getenv("FLYWHEEL_BREADTH_SAT", "20")),
        help="Override BREADTH_SATURATION_TENANTS (default %(default)s).",
    )
    parser.add_argument(
        "--half-life",
        type=int,
        default=int(os.getenv("FLYWHEEL_HALF_LIFE_DAYS", "180")),
        help="Override CONFIDENCE_HALF_LIFE_DAYS (default %(default)s).",
    )
    parser.add_argument(
        "--no-validate", action="store_true",
        help="Skip the invariant-check step at the end.",
    )
    args = parser.parse_args(argv)

    params = Params(
        breadth_saturation_tenants=args.tenants,
        confidence_half_life_days=args.half_life,
    )

    rows = evaluate(SCENARIOS, params)

    if args.csv:
        _print_csv(rows)
    else:
        print(
            f"# breadth_saturation_tenants={params.breadth_saturation_tenants} "
            f"confidence_half_life_days={params.confidence_half_life_days}"
        )
        _print_table(rows)

    if not args.no_validate:
        failures = _validate_invariants(rows)
        if failures:
            print()
            print("INVARIANT FAILURES:")
            for f in failures:
                print(f"  ✗ {f}")
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
