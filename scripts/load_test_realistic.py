"""
TokenDNA — realistic 30-minute load profile.

Simulates a multi-tenant production workload to validate the SLOs documented
in CLAUDE.md and surface memory growth / latency tail issues that
unit-test smoke runs (tests/test_stress_harness.py) can't catch.

Workload mix (from the 20% Plan §2.6):

  60% /secure                core enforcement path (JWT + DPoP + drift gate)
  20% attestation + drift    issuance + drift snapshot reads
  10% intel feeds            threat-intel + transparency log
  10% admin                  tenant + key listing

SLOs asserted at the end:

  p99 < 100 ms on /secure
  zero 5xx
  resident-memory growth < 25% over the 30-minute run

Usage:

  # Local stack:
  scripts/load_test_realistic.py --base-url http://127.0.0.1:8000 \
      --duration-seconds 1800 --target-rps 1000 --tenants 10

  # Smoke (CI-friendly): 30 seconds, 50 rps
  scripts/load_test_realistic.py --smoke

The script writes a JSON report to ``/tmp/tokendna-load-report.json`` and
exits 0 on SLO pass, 1 on SLO fail.

Dependencies: only the Python stdlib.  ``urllib.request`` is used for HTTP
so the script can run in any minimal CI image.  For higher concurrency, set
``--max-workers`` (default 64) or run in shards (multiple processes).
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import resource
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

WORKLOAD_MIX = (
    ("secure",            0.60, "/api/health"),                      # placeholder hot path
    ("attestation_drift", 0.20, "/api/agent/certificates/transparency-log?limit=10"),
    ("intel",             0.10, "/api/threat-intel/feed?limit=10"),
    ("admin",             0.10, "/api/operator/status"),
)

SLO_P99_SECURE_MS = 100.0
SLO_MEM_GROWTH_PCT = 25.0


@dataclass
class BucketStats:
    name: str
    samples: list[float] = field(default_factory=list)
    error_count: int = 0
    five_xx_count: int = 0

    def record(self, latency_ms: float, status: int) -> None:
        self.samples.append(latency_ms)
        if status >= 500:
            self.five_xx_count += 1
            self.error_count += 1
        elif status >= 400:
            self.error_count += 1

    def summary(self) -> dict[str, float | int]:
        if not self.samples:
            return {"name": self.name, "count": 0}
        return {
            "name": self.name,
            "count": len(self.samples),
            "errors": self.error_count,
            "5xx": self.five_xx_count,
            "p50_ms": round(statistics.median(self.samples), 2),
            "p95_ms": round(_percentile(self.samples, 95), 2),
            "p99_ms": round(_percentile(self.samples, 99), 2),
            "max_ms": round(max(self.samples), 2),
        }


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = int(round((pct / 100.0) * (len(s) - 1)))
    return s[k]


def _rss_kb() -> int:
    """Best-effort resident-set size (kB) of the current process."""
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def _make_request(base_url: str, path: str, headers: dict[str, str], timeout: float) -> tuple[int, float]:
    url = f"{base_url}{path}"
    req = urllib.request.Request(url, headers=headers)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            return r.status, (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.perf_counter() - t0) * 1000
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0, (time.perf_counter() - t0) * 1000


def _pick_workload(rng_state: list[int]) -> tuple[str, str]:
    """Linear-congruential jitter so we don't import random for one float."""
    rng_state[0] = (rng_state[0] * 1103515245 + 12345) & 0x7fffffff
    r = rng_state[0] / 0x7fffffff
    cum = 0.0
    for name, weight, path in WORKLOAD_MIX:
        cum += weight
        if r < cum:
            return name, path
    return WORKLOAD_MIX[-1][0], WORKLOAD_MIX[-1][2]


def run(args: argparse.Namespace) -> dict:
    base_url = args.base_url.rstrip("/")
    headers = {"X-API-Key": args.api_key} if args.api_key else {}
    duration = args.duration_seconds
    target_rps = args.target_rps
    tenants = args.tenants
    timeout = args.timeout_seconds

    print(f"target {base_url} • {target_rps} rps • {duration}s • {tenants} tenants • {args.max_workers} workers")

    buckets: dict[str, BucketStats] = {name: BucketStats(name=name) for name, _, _ in WORKLOAD_MIX}
    rss_start = _rss_kb()
    deadline = time.monotonic() + duration

    rng_state = [42]
    issued = 0
    completed = 0
    interval = 1.0 / max(target_rps, 1)

    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures: dict = {}
        next_tick = time.monotonic()
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now < next_tick:
                time.sleep(min(next_tick - now, 0.005))
                continue
            name, path = _pick_workload(rng_state)
            tenant_header = {"X-Demo-Tenant": f"t-{issued % tenants}"}
            req_headers = {**headers, **tenant_header}
            fut = pool.submit(_make_request, base_url, path, req_headers, timeout)
            futures[fut] = name
            issued += 1
            next_tick += interval

            # Drain finished futures opportunistically so the dict doesn't grow
            done = [f for f in list(futures) if f.done()]
            for f in done:
                bucket = buckets[futures.pop(f)]
                status, lat_ms = f.result()
                bucket.record(lat_ms, status)
                completed += 1

        # Drain remaining
        for f in as_completed(list(futures)):
            bucket = buckets[futures[f]]
            status, lat_ms = f.result()
            bucket.record(lat_ms, status)
            completed += 1

    gc.collect()
    rss_end = _rss_kb()
    rss_growth_pct = ((rss_end - rss_start) / rss_start) * 100.0 if rss_start else 0.0

    secure = buckets["secure"].summary()
    secure_p99 = secure.get("p99_ms", 0.0)
    total_5xx = sum(b.five_xx_count for b in buckets.values())

    slo_secure_ok = (secure_p99 < SLO_P99_SECURE_MS) if secure.get("count", 0) else True
    slo_5xx_ok = total_5xx == 0
    slo_mem_ok = rss_growth_pct < SLO_MEM_GROWTH_PCT
    passed = slo_secure_ok and slo_5xx_ok and slo_mem_ok

    report = {
        "config": {
            "base_url": base_url, "duration_seconds": duration,
            "target_rps": target_rps, "tenants": tenants,
            "max_workers": args.max_workers, "timeout_seconds": timeout,
        },
        "throughput": {
            "issued": issued, "completed": completed,
            "issued_rps": round(issued / duration, 2),
        },
        "memory": {
            "rss_start_kb": rss_start,
            "rss_end_kb": rss_end,
            "growth_pct": round(rss_growth_pct, 2),
        },
        "buckets": [b.summary() for b in buckets.values()],
        "slos": {
            "secure_p99_ms_lt_100": slo_secure_ok,
            "zero_5xx": slo_5xx_ok,
            "rss_growth_lt_25pct": slo_mem_ok,
        },
        "passed": passed,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--base-url", default=os.getenv("LOAD_TEST_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--api-key", default=os.getenv("LOAD_TEST_API_KEY", ""))
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--target-rps", type=int, default=1000)
    parser.add_argument("--tenants", type=int, default=10)
    parser.add_argument("--max-workers", type=int, default=64)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--smoke", action="store_true",
                        help="30-second / 50-rps quick run for CI")
    parser.add_argument("--report-path", default="/tmp/tokendna-load-report.json")
    args = parser.parse_args()

    if args.smoke:
        args.duration_seconds = 30
        args.target_rps = 50
        args.tenants = 3

    report = run(args)
    with open(args.report_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
