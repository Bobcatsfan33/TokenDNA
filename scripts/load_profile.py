#!/usr/bin/env python3
from __future__ import annotations

"""
TokenDNA sustained load profile scaffold.

Runs lightweight concurrent request waves against target endpoints and
produces latency/error statistics suitable for CI gating.
"""

import argparse
import concurrent.futures
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class Sample:
    endpoint: str
    ok: bool
    status_code: int
    latency_ms: float
    error: str


def _call(base_url: str, endpoint: str, timeout: float) -> Sample:
    url = f"{base_url.rstrip('/')}{endpoint}"
    req = urllib.request.Request(url)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
            return Sample(endpoint=endpoint, ok=True, status_code=int(resp.getcode()), latency_ms=latency_ms, error="")
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return Sample(endpoint=endpoint, ok=False, status_code=int(exc.code), latency_ms=latency_ms, error=str(exc.reason))
    except Exception as exc:  # pragma: no cover - smoke harness
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return Sample(endpoint=endpoint, ok=False, status_code=0, latency_ms=latency_ms, error=str(exc))


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, int(len(ordered) * 0.95) - 1)
    return ordered[idx]


def run_load_profile(
    *,
    base_url: str,
    endpoints: list[str],
    concurrency: int,
    requests_per_endpoint: int,
    timeout: float,
) -> dict[str, Any]:
    samples: list[Sample] = []
    tasks: list[tuple[str, str]] = []
    for endpoint in endpoints:
        for _ in range(requests_per_endpoint):
            tasks.append((base_url, endpoint))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = [executor.submit(_call, base, ep, timeout) for base, ep in tasks]
        for future in concurrent.futures.as_completed(futures):
            samples.append(future.result())

    by_endpoint: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        endpoint_samples = [s for s in samples if s.endpoint == endpoint]
        latencies = [s.latency_ms for s in endpoint_samples]
        ok_count = len([s for s in endpoint_samples if s.ok])
        by_endpoint[endpoint] = {
            "count": len(endpoint_samples),
            "ok_count": ok_count,
            "error_count": len(endpoint_samples) - ok_count,
            "p95_latency_ms": _p95(latencies),
            "max_latency_ms": max(latencies) if latencies else 0.0,
        }

    total = len(samples)
    ok_total = len([s for s in samples if s.ok])
    latencies_total = [s.latency_ms for s in samples]
    return {
        "base_url": base_url,
        "concurrency": concurrency,
        "requests_per_endpoint": requests_per_endpoint,
        "endpoints": endpoints,
        "summary": {
            "count": total,
            "ok_count": ok_total,
            "error_count": total - ok_total,
            "error_rate": (float(total - ok_total) / float(total)) if total else 0.0,
            "p95_latency_ms": _p95(latencies_total),
        },
        "by_endpoint": by_endpoint,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run sustained load profile")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--requests-per-endpoint", type=int, default=25)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--max-error-rate", type=float, default=0.10)
    parser.add_argument("--max-p95-ms", type=float, default=250.0)
    parser.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help="Endpoint path to probe (repeatable). Default: /, /api/health",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat connection failures as hard gate failures (default behavior)",
    )
    args = parser.parse_args()

    endpoints = args.endpoint or ["/", "/api/health"]
    report = run_load_profile(
        base_url=args.base_url,
        endpoints=endpoints,
        concurrency=max(1, int(args.concurrency)),
        requests_per_endpoint=max(1, int(args.requests_per_endpoint)),
        timeout=max(0.1, float(args.timeout)),
    )
    print(json.dumps(report, indent=2, sort_keys=True))

    summary = report["summary"]
    if summary["error_rate"] > float(args.max_error_rate):
        return 1
    if summary["p95_latency_ms"] > float(args.max_p95_ms):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
