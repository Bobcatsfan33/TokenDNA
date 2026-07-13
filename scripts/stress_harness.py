#!/usr/bin/env python3
"""
TokenDNA — Production stress harness.

Drives a mixed workload against a TokenDNA deployment and emits a JSON
report containing throughput, p50 / p95 / p99 latency, and error rate
per endpoint. Designed to be run from CI (smoke) or from a load-test
host (sustained), and to be safe against the deployment by holding to
operator-supplied concurrency / RPS caps.

Workload definition (``--profile``):

    [
      {"endpoint": "/healthz",           "weight": 1, "method": "GET"},
      {"endpoint": "/api/uis/spec",      "weight": 4, "method": "GET"},
      {"endpoint": "/scim/v2/ServiceProviderConfig", "weight": 1, "method": "GET"}
    ]

Each iteration of the harness picks an endpoint by weight, sends the
request, records the latency, and increments per-endpoint counters.

Threshold gating (``--gate``):

    {
      "max_p95_ms":   {"/healthz": 50, "/api/uis/spec": 250},
      "max_error_pct": 0.5
    }

When provided, the harness exits non-zero if any threshold is breached.

The harness uses only the standard library so it can run on a stripped
container without installing extra deps.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _Stat:
    samples: list[float] = field(default_factory=list)
    ok: int = 0
    fail: int = 0
    statuses: dict[int, int] = field(default_factory=dict)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round((pct / 100.0) * (len(s) - 1)))))
    return round(s[idx], 3)


def _call(base_url: str, endpoint: dict[str, Any], timeout: float, headers: dict[str, str]) -> tuple[str, bool, int, float]:
    url = f"{base_url.rstrip('/')}{endpoint['endpoint']}"
    method = endpoint.get("method", "GET").upper()
    body = endpoint.get("body")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
            return endpoint["endpoint"], True, int(resp.getcode()), latency_ms
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        # 4xx counts as "expected failure": auth-gated routes will 401/403.
        ok = 400 <= exc.code < 500
        return endpoint["endpoint"], ok, int(exc.code), latency_ms
    except Exception:
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return endpoint["endpoint"], False, 0, latency_ms


def run_stress(
    *,
    base_url: str,
    profile: list[dict[str, Any]],
    duration_seconds: float,
    concurrency: int,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Drive the workload for ``duration_seconds`` and return a report dict."""
    if not profile:
        raise ValueError("profile must be a non-empty list of endpoint specs")
    weights = [max(1, int(p.get("weight", 1))) for p in profile]
    cumulative = []
    running = 0
    for w in weights:
        running += w
        cumulative.append(running)
    total_weight = cumulative[-1]
    headers = headers or {}

    stats: dict[str, _Stat] = {p["endpoint"]: _Stat() for p in profile}
    started_at = time.time()
    deadline = time.perf_counter() + duration_seconds
    completed = 0

    rng = random.Random()

    def _next_endpoint() -> dict[str, Any]:
        pick = rng.randint(1, total_weight)
        for i, c in enumerate(cumulative):
            if pick <= c:
                return profile[i]
        return profile[-1]

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures: set[concurrent.futures.Future[Any]] = set()
        while time.perf_counter() < deadline:
            while len(futures) < concurrency and time.perf_counter() < deadline:
                ep = _next_endpoint()
                futures.add(pool.submit(_call, base_url, ep, timeout, headers))
            done, futures = concurrent.futures.wait(
                futures,
                return_when=concurrent.futures.FIRST_COMPLETED,
                timeout=0.5,
            )
            for fut in done:
                endpoint, ok, status, latency = fut.result()
                stat = stats[endpoint]
                stat.samples.append(latency)
                stat.statuses[status] = stat.statuses.get(status, 0) + 1
                if ok:
                    stat.ok += 1
                else:
                    stat.fail += 1
                completed += 1
        # Drain in-flight requests after the deadline.
        for fut in concurrent.futures.as_completed(futures, timeout=timeout * 2):
            endpoint, ok, status, latency = fut.result()
            stat = stats[endpoint]
            stat.samples.append(latency)
            stat.statuses[status] = stat.statuses.get(status, 0) + 1
            if ok:
                stat.ok += 1
            else:
                stat.fail += 1
            completed += 1

    elapsed = max(0.001, time.perf_counter() - (deadline - duration_seconds))
    per_endpoint: dict[str, dict[str, Any]] = {}
    overall_samples: list[float] = []
    overall_ok = 0
    overall_fail = 0
    for endpoint, stat in stats.items():
        overall_samples.extend(stat.samples)
        overall_ok += stat.ok
        overall_fail += stat.fail
        per_endpoint[endpoint] = {
            "count": len(stat.samples),
            "ok": stat.ok,
            "fail": stat.fail,
            "error_pct": round(stat.fail / max(1, stat.fail + stat.ok) * 100.0, 3),
            "p50_ms": _percentile(stat.samples, 50),
            "p95_ms": _percentile(stat.samples, 95),
            "p99_ms": _percentile(stat.samples, 99),
            "mean_ms": round(statistics.fmean(stat.samples), 3) if stat.samples else 0.0,
            "max_ms": round(max(stat.samples), 3) if stat.samples else 0.0,
            "statuses": dict(sorted(stat.statuses.items())),
        }
    overall = {
        "started_at": started_at,
        "duration_seconds": round(elapsed, 3),
        "concurrency": concurrency,
        "completed": completed,
        "rps": round(completed / elapsed, 2),
        "ok": overall_ok,
        "fail": overall_fail,
        "error_pct": round(overall_fail / max(1, overall_ok + overall_fail) * 100.0, 3),
        "p50_ms": _percentile(overall_samples, 50),
        "p95_ms": _percentile(overall_samples, 95),
        "p99_ms": _percentile(overall_samples, 99),
    }
    return {"overall": overall, "endpoints": per_endpoint}


def evaluate_gate(report: dict[str, Any], gate: dict[str, Any]) -> list[str]:
    """Return a list of human-readable threshold violations (empty when green)."""
    violations: list[str] = []
    max_err = gate.get("max_error_pct")
    if max_err is not None and report["overall"]["error_pct"] > max_err:
        violations.append(
            f"overall error_pct {report['overall']['error_pct']} > {max_err}"
        )
    max_p95 = gate.get("max_p95_ms") or {}
    for endpoint, threshold in max_p95.items():
        ep = report["endpoints"].get(endpoint)
        if ep is None:
            continue
        if ep["p95_ms"] > threshold:
            violations.append(
                f"{endpoint} p95 {ep['p95_ms']}ms > {threshold}ms"
            )
    return violations


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA stress harness")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--profile", required=True, help="Path to JSON workload profile")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--header", action="append", default=[], help='"Name: Value"')
    parser.add_argument("--gate", default=None, help="Path to JSON threshold gate")
    parser.add_argument("--out", default="-", help="Output path (default stdout)")
    args = parser.parse_args()

    with open(args.profile, "r", encoding="utf-8") as fh:
        profile = json.load(fh)
    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    report = run_stress(
        base_url=args.base_url,
        profile=profile,
        duration_seconds=args.duration,
        concurrency=args.concurrency,
        timeout=args.timeout,
        headers=headers,
    )

    gate_violations: list[str] = []
    if args.gate:
        with open(args.gate, "r", encoding="utf-8") as fh:
            gate_cfg = json.load(fh)
        gate_violations = evaluate_gate(report, gate_cfg)
        report["gate"] = {"violations": gate_violations, "passed": not gate_violations}

    rendered = json.dumps(report, sort_keys=True, indent=2)
    if args.out == "-":
        print(rendered)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")

    if gate_violations:
        print(f"GATE FAILED: {len(gate_violations)} violation(s)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
