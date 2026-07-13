from __future__ import annotations

"""
Enterprise readiness smoke scaffolding.

This is a lightweight harness for local load/security dry-runs without requiring
external infrastructure. It intentionally keeps checks simple so teams can plug
it into CI or run ad hoc during hardening work.
"""

import argparse
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class ProbeResult:
    path: str
    ok: bool
    status_code: int
    latency_ms: float
    detail: str


def _request(url: str, timeout: float, headers: dict[str, str] | None = None) -> ProbeResult:
    req = urllib.request.Request(url, headers=headers or {})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency = (time.perf_counter() - started) * 1000.0
            return ProbeResult(
                path=url,
                ok=True,
                status_code=int(resp.getcode()),
                latency_ms=round(latency, 3),
                detail="ok",
            )
    except urllib.error.HTTPError as exc:
        latency = (time.perf_counter() - started) * 1000.0
        return ProbeResult(
            path=url,
            ok=False,
            status_code=int(exc.code),
            latency_ms=round(latency, 3),
            detail=f"http_error:{exc.reason}",
        )
    except Exception as exc:  # pragma: no cover - smoke helper
        latency = (time.perf_counter() - started) * 1000.0
        return ProbeResult(
            path=url,
            ok=False,
            status_code=0,
            latency_ms=round(latency, 3),
            detail=f"error:{exc}",
        )


def run_smoke(base_url: str, timeout: float = 3.0) -> dict:
    checks = [
        ("/", {}),
        ("/api/health", {"X-API-Key": "placeholder-key"}),
        ("/api/operator/status", {"X-API-Key": "placeholder-key"}),
    ]
    results: list[ProbeResult] = []
    for path, headers in checks:
        results.append(_request(f"{base_url.rstrip('/')}{path}", timeout=timeout, headers=headers))

    latencies = [r.latency_ms for r in results]
    p95 = sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0.0
    return {
        "base_url": base_url,
        "count": len(results),
        "ok_count": len([r for r in results if r.ok]),
        "p95_latency_ms": p95,
        "results": [r.__dict__ for r in results],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA load/security smoke scaffold")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    report = run_smoke(base_url=args.base_url, timeout=args.timeout)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
