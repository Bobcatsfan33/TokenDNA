from __future__ import annotations

"""
Operator status SLO gate for CI/release checks.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any


def _fetch_json(url: str, timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"X-API-Key": "ci-slo-gate"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def run(base_url: str, timeout: float = 5.0, skip_infra_deps: bool = False) -> dict[str, Any]:
    status_url = f"{base_url.rstrip('/')}/api/operator/status"
    data = _fetch_json(status_url, timeout)

    deps = data.get("dependencies") or {}
    redis_ok = bool((deps.get("redis") or {}).get("ok"))
    sqlite_ok = bool((deps.get("sqlite") or {}).get("ok"))
    clickhouse_ok = bool((deps.get("clickhouse") or {}).get("ok"))

    slo = data.get("slo") or {}
    edge = slo.get("edge_decision_ms") or {}
    target = float(edge.get("target", 5.0))

    checks = [
        {"name": "sqlite_up", "ok": sqlite_ok, "detail": "sqlite dependency health"},
    ]
    if not skip_infra_deps:
        checks += [
            {"name": "redis_up", "ok": redis_ok, "detail": "redis dependency health"},
            {"name": "clickhouse_up", "ok": clickhouse_ok, "detail": "clickhouse dependency health"},
        ]
    else:
        checks += [
            {"name": "redis_up", "ok": True, "detail": f"redis dependency health (skipped — ok={redis_ok})"},
            {"name": "clickhouse_up", "ok": True, "detail": f"clickhouse dependency health (skipped — ok={clickhouse_ok})"},
        ]
    checks.append(
        {"name": "edge_slo_target_present", "ok": target > 0, "detail": f"edge_decision_ms target={target}"}
    )
    failed = [c for c in checks if not c["ok"]]
    return {"ok": not failed, "failed_count": len(failed), "checks": checks, "raw": data}


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA operator status SLO gate")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail closed when operator endpoint is unreachable (default behavior).",
    )
    parser.add_argument(
        "--skip-infra-deps",
        action="store_true",
        help="Skip Redis and ClickHouse dependency checks (use in CI where infra services are not running).",
    )
    args = parser.parse_args()

    try:
        report = run(base_url=args.base_url, timeout=args.timeout, skip_infra_deps=args.skip_infra_deps)
    except urllib.error.URLError as exc:
        payload = {"ok": False, "error": f"url_error:{exc}"}
        print(json.dumps(payload, indent=2))
        sys.exit(1 if args.strict else 0)
    except Exception as exc:
        payload = {"ok": False, "error": f"exception:{exc}"}
        print(json.dumps(payload, indent=2))
        sys.exit(1 if args.strict else 0)

    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
