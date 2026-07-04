#!/usr/bin/env python3
"""
TokenDNA detection-efficacy benchmark.

Replays the three RSA-2026 runtime-risk scenarios TokenDNA's README claims to
close, against a *local, in-process instance* of the API (FastAPI ``TestClient``
booted with ``DEV_MODE=true`` + ``TOKENDNA_ENV=ci``), and emits a reproducible
JSON + Markdown report covering:

  * detection rate  — fraction of injected attacks the engine flags
  * false-positive rate — fraction of a benign-traffic baseline that trips a flag
  * decision latency — p50/p95/p99 of the decisive HTTP decision call, compared
    against ``EDGE_DECISION_SLO_MS``

The three scenarios (endpoints reused from ``scripts/demo_runtime_risk_engine``):

  1. Permission drift        POST /api/drift/record   (+ GET /api/drift/alerts)
  2. Policy self-modification POST /api/policy/guard/evaluate
  3. MCP tool-chain attack    POST /api/mcp/inspect    (read -> exfil in-session)

Honesty notes (see docs/BENCHMARK.md for the full methodology + limitations):
  * This is a *functional* efficacy check on deterministic, hand-authored
    scenarios — NOT an independent red-team or a garak/live-traffic study.
  * Latency is measured at the HTTP layer in-process; it is a conservative
    UPPER BOUND on the native edge decision the SLO targets. Latency is
    REPORTED, never gated (``--strict`` gates only detection + FP).

Usage:
    TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py           # run + report
    TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py --strict  # CI gate
    TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py --iterations 50 \
        --out-dir reports/
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# A benign baseline that should never trip a flag, and an attack that always
# should. FP tolerance is 0 and detection floor is 1.0 under --strict.
DEFAULT_ITERATIONS = 25


def _bootstrap_env() -> tempfile.TemporaryDirectory:
    """Configure a hermetic in-process instance BEFORE importing the app.

    DEV_MODE requires an explicit dev environment post-#140; ``TOKENDNA_ENV=ci``
    satisfies the deny-by-default guard. License enforcement is left ``off`` so
    the synthetic DEV_MODE tenant keeps its ent.* entitlement.
    """
    tmp = tempfile.TemporaryDirectory()
    os.environ["DEV_MODE"] = "true"
    os.environ.setdefault("TOKENDNA_ENV", "ci")
    os.environ["DATA_DB_PATH"] = str(Path(tmp.name) / "efficacy.db")
    # Redirect the SOC2 audit sink into the sandbox so runs are hermetic and
    # don't spew "permission denied: /var/log/aegis" on developer machines / CI.
    os.environ["AUDIT_LOG_PATH"] = str(Path(tmp.name) / "audit.jsonl")
    os.environ.pop("TOKENDNA_LICENSE_ENFORCEMENT", None)  # default off
    os.environ.pop("TOKENDNA_LICENSE_KEY", None)
    return tmp


def _slo_ms() -> float:
    return max(0.001, float(os.getenv("EDGE_DECISION_SLO_MS", "5")))


# ── Scenario drivers ─────────────────────────────────────────────────────────
# Each returns (detected: bool, latency_ms: float, detail: dict). ``latency_ms``
# times the single decisive decision call.

def _drift_attack(client, tag: str) -> tuple[bool, float, dict]:
    agent, policy = f"agent-{tag}", f"pol-{tag}"
    # Baseline: small, attested — establishes the drift baseline weight.
    client.post("/api/drift/record", json={
        "agent_id": agent, "policy_id": policy,
        "scope": ["s3:read:reports"], "has_attestation": True, "changed_by": "ops",
    })
    escalations = [
        ["s3:read:reports", "s3:read:logs"],
        ["s3:read:reports", "s3:read:logs", "s3:read:audit"],
        ["s3:read:*", "s3:write:reports", "s3:write:logs", "s3:write:audit",
         "iam:CreateAccessKey", "iam:PutRolePolicy"],
    ]
    latency = 0.0
    for scope in escalations:
        t0 = time.perf_counter()
        client.post("/api/drift/record", json={
            "agent_id": agent, "policy_id": policy,
            "scope": scope, "has_attestation": False, "changed_by": "ops",
        })
        latency = (time.perf_counter() - t0) * 1000.0  # decisive = last escalation
    alerts = client.get(f"/api/drift/alerts?agent_id={agent}&status=open").json()
    rows = alerts.get("alerts", []) if isinstance(alerts, dict) else []
    return bool(rows), latency, {"alerts": len(rows)}


def _drift_benign(client, tag: str) -> tuple[bool, float, dict]:
    agent, policy = f"agent-{tag}", f"pol-{tag}"
    for scope in (["s3:read:reports"], ["s3:read:reports", "s3:read:logs"]):
        t0 = time.perf_counter()
        client.post("/api/drift/record", json={
            "agent_id": agent, "policy_id": policy,
            "scope": scope, "has_attestation": True, "changed_by": "ops",
        })
        latency = (time.perf_counter() - t0) * 1000.0
    alerts = client.get(f"/api/drift/alerts?agent_id={agent}&status=open").json()
    rows = alerts.get("alerts", []) if isinstance(alerts, dict) else []
    return bool(rows), latency, {"alerts": len(rows)}


def _policy_attack(client, tag: str) -> tuple[bool, float, dict]:
    agent, policy = f"agent-{tag}", f"pol-{tag}"
    t0 = time.perf_counter()
    r = client.post("/api/policy/guard/evaluate", json={
        "actor_id": agent, "actor_type": "agent", "action_type": "update",
        "target_policy_id": policy, "target_policy_name": f"{agent}-policy",
        "scope_delta": ["iam:CreateAccessKey", "iam:PutRolePolicy"],
        "metadata": {"governed_agent": agent},
    }).json()
    latency = (time.perf_counter() - t0) * 1000.0
    disp = str(r.get("disposition", "allow")).lower()
    detected = disp in {"block", "flag"} or bool(r.get("violation_id")) or bool(r.get("rules_triggered"))
    return detected, latency, {"disposition": disp, "rules": r.get("rules_triggered")}


def _policy_benign(client, tag: str) -> tuple[bool, float, dict]:
    # Legitimate control: a HUMAN operator makes a routine, non-governance
    # policy update. This is exactly the traffic the guard must NOT flag —
    # only agent self-modification (the attack) should trip.
    policy = f"pol-{tag}"
    t0 = time.perf_counter()
    r = client.post("/api/policy/guard/evaluate", json={
        "actor_id": f"operator-{tag}", "actor_type": "human", "action_type": "update",
        "target_policy_id": policy, "target_policy_name": f"reporting-schedule-{tag}",
        "scope_delta": [],  # no scope change
        "metadata": {},
    }).json()
    latency = (time.perf_counter() - t0) * 1000.0
    disp = str(r.get("disposition", "allow")).lower()
    detected = disp in {"block", "flag"} or bool(r.get("violation_id"))
    return detected, latency, {"disposition": disp}


def _mcp_attack(client, tag: str) -> tuple[bool, float, dict]:
    session, agent = f"sess-{tag}", f"agent-{tag}"
    # read a sensitive path, then exfil within the same session window.
    client.post("/api/mcp/inspect", json={
        "session_id": session, "agent_id": agent, "tool_name": "read_file",
        "params": {"path": "/etc/secrets/finance.json"},
    })
    t0 = time.perf_counter()
    r = client.post("/api/mcp/inspect", json={
        "session_id": session, "agent_id": agent, "tool_name": "send_email",
        "params": {"to": "external@elsewhere.io", "subject": "r", "body": "snapshot"},
    }).json()
    latency = (time.perf_counter() - t0) * 1000.0
    chains = r.get("chain_patterns", []) if isinstance(r, dict) else []
    rec = str(r.get("recommendation", "allow")).lower()
    detected = bool(chains) or rec in {"block", "flag"}
    return detected, latency, {"chain_patterns": len(chains), "recommendation": rec}


def _mcp_benign(client, tag: str) -> tuple[bool, float, dict]:
    session, agent = f"sess-{tag}", f"agent-{tag}"
    client.post("/api/mcp/inspect", json={
        "session_id": session, "agent_id": agent, "tool_name": "read_file",
        "params": {"path": "/data/reports/summary.txt"},
    })
    t0 = time.perf_counter()
    r = client.post("/api/mcp/inspect", json={
        "session_id": session, "agent_id": agent, "tool_name": "read_file",
        "params": {"path": "/data/reports/detail.txt"},
    }).json()
    latency = (time.perf_counter() - t0) * 1000.0
    chains = r.get("chain_patterns", []) if isinstance(r, dict) else []
    rec = str(r.get("recommendation", "allow")).lower()
    detected = bool(chains) or rec == "block"
    return detected, latency, {"chain_patterns": len(chains), "recommendation": rec}


SCENARIOS: dict[str, dict[str, Callable]] = {
    "permission_drift": {"attack": _drift_attack, "benign": _drift_benign},
    "policy_self_modification": {"attack": _policy_attack, "benign": _policy_benign},
    "mcp_chain_attack": {"attack": _mcp_attack, "benign": _mcp_benign},
}


# ── Runner ───────────────────────────────────────────────────────────────────

def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 4)


def run(iterations: int = DEFAULT_ITERATIONS) -> dict[str, Any]:
    from fastapi.testclient import TestClient  # imported after env bootstrap

    import api  # noqa: PLC0415

    per_scenario: dict[str, Any] = {}
    all_latencies: list[float] = []
    total_attacks = total_detected = total_benign = total_fp = 0

    with TestClient(api.app) as client:
        # DEV_MODE bypasses auth; probe one endpoint to fail fast if not.
        probe = client.post("/api/drift/record", json={
            "agent_id": "probe", "policy_id": "probe", "scope": ["x"],
            "has_attestation": True,
        })
        if probe.status_code in (401, 403):
            raise SystemExit(
                f"instance is gating requests (HTTP {probe.status_code}); the "
                "benchmark needs DEV_MODE=true + TOKENDNA_ENV=ci. Aborting."
            )

        for name, fns in SCENARIOS.items():
            detected = 0
            fps = 0
            lats: list[float] = []
            for _ in range(iterations):
                tag = uuid.uuid4().hex[:10]
                d, lat, _detail = fns["attack"](client, tag)
                detected += int(d)
                lats.append(lat)
                bt = uuid.uuid4().hex[:10]
                fp, _lat_b, _db = fns["benign"](client, bt)
                fps += int(fp)
            per_scenario[name] = {
                "iterations": iterations,
                "detected": detected,
                "detection_rate": round(detected / iterations, 4),
                "false_positives": fps,
                "false_positive_rate": round(fps / iterations, 4),
                "latency_ms": {
                    "p50": _pct(lats, 0.50),
                    "p95": _pct(lats, 0.95),
                    "p99": _pct(lats, 0.99),
                    "max": round(max(lats), 4) if lats else 0.0,
                },
            }
            all_latencies.extend(lats)
            total_attacks += iterations
            total_detected += detected
            total_benign += iterations
            total_fp += fps

    slo = _slo_ms()
    p95 = _pct(all_latencies, 0.95)
    report = {
        "benchmark": "tokendna-detection-efficacy",
        "iterations_per_scenario": iterations,
        "scenarios": per_scenario,
        "summary": {
            "detection_rate": round(total_detected / total_attacks, 4) if total_attacks else 0.0,
            "attacks_detected": total_detected,
            "attacks_total": total_attacks,
            "false_positive_rate": round(total_fp / total_benign, 4) if total_benign else 0.0,
            "false_positives": total_fp,
            "benign_total": total_benign,
            "latency_ms": {
                "p50": _pct(all_latencies, 0.50),
                "p95": p95,
                "p99": _pct(all_latencies, 0.99),
            },
            "edge_decision_slo_ms": slo,
            "p95_within_slo": p95 <= slo,
            "latency_note": (
                "end-to-end in-process HTTP-layer latency; a conservative upper "
                "bound on the native edge decision the SLO targets. Advisory only."
            ),
        },
    }
    return report


def _render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# TokenDNA Detection-Efficacy Report",
        "",
        f"- Iterations per scenario: **{report['iterations_per_scenario']}**",
        f"- Overall detection rate: **{s['detection_rate']*100:.1f}%** "
        f"({s['attacks_detected']}/{s['attacks_total']})",
        f"- False-positive rate: **{s['false_positive_rate']*100:.1f}%** "
        f"({s['false_positives']}/{s['benign_total']})",
        f"- Decision latency p50/p95/p99: "
        f"**{s['latency_ms']['p50']} / {s['latency_ms']['p95']} / "
        f"{s['latency_ms']['p99']} ms** "
        f"(SLO {s['edge_decision_slo_ms']} ms — "
        f"{'within' if s['p95_within_slo'] else 'ABOVE (advisory, see note)'})",
        "",
        "> " + s["latency_note"],
        "",
        "## Per-scenario",
        "",
        "| Scenario | Detection | False-positive | p50 ms | p95 ms | p99 ms |",
        "|---|---|---|---|---|---|",
    ]
    for name, d in report["scenarios"].items():
        lat = d["latency_ms"]
        lines.append(
            f"| {name} | {d['detection_rate']*100:.0f}% "
            f"({d['detected']}/{d['iterations']}) | "
            f"{d['false_positive_rate']*100:.0f}% "
            f"({d['false_positives']}/{d['iterations']}) | "
            f"{lat['p50']} | {lat['p95']} | {lat['p99']} |"
        )
    lines.append("")
    lines.append("_See `docs/BENCHMARK.md` for methodology and what this does NOT cover._")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    ap.add_argument("--out-dir", type=Path, default=Path("."))
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if detection < 100%% or any false positive")
    ap.add_argument("--json-only", action="store_true", help="suppress the summary print")
    args = ap.parse_args()

    tmp = _bootstrap_env()
    try:
        report = run(iterations=max(1, args.iterations))
    finally:
        tmp.cleanup()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "efficacy_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = _render_markdown(report)
    (args.out_dir / "efficacy_report.md").write_text(md, encoding="utf-8")

    if not args.json_only:
        print(md)
        print(f"→ wrote {args.out_dir / 'efficacy_report.json'} and "
              f"{args.out_dir / 'efficacy_report.md'}")

    s = report["summary"]
    if args.strict:
        problems = []
        if s["detection_rate"] < 1.0:
            problems.append(f"detection_rate={s['detection_rate']} < 1.0")
        if s["false_positive_rate"] > 0.0:
            problems.append(f"false_positive_rate={s['false_positive_rate']} > 0")
        if problems:
            print("STRICT FAIL: " + "; ".join(problems), file=sys.stderr)
            return 1
        print("STRICT OK: detection 100%, zero false positives.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
