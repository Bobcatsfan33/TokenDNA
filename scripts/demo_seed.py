#!/usr/bin/env python3
"""
TokenDNA Runtime Risk Engine — Demo Seed Script

Populates a fresh TokenDNA instance with a realistic attack scenario:

  STAGE 1 — Normal baseline (agents authenticating legitimately)
  STAGE 2 — Credential probe (attacker trying stolen tokens)
  STAGE 3 — Compromise event (attacker gains foothold in agent-01)
  STAGE 4 — Privilege escalation (agent-01 escalates via tool-call chain)
  STAGE 5 — Lateral movement (attacker pivots to agent-02)
  STAGE 6 — Data exfiltration attempt

Run against a live TokenDNA instance:

  DEV_MODE=true uvicorn api:app --port 8000 &
  python scripts/demo_seed.py

Or in --dry-run mode to see what would be sent:

  python scripts/demo_seed.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


BASE_URL = "http://localhost:8000"
API_KEY  = "demo-key"        # DEV_MODE bypasses auth


def _req(method: str, path: str, body: dict | None = None, dry_run: bool = False) -> dict:
    url = f"{BASE_URL.rstrip('/')}{path}"
    if dry_run:
        print(f"  [DRY] {method} {path}" + (f" → {json.dumps(body)[:80]}..." if body else ""))
        return {}
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:200]
        print(f"  ⚠ HTTP {e.code} on {method} {path}: {body_text}", file=sys.stderr)
        return {}
    except Exception as exc:
        print(f"  ⚠ {exc}", file=sys.stderr)
        return {}


def _print_section(title: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print('─'*60)


def _print_result(label: str, data: dict) -> None:
    if not data:
        return
    # Pretty-print only the interesting keys
    interesting = {k: v for k, v in data.items()
                   if k not in ("uis_event", "tenant_id") and v is not None}
    print(f"  ✓ {label}: {json.dumps(interesting, separators=(',', ':'))[:120]}")


def wait_for_api(max_tries: int = 30, dry_run: bool = False) -> None:
    if dry_run:
        return
    print("Waiting for API...", end="", flush=True)
    for i in range(max_tries):
        try:
            urllib.request.urlopen(f"{BASE_URL}/", timeout=2)
            print(" ready ✓")
            return
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    print(" timed out", file=sys.stderr)
    sys.exit(1)


# ── Stage helpers ──────────────────────────────────────────────────────────────

def normalize_event(
    subject: str,
    agent_id: str | None,
    entity_type: str,
    issuer: str,
    protocol: str,
    auth_method: str,
    risk_score: int,
    risk_tier: str,
    impossible_travel: bool = False,
    lateral_movement: bool = False,
    attestation_id: str | None = None,
    dry_run: bool = False,
) -> dict:
    return _req("POST", "/api/uis/normalize", {
        "protocol": protocol,
        "subject": subject,
        "claims": {
            "entity_type": entity_type,
            "agent_id": agent_id,
            "iss": issuer,
            "agent_model": "gpt-4o" if agent_id else None,
            "attestation_id": attestation_id,
        },
        "request_context": {
            "ip": "203.0.113.42" if impossible_travel else "10.0.1.5",
            "country": "CN" if impossible_travel else "US",
            "asn": "AS4134" if impossible_travel else "AS16509",
        },
        "risk_context": {
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "impossible_travel": impossible_travel,
            "lateral_movement": lateral_movement,
            "indicators": (
                ["scope_escalation_detected"] if (risk_tier == "high" and not impossible_travel) else []
            ) + (
                ["supply_chain_integrity_check_failed"] if (risk_score > 80 and lateral_movement) else []
            ),
        },
    }, dry_run=dry_run)


def run_demo(dry_run: bool = False) -> None:
    wait_for_api(dry_run=dry_run)

    print("\n" + "═"*60)
    print("  TokenDNA Runtime Risk Engine — Demo Seeding")
    print("═"*60)

    # ── Stage 1: Normal baseline ───────────────────────────────────────────────
    _print_section("STAGE 1 — Baseline: Normal agent authentication (5 events)")
    agents = [
        ("agent-orchestrator@acme.svc", "agt-orchestrator", "https://auth.acme.io", "att-orch-001"),
        ("agent-data-analyst@acme.svc",  "agt-analyst",      "https://auth.acme.io", "att-anal-001"),
        ("agent-api-gateway@acme.svc",   "agt-gateway",      "https://auth.acme.io", "att-gw-001"),
    ]
    for subj, aid, iss, att in agents:
        for _ in range(5):  # 5 baseline events each = meets MIN_STABLE_OBSERVATIONS threshold
            r = normalize_event(
                subject=subj, agent_id=aid, entity_type="machine",
                issuer=iss, protocol="spiffe", auth_method="mtls",
                risk_score=8, risk_tier="low",
                attestation_id=att, dry_run=dry_run,
            )
    print(f"  ✓ Seeded {len(agents)*5} baseline events across {len(agents)} agents")

    # ── Stage 2: Credential probe ──────────────────────────────────────────────
    _print_section("STAGE 2 — Credential Probe (attacker testing stolen tokens)")
    for i in range(3):
        normalize_event(
            subject="agent-orchestrator@acme.svc", agent_id="agt-orchestrator",
            entity_type="machine", issuer="https://auth.acme.io",
            protocol="oidc", auth_method="bearer_reuse",
            risk_score=55 + i*5, risk_tier="medium",
            dry_run=dry_run,
        )
    print("  ✓ 3 credential probe events — medium risk, credential_abuse category")

    # ── Stage 3: Compromise ────────────────────────────────────────────────────
    _print_section("STAGE 3 — Compromise: agt-orchestrator accessed from unusual location")
    r = normalize_event(
        subject="agent-orchestrator@acme.svc", agent_id="agt-orchestrator",
        entity_type="machine", issuer="https://auth.acme.io",
        protocol="oidc", auth_method="stolen_token",
        risk_score=85, risk_tier="high",
        impossible_travel=True,
        dry_run=dry_run,
    )
    print("  ✓ Impossible travel detected → auth_anomaly / T1078 / HIGH confidence")

    # ── Stage 4: Privilege escalation ─────────────────────────────────────────
    _print_section("STAGE 4 — Privilege Escalation via tool-call chain")
    r = normalize_event(
        subject="agent-orchestrator@acme.svc", agent_id="agt-orchestrator",
        entity_type="machine", issuer="https://auth.acme.io",
        protocol="spiffe", auth_method="admin_scope_granted",   # New tool — anomaly fires
        risk_score=88, risk_tier="high",
        dry_run=dry_run,
    )
    print("  ✓ New tool in stable agent toolkit → NEW_TOOL_IN_STABLE_AGENT_TOOLKIT anomaly")

    # ── Stage 5: Lateral movement ──────────────────────────────────────────────
    _print_section("STAGE 5 — Lateral Movement: pivoting to agt-analyst")
    r = normalize_event(
        subject="agent-data-analyst@acme.svc", agent_id="agt-analyst",
        entity_type="machine", issuer="https://auth.acme.io",
        protocol="oidc", auth_method="delegated_token",
        risk_score=90, risk_tier="critical",
        lateral_movement=True,
        attestation_id="att-compromised-pivot",  # New verifier — anomaly fires
        dry_run=dry_run,
    )
    print("  ✓ Lateral movement flagged → UNFAMILIAR_VERIFIER_IN_TRUST_PATH anomaly")

    # ── Stage 6: Exfiltration attempt ─────────────────────────────────────────
    _print_section("STAGE 6 — Exfiltration Attempt")
    r = normalize_event(
        subject="agent-data-analyst@acme.svc", agent_id="agt-analyst",
        entity_type="machine", issuer="https://auth.acme.io",
        protocol="oauth2_opaque", auth_method="s3_presigned",
        risk_score=95, risk_tier="critical",
        dry_run=dry_run,
    )
    print("  ✓ Exfiltration attempt — exfiltration category")

    # ── Add a custom playbook ──────────────────────────────────────────────────
    _print_section("Custom Playbook: ACME-specific AI Agent Compromise Pattern")
    r = _req("POST", "/api/intent/playbooks", {
        "name": "ACME AI Agent Compromise → Data Theft",
        "description": "Specific to ACME's agent fleet: credential probe followed by impossible travel then exfiltration.",
        "severity": "critical",
        "steps": [
            {"category": "credential_abuse", "min_confidence": 0.4},
            {"category": "auth_anomaly",     "min_confidence": 0.5},
            {"category": "exfiltration",     "min_confidence": 0.4},
        ],
        "window_seconds": 7200,
    }, dry_run=dry_run)
    if r.get("playbook_id"):
        print(f"  ✓ Custom playbook created: {r['playbook_id']}")

    # ── Blast radius simulation ────────────────────────────────────────────────
    _print_section("Blast Radius Simulation: agt-orchestrator compromised")
    r = _req("POST", "/api/simulate/blast_radius", {
        "agent_label": "agt-orchestrator",
        "max_hops": 6,
    }, dry_run=dry_run)
    if r and not dry_run:
        print(f"  ✓ Impact score:     {r.get('impact_score', '?')}/100")
        print(f"  ✓ Risk tier:        {r.get('risk_tier', '?').upper()}")
        print(f"  ✓ Nodes reachable:  {r.get('total_nodes_reached', '?')}")
        if r.get('policies_containing_blast'):
            print(f"  ✓ Policy overlap:   {r['policies_containing_blast']}")
        nodes = r.get("reachable_nodes", [])
        if nodes:
            print(f"  ✓ Reachable nodes:")
            for n in nodes[:5]:
                print(f"      [{n['node_type']:10}] {n['label']} (hop {n['hop_distance']}, +{n['impact_contribution']} pts)")

    # ── Summary queries ────────────────────────────────────────────────────────
    _print_section("Summary")

    r = _req("GET", "/api/graph/stats", dry_run=dry_run)
    if r and not dry_run:
        print(f"  Trust Graph:  {r.get('node_count','?')} nodes, {r.get('edge_count','?')} edges, {r.get('anomaly_count','?')} anomalies")

    r = _req("GET", "/api/graph/anomalies?limit=5", dry_run=dry_run)
    if r and not dry_run:
        anomalies = r.get("anomalies", [])
        print(f"  Anomalies:    {len(anomalies)} detected")
        for a in anomalies[:3]:
            print(f"    [{a['severity'].upper():8}] {a['anomaly_type']} — {a['subject_node']}")

    r = _req("GET", "/api/intent/matches", dry_run=dry_run)
    if r and not dry_run:
        matches = r.get("matches", [])
        print(f"  Intent matches: {len(matches)} attack sequences detected")
        for m in matches[:3]:
            print(f"    [{m['severity'].upper():8}] {m['playbook_name']} (conf={m['confidence']:.2f})")

    print("\n" + "═"*60)
    print("  Demo seeding complete.")
    print(f"  Dashboard: {BASE_URL}/dashboard")
    print(f"  API docs:  {BASE_URL}/docs")
    print("═"*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed TokenDNA demo data")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    BASE_URL = args.base_url
    run_demo(dry_run=args.dry_run)
