#!/usr/bin/env python3
"""
TokenDNA — Agent Identity Teardown
==================================

The whole product in four verdicts. Each scenario asks TokenDNA one of its
three questions about an AI agent — VERIFY / AUTHORIZE / CONTAIN — and prints
the runtime verdict with the evidence behind it.

    SCENARIO 1  Verified agent, allowed action            ->  ALLOW
    SCENARIO 2  Unverified agent, no policy               ->  BLOCK
    SCENARIO 3  Verified agent, compromise signals +
                high blast radius                         ->  REVIEW
    SCENARIO 4  Agent modifies its own governing policy   ->  BLOCK (CRITICAL)

Verdict legend (TokenDNA risk tiers -> demo labels):

    allow   -> ALLOW    proceed
    step_up -> REVIEW   route to a human / step-up before proceeding
    block   -> BLOCK    refuse; violation recorded for operator approval

Run against a live instance (no external services needed):

    DEV_MODE=true DATA_DB_PATH=./tokendna.db uvicorn api:app --port 8000 &
    python examples/agent_identity_teardown.py

Or preview the calls without a server:

    python examples/agent_identity_teardown.py --dry-run

The script is idempotent (unique IDs per run) and exits non-zero if any
scenario returns a verdict other than the expected one, so it doubles as a
smoke test. Everything here is a real API call evaluated by the real
engines — nothing is mocked or hardcoded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any

BASE_URL = os.getenv("TOKENDNA_URL", "http://localhost:8000")

RUN = uuid.uuid4().hex[:8]
GOOD_AGENT = f"billing-bot-{RUN}"      # verified, well-behaved
GHOST_AGENT = f"unknown-bot-{RUN}"     # nobody attested this thing
DRIFTED_AGENT = f"ops-bot-{RUN}"       # verified once, compromised since
POLICY = f"pol-ops-{RUN}"

FAILURES: list[str] = []


# ── plumbing ─────────────────────────────────────────────────────────────────

def call(method: str, path: str, body: dict | None = None, *, dry: bool = False) -> dict[str, Any]:
    if dry:
        print(f"  [DRY] {method} {path}")
        if body:
            print("        " + json.dumps(body)[:160])
        return {}
    req = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode() or "{}")


def banner(n: int, title: str, question: str) -> None:
    print(f"\n{'=' * 74}\n  SCENARIO {n} — {title}\n  Question: {question}\n{'=' * 74}")


LABEL = {"allow": "ALLOW", "step_up": "REVIEW", "block": "BLOCK"}


def verdict_line(action: str, reasons: list[str], expected: str, scenario: str) -> None:
    label = LABEL.get(action, action.upper())
    ok = "✓" if label == expected else "✗ EXPECTED " + expected
    print(f"\n  VERDICT: {label}   {ok}")
    for r in reasons or []:
        print(f"    reason: {r}")
    if label != expected:
        FAILURES.append(f"{scenario}: got {label}, expected {expected}")


# ── scenarios ────────────────────────────────────────────────────────────────

def scenario_1(dry: bool) -> None:
    banner(1, "Verified agent, allowed action",
           "VERIFY + AUTHORIZE — legitimate identity doing what it is attested to do")
    print(f"  {GOOD_AGENT}: valid certificate, attestation grants invoices:read/write,")
    print("  runtime evidence matches the attested baseline, action within scope.")
    r = call("POST", "/api/abac/evaluate", {
        "uis_event": {"threat": {"risk_score": 88, "risk_tier": "allow"},
                      "subject": {"agent_id": GOOD_AGENT}},
        "attestation": {"attestation_id": f"att-{RUN}-1",
                        "why": {"scope": ["invoices:read", "invoices:write"]}},
        "certificate_verified": True,
        "observed_scope": ["invoices:read"],
        "required_scope": ["invoices:read"],
        "actor_subject": GOOD_AGENT,
    }, dry=dry)
    if dry:
        return
    dec = r.get("decision", {})
    verdict_line(dec.get("action", "?"), dec.get("reasons", []), "ALLOW", "scenario 1")


def scenario_2(dry: bool) -> None:
    banner(2, "Unverified agent, no policy",
           "VERIFY — an agent nobody attested presents an unverifiable credential")
    print(f"  {GHOST_AGENT}: no attestation baseline exists, certificate fails verification.")
    r = call("POST", "/api/abac/evaluate", {
        "uis_event": {"threat": {"risk_score": 45, "risk_tier": "step_up"},
                      "subject": {"agent_id": GHOST_AGENT}},
        "certificate_verified": False,
        "observed_scope": ["invoices:read"],
        "required_scope": ["invoices:read"],
        "actor_subject": GHOST_AGENT,
    }, dry=dry)
    if dry:
        return
    dec = r.get("decision", {})
    verdict_line(dec.get("action", "?"), dec.get("reasons", []), "BLOCK", "scenario 2")


def scenario_3(dry: bool) -> None:
    banner(3, "Verified agent, compromise signals + high blast radius",
           "CONTAIN — identity checks out, but the agent is no longer the agent you attested")
    # 3a. Seed the compromise evidence: unattested permission growth.
    print(f"  {DRIFTED_AGENT}: seeding unattested scope growth (1 -> 6 permissions)...")
    for scope in (["deploy:read"],
                  ["deploy:read", "deploy:write", "iam:CreateAccessKey",
                   "iam:PutRolePolicy", "s3:write:*", "kms:Decrypt"]):
        call("POST", "/api/drift/record", {
            "agent_id": DRIFTED_AGENT, "policy_id": POLICY, "scope": scope,
            "has_attestation": False, "changed_by": DRIFTED_AGENT,
        }, dry=dry)

    # 3b. Seed an MCP tool chain: sensitive read followed by an exfil channel.
    print("  seeding MCP tool chain: read_file(/etc/secrets) -> send_email(external)...")
    for tool, params in (("read_file", {"path": "/etc/secrets/finance.json"}),
                         ("send_email", {"to": "external@elsewhere.io",
                                         "subject": "report", "body": "snapshot"})):
        mr = call("POST", "/api/mcp/inspect", {
            "session_id": f"sess-{RUN}", "tool_name": tool,
            "params": params, "agent_id": DRIFTED_AGENT,
        }, dry=dry)
        if not dry and mr.get("allowed") is False:
            print(f"    mcp_inspector: {tool} flagged (risk={mr.get('risk_score')})")

    # 3c. Show the blast radius the operator would see.
    if not dry:
        blast = call("POST", "/api/simulate/blast_radius",
                     {"agent_label": DRIFTED_AGENT, "max_hops": 6})
        growth = call("GET",
                      f"/api/drift/blast-comparison/{DRIFTED_AGENT}?policy_id={POLICY}")
        print(f"  blast radius: impact={blast.get('impact_score')} "
              f"tier={blast.get('risk_tier')} nodes={blast.get('total_nodes_reached')}")
        if growth.get("found"):
            print(f"  {growth.get('notes')}")

    # 3d. The agent now acts — its runtime soul hash no longer matches the
    # attested baseline (integrity compromise) and its scope has escalated.
    print("  agent acts with a runtime soul-hash that no longer matches attestation...")
    r = call("POST", "/api/abac/evaluate", {
        "uis_event": {"threat": {"risk_score": 75, "risk_tier": "allow"},
                      "subject": {"agent_id": DRIFTED_AGENT}},
        "attestation": {"attestation_id": f"att-{RUN}-3",
                        "what": {"soul_hash": "sha256:attested-baseline"},
                        "why": {"scope": ["deploy:read"]}},
        "certificate_verified": True,
        "request_headers": {"x-agent-soul-hash": "sha256:TAMPERED-AT-RUNTIME"},
        "observed_scope": ["deploy:read", "deploy:write", "iam:CreateAccessKey"],
        "required_scope": ["deploy:read"],
        "actor_subject": DRIFTED_AGENT,
    }, dry=dry)
    if dry:
        return
    dec = r.get("decision", {})
    drift = r.get("drift") or {}
    if drift:
        print(f"  runtime drift: score={drift.get('score')} severity={drift.get('severity')}"
              f" evidence={drift.get('reasons')}")
    verdict_line(dec.get("action", "?"), dec.get("reasons", []), "REVIEW", "scenario 3")


def scenario_4(dry: bool) -> None:
    banner(4, "Critical self-policy modification",
           "AUTHORIZE — the agent tries to expand its own permission boundary")
    print(f"  {DRIFTED_AGENT} attempts to add iam:CreateAccessKey to its own policy...")
    r = call("POST", "/api/policy/guard/evaluate", {
        "request_id": f"req-{RUN}-selfmod",
        "actor_id": DRIFTED_AGENT,
        "actor_type": "agent",
        "action_type": "modify_policy",
        "target_policy_id": POLICY,
        "target_policy_name": f"{DRIFTED_AGENT}-policy",
        "scope_delta": ["iam:CreateAccessKey", "iam:PutRolePolicy"],
        "metadata": {"governed_agent": DRIFTED_AGENT},
    }, dry=dry)
    if dry:
        return
    print(f"  rules triggered: {r.get('rules_triggered')}"
          f"  violation recorded: {bool(r.get('violation_id'))}")
    verdict_line(r.get("disposition", "?"), r.get("reasons", []), "BLOCK", "scenario 4")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="TokenDNA agent identity teardown demo")
    ap.add_argument("--dry-run", action="store_true", help="print calls without a server")
    args = ap.parse_args()

    print("TokenDNA — Agent Identity Teardown")
    print(f"target: {BASE_URL}   run: {RUN}")

    if not args.dry_run:
        try:
            call("GET", "/healthz")
        except Exception:
            print(f"\nNo TokenDNA instance at {BASE_URL}.")
            print("Start one with:  DEV_MODE=true DATA_DB_PATH=./tokendna.db "
                  "uvicorn api:app --port 8000")
            return 2

    scenario_1(args.dry_run)
    scenario_2(args.dry_run)
    scenario_3(args.dry_run)
    scenario_4(args.dry_run)

    print(f"\n{'=' * 74}")
    if args.dry_run:
        print("  DRY RUN complete — start a server and re-run for live verdicts.")
        return 0
    if FAILURES:
        print("  RESULT: FAIL")
        for f in FAILURES:
            print(f"    ✗ {f}")
        return 1
    print("  RESULT: 4/4 verdicts as expected — ALLOW · BLOCK · REVIEW · BLOCK")
    print("  Every verdict above was computed live by the abac, attestation-drift,")
    print("  permission-drift, mcp_inspector, blast-radius, and policy_guard engines.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
