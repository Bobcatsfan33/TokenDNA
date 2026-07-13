#!/usr/bin/env python3
"""
TokenDNA Runtime Risk Engine — live demo arc (Act 1 intra-org + Act 2 cross-org)

The narrative customers see in a sales meeting:

    ── ACT 1 — Intra-org Runtime Risk Engine ───────────────────────────
    SCENE 1.  Baseline    — innocuous activity from a legitimate agent
    SCENE 2.  Drift       — agent's permission scope grows >2x without
                            attestation; PERMISSION_WEIGHT_DRIFT fires
    SCENE 3.  Self-mod    — agent writes a policy expanding its own
                            permission boundary; POLICY_SCOPE_MODIFICATION
                            fires (CRITICAL)
    SCENE 4.  MCP chain   — agent invokes a read tool then an exfil tool
                            within the MCP chain window; MCP_CHAIN_PATTERN
                            fires
    SCENE 5.  Deception   — agent trips a honeytoken decoy
    SCENE 6.  Blast       — operator runs simulate_blast_radius and sees
                            ALL the live signals attached to one agent
    SCENE 7.  Verdict     — policy_guard rejects the next attempted action;
                            policy_advisor surfaces a tightening suggestion;
                            operator approves it

    ── ACT 2 — Federated Agent Trust (cross-org) ───────────────────────
    SCENE 8.  Federation  — Acme initiates a federation handshake to Beta;
                            Beta accepts; mutual trust is established
    SCENE 9.  Cross-org   — agent at Acme attempts an action against Beta
                            WITHOUT a federation_trust_id → CONST-06 BLOCKs
                            the action and CROSS_ORG_ACTION_WITHOUT_HANDSHAKE
                            fires in Acme's trust graph
    SCENE 10. Approved    — same action retried WITH the trust_id passes
                            CONST-06 cleanly

Run against a live TokenDNA instance:

    DEV_MODE=true uvicorn api:app --port 8000 &
    python scripts/demo_runtime_risk_engine.py

Or in --dry-run mode to see what would be sent:

    python scripts/demo_runtime_risk_engine.py --dry-run

The script is idempotent — every step uses unique IDs so you can re-run
it against the same instance without polluting prior demo state.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


BASE_URL = "http://localhost:8000"
API_KEY  = "demo-key"            # DEV_MODE bypasses auth

# Stable run identifier — every demo run gets fresh agent / session names
# so the same script can be replayed against a long-running instance.
RUN_TAG = uuid.uuid4().hex[:8]
TENANT  = "demo-tenant"
AGENT   = f"finance-bot-{RUN_TAG}"
ANALYST = f"analyst-{RUN_TAG}@acme.com"
SESSION = f"sess-{RUN_TAG}"
POLICY  = f"pol-finance-{RUN_TAG}"


# ── HTTP helper ───────────────────────────────────────────────────────────────


def _req(
    method: str,
    path: str,
    body: dict | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    url = f"{BASE_URL.rstrip('/')}{path}"
    if dry_run:
        preview = json.dumps(body)[:80] if body else ""
        print(f"  [DRY] {method:6} {path}  {preview}")
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


def _scene(num: int, title: str) -> None:
    print()
    print("─" * 72)
    print(f"  SCENE {num}.  {title}")
    print("─" * 72)


def _step(label: str, result: dict[str, Any] | None = None) -> None:
    if result is None:
        print(f"  → {label}")
        return
    summary = ", ".join(
        f"{k}={v}"
        for k, v in result.items()
        if k in ("disposition", "recommendation", "risk_score",
                 "growth_factor", "anomaly_count", "violation_count",
                 "drift_id", "violation_id", "suggestion_id",
                 "impact_score", "risk_tier", "total_nodes_reached",
                 "chain_pattern_count")
    )
    print(f"  ✓ {label}  {summary}")


def wait_for_api(max_tries: int = 30, dry_run: bool = False) -> bool:
    if dry_run:
        return True
    print("Waiting for API ", end="", flush=True)
    for _ in range(max_tries):
        try:
            req = urllib.request.Request(f"{BASE_URL}/healthz")
            with urllib.request.urlopen(req, timeout=2):
                print(" up")
                return True
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    print(" TIMEOUT", file=sys.stderr)
    return False


# ── Scene helpers ─────────────────────────────────────────────────────────────


def scene_baseline(dry_run: bool) -> None:
    _scene(1, "Baseline — innocuous activity")
    # A simple permission observation with attestation; keeps the scope small.
    r = _req("POST", "/api/drift/record", {
        "agent_id": AGENT,
        "policy_id": POLICY,
        "scope": ["s3:read:reports"],
        "has_attestation": True,
        "changed_by": "ops-bot",
    }, dry_run=dry_run)
    _step("baseline observation recorded", r if r else None)


def scene_drift(dry_run: bool) -> None:
    _scene(2, "Permission Drift — scope grows >2x without attestation")
    sizes = [
        ["s3:read:reports", "s3:read:logs"],
        ["s3:read:reports", "s3:read:logs", "s3:read:audit"],
        ["s3:read:*", "s3:write:reports", "s3:write:logs", "s3:write:audit",
         "iam:CreateAccessKey", "iam:PutRolePolicy"],
    ]
    for i, scope in enumerate(sizes, start=1):
        r = _req("POST", "/api/drift/record", {
            "agent_id": AGENT,
            "policy_id": POLICY,
            "scope": scope,
            "has_attestation": False,
            "changed_by": "ops-bot",
        }, dry_run=dry_run)
        _step(f"drift step {i}/{len(sizes)} — scope size {len(scope)}", r)


def scene_self_modification(dry_run: bool) -> None:
    _scene(3, "Self-Modification — POLICY_SCOPE_MODIFICATION fires CRITICAL")
    # The agent itself attempts to expand its own scope via policy_guard.
    r = _req("POST", "/api/policy/guard/evaluate", {
        "request_id": f"req-{RUN_TAG}-selfmod",
        "actor_id": AGENT,
        "actor_type": "agent",
        "action_type": "modify_policy",
        "target_policy_id": POLICY,
        "target_policy_name": f"{AGENT}-policy",
        "tenant_id": TENANT,
        "scope_delta": ["iam:CreateAccessKey", "iam:PutRolePolicy"],
        "metadata": {"governed_agent": AGENT},
    }, dry_run=dry_run)
    _step("policy_guard evaluation", r)


def scene_mcp_chain(dry_run: bool) -> None:
    _scene(4, "MCP Tool Chain — read → exfil within session window")
    for tool, params, label in (
        ("read_file",
         {"path": "/etc/secrets/finance.json"},
         "MCP read_file (sensitive path)"),
        ("send_email",
         {"to": "external@elsewhere.io",
          "subject": "report",
          "body": "snapshot"},
         "MCP send_email (exfil channel)"),
    ):
        r = _req("POST", "/api/mcp/inspect", {
            "session_id": SESSION,
            "tool_name": tool,
            "params": params,
            "agent_id": AGENT,
        }, dry_run=dry_run)
        _step(label, r)


def scene_deception(dry_run: bool) -> None:
    _scene(5, "Deception — agent trips a honeytoken decoy")
    # Plant a decoy first so it exists.
    r = _req("POST", "/api/honeypot/decoy/honeytoken", {
        "name": f"finance-token-{RUN_TAG}",
        "trigger_endpoint": "/decoy/finance",
    }, dry_run=dry_run)
    decoy_id = r.get("decoy_id") or "decoy-stub"
    _step("honeytoken planted", {"decoy_id": decoy_id})
    # Record a hit — agent touched the decoy.
    r = _req("POST", "/api/honeypot/hits/record", {
        "decoy_id": decoy_id,
        "agent_id": AGENT,
        "context": {"endpoint": "/decoy/finance", "method": "GET"},
    }, dry_run=dry_run)
    _step("honeytoken trip recorded", r)


def scene_blast(dry_run: bool) -> None:
    _scene(6, "Blast Radius — live anomalies + MCP violations attached")
    r = _req("POST", "/api/simulate/blast_radius", {
        "agent_label": AGENT,
        "max_hops": 6,
    }, dry_run=dry_run)
    if r:
        anomalies = r.get("recent_anomalies_in_blast", [])
        violations = r.get("recent_mcp_violations_in_blast", [])
        print(f"    impact_score: {r.get('impact_score')} ({r.get('risk_tier')})")
        print(f"    nodes reached: {r.get('total_nodes_reached')}")
        print(f"    live trust-graph anomalies on blast: {len(anomalies)}")
        for a in anomalies[:5]:
            print(f"      • [{a.get('severity', '?').upper()}] "
                  f"{a.get('anomaly_type')} → {a.get('subject_node')}")
        print(f"    open MCP violations on blast: {len(violations)}")
        for v in violations[:5]:
            print(f"      • {v.get('violation_type')} on {v.get('tool_name')}"
                  f" (risk={v.get('risk_score'):.2f})")


def scene_federation(dry_run: bool) -> dict[str, Any]:
    _scene(8, "Federation — Acme ↔ Beta mutual trust handshake")
    if dry_run:
        print("  [DRY] federation.initiate_handshake(local=acme, remote=beta, scope=['agent-acme-*'])")
        print("  [DRY] federation.accept_handshake(handshake_id=..., accepting_org=acme, ...)")
        return {"trust_id": "trust-stub"}
    # Federation bootstrap is a server-side op; run it in-process so the
    # demo proves the full trust path even before HTTP routes for FAT ship.
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from modules.identity import federation as _fed
    _fed.init_db()
    # Idempotent: if a federation trust between acme↔beta already exists
    # (e.g. seeded by demo_seed_v2.py), reuse it instead of crashing on
    # the UNIQUE(local_org_id, remote_org_id) constraint.
    existing = _fed.find_active_trust(
        local_org_id="acme", remote_org_id="beta",
        agent_label="finance-bot-01",
    )
    if existing is not None:
        _step(f"reusing existing federation trust  trust_id={existing.trust_id[:8]}")
        return {"trust_id": existing.trust_id}

    offer = _fed.initiate_handshake(
        local_org_id="beta",        # Beta offers federation to Acme
        remote_org_id="acme",
        accepted_scope=["finance-bot-*"],
        policy_summary={"soc2": True, "iso27001": True},
    )
    _step(f"Beta initiated handshake to Acme  handshake_id={offer.handshake_id[:8]}")
    trust = _fed.accept_handshake(
        handshake_id=offer.handshake_id,
        accepting_org_id="acme",
        remote_federation_key="acme-key-" + RUN_TAG,
        accepted_by="ops@acme.com",
    )
    _step(f"Acme accepted   trust_id={trust.trust_id[:8]}  scope={trust.accepted_scope}")
    return {"trust_id": trust.trust_id}


def scene_cross_org_blocked(dry_run: bool) -> None:
    _scene(9, "Cross-org without trust — CONST-06 BLOCKs")
    r = _req("POST", "/api/policy/guard/evaluate", {
        "request_id": f"req-{RUN_TAG}-xorg-blocked",
        "actor_id": AGENT,
        "actor_type": "agent",
        "action_type": "read_resource",
        "target_policy_id": "beta/pol-invoice",
        "target_policy_name": "beta-cross-org-policy",
        "tenant_id": "acme",
        "metadata": {
            "remote_org_id": "beta",
            # No federation_trust_id — CONST-06 must BLOCK
        },
    }, dry_run=dry_run)
    _step("policy_guard.evaluate (no trust_id) → expect BLOCK", r)


def scene_cross_org_approved(dry_run: bool, trust_id: str) -> None:
    _scene(10, "Cross-org WITH trust — CONST-06 passes")
    r = _req("POST", "/api/policy/guard/evaluate", {
        "request_id": f"req-{RUN_TAG}-xorg-approved",
        "actor_id": AGENT,
        "actor_type": "agent",
        "action_type": "read_resource",
        "target_policy_id": "beta/pol-invoice",
        "target_policy_name": "beta-cross-org-policy",
        "tenant_id": "acme",
        "metadata": {
            "remote_org_id": "beta",
            "federation_trust_id": trust_id,
        },
    }, dry_run=dry_run)
    _step("policy_guard.evaluate (with trust_id) → expect ALLOW", r)


def scene_verdict(dry_run: bool) -> None:
    _scene(7, "Verdict — policy_guard rejects, advisor recommends, operator approves")
    # Generate a fresh suggestion based on the recent violations.
    advice = _req("POST", "/api/policy/suggestions/analyze", {
        "lookback_hours": 1,
        "min_confidence": 0.0,
    }, dry_run=dry_run)
    _step("advisor analysis", advice)

    # List pending suggestions to find one to approve.
    pending = _req("GET", "/api/policy/suggestions?status=pending&limit=1",
                   dry_run=dry_run)
    suggestions = pending.get("suggestions", []) if isinstance(pending, dict) else []
    if suggestions:
        sid = suggestions[0]["suggestion_id"]
        r = _req(
            "POST",
            f"/api/policy/suggestions/{sid}/approve",
            {"approved_by": ANALYST, "note": "demo approval", "run_regression": False},
            dry_run=dry_run,
        )
        _step(f"operator approved suggestion {sid[:8]}", r)
    else:
        _step("no pending suggestions to approve (advisor may emit on next analyze)")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    global BASE_URL
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be sent without hitting the API")
    parser.add_argument("--base-url", default=BASE_URL,
                        help="API base URL (default %(default)s)")
    args = parser.parse_args()
    BASE_URL = args.base_url

    print(f"\nTokenDNA Runtime Risk Engine — demo run {RUN_TAG}")
    print(f"  tenant={TENANT}  agent={AGENT}  session={SESSION}\n")

    if not wait_for_api(dry_run=args.dry_run):
        return 1

    # Act 1 — intra-org Runtime Risk Engine
    scene_baseline(args.dry_run)
    scene_drift(args.dry_run)
    scene_self_modification(args.dry_run)
    scene_mcp_chain(args.dry_run)
    scene_deception(args.dry_run)
    scene_blast(args.dry_run)
    scene_verdict(args.dry_run)

    # Act 2 — Federated Agent Trust (cross-org)
    fed_state = scene_federation(args.dry_run)
    scene_cross_org_blocked(args.dry_run)
    scene_cross_org_approved(args.dry_run, trust_id=fed_state["trust_id"])

    print()
    print("=" * 72)
    print("  Demo arc complete.  Open the dashboard for the visual story:")
    print(f"    {BASE_URL.replace(':8000', '')}/dashboard")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
