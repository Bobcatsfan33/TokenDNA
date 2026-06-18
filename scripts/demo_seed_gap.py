#!/usr/bin/env python3
"""Gap-roadmap demo seeder — fake data for the features demo_seed_v2 doesn't cover.

Seeds a coherent **airline-agent-demo** narrative for the dev tenant so every
gap-roadmap feature shows live, interactive data:

  * Asset inventory  — scan an airline agent workflow (agents/tools/MCP/vulns)
  * Kill switch       — configure IdP (Okta/Entra) + MCP credentials + live
                        sessions for the demo agents so /api/kill/{id}/preview
                        shows every plane connected and a rip returns real
                        per-plane receipts
  * Governed retrieval — per-agent allowed-source policies
  * Campaigns          — a multi-session/agent/model attack campaign
  * SIEM               — MCP gateway sessions + enforcements (per-call audit)

Run standalone (gap only) or via the launcher which runs demo_seed_v2 first.
Every enrichment is best-effort: a signature mismatch in one never aborts the
rest (the demo must always come up).

Usage:
    python scripts/demo_seed_gap.py                 # gap features only
    python scripts/demo_seed_gap.py --with-base     # demo_seed_v2 base first
    DATA_DB_PATH=/tmp/demo.db python scripts/demo_seed_gap.py
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Callable

# Make the repo root importable when run as a script (scripts/ is sys.path[0]).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEMO_TENANT = "acme"

# The airline-agent-demo workflow (matches the Zscaler-style sample). Agent
# names here are reused across every kill-switch plane so the console graph is
# fully wired.
AIRLINE_WORKFLOW = {
    "framework": "langgraph",
    "source": "airline-agent-demo",
    "nodes": [
        {"name": "triage-agent", "tools": ["search_flights", "lookup_booking"]},
        {"name": "booking-agent", "tools": [{"name": "create_booking",
                                              "input_schema": {"flight": "str"}}]},
        {"name": "payment-agent", "tools": ["charge_card", "issue_refund", "update_policy"]},
    ],
    "edges": [["triage-agent", "booking-agent"], ["booking-agent", "payment-agent"]],
    "mcp_servers": [
        {"name": "crm-mcp", "auth": "none", "tools": ["read_customer", "write_note"]},
        {"name": "ledger-mcp", "auth": "oauth", "tools": ["post_charge"]},
    ],
    # no observability key -> triggers missing_observability finding
}

DEMO_AGENTS = ["triage-agent", "booking-agent", "payment-agent"]


def _try(summary: dict, key: str, fn: Callable[[], Any]) -> None:
    """Run an enrichment best-effort; record count or error."""
    try:
        result = fn()
        summary[key] = result if isinstance(result, (int, str)) else "ok"
    except Exception as exc:  # noqa: BLE001 - demo must always come up
        summary[key] = f"skipped: {exc}"
        print(f"  ! {key}: {exc}", file=sys.stderr)


def seed_gap(tenant_id: str = DEMO_TENANT) -> dict[str, Any]:
    """Seed all gap-roadmap features for a tenant. Returns a counts summary."""
    summary: dict[str, Any] = {"tenant": tenant_id}

    # ── Asset inventory: scan the airline workflow ────────────────────────────
    def _assets():
        from modules.identity import asset_inventory
        r = asset_inventory.scan_workflow(
            tenant_id=tenant_id, definition=AIRLINE_WORKFLOW, source="airline-agent-demo")
        # a second scan so history is non-trivial
        asset_inventory.scan_workflow(
            tenant_id=tenant_id,
            definition={"framework": "crewai", "source": "support-crew",
                        "agents": [{"role": "support-agent", "tools": ["kb_search"]}],
                        "mcp_servers": [{"name": "tickets-mcp"}]},
            source="support-crew")
        return f"{r['counts']['agents']}a/{r['counts']['tools']}t/{r['counts']['mcp_servers']}m/{r['counts']['vulnerabilities']}v"
    _try(summary, "asset_scan", _assets)

    # ── Kill switch: IdP config so Okta/Entra planes show connected ───────────
    def _idp():
        # In-memory config (no real Okta/Entra creds) — the planes show connected
        # and a rip is a clean no-op. NOTE: in-memory only, so the running server
        # also sets this at startup via TOKENDNA_DEMO (see api_routers/demo.py).
        from modules.identity import idp_revocation as idp
        idp.configure_demo_idp(tenant_id)
        return "okta+entra"
    _try(summary, "idp_config", _idp)

    # ── Kill switch: MCP credentials + tool grants for the demo agents ────────
    def _mcp_grants():
        from modules.identity import mcp_gateway
        n = 0
        for a in DEMO_AGENTS:
            mcp_gateway.grant_credential(tenant_id=tenant_id, agent_id=a,
                                         server_id="crm-mcp", credential_ref=f"vault://mcp/{a}")
            mcp_gateway.grant_tool(tenant_id=tenant_id, agent_id=a,
                                   server_id="crm-mcp", tool_name="read_customer")
            n += 1
        return n
    _try(summary, "mcp_grants", _mcp_grants)

    # ── Kill switch: live sessions so the session plane has something to kill ──
    def _sessions():
        from modules.identity import session_registry
        n = 0
        for a in DEMO_AGENTS:
            session_registry.register_session(tenant_id=tenant_id, agent_id=a, channel="websocket")
            n += 1
        return n
    _try(summary, "live_sessions", _sessions)

    # ── SIEM: MCP gateway sessions + enforcements (per-call audit feed) ───────
    def _siem():
        from modules.identity import mcp_gateway
        n = 0
        for a in DEMO_AGENTS:
            sess = mcp_gateway.open_session(tenant_id=tenant_id, agent_id=a,
                                            server_id="crm-mcp", mode="block")
            mcp_gateway.enforce(session_id=sess["session_id"], tenant_id=tenant_id,
                                tool_name="read_customer", params={"id": "cust-42"})
            mcp_gateway.enforce(session_id=sess["session_id"], tenant_id=tenant_id,
                                tool_name="write_note", params={"note": "x"})
            n += 2
        return n
    _try(summary, "siem_mcp_calls", _siem)

    # ── Governed retrieval: per-agent allowed sources ─────────────────────────
    def _retrieval():
        from modules.identity import governed_retrieval as gr
        gr.add_allowed_source(tenant_id=tenant_id, agent_id="triage-agent",
                              pattern="https://api.flights.example.com/*", added_by="demo")
        gr.add_allowed_source(tenant_id=tenant_id, agent_id="booking-agent",
                              pattern="snowflake://bookings/*", added_by="demo")
        gr.add_allowed_source(tenant_id=tenant_id, agent_id=gr.ANY_AGENT,
                              pattern="https://public.example.com/*", added_by="demo")
        return 3
    _try(summary, "retrieval_sources", _retrieval)

    # ── Campaign correlation: a multi-session/agent/model reassembly ──────────
    def _campaign():
        from modules.identity import campaign_correlation as cc
        base = 1_700_000_000.0
        signals = [
            {"signal_id": "c1", "severity": "high", "ts": base, "agent_id": "triage-agent",
             "session_id": "sess-1", "model_id": "gpt-4o", "target": "bookings", "technique": "recon"},
            {"signal_id": "c2", "severity": "high", "ts": base + 120, "agent_id": "booking-agent",
             "session_id": "sess-2", "model_id": "claude", "target": "bookings", "technique": "enumerate"},
            {"signal_id": "c3", "severity": "critical", "ts": base + 300, "agent_id": "payment-agent",
             "session_id": "sess-3", "model_id": "gpt-4o", "target": "bookings", "technique": "exfil"},
        ]
        camps = cc.build_campaigns(tenant_id=tenant_id, signals=signals, window_seconds=3600)
        return len(camps)
    _try(summary, "campaigns", _campaign)

    # ── Enrichments for older features the base seeder may not fully cover ─────
    def _governed_certs():
        # Attestation certs feed the cert_dashboard fleet view + expiry sweep.
        from datetime import datetime, timedelta, timezone
        from modules.identity import attestation_store, cert_dashboard
        attestation_store.init_db()
        now = datetime.now(timezone.utc)
        for i, a in enumerate(DEMO_AGENTS):
            cid = f"cert-{a}"
            expires = (now + timedelta(days=[3, 45, 200][i])).isoformat()
            cert = {
                "certificate_id": cid, "tenant_id": tenant_id, "attestation_id": f"att-{a}",
                "issued_at": now.isoformat(), "expires_at": expires,
                "issuer": "ca.tokendna.demo", "subject": a,
                "signature_alg": "HS256", "ca_key_id": "tokendna-ca-demo",
                "status": "active", "revoked_at": None, "revocation_reason": None,
                "signature": "demo-sig",
            }
            cert["certificate_json"] = dict(cert)
            attestation_store.insert_certificate(tenant_id, cert)
        cert_dashboard.run_expiry_sweep(tenant_id=tenant_id)
        return len(DEMO_AGENTS)
    _try(summary, "certs", _governed_certs)

    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed gap-roadmap demo data")
    ap.add_argument("--tenant", default=DEMO_TENANT)
    ap.add_argument("--with-base", action="store_true",
                    help="run demo_seed_v2 (agents/events/violations/...) first")
    args = ap.parse_args()

    if args.with_base:
        print("→ seeding base (demo_seed_v2)…")
        try:
            from scripts import demo_seed_v2
            base = demo_seed_v2.seed_agents_and_history()
            print(f"  base: {base.get('agents', '?')} agents, {base.get('uis_events', '?')} events")
        except Exception as exc:  # noqa: BLE001
            print(f"  ! base seed skipped: {exc}", file=sys.stderr)

    print(f"→ seeding gap features for tenant '{args.tenant}'…")
    summary = seed_gap(args.tenant)
    print("\nGap demo seed summary:")
    for k, v in summary.items():
        print(f"  {k:18} {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
