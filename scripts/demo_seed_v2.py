#!/usr/bin/env python3
"""
TokenDNA Runtime Risk Engine — Demo Seed v2

Builds a 30-day operational backdrop on a fresh TokenDNA instance so that
the live demo arc (``demo_runtime_risk_engine.py``) plays out against a
realistic environment instead of a sterile blank slate.

What it produces
────────────────

  * Two tenants — ``acme`` (the primary demo tenant) and ``beta``
    (federation peer).
  * ~50 Acme agents + ~20 Beta agents distributed across realistic
    archetypes (admin, finance, data-loader, support, engineering,
    ops, plus 2 deliberately drifty agents).
  * 30 days of UIS auth events with realistic IP/ASN/geo distribution
    drawn from ``data/demo_fixtures/geo_samples.json``.
  * Drift baselines so ``permission_drift`` has longitudinal history
    to detect against during the live arc.
  * Pre-existing ``policy_guard`` violations (some open, some
    approved/rejected) — the dashboard is never empty on first land.
  * Pre-existing ``policy_advisor`` suggestions ready for review.
  * 8 honeytoken decoys planted with realistic names.
  * An established Acme ↔ Beta federation trust (so cross-org demo
    scenes can revoke/re-establish on stage).
  * MITRE ATT&CK technique tagging on every event using the curated
    set in ``data/demo_fixtures/mitre_techniques.json``.
  * Multi-stage attack chain history per the templates in
    ``data/demo_fixtures/attack_chains.json``.

The seeder writes DIRECTLY through the storage layer (not via HTTP) so
it can backdate timestamps for longitudinal history that drift detection
needs.  It is idempotent on the tenant_id key — re-running against the
same DB clears prior demo state for the seeded tenants first.

Usage
─────

  # Default — seeds ``acme`` and ``beta`` against the default DB path.
  python scripts/demo_seed_v2.py

  # Use a specific SQLite file (typical for demo isolation).
  DATA_DB_PATH=/tmp/tokendna-demo.db python scripts/demo_seed_v2.py

  # Show what would be seeded without writing.
  python scripts/demo_seed_v2.py --dry-run

After seeding:

  DATA_DB_PATH=/tmp/tokendna-demo.db DEV_MODE=true \\
      uvicorn api:app --port 8000 &
  python scripts/demo_runtime_risk_engine.py
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


# ── Paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "data" / "demo_fixtures"

# Make the modules importable when run as a script.
sys.path.insert(0, str(REPO_ROOT))


# ── Tenants ───────────────────────────────────────────────────────────────────

ACME = "acme"
BETA = "beta"

DEMO_TENANTS = (ACME, BETA)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _backdated(days_ago: float, jitter_minutes: int = 0) -> str:
    """Return an ISO8601 timestamp ``days_ago`` days in the past."""
    now = datetime.now(timezone.utc)
    delta = timedelta(days=days_ago, minutes=random.randint(-jitter_minutes, jitter_minutes))
    return _iso(now - delta)


def _pick_geo(geo_samples: list[dict], category_weights: dict[str, int]) -> dict:
    """Weighted pick across categories."""
    pool = [g for g in geo_samples if g["category"] in category_weights]
    weights = [
        category_weights.get(g["category"], 0) * g["weight"]
        for g in pool
    ]
    return random.choices(pool, weights=weights, k=1)[0]


def _agent_label(archetype: dict, n: int, prefix: str = "") -> str:
    pat = archetype["name_pattern"]
    base = pat.format(n=str(n).zfill(2))
    return f"{prefix}{base}" if prefix else base


def _print_section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print("─" * 60)


def _print_step(label: str, detail: str = "") -> None:
    suffix = f"  {detail}" if detail else ""
    print(f"  ✓ {label}{suffix}")


# ── Tenant cleanup ────────────────────────────────────────────────────────────


_DEMO_TABLES_TO_PURGE = (
    "uis_events",
    "tg_nodes",
    "tg_edges",
    "tg_anomalies",
    "drift_observations",
    "drift_alerts",
    "policy_guard_violations",
    "policy_suggestions",
    "honeypot_decoys",
    "honeypot_hits",
    "intent_matches",
    "intent_match_state",
    "mcp_call_log",
    "mcp_violations",
    "federation_handshakes",
    "federation_trusts",
)


def _purge_demo_tenants(conn: sqlite3.Connection) -> int:
    """
    Remove prior demo state so the seeder is idempotent.  Only deletes rows
    where ``tenant_id`` matches a demo tenant — leaves any other tenant data
    in place.  Federation tables purge by ``local_org_id`` instead.
    """
    deleted = 0
    cursor = conn.cursor()
    for table in _DEMO_TABLES_TO_PURGE:
        try:
            if table.startswith("federation_"):
                col = "local_org_id"
            elif table in ("intent_matches", "intent_match_state"):
                col = "tenant_id"
            else:
                col = "tenant_id"
            for tenant in DEMO_TENANTS:
                cursor.execute(
                    f"DELETE FROM {table} WHERE {col}=?", (tenant,)
                )
                deleted += cursor.rowcount
        except sqlite3.OperationalError:
            # Table may not exist on a fresh DB — that's fine.
            pass
    conn.commit()
    return deleted


# ── UIS event generator ───────────────────────────────────────────────────────


def _make_uis_event(
    *,
    tenant: str,
    agent_label: str,
    archetype: dict,
    geo: dict,
    when: str,
    mitre_id: str | None = None,
    outcome: str = "success",
    auth_method_override: str | None = None,
) -> dict[str, Any]:
    """Build a fully-populated UIS event dict matching the ingest schema."""
    auth_method = auth_method_override or archetype["auth_method"]
    return {
        "uis_version": "1.0",
        "event_id": f"ev-{uuid.uuid4().hex[:16]}",
        "event_timestamp": when,
        "identity": {
            "entity_type": "machine",
            "subject": f"{agent_label}@svc.local",
            "tenant_id": tenant,
            "tenant_name": tenant.title(),
            "machine_classification": "agent",
            "agent_id": agent_label,
        },
        "auth": {
            "method": auth_method,
            "mfa_asserted": True,
            "protocol": archetype["protocol"],
            "credential_strength": "standard",
        },
        "token": {
            "issuer": f"https://auth.{tenant}.example.com",
            "audience": "tokendna-demo",
            "expires_in": 3600,
        },
        "binding": {
            "attestation_id": (
                f"att-{uuid.uuid4().hex[:12]}" if archetype.get("should_attest") else None
            ),
            "spiffe_id": (
                f"spiffe://{tenant}/agents/{agent_label}"
                if archetype["protocol"] == "x509-svid" else None
            ),
        },
        "network": {
            "ip": geo["ip"],
            "country": geo["country"],
            "city": geo["city"],
            "asn": geo["asn"],
            "asn_org": geo["asn_org"],
        },
        "outcome": outcome,
        "metadata": {
            "mitre_technique": mitre_id,
            "demo_seeded": True,
        },
    }


# ── Seeder ────────────────────────────────────────────────────────────────────


def seed_agents_and_history(
    *,
    days_back: int = 30,
    rng_seed: int = 42,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Main seeder entry point.  Returns a summary dict with counts of every
    artifact created.  When ``dry_run=True`` nothing is written — used
    by tests + the --dry-run flag.
    """
    random.seed(rng_seed)

    techniques = _load_fixture("mitre_techniques.json")["techniques"]
    geo_samples = _load_fixture("geo_samples.json")["samples"]
    archetypes_doc = _load_fixture("agent_archetypes.json")
    chains = _load_fixture("attack_chains.json")["chains"]

    summary: dict[str, Any] = {
        "tenants": list(DEMO_TENANTS),
        "agents": {ACME: 0, BETA: 0},
        "uis_events": 0,
        "drift_observations": 0,
        "policy_violations": 0,
        "policy_suggestions": 0,
        "honeypot_decoys": 0,
        "intent_matches": 0,
        "federation_trusts": 0,
        "attack_chain_traces": 0,
        "mitre_techniques_referenced": len(techniques),
        "dry_run": dry_run,
    }

    # Connection — write straight through SQLite for speed and timestamp control.
    db_path = os.getenv("DATA_DB_PATH", "/tmp/tokendna-demo.db")
    if dry_run:
        # In dry-run mode we still have to talk to the modules to know what
        # they would do — but we never open a real connection.
        _print_section("Demo Seed v2 — DRY RUN (no writes)")
        _print_step("would purge prior demo tenant state")
        _print_step(f"would seed against {db_path}")
    else:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        # Ensure all module schemas exist before we write — easier than
        # tracking which migration applied.
        from modules.identity import (
            blast_radius,
            honeypot_mesh,
            federation,
            intent_correlation,
            mcp_inspector,
            permission_drift,
            policy_advisor,
            policy_guard,
            trust_graph,
            uis_store,
        )
        for module in (
            uis_store, trust_graph, policy_guard, policy_advisor,
            permission_drift, honeypot_mesh, intent_correlation,
            mcp_inspector, federation,
        ):
            module.init_db()
        # blast_radius reuses the trust_graph schema; no init.
        del blast_radius
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        purged = _purge_demo_tenants(conn)
        if purged:
            _print_step(f"purged {purged} rows of prior demo state")
        else:
            _print_step("no prior demo state to purge")

    # ── 1. Seed agents + UIS history ──────────────────────────────────────────
    _print_section("Stage 1 — Agents + 30-day UIS history")

    def _seed_for_tenant(tenant: str, archetypes: list[dict]) -> tuple[int, int, list[str]]:
        agent_count = 0
        event_count = 0
        agent_labels: list[str] = []
        for arch in archetypes:
            # Build the full event batch for THIS archetype, then bulk-insert
            # in one transaction.  Per-event insert_event would be ~100x
            # slower because each call opens its own transaction.
            arch_events: list[dict] = []
            for n in range(1, arch["count"] + 1):
                label = _agent_label(arch, n)
                agent_labels.append(label)
                agent_count += 1
                total_events = int(arch["mean_actions_per_day"] * days_back * random.uniform(0.6, 1.1))
                for _ in range(total_events):
                    days_ago = random.uniform(0.1, days_back)
                    geo = _pick_geo(geo_samples, arch["geo_category_weights"])
                    technique = random.choice(techniques)
                    arch_events.append(_make_uis_event(
                        tenant=tenant,
                        agent_label=label,
                        archetype=arch,
                        geo=geo,
                        when=_backdated(days_ago, jitter_minutes=120),
                        mitre_id=technique["id"],
                        outcome="success",
                    ))
            if not dry_run and arch_events:
                # skip_downstream=True — the seeder does its own attack-chain
                # planting in Stage 6, and per-event trust_graph ingest on
                # ~70k events is the original bottleneck we're eliminating.
                uis_store.bulk_insert_events(
                    tenant, arch_events, skip_downstream=True,
                )
            event_count += len(arch_events)
        return agent_count, event_count, agent_labels

    acme_archetypes = archetypes_doc["archetypes"]
    beta_archetypes = archetypes_doc["remote_org_archetypes"]

    if not dry_run:
        # uis_store needs to be reachable from this scope after init.
        from modules.identity import uis_store

    acme_agents_n, acme_events_n, acme_labels = _seed_for_tenant(ACME, acme_archetypes)
    beta_agents_n, beta_events_n, beta_labels = _seed_for_tenant(BETA, beta_archetypes)

    summary["agents"][ACME] = acme_agents_n
    summary["agents"][BETA] = beta_agents_n
    summary["uis_events"] = acme_events_n + beta_events_n
    _print_step(f"acme: {acme_agents_n} agents, {acme_events_n} UIS events")
    _print_step(f"beta: {beta_agents_n} agents, {beta_events_n} UIS events")

    # ── 2. Drift baselines ────────────────────────────────────────────────────
    _print_section("Stage 2 — Drift baselines")

    drift_obs = 0
    if not dry_run:
        from modules.identity import permission_drift
    drifty = [a for a in acme_archetypes if a.get("drift_pattern") == "scope_grows_over_window"]
    for arch in drifty:
        for n in range(1, arch["count"] + 1):
            label = _agent_label(arch, n)
            # Seed gradually-growing scope WITHOUT attestation across the window.
            for stage_days_ago, scope_size in (
                (28, 1), (24, 1), (20, 2), (16, 2),
                (12, 3), (8, 4), (4, 5), (1, 7),
            ):
                if dry_run:
                    drift_obs += 1
                    continue
                obs_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO drift_observations
                        (observation_id, tenant_id, agent_id, policy_id, scope,
                         scope_weight, recorded_at, source_event,
                         has_attestation, changed_by, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, 'demo-seeder', '{}')
                    """,
                    (
                        obs_id, ACME, label, "pol-finance-shared",
                        json.dumps([f"perm-{i}" for i in range(scope_size)]),
                        float(scope_size),
                        _backdated(stage_days_ago, jitter_minutes=240),
                    ),
                )
                drift_obs += 1
    if not dry_run:
        conn.commit()
    summary["drift_observations"] = drift_obs
    _print_step(f"{drift_obs} backdated drift observations across {len(drifty) * 2} agents")

    # ── 3. Policy violations + suggestions ────────────────────────────────────
    _print_section("Stage 3 — Pre-existing policy_guard violations + advisor suggestions")

    violation_count = 0
    suggestion_count = 0
    if not dry_run:
        from modules.identity import policy_guard, policy_advisor

    sample_actions = [
        ("agent-acme-driftyA", ["iam:CreateAccessKey"], "blocked"),
        ("finance-bot-03", ["s3:write:reports"], "approved"),
        ("eng-asst-07", ["k8s:write:prod"], "rejected"),
        ("admin-bot-02", ["audit:delete"], "blocked"),
        ("support-asst-04", ["crm:export:all"], "blocked"),
    ]
    for actor, scope_delta, status in sample_actions:
        if dry_run:
            violation_count += 1
            continue
        action = policy_guard.PolicyAction(
            request_id=f"req-seed-{uuid.uuid4().hex[:8]}",
            actor_id=actor,
            actor_type="agent",
            action_type="modify_policy",
            target_policy_id=f"pol-{actor}",
            target_policy_name=f"{actor}-policy",
            tenant_id=ACME,
            scope_delta=scope_delta,
            metadata={"governed_agent": actor, "demo_seeded": True},
        )
        result = policy_guard.evaluate(action)
        if result.violation_id and status != "blocked":
            # Apply the resolution that the demo storyboard wants.
            if status == "approved":
                policy_guard.approve_violation(
                    violation_id=result.violation_id, tenant_id=ACME,
                    approved_by="ops@acme.com", note="seeded — demo prior-state",
                )
            elif status == "rejected":
                policy_guard.reject_violation(
                    violation_id=result.violation_id, tenant_id=ACME,
                    rejected_by="ops@acme.com", note="seeded — demo prior-state",
                )
        if result.violation_id:
            violation_count += 1

    # Run the advisor against the seeded violations to produce suggestions.
    if not dry_run:
        advice = policy_advisor.analyze_and_generate(
            tenant_id=ACME, lookback_hours=720, min_confidence=0.0,
        )
        suggestion_count = advice.get("suggestions_generated", 0)
    else:
        suggestion_count = len(sample_actions)

    summary["policy_violations"] = violation_count
    summary["policy_suggestions"] = suggestion_count
    _print_step(f"{violation_count} policy_guard violations seeded (mix of open/approved/rejected)")
    _print_step(f"{suggestion_count} policy_advisor suggestions ready for review")

    # ── 4. Honeytokens ────────────────────────────────────────────────────────
    _print_section("Stage 4 — Honeytoken decoys")

    decoy_count = 0
    if not dry_run:
        from modules.identity import honeypot_mesh

    HONEYS = [
        ("finance-vault-token-Q4",       "/decoy/finance/vault"),
        ("slack-integration-key-prod",   "/decoy/slack/integration"),
        ("github-deploy-key-platform",   "/decoy/github/deploy"),
        ("aws-access-key-billing",       "/decoy/aws/billing"),
        ("notion-api-token-engineering", "/decoy/notion/api"),
        ("snowflake-rw-prod",            "/decoy/snowflake/prod"),
        ("salesforce-export-token",      "/decoy/sfdc/export"),
        ("okta-admin-bearer",            "/decoy/okta/admin"),
    ]
    for name, endpoint in HONEYS:
        if dry_run:
            decoy_count += 1
            continue
        try:
            honeypot_mesh.seed_honeytoken(
                tenant_id=ACME,
                kind="honeytoken_credential",
                metadata={"name": name, "trigger_endpoint": endpoint, "demo_seeded": True},
            )
        except Exception:
            pass  # don't let honeypot integration block the seeder
        decoy_count += 1
    summary["honeypot_decoys"] = decoy_count
    _print_step(f"{decoy_count} honeytokens planted")

    # ── 5. Federation handshake (Acme ↔ Beta) ─────────────────────────────────
    _print_section("Stage 5 — Federation: Acme ↔ Beta mutual trust")

    if not dry_run:
        from modules.identity import federation as _fed
        offer = _fed.initiate_handshake(
            local_org_id=BETA,
            remote_org_id=ACME,
            accepted_scope=["finance-bot-*", "support-asst-*"],
            policy_summary={"soc2": True, "iso27001": True, "demo_seeded": True},
        )
        trust = _fed.accept_handshake(
            handshake_id=offer.handshake_id,
            accepting_org_id=ACME,
            remote_federation_key=f"acme-key-{uuid.uuid4().hex[:12]}",
            accepted_by="ops@acme.com",
        )
        summary["federation_trusts"] = 1
        summary["federation_trust_id"] = trust.trust_id
        _print_step(f"federation trust {trust.trust_id[:8]} established")
    else:
        summary["federation_trusts"] = 1
        _print_step("would establish acme↔beta federation trust")

    # ── 6. Attack chain history (intent_correlation seeds) ────────────────────
    _print_section("Stage 6 — Historical attack chain traces")

    chain_traces = 0
    chain_events: list[dict] = []
    for chain in chains:
        # Plant one trace per chain template.  Spread events across the
        # chain's ``spans_minutes`` window, backdated 7-21 days ago so they
        # show up in the dashboard's "recent threats" without being
        # mistaken for live activity.
        chain_start_days_ago = random.uniform(7.0, 21.0)
        for stage in chain["stages"]:
            for _ in range(stage["count"]):
                if not dry_run:
                    technique_id = stage.get("mitre", "T1078")
                    label = random.choice(acme_labels)
                    geo = random.choice(geo_samples)
                    chain_events.append(_make_uis_event(
                        tenant=ACME,
                        agent_label=label,
                        archetype=acme_archetypes[0],
                        geo=geo,
                        when=_backdated(chain_start_days_ago, jitter_minutes=30),
                        mitre_id=technique_id,
                        outcome=stage.get("outcome", "success"),
                        auth_method_override=stage.get("auth_method"),
                    ))
                chain_traces += 1
    if not dry_run and chain_events:
        uis_store.bulk_insert_events(ACME, chain_events, skip_downstream=True)
    summary["attack_chain_traces"] = chain_traces
    _print_step(f"{chain_traces} attack-chain trace events planted across {len(chains)} chains")

    if not dry_run:
        conn.close()

    # ── Done ──────────────────────────────────────────────────────────────────
    _print_section("Demo Seed v2 — complete")
    _print_step(f"tenants:          {ACME}, {BETA}")
    _print_step(f"agents:           {sum(summary['agents'].values())}  ({acme_agents_n} acme + {beta_agents_n} beta)")
    _print_step(f"uis_events:       {summary['uis_events']:,}")
    _print_step(f"drift_observations: {summary['drift_observations']}")
    _print_step(f"policy_violations: {summary['policy_violations']}")
    _print_step(f"policy_suggestions: {summary['policy_suggestions']}")
    _print_step(f"honeytokens:      {summary['honeypot_decoys']}")
    _print_step(f"federation_trusts: {summary['federation_trusts']}")
    _print_step(f"attack_chain_traces: {summary['attack_chain_traces']}")
    if dry_run:
        print("\n  (dry-run — nothing was written)\n")
    else:
        print(f"\n  Demo environment ready at:  {db_path}")
        print(f"  Next:  uvicorn api:app --port 8000")
        print(f"  Then:  python scripts/demo_runtime_risk_engine.py\n")
    return summary


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be seeded without writing")
    parser.add_argument("--days", type=int, default=30,
                        help="Days of history to seed (default 30)")
    parser.add_argument("--seed", type=int, default=42,
                        help="RNG seed for reproducibility (default 42)")
    args = parser.parse_args()

    seed_agents_and_history(
        days_back=args.days,
        rng_seed=args.seed,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
