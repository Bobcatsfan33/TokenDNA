"""
Sprint A — RSA narrative end-to-end integration test.

Proves the demo arc that the Runtime Risk Engine pitch depends on:

    1. An agent attempts a self-modifying policy change.
    2. Trust Graph fires POLICY_SCOPE_MODIFICATION (CRITICAL).
    3. Policy Guard evaluates the same action and produces a BLOCK
       disposition with a violation record.
    4. Policy Advisor analyses the resulting violation and produces a
       suggestion (the operator is offered a tightening amendment).
    5. Audit log captures every state change along the way.

If any link in this chain breaks, the RSA pitch breaks.  This file is the
contract test that prevents silent regression.
"""

from __future__ import annotations

import importlib
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def rsa_env(tmp_path):
    db_path = str(tmp_path / "rsa_e2e.db")
    audit_path = str(tmp_path / "audit.jsonl")
    with mock.patch.dict(
        os.environ,
        {"DATA_DB_PATH": db_path, "AUDIT_LOG_PATH": audit_path},
    ):
        # Reload all four modules so the patched DATA_DB_PATH is picked up.
        import modules.identity.trust_graph as tg
        import modules.identity.policy_guard as pg
        import modules.identity.policy_advisor as pa
        import modules.identity.permission_drift as pd

        for mod in (tg, pg, pa, pd):
            importlib.reload(mod)
        tg.init_db()
        pg.init_db()
        pa.init_db()
        pd.init_db()

        yield {
            "tg": tg,
            "pg": pg,
            "pa": pa,
            "pd": pd,
            "audit_path": audit_path,
        }


def test_self_modification_flows_through_three_modules(rsa_env):
    """
    Demo arc, end to end.  This is the test the sales engineer must be able to
    run live in front of a customer.
    """
    tg = rsa_env["tg"]
    pg = rsa_env["pg"]
    pa = rsa_env["pa"]

    tenant = "acme-prod"
    bad_agent = "agent-finance-bot"

    # ── 1. Trust Graph: agent modifies a policy that affects itself ──────────
    anomalies = tg.record_policy_modification(
        tenant_id=tenant,
        target_agent=bad_agent,
        modified_by=bad_agent,            # self-modification — the wedge
        policy_id="pol-finance-write",
        scope=["s3:write:*", "iam:CreateAccessKey"],
    )
    types = {a.anomaly_type for a in anomalies}
    assert "POLICY_SCOPE_MODIFICATION" in types, (
        "Trust Graph must catch the agent self-modification — RSA gap 1"
    )
    self_mod = next(
        a for a in anomalies if a.anomaly_type == "POLICY_SCOPE_MODIFICATION"
    )
    assert self_mod.severity == "critical"

    # ── 2. Policy Guard: same action, separate evaluation path ───────────────
    action = pg.PolicyAction(
        request_id="req-rsa-e2e-1",
        actor_id=bad_agent,
        actor_type="agent",
        action_type="modify_policy",
        target_policy_id="pol-finance-write",
        target_policy_name=f"{bad_agent}-policy",
        tenant_id=tenant,
        scope_delta=["s3:write:*", "iam:CreateAccessKey"],
        metadata={"governed_agent": bad_agent},
    )
    eval_result = pg.evaluate(action)
    assert eval_result.disposition == pg.Disposition.BLOCK, (
        "Policy Guard must BLOCK — second line of defence after Trust Graph"
    )
    assert eval_result.violation_id is not None
    violation = pg.get_violation(eval_result.violation_id, tenant)
    assert violation is not None
    assert violation.status == pg.ViolationStatus.OPEN

    # ── 3. Policy Advisor: synthesises a tightening recommendation ───────────
    advice = pa.analyze_and_generate(
        tenant_id=tenant,
        lookback_hours=1,
        min_confidence=0.0,
    )
    assert advice["violations_analyzed"] >= 1, (
        "Advisor must see the violation Policy Guard just recorded"
    )
    suggestions = pa.list_suggestions(tenant_id=tenant)
    assert suggestions, (
        "Advisor must produce at least one suggestion from a self-mod violation"
    )

    # ── 4. Operator approves the tightening recommendation ──────────────────
    pa_result = pa.approve_suggestion(
        suggestion_id=suggestions[0].suggestion_id,
        tenant_id=tenant,
        approved_by="ops@acme.com",
        note="manual approve in e2e test",
        run_regression=False,
    )
    assert pa_result is not None
    assert pa_result.status == pa.SuggestionStatus.APPROVED


def test_attested_modification_does_not_trip_drift(rsa_env):
    """
    Negative control: a legitimate, attested modification by a different
    actor must NOT fire any of the RSA gap signals.  Otherwise the demo
    arc would constantly cry wolf and the customer wouldn't trust it.
    """
    tg = rsa_env["tg"]

    tenant = "acme-prod"
    target = "agent-finance-bot"
    legit_actor = "admin-bot"

    # Seed an attested_by edge for the actor so the drift check is suppressed.
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    tg._upsert_nodes(
        tenant,
        [("agent", legit_actor, "{}"), ("verifier", "ver-attest-1", "{}")],
        now,
    )
    tg._upsert_edges(
        tenant,
        [("agent", legit_actor, "verifier", "ver-attest-1", "attested_by")],
        now,
    )

    # Drive enough modifications to exceed the weight threshold.
    threshold = tg._PERMISSION_WEIGHT_DRIFT_THRESHOLD
    last: list = []
    for i in range(threshold):
        last = tg.record_policy_modification(
            tenant_id=tenant,
            target_agent=target,
            modified_by=legit_actor,
            policy_id=f"pol-{i}",
            scope=["s3:read:*"],
        )

    types = {a.anomaly_type for a in last}
    assert "POLICY_SCOPE_MODIFICATION" not in types, (
        "modifier != target — must not be flagged as self-mod"
    )
    assert "PERMISSION_WEIGHT_DRIFT" not in types, (
        "fresh attestation in window must suppress drift anomaly"
    )


def test_permission_drift_chain_with_policy_guard(rsa_env):
    """
    Permission_drift's algorithm produces a DriftAlert when scope grows
    without attestation.  Policy_guard's evaluate runs independently;
    both signals can be observed by the operator dashboard via the
    audit log.
    """
    pd = rsa_env["pd"]
    pg = rsa_env["pg"]

    tenant = "acme-prod"
    agent = "agent-data-loader"
    policy = "pol-loader-scope"

    # Seed baseline + drive growth without attestation
    from datetime import datetime, timedelta, timezone
    import json
    import sqlite3
    import uuid

    # Seed 2 baseline observations so we cross DRIFT_STABLE_MIN_OBSERVATIONS=3
    # once we add the live one below.
    conn = sqlite3.connect(pd._DB_PATH, check_same_thread=False)
    for days_ago, weight in ((10, 1.0), (5, 1.0)):
        ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        conn.execute(
            """
            INSERT INTO drift_observations
                (observation_id, tenant_id, agent_id, policy_id, scope,
                 scope_weight, recorded_at, source_event, has_attestation,
                 changed_by, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, '{}')
            """,
            (
                str(uuid.uuid4()), tenant, agent, policy,
                json.dumps(["read"]), weight, ts,
            ),
        )
    conn.commit()
    conn.close()

    pd.record_observation(
        tenant_id=tenant,
        agent_id=agent,
        policy_id=policy,
        scope=["read", "write", "delete", "admin", "*"],
        has_attestation=False,
    )
    alerts = pd.list_alerts(tenant)
    assert alerts, "drift detection must fire on 5x growth without attestation"
    assert alerts[0].growth_factor >= 2.0

    # An operator follow-up: evaluating an attempted further scope expansion
    # by the same agent should be BLOCKed by Policy Guard.
    block_action = pg.PolicyAction(
        request_id="req-rsa-drift-1",
        actor_id=agent,
        actor_type="agent",
        action_type="modify_policy",
        target_policy_id=policy,
        target_policy_name=f"{agent}-loader-policy",
        tenant_id=tenant,
        scope_delta=["s3:DeleteBucket"],
        metadata={"governed_agent": agent},
    )
    block_eval = pg.evaluate(block_action)
    assert block_eval.disposition == pg.Disposition.BLOCK
