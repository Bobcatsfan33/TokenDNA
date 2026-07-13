from __future__ import annotations

from modules.identity.agent_assurance import (
    AgentActionRequest,
    BlastRadiusSummary,
    CompromiseSignal,
    CredentialEvidence,
    PermissionGrant,
    assess_agent_action,
)


def test_allows_verified_agent_with_matching_policy() -> None:
    verdict = assess_agent_action(
        AgentActionRequest(
            tenant_id="acme",
            agent_id="research-agent",
            action="read",
            resource="repo://research/private",
            credentials=[
                CredentialEvidence(
                    credential_id="tdn-pass-1",
                    agent_id="research-agent",
                    evidence_type="passport",
                )
            ],
            permission_grants=[
                PermissionGrant(
                    permission="read",
                    resource_pattern="repo://research/*",
                    source="agent-policy-v3",
                )
            ],
        )
    )

    assert verdict.outcome == "allow"
    assert verdict.identity_status == "verified"
    assert verdict.policy_status == "allowed"
    assert verdict.compromise_status == "clear"
    assert verdict.remediation == ["allow and continue monitoring"]


def test_blocks_unverified_agent_and_missing_policy() -> None:
    verdict = assess_agent_action(
        AgentActionRequest(
            tenant_id="acme",
            agent_id="unknown-agent",
            action="write",
            resource="s3://prod-ledger/payments.csv",
        )
    )

    assert verdict.outcome == "block"
    assert verdict.identity_status == "unverified"
    assert verdict.policy_status == "denied"
    assert "credential" in verdict.remediation[0]
    assert any("policy grant" in step for step in verdict.remediation)


def test_sends_high_compromise_signal_to_review_with_blast_context() -> None:
    verdict = assess_agent_action(
        AgentActionRequest(
            tenant_id="acme",
            agent_id="payments-agent",
            action="read",
            resource="s3://payments/reports/2026.csv",
            credentials=[
                CredentialEvidence(
                    credential_id="tdn-pass-2",
                    agent_id="payments-agent",
                )
            ],
            permission_grants=[
                PermissionGrant(permission="read", resource_pattern="s3://payments/*")
            ],
            compromise_signals=[
                CompromiseSignal(
                    signal_type="permission_drift",
                    severity="high",
                    detail="scope grew 3x without attestation",
                )
            ],
            blast_radius=BlastRadiusSummary(
                impact_score=72,
                risk_tier="high",
                total_nodes_reached=9,
                affected_assets=["payments-db", "invoice-tool"],
            ),
        )
    )

    assert verdict.outcome == "review"
    assert verdict.compromise_status == "suspected"
    assert verdict.blast_radius is not None
    assert verdict.blast_radius["risk_tier"] == "high"
    assert any("containment" in step for step in verdict.remediation)


def test_blocks_revoked_credential_even_if_policy_matches() -> None:
    verdict = assess_agent_action(
        AgentActionRequest(
            tenant_id="acme",
            agent_id="support-agent",
            action="read",
            resource="ticket://123",
            credentials=[
                CredentialEvidence(
                    credential_id="tdn-pass-revoked",
                    agent_id="support-agent",
                    status="revoked",
                )
            ],
            permission_grants=[
                PermissionGrant(permission="read", resource_pattern="ticket://*")
            ],
        )
    )

    assert verdict.outcome == "block"
    assert verdict.identity_status == "revoked"


def test_blocks_critical_compromise_signal() -> None:
    verdict = assess_agent_action(
        AgentActionRequest(
            tenant_id="acme",
            agent_id="booking-agent",
            action="book",
            resource="booking://flight/123",
            credentials=[CredentialEvidence(credential_id="tdn-pass-3", agent_id="booking-agent")],
            permission_grants=[
                PermissionGrant(permission="book", resource_pattern="booking://flight/*")
            ],
            compromise_signals=[
                CompromiseSignal(
                    signal_type="self_policy_modification",
                    severity="critical",
                    detail="agent attempted to remove its governing policy",
                )
            ],
        )
    )

    assert verdict.outcome == "block"
    assert verdict.compromise_status == "compromised"
    assert any("revoke active sessions" in step for step in verdict.remediation)
