"""Tests for response action implementations + router."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import json

import pytest

from tokendna_platform.findings import Finding, FindingSeverity
from tokendna_platform.response.actions import (
    AWSWAFBlockIP,
    JiraTicket,
    OktaRevokeSession,
    PagerDutyEscalate,
)
from tokendna_platform.response.router import ResponseRouter, ResponseRule


def _f(severity: FindingSeverity = FindingSeverity.CRITICAL,
       metadata: dict | None = None) -> Finding:
    return Finding.new(
        title="self-modification attempt",
        severity=severity,
        tenant_id="t1",
        subject="alice@example.com",
        source_engine="policy_guard",
        metadata=metadata or {},
    )


def test_okta_revoke_session_posts_to_user_endpoint() -> None:
    captured = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["headers"] = headers

    a = OktaRevokeSession(domain="example.okta.com", api_token="t", http=http)
    outcome = a.execute(_f())
    assert outcome.succeeded is True
    assert "/api/v1/users/alice@example.com/sessions" in captured["url"]
    assert captured["headers"]["Authorization"] == "SSWS t"


def test_aws_waf_block_ip_skips_when_no_ip_in_metadata() -> None:
    a = AWSWAFBlockIP(webhook_url="https://example.com/waf", http=lambda *a, **k: None)
    outcome = a.execute(_f(metadata={}))
    assert outcome.succeeded is False
    assert "no source_ip" in outcome.detail.lower()


def test_aws_waf_block_ip_posts_when_ip_present() -> None:
    captured = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["body"] = json.loads(body.decode())

    a = AWSWAFBlockIP(webhook_url="https://example.com/waf", http=http)
    outcome = a.execute(_f(metadata={"source_ip": "203.0.113.7"}))
    assert outcome.succeeded is True
    assert captured["body"]["ip"] == "203.0.113.7"


def test_pagerduty_escalate_posts_to_v2_enqueue() -> None:
    captured = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["body"] = json.loads(body.decode())

    a = PagerDutyEscalate(routing_key="abc", http=http)
    a.execute(_f())
    assert captured["url"] == "https://events.pagerduty.com/v2/enqueue"
    assert captured["body"]["routing_key"] == "abc"
    assert captured["body"]["event_action"] == "trigger"


def test_jira_ticket_uses_basic_auth() -> None:
    captured = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["body"] = json.loads(body.decode())
        captured["headers"] = headers

    a = JiraTicket(
        base_url="https://example.atlassian.net",
        email="alice@example.com", api_token="t",
        project_key="SEC", http=http,
    )
    a.execute(_f())
    assert captured["url"].endswith("/rest/api/3/issue")
    assert captured["headers"]["Authorization"].startswith("Basic ")
    assert captured["body"]["fields"]["project"]["key"] == "SEC"


def test_jira_rejects_non_https_base_url() -> None:
    with pytest.raises(ValueError):
        JiraTicket(
            base_url="http://example.atlassian.net",
            email="x", api_token="x", project_key="SEC",
        )


def test_router_runs_only_matching_rules() -> None:
    router = ResponseRouter()
    actions_called: list[str] = []

    class Stub:
        def __init__(self, name):
            self._name = name
        @property
        def name(self):
            return self._name
        def execute(self, finding):
            from tokendna_platform.response.actions import ResponseOutcome
            actions_called.append(self._name)
            return ResponseOutcome(self._name, finding.finding_id, True)

    router.register_action(Stub("a1"))
    router.register_action(Stub("a2"))
    router.add_rule(ResponseRule(
        name="critical_only", predicate=lambda f: f.severity == FindingSeverity.CRITICAL,
        actions=("a1", "a2"),
    ))
    outcomes = router.dispatch(_f(FindingSeverity.LOW))
    assert outcomes == []
    outcomes = router.dispatch(_f(FindingSeverity.CRITICAL))
    assert [o.action_name for o in outcomes] == ["a1", "a2"]
    assert all(o.succeeded for o in outcomes)


def test_router_records_unknown_action_as_failed() -> None:
    router = ResponseRouter()
    router.add_rule(ResponseRule("r", lambda f: True, ("nonexistent",)))
    outcomes = router.dispatch(_f())
    assert len(outcomes) == 1
    assert outcomes[0].succeeded is False
    assert "not registered" in outcomes[0].detail


def test_router_isolates_action_exception() -> None:
    router = ResponseRouter()

    class Boom:
        @property
        def name(self):
            return "boom"
        def execute(self, finding):
            raise RuntimeError("boom")

    router.register_action(Boom())
    router.add_rule(ResponseRule("r", lambda f: True, ("boom",)))
    outcomes = router.dispatch(_f())
    assert outcomes[0].succeeded is False
    assert "raised" in outcomes[0].detail
