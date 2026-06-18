"""Tests for policy guardrail export (Gap roadmap Epic 3.2 / C4)."""
from __future__ import annotations

import json

import pytest

from modules.identity import policy_export as px


def _spec():
    return px.PolicySpec(
        name="rogue agent guard",
        description="block scope expansion",
        denied_topics=[px.DeniedTopic(name="tighten_scope", definition="agent expanded scope",
                                      examples=["s3:*"])],
        blocked_words=["s3:*", "iam:PassRole"],
        pii_entities=["EMAIL", "US_SOCIAL_SECURITY_NUMBER"],
    )


# ── bedrock ─────────────────────────────────────────────────────────────────

def test_bedrock_shape():
    cfg = px.to_bedrock(_spec())
    assert cfg["name"] == "rogue-agent-guard"  # sanitized
    assert cfg["topicPolicyConfig"]["topicsConfig"][0]["type"] == "DENY"
    assert {w["text"] for w in cfg["wordPolicyConfig"]["wordsConfig"]} == {"s3:*", "iam:PassRole"}
    assert cfg["sensitiveInformationPolicyConfig"]["piiEntitiesConfig"][0]["action"] == "BLOCK"


def test_bedrock_cli_roundtrips_to_json():
    cfg = px.to_bedrock(_spec())
    cli = px.to_bedrock_cli(cfg)
    assert cli.startswith("aws bedrock create-guardrail --cli-input-json '")
    # extract the JSON between the single quotes and re-parse
    raw = cli[cli.index("'") + 1: cli.rindex("'")].replace("'\\''", "'")
    assert json.loads(raw)["name"] == "rogue-agent-guard"


def test_name_sanitized_and_truncated():
    assert px._sanitize_name("My Guard! @#$") == "My-Guard"
    assert len(px._sanitize_name("x" * 80)) == 50


def test_empty_policy_omits_optional_blocks():
    cfg = px.to_bedrock(px.PolicySpec(name="empty"))
    assert "topicPolicyConfig" not in cfg
    assert "wordPolicyConfig" not in cfg


# ── multi-target ──────────────────────────────────────────────────────────────

def test_openai_target():
    out = px.export_policy(_spec(), "openai")
    assert out["target"] == "openai"
    assert out["config"]["blocked_words"] == ["s3:*", "iam:PassRole"]


def test_generic_target():
    out = px.export_policy(_spec(), "generic")
    assert out["config"]["denied_topics"][0]["name"] == "tighten_scope"


def test_bedrock_target_includes_cli():
    out = px.export_policy(_spec(), "bedrock")
    assert "cli" in out and out["cli"].startswith("aws bedrock create-guardrail")


def test_unsupported_target_raises():
    with pytest.raises(ValueError):
        px.export_policy(_spec(), "azure")


# ── from advisor suggestions ──────────────────────────────────────────────────

def test_spec_from_suggestions_dicts():
    suggestions = [
        {"amendment_type": "tighten_scope", "gap_description": "agent over-scoped",
         "amendment": {"remove_scopes": ["s3:*", "iam:*"]}},
        {"amendment_type": "rate_limit", "gap_description": "burst calls",
         "amendment": {"patterns": ["tool:exfil"]}},
    ]
    spec = px.spec_from_suggestions("gen", suggestions)
    assert {t.name for t in spec.denied_topics} == {"tighten_scope", "rate_limit"}
    assert "s3:*" in spec.blocked_words and "tool:exfil" in spec.blocked_words


def test_spec_from_dict():
    spec = px.spec_from_dict({"name": "x", "denied_topics": [{"name": "t", "definition": "d"}],
                              "blocked_words": ["w"], "pii_entities": ["EMAIL"]})
    assert spec.blocked_words == ["w"] and spec.pii_entities == ["EMAIL"]


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "px_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.product import commercial_tiers as ct
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(tenant_id="t", tenant_name="T", plan=Plan.ENTERPRISE,
                           api_key_id="k", role="owner")
    app_module.app.dependency_overrides[ct.get_tenant] = lambda: tenant
    yield TestClient(app_module.app, raise_server_exceptions=False)
    app_module.app.dependency_overrides.clear()


def test_api_targets(client):
    r = client.get("/api/policy/export/targets")
    assert r.status_code == 200
    assert "bedrock" in r.json()["targets"]


def test_api_export_from_spec(client):
    r = client.post("/api/policy/export", json={
        "target": "bedrock", "name": "demo",
        "spec": {"denied_topics": [{"name": "exfil", "definition": "data exfil"}],
                 "blocked_words": ["scp"]},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target"] == "bedrock"
    assert body["config"]["name"] == "demo"
    assert "cli" in body


def test_api_export_requires_spec_or_suggestions(client):
    r = client.post("/api/policy/export", json={"target": "bedrock", "name": "x"})
    assert r.status_code == 400
