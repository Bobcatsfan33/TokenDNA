"""Tests for the SIEM forwarders (no real Splunk / Datadog needed)."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

import json

import pytest

from tokendna_platform.findings import Finding, FindingSeverity
from tokendna_platform.siem_forward.forwarder import (
    DatadogForwarder,
    SplunkHECForwarder,
)


def _f() -> Finding:
    return Finding.new(
        title="drift detected",
        severity=FindingSeverity.HIGH,
        tenant_id="t1",
        subject="alice@example.com",
        source_engine="permission_drift",
    )


def test_splunk_payload_includes_event_and_sourcetype() -> None:
    captured: dict = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["body"] = json.loads(body.decode())
        captured["headers"] = headers

    f = SplunkHECForwarder(
        hec_url="https://splunk.example.com",
        hec_token="abc",
        index="ai_security",
        http=http,
    )
    f.forward(_f())
    assert captured["url"].endswith("/services/collector/event")
    assert captured["body"]["sourcetype"] == "tokendna:finding"
    assert captured["body"]["index"] == "ai_security"
    assert captured["body"]["event"]["title"] == "drift detected"
    assert captured["body"]["event"]["severity"] == "high"
    assert captured["headers"]["Authorization"] == "Splunk abc"


def test_splunk_rejects_non_https_url() -> None:
    with pytest.raises(ValueError):
        SplunkHECForwarder(hec_url="http://splunk.example.com", hec_token="t")


def test_datadog_payload_includes_tags_and_message() -> None:
    captured: dict = {}

    def http(url, body, headers):
        captured["url"] = url
        captured["body"] = json.loads(body.decode())
        captured["headers"] = headers

    f = DatadogForwarder(api_key="dd-key", site="datadoghq.eu", http=http)
    f.forward(_f())
    assert "datadoghq.eu" in captured["url"]
    assert captured["body"]["ddsource"] == "tokendna"
    assert "tenant:t1" in captured["body"]["ddtags"]
    assert "engine:permission_drift" in captured["body"]["ddtags"]
    assert captured["body"]["message"] == "drift detected"
    assert captured["headers"]["DD-API-KEY"] == "dd-key"
