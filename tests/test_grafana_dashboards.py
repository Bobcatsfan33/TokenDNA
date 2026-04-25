"""Structural tests for the Grafana dashboards + Prometheus alert rules.

These do not invoke Grafana or promtool. They verify the JSON / YAML
shape and that every PromQL expression references a metric we actually
emit from ``modules/observability/metrics.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_DASH = _REPO / "deploy" / "grafana"

_DASHBOARDS = ["tokendna-overview.json", "tokendna-security.json"]


# Metrics emitted by modules/observability/metrics.py (suffixes covered).
_KNOWN_METRICS = {
    "tokendna_http_requests_total",
    "tokendna_http_request_duration_seconds",
    "tokendna_http_request_duration_seconds_bucket",
    "tokendna_uis_events_total",
    "tokendna_policy_decisions_total",
    "tokendna_secret_gate_failures_total",
    # Recording metrics that prometheus may expose without us defining them:
    "up",
}


def _extract_metrics(expr: str) -> set[str]:
    return set(re.findall(r"(tokendna_[a-z_]+|\bup\b)", expr))


@pytest.mark.parametrize("filename", _DASHBOARDS)
def test_dashboard_loads_and_has_panels(filename: str):
    body = json.loads((_DASH / filename).read_text())
    assert body["uid"]
    assert body["title"]
    assert isinstance(body.get("panels"), list)
    assert len(body["panels"]) > 0


@pytest.mark.parametrize("filename", _DASHBOARDS)
def test_dashboard_metrics_are_known(filename: str):
    body = json.loads((_DASH / filename).read_text())
    seen: set[str] = set()
    for panel in body["panels"]:
        for target in panel.get("targets", []):
            seen.update(_extract_metrics(target.get("expr", "")))
    unknown = seen - _KNOWN_METRICS
    assert not unknown, (
        f"{filename} references metrics not emitted by metrics.py: {sorted(unknown)}"
    )


@pytest.mark.parametrize("filename", _DASHBOARDS)
def test_dashboard_uses_datasource_template(filename: str):
    body = json.loads((_DASH / filename).read_text())
    template_names = {v["name"] for v in body.get("templating", {}).get("list", [])}
    assert "datasource" in template_names, "dashboards must template the datasource"


def test_alert_rules_load():
    yaml = pytest.importorskip("yaml")
    body = yaml.safe_load((_DASH / "alert-rules.yaml").read_text())
    assert "groups" in body
    assert len(body["groups"]) >= 1
    rules = [r for g in body["groups"] for r in g.get("rules", [])]
    assert len(rules) >= 4
    for r in rules:
        assert "alert" in r
        assert "expr" in r
        assert "labels" in r and "severity" in r["labels"]
        assert "annotations" in r and "summary" in r["annotations"]


def test_alert_rules_reference_known_metrics():
    yaml = pytest.importorskip("yaml")
    body = yaml.safe_load((_DASH / "alert-rules.yaml").read_text())
    seen: set[str] = set()
    for g in body["groups"]:
        for r in g.get("rules", []):
            seen.update(_extract_metrics(r["expr"]))
    unknown = seen - _KNOWN_METRICS
    assert not unknown, f"alert-rules.yaml references unknown metrics: {sorted(unknown)}"


def test_critical_alerts_have_runbook_links():
    yaml = pytest.importorskip("yaml")
    body = yaml.safe_load((_DASH / "alert-rules.yaml").read_text())
    page_alerts = [
        r for g in body["groups"]
        for r in g.get("rules", [])
        if r.get("labels", {}).get("severity") == "page"
    ]
    assert len(page_alerts) >= 2
    missing_runbook = [r["alert"] for r in page_alerts if "runbook_url" not in r.get("annotations", {})]
    # We require a runbook URL for the two highest-severity alerts.
    high_priority = {"TokendnaSecretGateFailure", "TokendnaHighErrorRate"}
    for name in high_priority:
        assert name not in missing_runbook, f"{name} must have a runbook_url"
