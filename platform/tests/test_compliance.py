"""Tests for the compliance report generators."""
# SPDX-License-Identifier: BUSL-1.1

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tokendna_platform.compliance.reports import (
    ComplianceFramework,
    EUAIActReport,
    NISTAIRMFReport,
    SOC2AIReport,
    build_report,
)
from tokendna_platform.findings import Finding, FindingSeverity


def _findings() -> list[Finding]:
    return [
        Finding.new(title="drift", severity=FindingSeverity.HIGH,
                    tenant_id="t1", subject="alice", source_engine="permission_drift"),
        Finding.new(title="self-mod", severity=FindingSeverity.CRITICAL,
                    tenant_id="t1", subject="alice", source_engine="policy_guard"),
        Finding.new(title="behavioural shift", severity=FindingSeverity.MEDIUM,
                    tenant_id="t1", subject="bob", source_engine="behavioral_dna"),
        Finding.new(title="trust edge", severity=FindingSeverity.LOW,
                    tenant_id="t1", subject="charlie", source_engine="trust_graph"),
    ]


def _window():
    end = datetime.now(timezone.utc)
    return end - timedelta(days=30), end


def test_eu_ai_act_report_includes_articles_9_10_13_14() -> None:
    start, end = _window()
    report = EUAIActReport(
        tenant_id="t1", period_start=start, period_end=end,
        findings=tuple(_findings()),
    )
    out = report.to_dict()
    assert out["framework"] == "eu_ai_act"
    assert "Art_9_risk_management" in out["controls"]
    assert "Art_10_data_governance" in out["controls"]
    assert "Art_13_transparency" in out["controls"]
    assert "Art_14_human_oversight" in out["controls"]
    assert out["controls"]["Art_14_human_oversight"]["finding_count"] == 1   # only policy_guard


def test_nist_ai_rmf_report_includes_four_functions() -> None:
    start, end = _window()
    report = NISTAIRMFReport(
        tenant_id="t1", period_start=start, period_end=end,
        findings=tuple(_findings()),
    )
    out = report.to_dict()
    assert set(out["functions"].keys()) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    # 1 high + 1 critical = 2 high-or-critical
    assert out["functions"]["MANAGE"]["high_or_critical"] == 2


def test_soc2_ai_report_maps_findings_to_cc_categories() -> None:
    start, end = _window()
    report = SOC2AIReport(
        tenant_id="t1", period_start=start, period_end=end,
        findings=tuple(_findings()),
    )
    out = report.to_dict()
    assert "CC6_logical_access" in out["trust_services_criteria"]
    assert "CC7_system_operations" in out["trust_services_criteria"]
    assert "CC8_change_management" in out["trust_services_criteria"]


def test_report_summary_includes_severity_breakdown() -> None:
    start, end = _window()
    report = EUAIActReport(
        tenant_id="t1", period_start=start, period_end=end,
        findings=tuple(_findings()),
    )
    out = report.to_dict()
    summary = out["summary"]
    assert summary["total_findings"] == 4
    assert summary["findings_by_severity"]["high"] == 1
    assert summary["findings_by_severity"]["critical"] == 1


def test_build_report_factory_dispatches_by_framework() -> None:
    start, end = _window()
    findings = _findings()
    eu = build_report(ComplianceFramework.EU_AI_ACT,
                      tenant_id="t1", period_start=start, period_end=end,
                      findings=findings)
    nist = build_report(ComplianceFramework.NIST_AI_RMF,
                        tenant_id="t1", period_start=start, period_end=end,
                        findings=findings)
    soc2 = build_report(ComplianceFramework.SOC2_AI,
                        tenant_id="t1", period_start=start, period_end=end,
                        findings=findings)
    assert isinstance(eu, EUAIActReport)
    assert isinstance(nist, NISTAIRMFReport)
    assert isinstance(soc2, SOC2AIReport)
