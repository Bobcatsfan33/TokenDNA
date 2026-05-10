"""Compliance report generators."""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

from ..findings import Finding, FindingSeverity


class ComplianceFramework(str, Enum):
    EU_AI_ACT = "eu_ai_act"
    NIST_AI_RMF = "nist_ai_rmf"
    SOC2_AI = "soc2_ai"


@dataclass
class ComplianceReport(ABC):
    """Base class for framework-specific reports."""

    tenant_id: str
    period_start: datetime
    period_end: datetime
    framework: ComplianceFramework = field(init=False)
    findings: tuple[Finding, ...] = ()
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Render the report.  Subclasses override to add framework-specific structure."""

    # ── Helpers shared by every framework ────────────────────────────────
    def _summary(self) -> dict[str, Any]:
        sev_counter: Counter[str] = Counter()
        engine_counter: Counter[str] = Counter()
        for f in self.findings:
            sev_counter[f.severity.value] += 1
            engine_counter[f.source_engine] += 1
        return {
            "total_findings":      len(self.findings),
            "findings_by_severity": dict(sev_counter),
            "findings_by_engine":   dict(engine_counter),
            "period_start":        self.period_start.isoformat(),
            "period_end":          self.period_end.isoformat(),
            "generated_at":        self.generated_at.isoformat(),
        }

    def _findings_payload(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for f in self.findings:
            d = dataclasses.asdict(f)
            d["severity"] = f.severity.value
            d["detected_at"] = f.detected_at.isoformat()
            out.append(d)
        return out


@dataclass
class EUAIActReport(ComplianceReport):
    """EU AI Act — Articles 9, 10, 13, 14 control evidence."""

    framework: ComplianceFramework = ComplianceFramework.EU_AI_ACT

    def to_dict(self) -> dict[str, Any]:
        # Article 9: Risk management
        # Article 10: Data and data governance
        # Article 13: Transparency and information
        # Article 14: Human oversight
        return {
            "framework": self.framework.value,
            "tenant_id": self.tenant_id,
            "summary":   self._summary(),
            "controls": {
                "Art_9_risk_management": {
                    "description":  "Continuous risk identification + mitigation",
                    "evidence":     "drift + behavioural-DNA findings (engine: behavioral_dna, permission_drift)",
                    "finding_count": sum(
                        1 for f in self.findings
                        if f.source_engine in ("behavioral_dna", "permission_drift")
                    ),
                },
                "Art_10_data_governance": {
                    "description":  "Data + access governance for AI training/inference",
                    "evidence":     "permission-change + AI-invocation events captured by ingestion layer",
                    "finding_count": sum(
                        1 for f in self.findings
                        if f.source_engine in ("permission_drift", "policy_guard")
                    ),
                },
                "Art_13_transparency": {
                    "description":  "Logging + traceability of AI system operation",
                    "evidence":     "Hash-chained event store + compliance.evidence_export",
                    "finding_count": len(self.findings),
                },
                "Art_14_human_oversight": {
                    "description":  "Detection-mode posture: humans review every BLOCK-equivalent finding",
                    "evidence":     "policy_guard detect-mode findings + alert channels",
                    "finding_count": sum(
                        1 for f in self.findings
                        if f.source_engine == "policy_guard"
                    ),
                },
            },
            "findings": self._findings_payload(),
        }


@dataclass
class NISTAIRMFReport(ComplianceReport):
    """NIST AI Risk Management Framework — Govern / Map / Measure / Manage."""

    framework: ComplianceFramework = ComplianceFramework.NIST_AI_RMF

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "tenant_id": self.tenant_id,
            "summary":   self._summary(),
            "functions": {
                "GOVERN":  {"finding_count": sum(1 for f in self.findings if f.source_engine == "policy_guard")},
                "MAP":     {"finding_count": sum(1 for f in self.findings if f.source_engine == "trust_graph")},
                "MEASURE": {"finding_count": sum(1 for f in self.findings if f.source_engine in ("behavioral_dna", "permission_drift"))},
                "MANAGE":  {
                    "high_or_critical": sum(
                        1 for f in self.findings
                        if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
                    ),
                },
            },
            "findings": self._findings_payload(),
        }


@dataclass
class SOC2AIReport(ComplianceReport):
    """SOC 2 AI addendum — CC6/CC7/CC8 + AI-specific controls."""

    framework: ComplianceFramework = ComplianceFramework.SOC2_AI

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "tenant_id": self.tenant_id,
            "summary":   self._summary(),
            "trust_services_criteria": {
                "CC6_logical_access": {
                    "evidence": "Permission-drift + Okta IDP audit trail",
                    "finding_count": sum(1 for f in self.findings if f.source_engine == "permission_drift"),
                },
                "CC7_system_operations": {
                    "evidence": "Trust-graph relational changes + behavioural drift",
                    "finding_count": sum(1 for f in self.findings if f.source_engine in ("trust_graph", "behavioral_dna")),
                },
                "CC8_change_management": {
                    "evidence": "policy_guard verdicts on config-change events",
                    "finding_count": sum(1 for f in self.findings if f.source_engine == "policy_guard"),
                },
            },
            "findings": self._findings_payload(),
        }


def build_report(
    framework: ComplianceFramework,
    *,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    findings: Iterable[Finding],
) -> ComplianceReport:
    """One-stop factory; useful for the dashboard + scheduled exports."""
    findings_tuple = tuple(findings)
    if framework == ComplianceFramework.EU_AI_ACT:
        return EUAIActReport(tenant_id=tenant_id,
                             period_start=period_start,
                             period_end=period_end,
                             findings=findings_tuple)
    if framework == ComplianceFramework.NIST_AI_RMF:
        return NISTAIRMFReport(tenant_id=tenant_id,
                               period_start=period_start,
                               period_end=period_end,
                               findings=findings_tuple)
    if framework == ComplianceFramework.SOC2_AI:
        return SOC2AIReport(tenant_id=tenant_id,
                            period_start=period_start,
                            period_end=period_end,
                            findings=findings_tuple)
    raise ValueError(f"unknown framework: {framework}")
