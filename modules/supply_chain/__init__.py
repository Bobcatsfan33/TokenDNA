"""
TokenDNA Supply Chain Defense — v3.0.0

Nine-module layer defending against supply chain attacks that exploit
valid credentials and mutable git references.

Modules
-------
tag_ledger      — Immutable HMAC-chained ledger of all tag events
tag_monitor     — GitHub webhook processor; detects forced tag rewrites
commit_analyzer — Semantic + structural commit risk scoring (6 signals)
lineage         — Fork ancestry tracking; flags suspicious commit origins
workflow_guard  — SHA-256 baseline enforcement for CI/CD workflow files
sha_pinning     — Detects mutable @vN / @main action refs; enforces SHA pins
pipeline_guard  — Unified pre-execution gate aggregating all signals
blast_radius    — Cross-repo dependency graph; calculates impact of compromised actions
temporal        — Per-actor commit timing baseline; detects off-hours / burst anomalies

NIST 800-53 Rev5 coverage
-------------------------
SA-12  Supply Chain Risk Management
SA-12(1) Acquisition Strategies / Tools / Methods
CM-3   Configuration Change Control
CM-14  Signed Components Only
SI-7   Software / Firmware / Information Integrity
SI-7(1) Integrity Checks
AU-2   Event Logging
AU-9   Protection of Audit Information
IR-4   Incident Handling
"""

from .tag_ledger import TagLedger, TagEvent, check_ledger_config
from .tag_monitor import TagMonitor, TagMutationEvent, check_tag_monitor_config
from .commit_analyzer import CommitAnalyzer, CommitAnalysis, CommitRiskSignal, check_commit_analyzer_config
from .lineage import LineageTracker, CommitLineage, ForkOrigin, check_lineage_config
from .workflow_guard import WorkflowGuard, WorkflowViolation, WorkflowFile, check_workflow_guard_config
from .sha_pinning import ShaPinningEnforcer, PinningReport, PinningViolation, check_sha_pinning_config
from .pipeline_guard import PipelineGuard, PipelineDecision, PipelineRunContext, check_pipeline_guard_config
from .blast_radius import BlastRadiusCalculator, BlastRadiusReport, ActionUsage, check_blast_radius_config
from .temporal import TemporalAnomalyDetector, TemporalAnomaly, CommitTemporalProfile, check_temporal_config


def check_supply_chain_config() -> dict:
    """
    Aggregate startup check across all supply chain defense modules.

    Returns a dict suitable for inclusion in the startup audit event
    and health endpoint.
    """
    import logging
    log = logging.getLogger(__name__)

    results: dict = {}
    checks = [
        ("ledger",    check_ledger_config),
        ("tag_monitor", check_tag_monitor_config),
        ("commit_analyzer", check_commit_analyzer_config),
        ("lineage",   check_lineage_config),
        ("workflow_guard", check_workflow_guard_config),
        ("sha_pinning", check_sha_pinning_config),
        ("pipeline_guard", check_pipeline_guard_config),
        ("blast_radius", check_blast_radius_config),
        ("temporal",  check_temporal_config),
    ]
    for name, fn in checks:
        try:
            results[name] = fn()
        except Exception as exc:
            results[name] = {"error": str(exc)}
            log.warning("Supply chain config check failed for %s: %s", name, exc)

    redis_modules = ["ledger", "lineage", "workflow_guard", "blast_radius", "temporal"]
    redis_ok = any(results.get(m, {}).get("redis_available") for m in redis_modules)

    results["summary"] = {
        "redis_available": redis_ok,
        "modules_loaded": len([v for v in results.values() if "error" not in v]),
        "modules_total": len(checks),
    }

    if redis_ok:
        log.info("Supply chain defense ACTIVE — %d/%d modules loaded, Redis available.",
                 results["summary"]["modules_loaded"], len(checks))
    else:
        log.warning(
            "Supply chain defense DEGRADED — Redis unavailable; "
            "ledger, lineage, and blast-radius tracking require Redis (SC_REDIS_URL)."
        )

    return results


__all__ = [
    # Tag ledger
    "TagLedger", "TagEvent", "check_ledger_config",
    # Tag monitor
    "TagMonitor", "TagMutationEvent", "check_tag_monitor_config",
    # Commit analyzer
    "CommitAnalyzer", "CommitAnalysis", "CommitRiskSignal", "check_commit_analyzer_config",
    # Lineage
    "LineageTracker", "CommitLineage", "ForkOrigin", "check_lineage_config",
    # Workflow guard
    "WorkflowGuard", "WorkflowViolation", "WorkflowFile", "check_workflow_guard_config",
    # SHA pinning
    "ShaPinningEnforcer", "PinningReport", "PinningViolation", "check_sha_pinning_config",
    # Pipeline guard
    "PipelineGuard", "PipelineDecision", "PipelineRunContext", "check_pipeline_guard_config",
    # Blast radius
    "BlastRadiusCalculator", "BlastRadiusReport", "ActionUsage", "check_blast_radius_config",
    # Temporal
    "TemporalAnomalyDetector", "TemporalAnomaly", "CommitTemporalProfile", "check_temporal_config",
    # Aggregate
    "check_supply_chain_config",
]
