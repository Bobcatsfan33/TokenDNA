"""
TokenDNA Pipeline Guard Module

Unified pipeline execution gate that integrates all supply chain defense signals
into a risk-based decision engine. Evaluates CI/CD pipeline runs before secrets
are exposed, considering workflow integrity, commit risk, SHA pinning compliance,
and tag mutation detection.

This module serves as the central enforcement point for supply chain defense,
aggregating signals from multiple modules to make allow/sandbox/block decisions.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

try:
    from modules.supply_chain.workflow_guard import WorkflowGuard, WorkflowViolation
    WORKFLOW_GUARD_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    WORKFLOW_GUARD_AVAILABLE = False
    logger.debug("workflow_guard module not available")

try:
    from modules.supply_chain.sha_pinning import ShaPinningEnforcer, PinningReport
    SHA_PINNING_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    SHA_PINNING_AVAILABLE = False
    logger.debug("sha_pinning module not available")

try:
    from modules.supply_chain.commit_analyzer import CommitAnalyzer
    COMMIT_ANALYZER_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    COMMIT_ANALYZER_AVAILABLE = False
    logger.debug("commit_analyzer module not available")

try:
    from modules.supply_chain.tag_monitor import TagMonitor
    TAG_MONITOR_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    TAG_MONITOR_AVAILABLE = False
    logger.debug("tag_monitor module not available")

try:
    from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
    AUDIT_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AUDIT_AVAILABLE = False
    logger.debug("audit_log module not available")


@dataclass
class PipelineRunContext:
    """Context information about a CI/CD pipeline execution."""

    run_id: str
    """Unique identifier for the pipeline run (e.g., GitHub Actions run ID)."""

    repo: str
    """Repository identifier in format 'owner/repo'."""

    actor: str
    """GitHub user or system actor that triggered the pipeline."""

    workflow_file: str
    """Relative path to the workflow definition file."""

    trigger_event: str
    """Type of trigger event: 'push', 'pull_request', 'release', 'workflow_dispatch', etc."""

    commit_sha: str
    """SHA of the commit being tested/deployed."""

    ref: str
    """Git reference (branch or tag) being tested."""

    timestamp: str
    """ISO8601 timestamp of pipeline start."""


@dataclass
class PipelineDecision:
    """Decision and reasoning for a pipeline execution."""

    run_id: str
    """Unique identifier for the pipeline run."""

    decision: str
    """Decision outcome: 'ALLOW', 'SANDBOX', or 'BLOCK'."""

    risk_score: float
    """Aggregated risk score (0-100)."""

    reasons: List[str] = field(default_factory=list)
    """Detailed reasons for the decision."""

    signals_fired: List[str] = field(default_factory=list)
    """List of security signals that triggered."""

    recommended_actions: List[str] = field(default_factory=list)
    """Recommended actions for pipeline operators or security teams."""


class PipelineGuard:
    """
    Unified execution gate for CI/CD pipelines with integrated supply chain defense.

    This class orchestrates multiple security modules (workflow guard, SHA pinning,
    commit analysis, tag monitoring) to make comprehensive risk assessments of
    pipeline execution. It supports three decisions:
    - ALLOW: Proceed with normal execution
    - SANDBOX: Execute with restrictions (e.g., no secret access)
    - BLOCK: Prevent execution entirely

    Attributes:
        commit_analyzer: Optional CommitAnalyzer instance for commit risk assessment.
        workflow_guard: Optional WorkflowGuard instance for workflow integrity checks.
        sha_enforcer: Optional ShaPinningEnforcer instance for pinning verification.
        tag_monitor: Optional TagMonitor instance for tag mutation detection.
    """

    def __init__(
        self,
        commit_analyzer: Optional[Any] = None,
        workflow_guard: Optional[Any] = None,
        sha_enforcer: Optional[Any] = None,
        tag_monitor: Optional[Any] = None,
    ):
        """
        Initialize the PipelineGuard with optional sub-module instances.

        If not provided, sub-modules are lazily instantiated based on availability.

        Args:
            commit_analyzer: Optional CommitAnalyzer instance.
            workflow_guard: Optional WorkflowGuard instance.
            sha_enforcer: Optional ShaPinningEnforcer instance.
            tag_monitor: Optional TagMonitor instance.
        """
        self.commit_analyzer = commit_analyzer
        self.workflow_guard = workflow_guard
        self.sha_enforcer = sha_enforcer
        self.tag_monitor = tag_monitor

    def evaluate(
        self,
        ctx: PipelineRunContext,
        workflow_content: Optional[str] = None,
        commit_data: Optional[Dict[str, Any]] = None,
    ) -> PipelineDecision:
        """
        Evaluate a pipeline run and make an allow/sandbox/block decision.

        Aggregates signals from all available sub-modules and computes a unified
        risk score, resulting in a decision and recommended actions.

        Args:
            ctx: PipelineRunContext with run metadata.
            workflow_content: Optional workflow YAML content for analysis.
            commit_data: Optional commit metadata dict with keys like 'files_changed', 'message', 'author'.

        Returns:
            PipelineDecision with decision, risk_score, and recommendations.
        """
        decision = PipelineDecision(run_id=ctx.run_id, decision="ALLOW", risk_score=0.0)
        contributions = []

        workflow_score, workflow_reasons = self._check_workflow_integrity(
            ctx, workflow_content
        )
        contributions.append((workflow_score, workflow_reasons))

        commit_score, commit_reasons = self._check_commit_risk(ctx, commit_data)
        contributions.append((commit_score, commit_reasons))

        pinning_score, pinning_reasons = self._check_pinning(ctx, workflow_content)
        contributions.append((pinning_score, pinning_reasons))

        tag_score, tag_reasons = self._check_tag_mutation(ctx)
        contributions.append((tag_score, tag_reasons))

        risk_score, all_reasons = self._aggregate_score(contributions)
        decision.risk_score = risk_score
        decision.reasons = all_reasons

        for score, reasons in contributions:
            if reasons:
                decision.signals_fired.extend(
                    [r.split(":")[0] for r in reasons if ":" in r]
                )

        decision.decision = self._decide(risk_score)
        decision.recommended_actions = self._recommendations(
            decision.decision, decision.signals_fired
        )

        if AUDIT_AVAILABLE:
            try:
                log_event(
                    event_type=AuditEventType.PIPELINE_EXECUTION,
                    outcome=AuditOutcome.SUCCESS if decision.decision == "ALLOW" else AuditOutcome.FAILURE,
                    details={
                        "module": "pipeline_guard",
                        "run_id": ctx.run_id,
                        "decision": decision.decision,
                        "risk_score": decision.risk_score,
                        "signals_fired": decision.signals_fired,
                    },
                )
            except Exception as e:
                logger.error(f"Failed to log audit event: {e}")

        return decision

    def _check_workflow_integrity(
        self, ctx: PipelineRunContext, workflow_content: Optional[str]
    ) -> Tuple[float, List[str]]:
        """
        Check workflow file integrity against registered baselines.

        Returns a risk score contribution (0-30) based on workflow violations.

        Args:
            ctx: PipelineRunContext.
            workflow_content: Optional workflow YAML content.

        Returns:
            Tuple of (risk_score_contribution, list_of_reasons).
        """
        if workflow_content is None:
            return 0.0, []

        if not WORKFLOW_GUARD_AVAILABLE:
            return 0.0, []

        if self.workflow_guard is None:
            try:
                self.workflow_guard = WorkflowGuard()
            except Exception as e:
                logger.error(f"Failed to initialize WorkflowGuard: {e}")
                return 0.0, []

        try:
            violation = self.workflow_guard.check_file(
                ctx.workflow_file, workflow_content, ctx.actor
            )

            if violation:
                severity_score = {
                    "CRITICAL": 30.0,
                    "HIGH": 20.0,
                    "MEDIUM": 10.0,
                }
                score = severity_score.get(violation.severity, 10.0)
                return (
                    score,
                    [
                        f"workflow_integrity: {violation.violation_type} ({violation.severity})"
                    ],
                )

            return 0.0, []

        except Exception as e:
            logger.error(f"Error checking workflow integrity: {e}")
            return 0.0, []

    def _check_commit_risk(
        self, ctx: PipelineRunContext, commit_data: Optional[Dict[str, Any]]
    ) -> Tuple[float, List[str]]:
        """
        Analyze commit metadata for risk indicators.

        Returns a risk score contribution (0-25) based on commit analysis.

        Args:
            ctx: PipelineRunContext.
            commit_data: Optional commit metadata dict.

        Returns:
            Tuple of (risk_score_contribution, list_of_reasons).
        """
        if commit_data is None:
            return 0.0, []

        if not COMMIT_ANALYZER_AVAILABLE:
            return 0.0, []

        if self.commit_analyzer is None:
            try:
                self.commit_analyzer = CommitAnalyzer()
            except Exception as e:
                logger.error(f"Failed to initialize CommitAnalyzer: {e}")
                return 0.0, []

        try:
            analysis = self.commit_analyzer.analyze(commit_data)

            if hasattr(analysis, 'risk_score'):
                return analysis.risk_score * 0.25, [
                    f"commit_risk: {analysis.risk_score if hasattr(analysis, 'risk_score') else 0} points"
                ]

            return 0.0, []

        except Exception as e:
            logger.error(f"Error analyzing commit risk: {e}")
            return 0.0, []

    def _check_pinning(
        self, ctx: PipelineRunContext, workflow_content: Optional[str]
    ) -> Tuple[float, List[str]]:
        """
        Verify SHA pinning compliance in workflow definitions.

        Returns a risk score contribution (0-25) based on unpinned actions.

        Args:
            ctx: PipelineRunContext.
            workflow_content: Optional workflow YAML content.

        Returns:
            Tuple of (risk_score_contribution, list_of_reasons).
        """
        if workflow_content is None:
            return 0.0, []

        if not SHA_PINNING_AVAILABLE:
            return 0.0, []

        if self.sha_enforcer is None:
            try:
                self.sha_enforcer = ShaPinningEnforcer()
            except Exception as e:
                logger.error(f"Failed to initialize ShaPinningEnforcer: {e}")
                return 0.0, []

        try:
            report = self.sha_enforcer.scan_workflow_content(
                workflow_content, ctx.workflow_file
            )

            if report.mutable_count > 0:
                score = min(25.0, report.mutable_count * 2.5)
                return (score, [f"pinning_violations: {report.mutable_count} mutable refs"])

            return 0.0, []

        except Exception as e:
            logger.error(f"Error checking SHA pinning: {e}")
            return 0.0, []

    def _check_tag_mutation(self, ctx: PipelineRunContext) -> Tuple[float, List[str]]:
        """
        Detect suspicious tag mutations or force-pushes to tags.

        Returns a risk score contribution (0-20) based on tag anomalies.

        Args:
            ctx: PipelineRunContext.

        Returns:
            Tuple of (risk_score_contribution, list_of_reasons).
        """
        if ctx.trigger_event != "push":
            return 0.0, []

        if not TAG_MONITOR_AVAILABLE:
            return 0.0, []

        if self.tag_monitor is None:
            try:
                self.tag_monitor = TagMonitor()
            except Exception as e:
                logger.error(f"Failed to initialize TagMonitor: {e}")
                return 0.0, []

        if not ctx.ref.startswith("refs/tags/"):
            return 0.0, []

        try:
            tag_name = ctx.ref.replace("refs/tags/", "")
            is_mutable = self.tag_monitor.is_tag_mutable(ctx.repo, tag_name)

            if is_mutable:
                return 20.0, ["tag_mutation: mutable tag detected"]

            return 0.0, []

        except Exception as e:
            logger.error(f"Error checking tag mutation: {e}")
            return 0.0, []

    @staticmethod
    def _aggregate_score(
        contributions: List[Tuple[float, List[str]]]
    ) -> Tuple[float, List[str]]:
        """
        Aggregate risk scores from multiple sources.

        Sums all contributions and collects all reasons, capping total at 100.

        Args:
            contributions: List of (score, reasons) tuples from each check.

        Returns:
            Tuple of (aggregated_score, all_reasons).
        """
        total_score = 0.0
        all_reasons = []

        for score, reasons in contributions:
            total_score += score
            all_reasons.extend(reasons)

        total_score = min(100.0, total_score)

        return total_score, all_reasons

    @staticmethod
    def _decide(score: float) -> str:
        """
        Determine the decision based on aggregated risk score.

        Args:
            score: Aggregated risk score (0-100).

        Returns:
            Decision string: 'BLOCK', 'SANDBOX', or 'ALLOW'.
        """
        if score >= 75.0:
            return "BLOCK"
        elif score >= 45.0:
            return "SANDBOX"
        else:
            return "ALLOW"

    @staticmethod
    def _recommendations(decision: str, signals: List[str]) -> List[str]:
        """
        Generate actionable recommendations based on decision and signals.

        Args:
            decision: Pipeline decision ('ALLOW', 'SANDBOX', 'BLOCK').
            signals: List of fired security signals.

        Returns:
            List of recommendation strings.
        """
        recommendations = []

        if decision == "BLOCK":
            recommendations.append("CRITICAL: Pipeline execution blocked. Review security signals above.")
            recommendations.append(
                "Contact security team to review and remediate violations before proceeding."
            )
            if "workflow_integrity" in signals:
                recommendations.append(
                    "Verify workflow file changes with code review before approval."
                )
            if "tag_mutation" in signals:
                recommendations.append("Audit tag creation and force-push permissions.")

        elif decision == "SANDBOX":
            recommendations.append("Pipeline will execute with restricted access (no secrets).")
            if "pinning_violations" in signals:
                recommendations.append(
                    "Pin all GitHub Actions to specific commit SHAs before releasing."
                )
            if "commit_risk" in signals:
                recommendations.append(
                    "Review commit history and author permissions before granting secret access."
                )

        else:  # ALLOW
            recommendations.append("Pipeline approved for normal execution.")
            if signals:
                recommendations.append("Monitor for any anomalies during execution.")

        return recommendations

    def get_status(self) -> Dict[str, Any]:
        """
        Retrieve the operational status of the PipelineGuard and its sub-modules.

        Returns:
            Dictionary with:
            - 'available': bool indicating if the module is operational
            - 'modules_active': dict mapping module names to their availability
        """
        status = {
            "available": True,
            "modules_active": {
                "workflow_guard": (
                    WORKFLOW_GUARD_AVAILABLE or self.workflow_guard is not None
                ),
                "sha_pinning": (
                    SHA_PINNING_AVAILABLE or self.sha_enforcer is not None
                ),
                "commit_analyzer": (
                    COMMIT_ANALYZER_AVAILABLE or self.commit_analyzer is not None
                ),
                "tag_monitor": (
                    TAG_MONITOR_AVAILABLE or self.tag_monitor is not None
                ),
            },
        }

        return status


def check_pipeline_guard_config() -> Dict[str, Any]:
    """
    Check the availability and status of the PipelineGuard module.

    Returns:
        Dictionary with keys:
        - 'available': bool indicating if the module is operational
        - 'modules_active': dict mapping module names to their availability
    """
    guard = PipelineGuard()
    return guard.get_status()
