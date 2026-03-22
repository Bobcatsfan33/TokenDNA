"""
TokenDNA Commit Analyzer Module

AI-powered commit semantic analysis for supply chain risk detection.
Scores commits by examining message/diff coherence, workflow touches,
file scatter, signing status, force indicators, and mass change patterns.

This module provides comprehensive commit risk assessment for CI/CD
security monitoring and supply chain defense.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class CommitRiskSignal:
    """
    Represents a single risk signal detected in a commit.

    Attributes:
        signal_name: Identifier of the risk signal (e.g., "workflow_touch").
        weight: Signal weight in risk score calculation (0-100 scale).
        triggered: Whether this signal was triggered by the commit.
        detail: Human-readable description of the signal and findings.
    """

    signal_name: str
    weight: float
    triggered: bool
    detail: str


@dataclass
class CommitAnalysis:
    """
    Complete analysis result for a single commit.

    Attributes:
        commit_sha: The commit SHA-1 hash.
        actor: The committer's username/email.
        repo: Repository identifier (owner/repo format).
        timestamp: ISO 8601 timestamp of the commit.
        risk_score: Weighted risk score from 0-100.
        risk_tier: Risk classification (CRITICAL, HIGH, MEDIUM, LOW, CLEAN).
        signals: List of all evaluated risk signals.
        recommendation: Action recommendation (BLOCK, REVIEW, MONITOR, PASS).
        workflow_files_touched: List of detected workflow/CI files modified.
        suspicious_patterns: List of suspicious patterns found in commit data.
    """

    commit_sha: str
    actor: str
    repo: str
    timestamp: str
    risk_score: float
    risk_tier: str
    signals: list[CommitRiskSignal]
    recommendation: str
    workflow_files_touched: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)


class CommitAnalyzer:
    """
    Analyzer for detecting supply chain risks in Git commits.

    Uses multi-factor signal analysis including workflow file touches,
    message coherence, file scatter patterns, signing status, and force
    indicators. Combines signals into a risk score and recommendation.

    Example:
        >>> analyzer = CommitAnalyzer()
        >>> result = analyzer.analyze({
        ...     "sha": "abc123",
        ...     "actor": "user@example.com",
        ...     "repo": "org/repo",
        ...     "message": "Critical security fix",
        ...     "timestamp": "2026-03-22T10:00:00Z",
        ...     "files_changed": [{"filename": ".github/workflows/test.yml"}],
        ...     "signed": True,
        ...     "parents": ["def456"]
        ... })
        >>> print(f"{result.risk_tier}: {result.recommendation}")
    """

    # Workflow file patterns
    WORKFLOW_PATTERNS = [
        r"\.github/workflows/",
        r"\.gitlab-ci\.yml",
        r"Jenkinsfile",
        r"\.circleci/",
        r"Dockerfile",
    ]

    # Force/bypass indicators in commit messages
    FORCE_KEYWORDS = [
        "force",
        "override",
        "bypass",
        "skip review",
        "skip checks",
        "revert",
        "hotfix",
    ]

    # Branch protection/CODEOWNERS files
    CRITICAL_CONFIG_FILES = [
        ".github/CODEOWNERS",
        ".github/branch-protection.yml",
        ".gitlab-ci.yml",
    ]

    def __init__(self) -> None:
        """Initialize the CommitAnalyzer with signal weights and thresholds."""
        logger.info("CommitAnalyzer initialized")

    def analyze(self, commit_data: dict) -> CommitAnalysis:
        """
        Perform comprehensive risk analysis on a commit.

        Args:
            commit_data: Dictionary containing:
                - sha: Commit SHA-1 hash
                - actor: Committer username/email
                - repo: Repository identifier
                - message: Commit message
                - timestamp: ISO 8601 timestamp
                - files_changed: List of {filename, additions, deletions, patch (optional)}
                - signed: Boolean indicating commit signature
                - parents: List of parent commit SHAs

        Returns:
            CommitAnalysis object with risk score, tier, signals, and recommendation.

        Raises:
            ValueError: If required commit_data fields are missing.
        """
        try:
            required_fields = ["sha", "actor", "repo", "message", "timestamp", "files_changed", "signed", "parents"]
            missing = [f for f in required_fields if f not in commit_data]
            if missing:
                raise ValueError(f"Missing required fields: {missing}")

            sha = commit_data["sha"]
            actor = commit_data["actor"]
            repo = commit_data["repo"]
            message = commit_data["message"]
            timestamp = commit_data["timestamp"]
            files_changed = commit_data.get("files_changed", [])
            signed = commit_data.get("signed", False)

            logger.debug(f"Analyzing commit {sha} in {repo} by {actor}")

            # Extract filenames
            files = [f.get("filename", "") for f in files_changed]

            # Evaluate all signals
            signals = [
                self._check_workflow_touch(files),
                self._check_message_coherence(message, files),
                self._check_file_scatter(files),
                self._check_mass_change(files_changed),
                self._check_unsigned(signed),
                self._check_force_indicators(message, files),
            ]

            # Compute risk score
            risk_score = self._compute_score(signals)

            # Determine tier
            risk_tier = self._tier(risk_score)

            # Determine recommendation
            workflow_touched = any(s.signal_name == "workflow_touch" and s.triggered for s in signals)
            recommendation = self._recommend(risk_tier, workflow_touched)

            # Collect workflow files and patterns
            workflow_files_touched = [f for f in files if any(re.search(p, f) for p in self.WORKFLOW_PATTERNS)]
            suspicious_patterns = [s.detail for s in signals if s.triggered]

            analysis = CommitAnalysis(
                commit_sha=sha,
                actor=actor,
                repo=repo,
                timestamp=timestamp,
                risk_score=risk_score,
                risk_tier=risk_tier,
                signals=signals,
                recommendation=recommendation,
                workflow_files_touched=workflow_files_touched,
                suspicious_patterns=suspicious_patterns,
            )

            logger.info(
                f"Commit {sha} analysis: score={risk_score:.1f}, tier={risk_tier}, " f"recommendation={recommendation}"
            )
            return analysis

        except Exception as e:
            logger.exception(f"Error analyzing commit {commit_data.get('sha', 'unknown')}: {e}")
            raise

    def _check_workflow_touch(self, files: list[str]) -> CommitRiskSignal:
        """
        Check if commit modifies CI/CD workflow files.

        Weight: 35 (high impact on supply chain)

        Args:
            files: List of modified filenames.

        Returns:
            CommitRiskSignal indicating workflow file touches.
        """
        matching_files = [f for f in files if any(re.search(p, f) for p in self.WORKFLOW_PATTERNS)]

        triggered = len(matching_files) > 0
        detail = f"Modified {len(matching_files)} workflow file(s): {', '.join(matching_files)}" if triggered else "No workflow files modified"

        return CommitRiskSignal(
            signal_name="workflow_touch",
            weight=35,
            triggered=triggered,
            detail=detail,
        )

    def _check_message_coherence(self, message: str, files: list[str]) -> CommitRiskSignal:
        """
        Assess coherence between commit message and changed files.

        Weight: 25

        Triggered if:
        - Message is < 10 characters
        - Generic message ("fix typo", "update readme") with > 5 files
        - Message lacks imperative verb

        Args:
            message: Commit message.
            files: List of modified filenames.

        Returns:
            CommitRiskSignal indicating message coherence.
        """
        reasons = []

        # Check message length
        if len(message.strip()) < 10:
            reasons.append("message too short (<10 chars)")

        # Check for generic messages with broad changes
        generic_patterns = [r"fix\s+typo", r"update\s+readme", r"formatting", r"cleanup"]
        is_generic = any(re.search(p, message, re.IGNORECASE) for p in generic_patterns)
        if is_generic and len(files) > 5:
            reasons.append(f"generic message with {len(files)} file changes")

        # Check for imperative verb
        first_word = message.split()[0].lower() if message.split() else ""
        common_verbs = {
            "add", "fix", "remove", "update", "refactor", "optimize", "improve",
            "implement", "change", "modify", "correct", "revert", "delete"
        }
        if first_word and first_word not in common_verbs and not message[0].isupper():
            reasons.append("missing imperative verb at start")

        triggered = len(reasons) > 0
        detail = "; ".join(reasons) if triggered else "Message coherence acceptable"

        return CommitRiskSignal(
            signal_name="message_coherence",
            weight=25,
            triggered=triggered,
            detail=detail,
        )

    def _check_file_scatter(self, files: list[str]) -> CommitRiskSignal:
        """
        Check for unrelated file changes across multiple directories.

        Weight: 20

        Triggered if files span > 4 distinct top-level directories.

        Args:
            files: List of modified filenames.

        Returns:
            CommitRiskSignal indicating file scatter.
        """
        directories = set()
        for f in files:
            parts = f.split("/")
            if parts:
                directories.add(parts[0])

        triggered = len(directories) > 4
        detail = f"Files scattered across {len(directories)} top-level directories" if triggered else f"Changes in {len(directories)} directory/directories"

        return CommitRiskSignal(
            signal_name="file_scatter",
            weight=20,
            triggered=triggered,
            detail=detail,
        )

    def _check_mass_change(self, files_changed: list[dict]) -> CommitRiskSignal:
        """
        Check for uncommonly large number of changes.

        Weight: 15

        Triggered if:
        - Total additions + deletions > 500
        - > 20 files modified

        Args:
            files_changed: List of file change dicts with additions/deletions.

        Returns:
            CommitRiskSignal indicating mass changes.
        """
        total_additions = sum(f.get("additions", 0) for f in files_changed)
        total_deletions = sum(f.get("deletions", 0) for f in files_changed)
        total_changes = total_additions + total_deletions
        file_count = len(files_changed)

        triggered = total_changes > 500 or file_count > 20
        detail = f"{file_count} files changed, {total_changes} total additions/deletions" if triggered else f"{file_count} files, {total_changes} changes"

        return CommitRiskSignal(
            signal_name="mass_change",
            weight=15,
            triggered=triggered,
            detail=detail,
        )

    def _check_unsigned(self, signed: bool) -> CommitRiskSignal:
        """
        Check if commit is cryptographically signed.

        Weight: 10

        Triggered if commit is not signed.

        Args:
            signed: Boolean indicating commit signature presence.

        Returns:
            CommitRiskSignal indicating unsigned commit.
        """
        triggered = not signed
        detail = "Commit lacks cryptographic signature" if triggered else "Commit is signed"

        return CommitRiskSignal(
            signal_name="unsigned",
            weight=10,
            triggered=triggered,
            detail=detail,
        )

    def _check_force_indicators(self, message: str, files: list[str]) -> CommitRiskSignal:
        """
        Check for force-push and bypass indicators.

        Weight: 20

        Triggered if:
        - Message contains force/override/bypass/skip keywords
        - Modified critical config files (CODEOWNERS, branch protection)

        Args:
            message: Commit message.
            files: List of modified filenames.

        Returns:
            CommitRiskSignal indicating force indicators.
        """
        reasons = []

        # Check message keywords
        for keyword in self.FORCE_KEYWORDS:
            if keyword.lower() in message.lower():
                reasons.append(f'keyword "{keyword}" in message')

        # Check critical files
        critical_touched = [f for f in files if f in self.CRITICAL_CONFIG_FILES]
        if critical_touched:
            reasons.append(f"modified critical config: {', '.join(critical_touched)}")

        triggered = len(reasons) > 0
        detail = "; ".join(reasons) if triggered else "No force/bypass indicators detected"

        return CommitRiskSignal(
            signal_name="force_indicators",
            weight=20,
            triggered=triggered,
            detail=detail,
        )

    def _compute_score(self, signals: list[CommitRiskSignal]) -> float:
        """
        Compute weighted risk score from triggered signals.

        Weighted sum normalized to 0-100 scale based on total possible weight.

        Args:
            signals: List of evaluated CommitRiskSignal objects.

        Returns:
            Risk score from 0.0 to 100.0.
        """
        total_weight = sum(s.weight for s in signals)
        if total_weight == 0:
            return 0.0

        triggered_weight = sum(s.weight for s in signals if s.triggered)
        score = (triggered_weight / total_weight) * 100

        return min(100.0, max(0.0, score))

    def _tier(self, score: float) -> str:
        """
        Classify risk score into categorical tier.

        Args:
            score: Risk score from 0-100.

        Returns:
            Risk tier: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "CLEAN".
        """
        if score >= 85:
            return "CRITICAL"
        elif score >= 65:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "CLEAN"

    def _recommend(self, tier: str, workflow_touched: bool) -> str:
        """
        Generate action recommendation based on tier and context.

        Args:
            tier: Risk tier classification.
            workflow_touched: Whether workflow files were modified.

        Returns:
            Recommendation: "BLOCK", "REVIEW", "MONITOR", or "PASS".
        """
        if tier == "CRITICAL":
            return "BLOCK"
        elif tier == "HIGH":
            return "BLOCK" if workflow_touched else "REVIEW"
        elif tier == "MEDIUM":
            return "REVIEW"
        elif tier == "LOW":
            return "MONITOR"
        else:
            return "PASS"

    def batch_analyze(self, commits: list[dict]) -> list[CommitAnalysis]:
        """
        Analyze multiple commits in batch.

        Args:
            commits: List of commit_data dictionaries.

        Returns:
            List of CommitAnalysis results.
        """
        results = []
        for commit in commits:
            try:
                result = self.analyze(commit)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze commit {commit.get('sha', 'unknown')}: {e}")
                continue

        logger.info(f"Batch analyzed {len(results)}/{len(commits)} commits")
        return results


def check_commit_analyzer_config() -> dict:
    """
    Verify CommitAnalyzer configuration and availability.

    Returns:
        Configuration dictionary with availability status and signal count.
    """
    try:
        analyzer = CommitAnalyzer()
        signal_count = 6  # workflow_touch, message_coherence, file_scatter, mass_change, unsigned, force_indicators

        return {
            "available": True,
            "signals_count": signal_count,
        }
    except Exception as e:
        logger.error(f"CommitAnalyzer configuration check failed: {e}")
        return {
            "available": False,
            "signals_count": 0,
            "error": str(e),
        }
