"""
TokenDNA SHA Pinning Module

Enforces cryptographic commit SHA pinning for GitHub Actions and other CI/CD frameworks.
Scans workflow files for mutable action references (e.g., @v5, @main, @latest) that can
be silently repointed by attackers, and ensures all external dependencies are pinned to
specific commit SHAs.

This module is part of the TokenDNA supply chain defense system and protects against
action tampering and dependency confusion attacks.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set

logger = logging.getLogger(__name__)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.debug("pyyaml not available; YAML parsing will be limited to regex")


@dataclass
class PinningViolation:
    """Represents a single action pinning violation in a workflow file."""

    file_path: str
    """Path to the workflow file containing the violation."""

    line_number: int
    """Line number within the file where the violation occurs."""

    action_ref: str
    """Full action reference as written (e.g., 'actions/checkout@v3')."""

    pin_ref: str
    """The ref/tag portion of the action (e.g., 'v3', 'main', SHA)."""

    violation_type: str
    """Type of violation: 'mutable_tag', 'branch_ref', 'latest_ref', or 'no_pin'."""

    severity: str
    """Severity level: 'HIGH', 'MEDIUM', or 'LOW'."""

    suggestion: str
    """Remediation suggestion for this violation."""


@dataclass
class PinningReport:
    """Summary report of pinning compliance for a single workflow file."""

    file_path: str
    """Path to the workflow file."""

    violations: List[PinningViolation] = field(default_factory=list)
    """List of pinning violations found in this file."""

    total_actions: int = 0
    """Total number of 'uses:' actions found in the workflow."""

    pinned_count: int = 0
    """Number of actions correctly pinned to SHAs."""

    mutable_count: int = 0
    """Number of actions using mutable references (tags, branches)."""

    compliance_score: float = 100.0
    """Compliance percentage (0-100)."""

    compliant: bool = True
    """Whether the file meets pinning compliance requirements."""


class ShaPinningEnforcer:
    """
    Enforces cryptographic pinning of GitHub Actions and external CI/CD dependencies.

    This class scans workflow definitions for mutable action references and ensures
    all external dependencies are pinned to immutable commit SHAs. It detects:
    - Mutable version tags (v1, v2.3, etc.)
    - Branch references (main, master, develop, etc.)
    - Floating refs (latest, tag without prefix)
    - Missing pins (empty or unparseable refs)

    Attributes:
        EXEMPT_ACTIONS: Set of action identifiers to exclude from pinning requirements.
    """

    EXEMPT_ACTIONS: Set[str] = set()

    def __init__(self):
        """
        Initialize the ShaPinningEnforcer.

        Loads exemption list from SC_PINNING_EXEMPT_ACTIONS environment variable
        (comma-separated action names).
        """
        exempt_env = os.getenv("SC_PINNING_EXEMPT_ACTIONS", "")
        if exempt_env:
            self.EXEMPT_ACTIONS = set(action.strip() for action in exempt_env.split(","))
            logger.info(f"Loaded {len(self.EXEMPT_ACTIONS)} exempt actions")

    def scan_workflow_content(
        self, content: str, file_path: str = "unknown"
    ) -> PinningReport:
        """
        Scan workflow YAML content for action pinning violations.

        Parses all 'uses:' directives and classifies each reference as pinned or
        mutable. Generates a compliance report with violations and recommendations.

        Args:
            content: Full text content of the workflow file.
            file_path: Path to the workflow file (for reporting).

        Returns:
            PinningReport object with detailed findings and compliance score.
        """
        report = PinningReport(file_path=file_path)

        uses_lines = self._extract_uses_lines(content)
        report.total_actions = len(uses_lines)

        for line_num, action_ref, pin_ref in uses_lines:
            action_name = action_ref.split("@")[0]

            if action_name in self.EXEMPT_ACTIONS:
                logger.debug(f"Skipping exempt action: {action_name}")
                report.pinned_count += 1
                continue

            violation_type, suggestion = self._classify_ref(pin_ref)

            if violation_type == "none":
                report.pinned_count += 1
            else:
                report.mutable_count += 1
                severity = self._severity(violation_type)

                violation = PinningViolation(
                    file_path=file_path,
                    line_number=line_num,
                    action_ref=action_ref,
                    pin_ref=pin_ref,
                    violation_type=violation_type,
                    severity=severity,
                    suggestion=suggestion,
                )
                report.violations.append(violation)

        report.compliance_score = self._compliance_score(
            report.total_actions, report.mutable_count
        )
        report.compliant = report.mutable_count == 0

        return report

    def scan_repo_path(self, repo_path: str) -> List[PinningReport]:
        """
        Recursively scan all workflow files in a repository.

        Walks the .github/workflows/ directory and generates a PinningReport
        for each YAML workflow file.

        Args:
            repo_path: Root path of the repository.

        Returns:
            List of PinningReport objects, one per workflow file found.
        """
        reports = []
        workflows_dir = Path(repo_path) / ".github" / "workflows"

        if not workflows_dir.exists():
            logger.info(f"No workflows directory found at {workflows_dir}")
            return reports

        try:
            for workflow_file in workflows_dir.glob("**/*.y[a]ml"):
                try:
                    content = workflow_file.read_text(encoding='utf-8')
                    relative_path = str(workflow_file.relative_to(repo_path))
                    report = self.scan_workflow_content(content, relative_path)
                    reports.append(report)
                except Exception as e:
                    logger.error(f"Error scanning workflow {workflow_file}: {e}")

        except Exception as e:
            logger.error(f"Error walking workflows directory: {e}")

        return reports

    @staticmethod
    def _extract_uses_lines(content: str) -> List[Tuple[int, str, str]]:
        """
        Extract all 'uses:' directives from workflow content.

        Parses YAML-like content (with optional full YAML parsing) to find lines
        containing 'uses:' and extracts the action reference and pin information.

        Args:
            content: Full text content of the workflow file.

        Returns:
            List of tuples: (line_number, action_ref, pin_ref)
            Example: (42, 'actions/checkout@v3', 'v3')
        """
        uses_lines = []
        pattern = r'^\s*uses:\s*([^\s]+(?:/[^\s@]+)?@([^\s]+))\s*(?:#.*)?$'

        for line_num, line in enumerate(content.split('\n'), start=1):
            match = re.match(pattern, line)
            if match:
                action_ref = match.group(1)
                pin_ref = match.group(2)

                uses_lines.append((line_num, action_ref, pin_ref))

        return uses_lines

    @staticmethod
    def _classify_ref(pin_ref: str) -> Tuple[str, str]:
        """
        Classify an action reference as pinned or mutable.

        Determines the violation type and generates a remediation suggestion.

        Args:
            pin_ref: The ref portion of an action (e.g., 'v3', 'main', or SHA).

        Returns:
            Tuple of (violation_type, suggestion):
            - violation_type: 'none', 'mutable_tag', 'branch_ref', 'latest_ref', or 'no_pin'
            - suggestion: Remediation instructions
        """
        if not pin_ref:
            return ("no_pin", "Specify a full commit SHA")

        pin_ref_lower = pin_ref.lower()

        if len(pin_ref) == 40 and all(c in '0123456789abcdef' for c in pin_ref_lower):
            return ("none", "Already pinned to SHA")

        if pin_ref_lower in ("latest", "main", "master", "develop"):
            return (
                "branch_ref",
                f"Pin to a specific commit SHA of '{pin_ref}' using: git rev-list -n 1 {pin_ref}",
            )

        if re.match(r'^v\d+(\.\d+)*$', pin_ref):
            return (
                "mutable_tag",
                f"Replace with commit SHA of tag '{pin_ref}' using: git rev-list -n 1 {pin_ref}",
            )

        if re.match(r'^\d+(\.\d+)*$', pin_ref):
            return (
                "mutable_tag",
                f"Replace with commit SHA of tag '{pin_ref}' using: git rev-list -n 1 {pin_ref}",
            )

        return ("no_pin", "Specify a full commit SHA")

    @staticmethod
    def _severity(violation_type: str) -> str:
        """
        Determine the severity of a pinning violation.

        Args:
            violation_type: Classification of the violation.

        Returns:
            Severity level: 'HIGH' or 'MEDIUM'.
        """
        if violation_type in ("branch_ref", "latest_ref", "no_pin"):
            return "HIGH"
        return "MEDIUM"

    @staticmethod
    def _compliance_score(total: int, mutable: int) -> float:
        """
        Calculate the pinning compliance score.

        Args:
            total: Total number of actions.
            mutable: Number of mutable (non-compliant) actions.

        Returns:
            Compliance percentage (0-100).
        """
        if total == 0:
            return 100.0

        return max(0.0, (total - mutable) / total * 100.0)

    @staticmethod
    def generate_remediation_script(reports: List[PinningReport]) -> str:
        """
        Generate a remediation script or instructions for fixing pinning violations.

        Creates a shell script with sed commands and manual instructions for
        updating action references to use commit SHAs.

        Args:
            reports: List of PinningReport objects to remediate.

        Returns:
            Multi-line string containing remediation instructions and script commands.
        """
        script_lines = [
            "#!/bin/bash",
            "# TokenDNA SHA Pinning Remediation Script",
            "# Review and execute the commands below to pin all GitHub Actions to commit SHAs",
            "",
        ]

        violation_count = sum(len(r.violations) for r in reports)

        if violation_count == 0:
            script_lines.append("# No pinning violations detected!")
            return "\n".join(script_lines)

        script_lines.append(f"# Total violations to remediate: {violation_count}")
        script_lines.append("")

        for report in reports:
            if not report.violations:
                continue

            script_lines.append(f"# File: {report.file_path}")

            for violation in report.violations:
                script_lines.append(f"# Line {violation.line_number}: {violation.action_ref}")
                script_lines.append(f"# Suggestion: {violation.suggestion}")

                safe_action = violation.action_ref.replace(
                    "@" + violation.pin_ref, "@<COMMIT_SHA>"
                )
                script_lines.append(f"# Change '{violation.action_ref}' to '{safe_action}'")
                script_lines.append("")

        script_lines.extend(
            [
                "# Manual remediation steps:",
                "# 1. For each action above, obtain the commit SHA:",
                "#    git rev-list -n 1 <tag_or_branch>",
                "# 2. Update the workflow file with the SHA",
                "# 3. Commit and push the changes",
                "# 4. Re-run this script to verify compliance",
            ]
        )

        return "\n".join(script_lines)


def check_sha_pinning_config() -> Dict[str, bool]:
    """
    Check the availability and status of the ShaPinningEnforcer module.

    Returns:
        Dictionary with key:
        - 'available': bool indicating if the module is operational
    """
    return {"available": True}
