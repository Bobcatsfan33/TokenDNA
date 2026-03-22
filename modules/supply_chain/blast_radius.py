"""
TokenDNA Blast Radius Calculator Module

Cross-repository impact analysis for GitHub Actions supply chain defense.
Maintains a dependency graph of GitHub Action references across repositories.
When an action is compromised, surfaces all affected repositories, transitive
impact, and blast severity.

This module provides rapid blast radius assessment and impact mitigation
planning for supply chain security.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    import redis
except ImportError:
    redis = None  # Optional dependency


logger = logging.getLogger(__name__)


@dataclass
class ActionUsage:
    """
    Represents a single GitHub Action usage in a repository.

    Attributes:
        action_ref: Full action reference (owner/action format).
        pinning_type: How action is pinned ('sha', 'tag', 'branch', 'latest').
        sha_pin: SHA hash if pinned to specific commit; None otherwise.
        repo: Repository identifier (owner/repo).
        workflow_file: Workflow file path (e.g., .github/workflows/test.yml).
        last_seen: ISO 8601 timestamp of last detection.
    """

    action_ref: str
    pinning_type: str  # "sha", "tag", "branch", "latest"
    sha_pin: Optional[str]
    repo: str
    workflow_file: str
    last_seen: str


@dataclass
class BlastRadiusReport:
    """
    Complete blast radius analysis for a compromised action.

    Attributes:
        action_ref: The affected action reference.
        direct_consumers: List of repos directly using the action.
        transitive_consumers: List of repos using via dependency.
        total_repos_affected: Total count of affected repositories.
        severity: Impact severity ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        sha_pinned_count: Number of repos with SHA-pinned usage.
        mutable_ref_count: Number of repos with unpinned/mutable references.
        recommendations: List of actionable mitigation steps.
        generated_at: ISO 8601 timestamp of report generation.
    """

    action_ref: str
    direct_consumers: list[str]
    transitive_consumers: list[str]
    total_repos_affected: int
    severity: str
    sha_pinned_count: int
    mutable_ref_count: int
    recommendations: list[str]
    generated_at: str


class BlastRadiusCalculator:
    """
    Calculates supply chain blast radius for compromised actions.

    Maintains a dependency graph of GitHub Actions across repositories.
    Enables rapid assessment of impact when an action is compromised,
    including identification of affected repos, pinning status, and
    mitigation recommendations.

    Attributes:
        redis_client: Optional Redis client for persistent storage.

    Example:
        >>> calc = BlastRadiusCalculator()
        >>> calc.record_usage("owner/action", "consumer/repo", ".github/workflows/ci.yml")
        >>> report = calc.calculate("owner/action")
        >>> print(f"Blast severity: {report.severity}, affecting {report.total_repos_affected} repos")
    """

    REDIS_PREFIX = "sc:blast"

    def __init__(self, redis_client: Optional[object] = None) -> None:
        """
        Initialize the BlastRadiusCalculator.

        Args:
            redis_client: Optional Redis client instance for persistence.
                         If None, uses in-memory storage (not persistent).
        """
        self.redis_client = redis_client
        self._in_memory_consumers = {}  # {action_ref: set of repos}
        self._in_memory_details = {}  # {(action_ref, repo): ActionUsage}
        self._in_memory_actions = set()  # Set of all tracked action refs

        logger.info(f"BlastRadiusCalculator initialized with redis={'Yes' if redis_client else 'No (in-memory)'}")

    def record_usage(
        self,
        action_ref: str,
        repo: str,
        workflow_file: str,
        pinning_type: str = "tag",
        sha_pin: Optional[str] = None,
    ) -> None:
        """
        Record a GitHub Action usage in a repository.

        Stores action reference, pinning status, and repository metadata
        for later blast radius analysis.

        Args:
            action_ref: Full action reference (e.g., 'actions/checkout').
            repo: Consumer repository identifier (owner/repo).
            workflow_file: Path to workflow file using the action.
            pinning_type: Pinning mechanism ('sha', 'tag', 'branch', 'latest').
            sha_pin: SHA hash if sha-pinned; None otherwise.

        Returns:
            None
        """
        try:
            now = datetime.utcnow().isoformat()
            action_set_key = f"{self.REDIS_PREFIX}:actions"
            consumer_key = f"{self.REDIS_PREFIX}:{action_ref}:consumers"
            detail_key = f"{self.REDIS_PREFIX}:{action_ref}:details:{repo}"

            usage_data = {
                "workflow_file": workflow_file,
                "pinning_type": pinning_type,
                "sha_pin": sha_pin or "none",
                "last_seen": now,
            }

            if self.redis_client:
                try:
                    # Add action to actions set
                    self.redis_client.sadd(action_set_key, action_ref)

                    # Add repo to consumers set
                    self.redis_client.sadd(consumer_key, repo)

                    # Store usage details
                    self.redis_client.hset(detail_key, mapping=usage_data)
                except Exception as e:
                    logger.warning(f"Redis usage recording failed: {e}, using in-memory fallback")
                    self._record_in_memory(action_ref, repo, usage_data)
            else:
                self._record_in_memory(action_ref, repo, usage_data)

            logger.debug(f"Recorded usage: {action_ref} in {repo} ({workflow_file})")

        except Exception as e:
            logger.error(f"Error recording action usage {action_ref}/{repo}: {e}")
            raise

    def _record_in_memory(self, action_ref: str, repo: str, usage_data: dict) -> None:
        """
        Record action usage in in-memory storage.

        Args:
            action_ref: Action reference.
            repo: Repository identifier.
            usage_data: Usage details dictionary.
        """
        self._in_memory_actions.add(action_ref)

        if action_ref not in self._in_memory_consumers:
            self._in_memory_consumers[action_ref] = set()
        self._in_memory_consumers[action_ref].add(repo)

        key = (action_ref, repo)
        self._in_memory_details[key] = usage_data

    def calculate(self, action_ref: str) -> BlastRadiusReport:
        """
        Calculate blast radius for a compromised action.

        Retrieves all affected repositories, analyzes pinning status,
        and generates severity classification and recommendations.

        Args:
            action_ref: The action reference to analyze.

        Returns:
            BlastRadiusReport with comprehensive impact analysis.
        """
        try:
            logger.info(f"Calculating blast radius for {action_ref}")

            direct_consumers = self._get_direct_consumers(action_ref)
            transitive_consumers = self._get_transitive_consumers(action_ref)

            total_repos = len(set(direct_consumers + transitive_consumers))

            # Analyze pinning status
            sha_pinned_count, mutable_ref_count = self._analyze_pinning(action_ref, direct_consumers)

            # Determine severity
            severity = self._severity(total_repos, mutable_ref_count)

            # Generate recommendations
            recommendations = self._recommendations(
                BlastRadiusReport(
                    action_ref=action_ref,
                    direct_consumers=direct_consumers,
                    transitive_consumers=transitive_consumers,
                    total_repos_affected=total_repos,
                    severity=severity,
                    sha_pinned_count=sha_pinned_count,
                    mutable_ref_count=mutable_ref_count,
                    recommendations=[],  # Placeholder
                    generated_at=datetime.utcnow().isoformat(),
                )
            )

            report = BlastRadiusReport(
                action_ref=action_ref,
                direct_consumers=direct_consumers,
                transitive_consumers=transitive_consumers,
                total_repos_affected=total_repos,
                severity=severity,
                sha_pinned_count=sha_pinned_count,
                mutable_ref_count=mutable_ref_count,
                recommendations=recommendations,
                generated_at=datetime.utcnow().isoformat(),
            )

            logger.info(
                f"Blast radius calculated: {total_repos} repos affected, "
                f"severity={severity}, mutable={mutable_ref_count}"
            )
            return report

        except Exception as e:
            logger.error(f"Error calculating blast radius for {action_ref}: {e}")
            raise

    def _get_direct_consumers(self, action_ref: str) -> list[str]:
        """
        Retrieve all direct consumers of an action.

        Args:
            action_ref: The action reference.

        Returns:
            List of repository identifiers.
        """
        try:
            consumer_key = f"{self.REDIS_PREFIX}:{action_ref}:consumers"

            if self.redis_client:
                try:
                    consumers = self.redis_client.smembers(consumer_key)
                    return list(consumers) if consumers else []
                except Exception as e:
                    logger.warning(f"Redis direct consumers retrieval failed: {e}")
                    return list(self._in_memory_consumers.get(action_ref, set()))
            else:
                return list(self._in_memory_consumers.get(action_ref, set()))

        except Exception as e:
            logger.error(f"Error retrieving direct consumers for {action_ref}: {e}")
            return []

    def _get_transitive_consumers(self, action_ref: str) -> list[str]:
        """
        Retrieve transitive consumers (repos using via dependency).

        Current implementation returns empty list; full implementation
        would require recursive dependency graph traversal.

        Args:
            action_ref: The action reference.

        Returns:
            List of transitive consumer repositories.
        """
        # Placeholder for transitive dependency resolution
        # Full implementation would require composite action analysis
        return []

    def _analyze_pinning(self, action_ref: str, repos: list[str]) -> tuple[int, int]:
        """
        Analyze SHA pinning status across all consumers.

        Args:
            action_ref: The action reference.
            repos: List of consumer repositories.

        Returns:
            Tuple of (sha_pinned_count, mutable_ref_count).
        """
        sha_pinned = 0
        mutable = 0

        for repo in repos:
            detail_key = f"{self.REDIS_PREFIX}:{action_ref}:details:{repo}"

            pinning_type = None
            if self.redis_client:
                try:
                    detail = self.redis_client.hget(detail_key, "pinning_type")
                    pinning_type = detail.decode() if detail else "unknown"
                except Exception as e:
                    logger.warning(f"Redis pinning detail retrieval failed: {e}")
                    key = (action_ref, repo)
                    pinning_type = self._in_memory_details.get(key, {}).get("pinning_type", "unknown")
            else:
                key = (action_ref, repo)
                pinning_type = self._in_memory_details.get(key, {}).get("pinning_type", "unknown")

            if pinning_type == "sha":
                sha_pinned += 1
            else:
                mutable += 1

        return sha_pinned, mutable

    def _severity(self, consumer_count: int, mutable_count: int) -> str:
        """
        Classify blast radius severity.

        Heuristics:
        - CRITICAL: >50 repos OR >20 mutable references
        - HIGH: >10 repos OR >5 mutable references
        - MEDIUM: >3 repos
        - LOW: 1-3 repos

        Args:
            consumer_count: Total number of affected repos.
            mutable_count: Count of repos with mutable references.

        Returns:
            Severity classification: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.
        """
        if consumer_count > 50 or mutable_count > 20:
            return "CRITICAL"
        elif consumer_count > 10 or mutable_count > 5:
            return "HIGH"
        elif consumer_count > 3:
            return "MEDIUM"
        else:
            return "LOW"

    def _recommendations(self, report: BlastRadiusReport) -> list[str]:
        """
        Generate actionable mitigation recommendations.

        Args:
            report: BlastRadiusReport to analyze.

        Returns:
            List of recommendation strings.
        """
        recommendations = []

        if report.severity == "CRITICAL":
            recommendations.append("IMMEDIATE: Prepare incident response for potentially compromised action")
            recommendations.append("URGENT: Notify all {} directly affected repositories".format(len(report.direct_consumers)))
            recommendations.append("Create emergency pull requests to pin or replace action")

        if report.mutable_ref_count > 0:
            recommendations.append(
                f"Pin {report.mutable_ref_count} repos using mutable references to specific commit SHA"
            )

        if report.sha_pinned_count > 0:
            recommendations.append(
                f"{report.sha_pinned_count} repos are SHA-pinned and less vulnerable to compromise"
            )

        if report.total_repos_affected > 20:
            recommendations.append("Consider creating a central policy enforcement rule for action pinning")

        recommendations.append("Review and audit affected workflows in all consumer repositories")
        recommendations.append("Monitor all {} affected repositories for suspicious activity".format(report.total_repos_affected))

        return recommendations

    def scan_workflow_content(self, content: str, repo: str, workflow_file: str) -> list[ActionUsage]:
        """
        Extract action references from workflow YAML content.

        Parses 'uses:' directives without requiring YAML library.
        Records all discovered usages automatically.

        Args:
            content: Workflow file content (text).
            repo: Repository identifier.
            workflow_file: Path to workflow file.

        Returns:
            List of ActionUsage objects found in content.
        """
        usages = []

        try:
            # Parse action references from "uses:" lines
            action_refs = self._parse_action_refs(content)

            for action_ref, pin_ref in action_refs:
                pinning_type, sha_pin = self._classify_pin(pin_ref)

                # Record usage
                self.record_usage(action_ref, repo, workflow_file, pinning_type, sha_pin)

                # Create ActionUsage object
                usage = ActionUsage(
                    action_ref=action_ref,
                    pinning_type=pinning_type,
                    sha_pin=sha_pin,
                    repo=repo,
                    workflow_file=workflow_file,
                    last_seen=datetime.utcnow().isoformat(),
                )
                usages.append(usage)

            logger.debug(f"Scanned {len(usages)} actions from {repo}/{workflow_file}")

        except Exception as e:
            logger.error(f"Error scanning workflow content: {e}")

        return usages

    def _parse_action_refs(self, content: str) -> list[tuple[str, str]]:
        """
        Extract action references from workflow content.

        Pattern matches 'uses: owner/action@ref' directives.

        Args:
            content: Workflow file content.

        Returns:
            List of (action_ref, pin_ref) tuples.
        """
        refs = []

        try:
            # Regex pattern for "uses: owner/action@ref" or "uses: owner/action@v1.2.3"
            pattern = r"uses:\s*([a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+)@([a-zA-Z0-9\-_.]+)"
            matches = re.finditer(pattern, content, re.IGNORECASE)

            for match in matches:
                action_ref = match.group(1)
                pin_ref = match.group(2)
                refs.append((action_ref, pin_ref))

        except Exception as e:
            logger.error(f"Error parsing action references: {e}")

        return refs

    def _classify_pin(self, pin_ref: str) -> tuple[str, Optional[str]]:
        """
        Classify the pinning type of an action reference.

        Heuristics:
        - 40-char hex string: SHA pin
        - "latest" or "main" or "master": branch reference
        - vN.N.N format: semantic version tag
        - Otherwise: tag or branch

        Args:
            pin_ref: The reference portion after '@' (e.g., 'abc123...', 'v1.0.0', 'main').

        Returns:
            Tuple of (pinning_type, sha_pin).
            pinning_type: 'sha', 'tag', 'branch', 'latest'
            sha_pin: SHA value if sha-pinned; None otherwise.
        """
        # Check if SHA (40-char hex)
        if re.match(r"^[a-f0-9]{40}$", pin_ref):
            return "sha", pin_ref

        # Check if common branch name
        if pin_ref.lower() in ["main", "master", "latest", "develop"]:
            return "branch", None

        # Check if semantic version (vN.N.N)
        if re.match(r"^v?\d+\.\d+\.\d+", pin_ref):
            return "tag", None

        # Default to branch if not recognized
        return "branch", None

    def get_all_tracked_actions(self) -> list[str]:
        """
        Retrieve all tracked action references.

        Returns:
            List of action references stored in the system.
        """
        try:
            action_set_key = f"{self.REDIS_PREFIX}:actions"

            if self.redis_client:
                try:
                    actions = self.redis_client.smembers(action_set_key)
                    return list(actions) if actions else []
                except Exception as e:
                    logger.warning(f"Redis actions retrieval failed: {e}")
                    return list(self._in_memory_actions)
            else:
                return list(self._in_memory_actions)

        except Exception as e:
            logger.error(f"Error retrieving tracked actions: {e}")
            return []


def check_blast_radius_config() -> dict:
    """
    Verify BlastRadiusCalculator configuration and availability.

    Returns:
        Configuration dictionary with availability status and tracked action count.
    """
    try:
        redis_available = False
        tracked_actions = 0

        if redis:
            try:
                test_client = redis.Redis(
                    host="localhost", port=6379, socket_connect_timeout=2, decode_responses=True
                )
                test_client.ping()
                redis_available = True

                # Try to count tracked actions
                try:
                    action_set_key = f"{BlastRadiusCalculator.REDIS_PREFIX}:actions"
                    tracked_actions = test_client.scard(action_set_key)
                except Exception:
                    tracked_actions = 0

            except Exception:
                redis_available = False

        return {
            "redis_available": redis_available,
            "tracked_actions": tracked_actions,
        }

    except Exception as e:
        logger.error(f"BlastRadiusCalculator configuration check failed: {e}")
        return {
            "redis_available": False,
            "tracked_actions": 0,
            "error": str(e),
        }
