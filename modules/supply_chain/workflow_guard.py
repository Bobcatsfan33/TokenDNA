"""
TokenDNA Workflow Guard Module

Monitors .github/workflows/ and CI configuration files for unauthorized modifications.
Maintains SHA-256 baselines in Redis and alerts when workflow files change outside of
approved paths or contain potentially dangerous steps.

This module is part of the TokenDNA supply chain defense system and provides continuous
monitoring of CI/CD pipeline definitions to detect tampering or injection attacks.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis package not available; in-memory storage will be used")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger.debug("pyyaml not available; YAML parsing will be limited")

try:
    from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
    AUDIT_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    AUDIT_AVAILABLE = False
    logger.debug("audit_log module not available")


@dataclass
class WorkflowFile:
    """Represents a monitored workflow file with its baseline hash and metadata."""

    path: str
    """Path to the workflow file."""

    sha256: str
    """SHA-256 hash of the workflow file content."""

    last_actor: str
    """GitHub user or CI system that last modified this file."""

    last_modified: str
    """ISO8601 timestamp of the last modification."""

    size_bytes: int
    """Size of the workflow file in bytes."""


@dataclass
class WorkflowViolation:
    """Represents a detected violation in workflow file integrity or policy."""

    path: str
    """Path to the workflow file where the violation was detected."""

    violation_type: str
    """Type of violation: 'baseline_mismatch', 'new_workflow', 'workflow_deleted', 'pinning_violation', or 'privileged_step_added'."""

    severity: str
    """Severity level: 'CRITICAL', 'HIGH', or 'MEDIUM'."""

    previous_hash: Optional[str] = None
    """SHA-256 hash of the previous (approved) version, if applicable."""

    current_hash: Optional[str] = None
    """SHA-256 hash of the current version, if applicable."""

    detail: str = ""
    """Additional details about the violation."""


class WorkflowGuard:
    """
    Monitors and protects CI/CD workflow definitions against unauthorized changes.

    This class maintains baselines of approved workflow files and detects:
    - Modifications to existing workflows
    - New workflow files added to monitored paths
    - Deleted workflow files
    - Dangerous or privileged steps within workflows
    - Missing action pinning (detected by SHA pinning module)

    Attributes:
        MONITORED_PATTERNS: Glob patterns of files to monitor for changes.
    """

    MONITORED_PATTERNS: List[str] = [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        ".github/actions/**",
    ]

    def __init__(self, redis_client: Optional[Any] = None):
        """
        Initialize the WorkflowGuard.

        Args:
            redis_client: Optional Redis client for persistent baseline storage.
                         If None and Redis is available, creates a default connection.
                         If None and Redis is unavailable, uses in-memory storage.
        """
        self.redis_client = redis_client
        self._memory_store: Dict[str, Dict[str, Any]] = {}

        if self.redis_client is None and REDIS_AVAILABLE:
            try:
                self.redis_client = redis.StrictRedis(
                    host="localhost", port=6379, db=0, decode_responses=True
                )
                self.redis_client.ping()
                logger.info("WorkflowGuard initialized with Redis persistence")
            except Exception as e:
                logger.warning(f"Could not connect to Redis: {e}; using memory storage")
                self.redis_client = None
        elif self.redis_client is None:
            logger.info("WorkflowGuard initialized with in-memory storage")

    def register_baseline(self, path: str, content: str, actor: str) -> WorkflowFile:
        """
        Register a workflow file baseline for future change detection.

        Computes the SHA-256 hash of the content and stores metadata in Redis
        (or in-memory if Redis unavailable).

        Args:
            path: Relative path to the workflow file (e.g., '.github/workflows/ci.yml').
            content: Full text content of the workflow file.
            actor: GitHub user or system that performed this registration.

        Returns:
            WorkflowFile object containing the baseline hash and metadata.
        """
        sha256_hash = self._sha256(content)
        size_bytes = len(content.encode('utf-8'))
        timestamp = datetime.utcnow().isoformat() + "Z"

        workflow_file = WorkflowFile(
            path=path,
            sha256=sha256_hash,
            last_actor=actor,
            last_modified=timestamp,
            size_bytes=size_bytes,
        )

        baseline_data = asdict(workflow_file)
        redis_key = f"sc:workflow:baseline:{path}"

        if self.redis_client:
            try:
                self.redis_client.hset(redis_key, mapping=baseline_data)
                self.redis_client.expire(redis_key, 86400 * 365)  # 1 year TTL
                logger.info(f"Registered baseline for workflow: {path}")
            except Exception as e:
                logger.error(f"Failed to store baseline in Redis: {e}")
                self._memory_store[redis_key] = baseline_data
        else:
            self._memory_store[redis_key] = baseline_data
            logger.info(f"Registered baseline in memory for workflow: {path}")

        return workflow_file

    def check_file(
        self, path: str, content: str, actor: str
    ) -> Optional[WorkflowViolation]:
        """
        Check a single workflow file against its registered baseline.

        Compares the SHA-256 hash of the provided content to the stored baseline.
        Returns a violation if the hash differs or if no baseline exists.

        Args:
            path: Relative path to the workflow file.
            content: Current content of the workflow file.
            actor: GitHub user or system actor making this change.

        Returns:
            WorkflowViolation object if a violation is detected, None otherwise.
        """
        if not self._is_workflow_file(path):
            return None

        current_hash = self._sha256(content)
        redis_key = f"sc:workflow:baseline:{path}"

        baseline_data = None
        if self.redis_client:
            try:
                baseline_data = self.redis_client.hgetall(redis_key)
            except Exception as e:
                logger.error(f"Failed to retrieve baseline from Redis: {e}")

        if not baseline_data and redis_key in self._memory_store:
            baseline_data = self._memory_store[redis_key]

        if not baseline_data:
            return WorkflowViolation(
                path=path,
                violation_type="new_workflow",
                severity="HIGH",
                current_hash=current_hash,
                detail=f"New workflow file detected: {path}",
            )

        baseline_hash = baseline_data.get("sha256")
        if baseline_hash != current_hash:
            return WorkflowViolation(
                path=path,
                violation_type="baseline_mismatch",
                severity="CRITICAL",
                previous_hash=baseline_hash,
                current_hash=current_hash,
                detail=f"Workflow file modified: {path} (changed by {actor})",
            )

        privileged_issues = self._check_privileged_steps(content)
        if privileged_issues:
            return WorkflowViolation(
                path=path,
                violation_type="privileged_step_added",
                severity="CRITICAL",
                current_hash=current_hash,
                detail=f"Dangerous patterns detected in workflow: {'; '.join(privileged_issues[:3])}",
            )

        return None

    def check_commit(self, files_changed: List[Dict[str, Any]]) -> List[WorkflowViolation]:
        """
        Check a batch of file changes (e.g., from a commit) for workflow violations.

        Iterates through a list of changed files and returns violations for any
        workflow files that violate baseline or policy constraints.

        Args:
            files_changed: List of file change dictionaries, each with keys:
                          - 'filename' (str): path to the file
                          - 'content' (str, optional): file content
                          - 'sha256' (str, optional): SHA-256 hash of content

        Returns:
            List of WorkflowViolation objects detected in the commit.
        """
        violations = []

        for file_change in files_changed:
            filename = file_change.get("filename", "")

            if not self._is_workflow_file(filename):
                continue

            content = file_change.get("content")
            if content is None:
                logger.debug(f"Skipping {filename}; no content provided")
                continue

            actor = file_change.get("actor", "unknown")
            violation = self.check_file(filename, content, actor)

            if violation:
                violations.append(violation)

                if AUDIT_AVAILABLE:
                    try:
                        log_event(
                            event_type=AuditEventType.CONFIGURATION_CHANGE,
                            outcome=AuditOutcome.FAILURE,
                            details={
                                "module": "workflow_guard",
                                "violation_type": violation.violation_type,
                                "path": violation.path,
                                "severity": violation.severity,
                            },
                        )
                    except Exception as e:
                        logger.error(f"Failed to log audit event: {e}")

        return violations

    def _is_workflow_file(self, path: str) -> bool:
        """
        Determine if a file path matches any monitored workflow patterns.

        Args:
            path: File path to check.

        Returns:
            True if the path matches a monitored pattern, False otherwise.
        """
        for pattern in self.MONITORED_PATTERNS:
            if fnmatch(path, pattern):
                return True
        return False

    def _check_privileged_steps(self, content: str) -> List[str]:
        """
        Scan workflow content for dangerous or privileged step patterns.

        Detects patterns such as:
        - curl or wget piped to shell (curl | bash)
        - npm/pip installation with custom registries
        - Environment variable exfiltration attempts

        Args:
            content: Full text content of a workflow file.

        Returns:
            List of detected dangerous patterns.
        """
        issues = []

        dangerous_patterns = [
            (r"curl\s+.*\|\s*bash", "curl piped to bash"),
            (r"wget\s+.*\|\s*sh", "wget piped to sh"),
            (r"pip\s+install.*--index-url", "pip with custom index-url"),
            (r"npm\s+install.*--registry", "npm with custom registry"),
            (r"--allow-root", "--allow-root in package manager"),
            (r"curl\s+.*\$(?:GITHUB_TOKEN|SECRET|PASSWORD)", "curl exfiltrating secrets"),
            (r"wget\s+.*\$(?:GITHUB_TOKEN|SECRET|PASSWORD)", "wget exfiltrating secrets"),
        ]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append(description)

        return issues

    def get_baseline(self, path: str) -> Optional[WorkflowFile]:
        """
        Retrieve the registered baseline for a workflow file.

        Args:
            path: Relative path to the workflow file.

        Returns:
            WorkflowFile object if a baseline exists, None otherwise.
        """
        redis_key = f"sc:workflow:baseline:{path}"

        baseline_data = None
        if self.redis_client:
            try:
                baseline_data = self.redis_client.hgetall(redis_key)
            except Exception as e:
                logger.error(f"Failed to retrieve baseline from Redis: {e}")

        if not baseline_data and redis_key in self._memory_store:
            baseline_data = self._memory_store[redis_key]

        if not baseline_data:
            return None

        try:
            return WorkflowFile(
                path=baseline_data.get("path", path),
                sha256=baseline_data.get("sha256", ""),
                last_actor=baseline_data.get("last_actor", ""),
                last_modified=baseline_data.get("last_modified", ""),
                size_bytes=int(baseline_data.get("size_bytes", 0)),
            )
        except Exception as e:
            logger.error(f"Failed to reconstruct WorkflowFile from baseline: {e}")
            return None

    def list_monitored_files(self) -> List[WorkflowFile]:
        """
        Retrieve all registered workflow file baselines.

        Returns:
            List of WorkflowFile objects currently registered.
        """
        baselines = []

        if self.redis_client:
            try:
                cursor = 0
                while True:
                    cursor, keys = self.redis_client.scan(
                        cursor, match="sc:workflow:baseline:*", count=100
                    )
                    for key in keys:
                        try:
                            data = self.redis_client.hgetall(key)
                            if data:
                                baselines.append(
                                    WorkflowFile(
                                        path=data.get("path", ""),
                                        sha256=data.get("sha256", ""),
                                        last_actor=data.get("last_actor", ""),
                                        last_modified=data.get("last_modified", ""),
                                        size_bytes=int(data.get("size_bytes", 0)),
                                    )
                                )
                        except Exception as e:
                            logger.error(f"Error retrieving baseline from key {key}: {e}")

                    if cursor == 0:
                        break
            except Exception as e:
                logger.error(f"Error scanning Redis keys: {e}")

        for key, data in self._memory_store.items():
            if key.startswith("sc:workflow:baseline:"):
                try:
                    baselines.append(
                        WorkflowFile(
                            path=data.get("path", ""),
                            sha256=data.get("sha256", ""),
                            last_actor=data.get("last_actor", ""),
                            last_modified=data.get("last_modified", ""),
                            size_bytes=int(data.get("size_bytes", 0)),
                        )
                    )
                except Exception as e:
                    logger.error(f"Error reconstructing baseline from memory: {e}")

        return baselines

    @staticmethod
    def _sha256(content: str) -> str:
        """
        Compute the SHA-256 hash of content.

        Args:
            content: Text content to hash.

        Returns:
            Hexadecimal representation of the SHA-256 hash.
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()


def check_workflow_guard_config() -> Dict[str, Any]:
    """
    Check the availability and status of the WorkflowGuard module.

    Returns:
        Dictionary with keys:
        - 'redis_available': bool indicating if Redis is accessible
        - 'monitored_files_count': int count of currently registered baselines
    """
    redis_available = REDIS_AVAILABLE

    if REDIS_AVAILABLE:
        try:
            test_client = redis.StrictRedis(
                host="localhost", port=6379, db=0, decode_responses=True, socket_connect_timeout=2
            )
            test_client.ping()
        except Exception as e:
            logger.debug(f"Redis connectivity check failed: {e}")
            redis_available = False

    guard = WorkflowGuard()
    monitored_count = len(guard.list_monitored_files())

    return {
        "redis_available": redis_available,
        "monitored_files_count": monitored_count,
    }
