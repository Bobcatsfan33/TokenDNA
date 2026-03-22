"""
Detects git tag mutations from GitHub webhook events and ledger mismatches.

This module processes GitHub push webhooks to detect suspicious tag operations,
particularly forced tag updates that could indicate supply chain tampering.

It integrates with the TagLedger to cross-reference mutations against recorded
history and emits AU-2 audit events for suspicious activity.

Example:
    >>> monitor = TagMonitor()
    >>> webhook_payload = {...}  # From GitHub
    >>> mutation = monitor.process_webhook(webhook_payload)
    >>> if mutation and mutation.severity == "CRITICAL":
    ...     print(f"Critical mutation detected: {mutation.tag_name}")
"""

import json
import logging
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

from .tag_ledger import TagLedger, TagEvent

try:
    from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
except ImportError:
    # Fallback if audit_log module is not available
    log_event = None
    AuditEventType = None
    AuditOutcome = None

logger = logging.getLogger(__name__)


@dataclass
class TagMutationEvent:
    """Record of a suspicious git tag mutation detected via webhook.

    Attributes:
        tag_name: Name of the git tag that was mutated.
        before_sha: Commit SHA before the mutation (or null for creation).
        after_sha: Commit SHA after the mutation (or null for deletion).
        actor: GitHub user who performed the operation.
        repo: Repository in format "owner/name".
        timestamp: ISO 8601 timestamp when the webhook was received.
        severity: Risk level assessment ("CRITICAL", "HIGH", "MEDIUM").
        forced: Boolean indicating if this was a forced push.
        unsigned: Boolean indicating if the push was unsigned (unverified).
        ledger_recorded: Boolean indicating if the mutation is in the TagLedger.
    """
    tag_name: str
    before_sha: str
    after_sha: str
    actor: str
    repo: str
    timestamp: str
    severity: str
    forced: bool
    unsigned: bool
    ledger_recorded: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


class TagMonitor:
    """Detects git tag mutations and anomalies from GitHub webhooks.

    Processes push events, identifies tag mutations (especially forced updates),
    cross-references with the TagLedger, and emits audit events for suspicious
    activity.
    """

    # Regex patterns for release tags
    RELEASE_TAG_PATTERN = re.compile(r"^v\d+(\.\d+){0,2}$")

    def __init__(self, ledger: Optional[TagLedger] = None) -> None:
        """Initialize the tag monitor with optional ledger instance.

        Args:
            ledger: Optional TagLedger instance. If not provided, a new one is created.
        """
        self.ledger = ledger or TagLedger()
        logger.info("TagMonitor initialized")

    def _is_forced(self, before_sha: str, after_sha: str) -> bool:
        """Determine if a tag update was a forced push.

        A forced push is indicated when the before SHA is not the null SHA
        (indicating a non-creation) and the SHA changed.

        Args:
            before_sha: SHA before the update.
            after_sha: SHA after the update.

        Returns:
            True if the update appears to be a forced push.
        """
        null_sha = "0000000000000000000000000000000000000000"
        is_creation = before_sha == null_sha
        sha_changed = before_sha != after_sha

        return sha_changed and not is_creation

    def _is_deletion(self, after_sha: str) -> bool:
        """Determine if a tag operation was a deletion.

        A deletion is indicated when the after SHA is the null SHA.

        Args:
            after_sha: SHA after the operation.

        Returns:
            True if the operation was a deletion.
        """
        null_sha = "0000000000000000000000000000000000000000"
        return after_sha == null_sha

    def _tag_is_release(self, tag_name: str) -> bool:
        """Check if a tag matches release version pattern (vN, vN.N, vN.N.N).

        Release tags follow semantic versioning prefixed with 'v' (e.g., v1.0.0).
        These are high-value targets for supply chain attacks.

        Args:
            tag_name: Name of the git tag.

        Returns:
            True if tag matches release pattern.
        """
        return bool(self.RELEASE_TAG_PATTERN.match(tag_name))

    def _assess_severity(
        self,
        forced: bool,
        deleted: bool,
        tag_matches_release: bool,
    ) -> str:
        """Assess the severity of a tag mutation.

        Severity is CRITICAL if a release tag is forced-updated, HIGH if any
        forced update, MEDIUM otherwise.

        Args:
            forced: Boolean indicating if the update was forced.
            deleted: Boolean indicating if the tag was deleted.
            tag_matches_release: Boolean indicating if tag is a release version.

        Returns:
            Severity level as string: "CRITICAL", "HIGH", or "MEDIUM".
        """
        if forced and tag_matches_release:
            return "CRITICAL"
        if forced:
            return "HIGH"
        return "MEDIUM"

    def process_webhook(self, payload: dict) -> Optional[TagMutationEvent]:
        """Process a GitHub push webhook and detect tag mutations.

        This method extracts tag information from a GitHub webhook payload,
        detects forced pushes and deletions, records the event in the ledger,
        and emits an audit event if the mutation is suspicious.

        Args:
            payload: GitHub webhook payload dict.

        Returns:
            TagMutationEvent if a mutation is detected and suspicious,
            None if the payload is not a tag-related push or represents
            normal tag activity.
        """
        try:
            # Extract webhook data
            ref = payload.get("ref", "")
            before = payload.get("before", "")
            after = payload.get("after", "")
            pusher_email = payload.get("pusher", {}).get("email", "unknown")
            repo_name = payload.get("repository", {}).get("full_name", "unknown")

            # Check if this is a tag push
            if not ref.startswith("refs/tags/"):
                return None

            # Extract tag name
            tag_name = ref.replace("refs/tags/", "")

            # Detect tag operations
            forced = self._is_forced(before, after)
            deleted = self._is_deletion(after)
            is_release = self._tag_is_release(tag_name)

            # Only report mutations (forced updates, not normal creates/deletes)
            if not forced and not deleted:
                return None

            timestamp = datetime.now(timezone.utc).isoformat()
            severity = self._assess_severity(forced, deleted, is_release)

            # Check if unsigned (GitHub marks signed commits)
            head_commit = payload.get("head_commit", {})
            unsigned = not head_commit.get("verification", {}).get("verified", False)

            # Record in ledger
            ledger_recorded = False
            try:
                if forced and not deleted:
                    self.ledger.record(
                        tag_name=tag_name,
                        commit_sha=after,
                        actor=pusher_email,
                        action="updated",
                        prev_sha=before,
                    )
                    ledger_recorded = True
            except Exception as e:
                logger.error(f"Failed to record mutation in ledger: {e}")

            # Create mutation event
            mutation = TagMutationEvent(
                tag_name=tag_name,
                before_sha=before,
                after_sha=after,
                actor=pusher_email,
                repo=repo_name,
                timestamp=timestamp,
                severity=severity,
                forced=forced,
                unsigned=unsigned,
                ledger_recorded=ledger_recorded,
            )

            # Emit audit event
            self._emit_audit_event(mutation)

            logger.warning(f"Tag mutation detected: {tag_name} in {repo_name} by {pusher_email}")
            return mutation

        except Exception as e:
            logger.error(f"Failed to process webhook: {e}")
            return None

    def _emit_audit_event(self, mutation: TagMutationEvent) -> None:
        """Emit an AU-2 audit event for a detected tag mutation.

        Args:
            mutation: TagMutationEvent to log.
        """
        if not log_event or not AuditEventType or not AuditOutcome:
            logger.debug("Audit logging not available, skipping AU-2 event")
            return

        try:
            detail = (
                f"Tag '{mutation.tag_name}' "
                f"{'forced update' if mutation.forced else 'deleted'} "
                f"in {mutation.repo} by {mutation.actor}"
            )
            if mutation.unsigned:
                detail += " (UNSIGNED)"

            log_event(
                event_type=AuditEventType.SUPPLY_CHAIN_TAG_MUTATION,
                outcome=AuditOutcome.SUSPICIOUS if mutation.severity in ["CRITICAL", "HIGH"] else AuditOutcome.SUCCESS,
                actor=mutation.actor,
                resource=f"git_tag:{mutation.tag_name}",
                detail=detail,
                severity=mutation.severity.lower(),
            )
            logger.debug(f"Emitted AU-2 audit event for {mutation.tag_name}")
        except Exception as e:
            logger.warning(f"Failed to emit audit event: {e}")

    def get_recent_mutations(self, limit: int = 20) -> list[TagMutationEvent]:
        """Retrieve recent tag mutations from the ledger.

        Filters the ledger's recent events to only include entries that represent
        mutations (forced updates or deletions).

        Args:
            limit: Maximum number of mutations to return (default 20).

        Returns:
            List of TagMutationEvent objects sorted by timestamp (newest first).
        """
        try:
            recent_events = self.ledger.get_recent(limit * 2)  # Get more to filter
            mutations = []

            for event in recent_events:
                # Reconstruct as TagMutationEvent if it represents a mutation
                # (only 'updated' actions with prev_sha indicate mutations)
                if event.action == "updated" and event.prev_sha and event.prev_sha != event.commit_sha:
                    mutation = TagMutationEvent(
                        tag_name=event.tag_name,
                        before_sha=event.prev_sha,
                        after_sha=event.commit_sha,
                        actor=event.actor,
                        repo="unknown",  # Not available from ledger
                        timestamp=event.timestamp,
                        severity=self._assess_severity(
                            forced=True,
                            deleted=False,
                            tag_matches_release=self._tag_is_release(event.tag_name),
                        ),
                        forced=True,
                        unsigned=False,  # Not tracked in ledger
                        ledger_recorded=True,
                    )
                    mutations.append(mutation)

            return sorted(mutations, key=lambda m: m.timestamp, reverse=True)[:limit]
        except Exception as e:
            logger.error(f"Failed to retrieve recent mutations: {e}")
            return []


def check_tag_monitor_config() -> dict:
    """Verify tag monitor configuration and readiness.

    Returns a dict indicating ledger readiness and GitHub webhook secret
    configuration.

    Returns:
        Dict with keys:
            - ledger_ready: Boolean indicating if TagLedger is operational.
            - github_webhook_secret_set: Boolean indicating if webhook secret is configured.
    """
    # Check ledger
    ledger_config = None
    try:
        from .tag_ledger import check_ledger_config
        ledger_config = check_ledger_config()
    except Exception as e:
        logger.debug(f"Failed to check ledger config: {e}")

    ledger_ready = ledger_config.get("redis_available", False) if ledger_config else False

    # Check GitHub webhook secret
    import os
    github_secret_set = bool(os.getenv("GITHUB_WEBHOOK_SECRET"))

    return {
        "ledger_ready": ledger_ready,
        "github_webhook_secret_set": github_secret_set,
    }
