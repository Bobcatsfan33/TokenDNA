"""
Immutable append-only ledger for git tag events with HMAC-SHA256 chaining.

This module implements a tamper-evident ledger that records all git tag operations
(creation, update, deletion) with cryptographic haining. Each entry is HMAC-SHA256
chained to its predecessor, making tampering detectable through chain verification.

The ledger is Redis-backed for persistence and supports efficient querying of tag
histories and recent events across all tags.

Example:
    >>> ledger = TagLedger()
    >>> event = ledger.record("v1.0.0", "abc123def456...", "alice@example.com", action="created")
    >>> history = ledger.get_history("v1.0.0")
    >>> if ledger.detect_mutation("v1.0.0", "def789..."):
    ...     print("Tag was mutated!")
    >>> ledger.verify_chain("v1.0.0")  # True if chain is intact
"""

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

try:
    import redis
except ImportError:
    redis = None

logger = logging.getLogger(__name__)


@dataclass
class TagEvent:
    """Immutable record of a git tag operation with cryptographic hash chain.

    Attributes:
        tag_name: Name of the git tag (e.g., "v1.0.0").
        commit_sha: Full commit SHA that the tag points to.
        prev_sha: Previous commit SHA that the tag pointed to (None for creation).
        actor: Email or identifier of the person who performed the action.
        timestamp: ISO 8601 timestamp in UTC when the event occurred.
        action: Type of operation: "created", "updated", or "deleted".
        entry_hash: HMAC-SHA256 hash of this entry, chained from previous hash.
        prev_entry_hash: HMAC-SHA256 hash of the previous entry (None for first entry).
    """
    tag_name: str
    commit_sha: str
    prev_sha: Optional[str]
    actor: str
    timestamp: str
    action: str
    entry_hash: str
    prev_entry_hash: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


class TagLedger:
    """Redis-backed immutable ledger for git tag events with HMAC-SHA256 chaining.

    Provides tamper-evident recording of tag mutations with chain verification
    and anomaly detection capabilities.
    """

    # Redis key prefixes
    TAG_LEDGER_KEY = "sc:tag_ledger"
    TAG_LEDGER_ALL_KEY = "sc:tag_ledger:all"

    def __init__(self, redis_client: Optional[redis.Redis] = None) -> None:
        """Initialize the tag ledger with optional Redis client.

        Args:
            redis_client: Optional redis.Redis instance. If not provided, attempts
                         to connect using REDIS_URL environment variable.

        Raises:
            No exceptions; Redis unavailability is non-fatal and logged.
        """
        self.redis_client = redis_client
        self.hmac_key = os.getenv("SC_LEDGER_HMAC_KEY", "dev-ledger-key-change-in-prod").encode()

        if self.redis_client is None:
            try:
                redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("Connected to Redis for tag ledger")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. TagLedger will operate in degraded mode.")
                self.redis_client = None

    def _compute_hash(self, event_data: dict, prev_hash: Optional[str] = None) -> str:
        """Compute HMAC-SHA256 hash for a ledger entry.

        The hash includes all event data plus the previous hash (if any), creating
        a cryptographic chain. This makes it impossible to tamper with history
        without detection.

        Args:
            event_data: Dictionary containing tag_name, commit_sha, prev_sha, actor,
                       timestamp, and action.
            prev_hash: Previous entry's hash (None for first entry).

        Returns:
            Hex-encoded HMAC-SHA256 hash string.
        """
        data = json.dumps(event_data, sort_keys=True)
        if prev_hash:
            data = f"{data}|{prev_hash}"

        h = hmac.new(self.hmac_key, data.encode(), hashlib.sha256)
        return h.hexdigest()

    def record(
        self,
        tag_name: str,
        commit_sha: str,
        actor: str,
        action: str = "updated",
        prev_sha: Optional[str] = None,
    ) -> TagEvent:
        """Record a tag event in the ledger with cryptographic chaining.

        This method creates an immutable record of a tag operation and stores it
        in Redis. The entry is chained to the previous entry via HMAC hash.

        Args:
            tag_name: Name of the git tag.
            commit_sha: Full commit SHA the tag points to.
            actor: Email or identifier of who made the change.
            action: Operation type ("created", "updated", or "deleted").
            prev_sha: Previous commit SHA the tag pointed to (for updates).

        Returns:
            TagEvent object with computed hash and chain references.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Get previous entry to link to
        prev_event = None
        prev_entry_hash = None
        try:
            if self.redis_client:
                prev_events = self._get_tag_events(tag_name)
                if prev_events:
                    prev_event = prev_events[-1]  # Most recent
                    prev_entry_hash = prev_event.entry_hash
        except Exception as e:
            logger.warning(f"Failed to retrieve previous entry for {tag_name}: {e}")

        # Compute hash for this entry
        event_data = {
            "tag_name": tag_name,
            "commit_sha": commit_sha,
            "prev_sha": prev_sha,
            "actor": actor,
            "timestamp": timestamp,
            "action": action,
        }
        entry_hash = self._compute_hash(event_data, prev_entry_hash)

        # Create the event
        event = TagEvent(
            tag_name=tag_name,
            commit_sha=commit_sha,
            prev_sha=prev_sha,
            actor=actor,
            timestamp=timestamp,
            action=action,
            entry_hash=entry_hash,
            prev_entry_hash=prev_entry_hash,
        )

        # Store in Redis
        try:
            if self.redis_client:
                # Append to tag-specific list
                key = f"{self.TAG_LEDGER_KEY}:{tag_name}"
                self.redis_client.rpush(key, json.dumps(event.to_dict()))

                # Add to sorted set for quick "recent" queries (score = timestamp epoch)
                epoch = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                self.redis_client.zadd(self.TAG_LEDGER_ALL_KEY, {f"{tag_name}#{entry_hash}": epoch})

                logger.info(f"Recorded tag event: {tag_name} {action} by {actor}")
        except Exception as e:
            logger.error(f"Failed to store tag event in Redis: {e}")

        return event

    def _get_tag_events(self, tag_name: str) -> list[TagEvent]:
        """Retrieve all stored events for a tag from Redis (internal helper)."""
        if not self.redis_client:
            return []

        key = f"{self.TAG_LEDGER_KEY}:{tag_name}"
        try:
            raw_events = self.redis_client.lrange(key, 0, -1)
            return [TagEvent(**json.loads(e)) for e in raw_events]
        except Exception as e:
            logger.warning(f"Failed to retrieve events for {tag_name}: {e}")
            return []

    def get_history(self, tag_name: str) -> list[TagEvent]:
        """Retrieve the complete mutation history for a tag.

        Returns all recorded events for the tag in chronological order, from
        creation through all subsequent mutations.

        Args:
            tag_name: Name of the git tag.

        Returns:
            List of TagEvent objects in chronological order, empty if no history.
        """
        return self._get_tag_events(tag_name)

    def get_recent(self, limit: int = 50) -> list[TagEvent]:
        """Retrieve the most recent tag events across all tags.

        Args:
            limit: Maximum number of events to return (default 50).

        Returns:
            List of TagEvent objects sorted by timestamp (newest first).
        """
        if not self.redis_client:
            return []

        try:
            # Get from sorted set (highest scores = newest)
            recent_keys = self.redis_client.zrevrange(self.TAG_LEDGER_ALL_KEY, 0, limit - 1)
            events = []

            for key_str in recent_keys:
                # Key format is "tag_name#entry_hash"
                tag_name = key_str.split("#")[0]
                tag_events = self._get_tag_events(tag_name)
                if tag_events:
                    events.append(tag_events[-1])  # Most recent event for this tag

            return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]
        except Exception as e:
            logger.warning(f"Failed to retrieve recent events: {e}")
            return []

    def detect_mutation(self, tag_name: str, current_sha: str) -> Optional[TagEvent]:
        """Detect if a tag has been mutated by comparing current SHA to ledger.

        Returns the last recorded event if the current commit SHA differs from
        what was previously recorded, indicating the tag was forcefully updated.

        Args:
            tag_name: Name of the git tag to check.
            current_sha: Current commit SHA that the tag points to.

        Returns:
            TagEvent of the last known state if mutation detected, None if consistent.
        """
        history = self.get_history(tag_name)
        if not history:
            logger.debug(f"No history found for {tag_name}, cannot detect mutation")
            return None

        last_event = history[-1]
        if last_event.commit_sha != current_sha:
            logger.warning(f"Tag mutation detected: {tag_name} changed from {last_event.commit_sha} to {current_sha}")
            return last_event

        return None

    def verify_chain(self, tag_name: str) -> bool:
        """Verify the integrity of the hash chain for a tag.

        Recomputes all hashes in the chain and verifies they match stored values.
        Returns False if any tampering is detected.

        Args:
            tag_name: Name of the git tag to verify.

        Returns:
            True if chain is valid, False if tampering detected or verification failed.
        """
        events = self.get_history(tag_name)
        if not events:
            return True  # No history to verify

        prev_hash = None
        for event in events:
            event_data = {
                "tag_name": event.tag_name,
                "commit_sha": event.commit_sha,
                "prev_sha": event.prev_sha,
                "actor": event.actor,
                "timestamp": event.timestamp,
                "action": event.action,
            }

            computed_hash = self._compute_hash(event_data, prev_hash)
            if computed_hash != event.entry_hash:
                logger.error(f"Chain verification failed for {tag_name}: hash mismatch at {event.timestamp}")
                return False

            prev_hash = event.entry_hash

        logger.info(f"Chain verification passed for {tag_name}")
        return True


def check_ledger_config() -> dict:
    """Verify tag ledger configuration and availability.

    Returns a dict indicating Redis connectivity, HMAC key configuration,
    and total number of ledger entries.

    Returns:
        Dict with keys:
            - redis_available: Boolean indicating if Redis is reachable.
            - hmac_key_set: Boolean indicating if SC_LEDGER_HMAC_KEY is customized.
            - ledger_entries_total: Integer count of total ledger entries across all tags.
    """
    redis_available = False
    ledger_entries_total = 0

    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        redis_available = True

        # Count entries in all tag ledgers
        keys = client.keys(f"{TagLedger.TAG_LEDGER_KEY}:*")
        for key in keys:
            ledger_entries_total += client.llen(key)
    except Exception as e:
        logger.debug(f"Redis check failed: {e}")

    hmac_key_set = os.getenv("SC_LEDGER_HMAC_KEY") is not None and \
                   os.getenv("SC_LEDGER_HMAC_KEY") != "dev-ledger-key-change-in-prod"

    return {
        "redis_available": redis_available,
        "hmac_key_set": hmac_key_set,
        "ledger_entries_total": ledger_entries_total,
    }
