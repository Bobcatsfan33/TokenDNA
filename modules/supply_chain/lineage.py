"""
TokenDNA Lineage Tracker Module

Fork lineage tracking and suspicious origin detection.
Records commit ancestry across repositories, detects commits from suspicious
fork origins (new forks, zero-contribution accounts), and flags merges from
untrusted lineage into protected branches.

This module provides fork origin analysis and contribution history tracking
for supply chain defense.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timedelta

try:
    import redis
except ImportError:
    redis = None  # Optional dependency


logger = logging.getLogger(__name__)


@dataclass
class ForkOrigin:
    """
    Represents the origin and metadata of a repository fork.

    Attributes:
        repo: Fork repository identifier (owner/repo).
        fork_age_days: Age of fork in days; None if unknown.
        prior_contributions: Number of prior contributions by fork creator.
        created_by: Username of fork creator.
        suspicious: Whether fork origin is marked as suspicious.
        reason: Explanation for suspicious classification.
    """

    repo: str
    fork_age_days: Optional[int]
    prior_contributions: int
    created_by: str
    suspicious: bool
    reason: str


@dataclass
class CommitLineage:
    """
    Complete lineage analysis for a single commit.

    Attributes:
        commit_sha: The commit SHA-1 hash.
        repo: Repository identifier.
        actor: The committer's username.
        parent_shas: List of parent commit SHA hashes.
        fork_origin: ForkOrigin data if commit originated from fork; None otherwise.
        lineage_score: Trust score from 0-100 (higher = more trustworthy).
        is_merge: Whether this is a merge commit.
        merge_from_fork: Whether merge originated from untrusted fork.
        suspicious: Whether lineage is suspicious.
        detail: Human-readable description of lineage analysis.
    """

    commit_sha: str
    repo: str
    actor: str
    parent_shas: list[str]
    fork_origin: Optional[ForkOrigin]
    lineage_score: float
    is_merge: bool
    merge_from_fork: bool
    suspicious: bool
    detail: str


class LineageTracker:
    """
    Tracks repository fork lineage and commit ancestry.

    Maintains metadata about forks, contribution history, and detects
    suspicious patterns indicating compromise via new forks or untrusted
    accounts.

    Attributes:
        redis_client: Optional Redis client for persistent storage.

    Example:
        >>> tracker = LineageTracker()
        >>> tracker.record_fork("evil/repo", "original/repo", "attacker", fork_age_days=1)
        >>> lineage = tracker.analyze_commit(
        ...     "abc123", "evil/repo", "attacker",
        ...     ["def456"], source_fork="evil/repo"
        ... )
        >>> print(f"Suspicious: {lineage.suspicious}")
    """

    REDIS_PREFIX = "sc:lineage"

    def __init__(self, redis_client: Optional[object] = None) -> None:
        """
        Initialize the LineageTracker.

        Args:
            redis_client: Optional Redis client instance for persistence.
                         If None, uses in-memory storage (not persistent).
        """
        self.redis_client = redis_client
        self._in_memory_forks = {}  # {fork_repo: ForkOrigin data}
        self._in_memory_contributions = {}  # {(actor, repo): count}
        self._in_memory_commits = {}  # {repo: [commit_shas]}

        logger.info(f"LineageTracker initialized with redis={'Yes' if redis_client else 'No (in-memory)'}")

    def record_fork(
        self,
        fork_repo: str,
        parent_repo: str,
        created_by: str,
        fork_age_days: int = 0,
    ) -> None:
        """
        Record metadata for a newly discovered fork.

        Stores fork creation date, creator, and parent relationship for
        later analysis of commits from the fork.

        Args:
            fork_repo: The fork repository identifier (owner/repo).
            parent_repo: The parent/upstream repository identifier.
            created_by: Username of the account that created the fork.
            fork_age_days: Age of fork in days (default: 0 for newly discovered).

        Returns:
            None
        """
        try:
            fork_key = f"{self.REDIS_PREFIX}:forks:{fork_repo}"

            fork_data = {
                "parent_repo": parent_repo,
                "created_by": created_by,
                "fork_age_days": str(fork_age_days),
                "first_seen": datetime.utcnow().isoformat(),
            }

            if self.redis_client:
                try:
                    self.redis_client.hset(fork_key, mapping=fork_data)
                except Exception as e:
                    logger.warning(f"Redis fork storage failed: {e}, using in-memory fallback")
                    self._in_memory_forks[fork_repo] = fork_data
            else:
                self._in_memory_forks[fork_repo] = fork_data

            logger.info(f"Recorded fork {fork_repo} from {parent_repo} by {created_by}")

        except Exception as e:
            logger.error(f"Error recording fork {fork_repo}: {e}")
            raise

    def record_contribution(self, actor: str, repo: str) -> None:
        """
        Increment contribution counter for an actor in a repository.

        Tracks the historical contribution count to identify new/unknown
        contributors vs. established developers.

        Args:
            actor: The contributor's username/email.
            repo: Repository identifier.

        Returns:
            None
        """
        try:
            contrib_key = f"{self.REDIS_PREFIX}:contributions:{actor}:{repo}"

            if self.redis_client:
                try:
                    self.redis_client.incr(contrib_key)
                except Exception as e:
                    logger.warning(f"Redis contribution tracking failed: {e}, using in-memory fallback")
                    key = (actor, repo)
                    self._in_memory_contributions[key] = self._in_memory_contributions.get(key, 0) + 1
            else:
                key = (actor, repo)
                self._in_memory_contributions[key] = self._in_memory_contributions.get(key, 0) + 1

        except Exception as e:
            logger.error(f"Error recording contribution {actor}/{repo}: {e}")

    def analyze_commit(
        self,
        commit_sha: str,
        repo: str,
        actor: str,
        parent_shas: list[str],
        branch: str = "main",
        source_fork: Optional[str] = None,
    ) -> CommitLineage:
        """
        Perform lineage analysis on a commit.

        Determines fork origin, contribution history, and suspicious patterns
        indicating compromise via untrusted fork or account.

        Args:
            commit_sha: The commit SHA-1 hash.
            repo: Repository identifier where commit was pushed.
            actor: Committer username.
            parent_shas: List of parent commit SHA hashes.
            branch: Target branch (default: "main").
            source_fork: Optional fork repository the commit originated from.

        Returns:
            CommitLineage object with detailed analysis and suspicious flag.
        """
        try:
            is_merge = len(parent_shas) > 1
            fork_origin = None
            merge_from_fork = False

            # Check if commit originated from suspicious fork
            if source_fork:
                fork_origin = self._get_fork_metadata(source_fork)
                if fork_origin:
                    fork_is_suspicious, reason = self._is_suspicious_fork(fork_origin)
                    if fork_is_suspicious:
                        merge_from_fork = True

            # Score the lineage
            lineage_score = self._score_lineage(fork_origin, actor, repo)

            # Determine if suspicious
            suspicious = False
            detail_parts = []

            if fork_origin and fork_origin.suspicious:
                suspicious = True
                detail_parts.append(f"Fork origin suspicious: {fork_origin.reason}")

            if merge_from_fork and branch in ["main", "master", "production"]:
                suspicious = True
                detail_parts.append(f"Merge from untrusted fork into protected branch: {branch}")

            if not detail_parts:
                detail_parts.append(f"Lineage score: {lineage_score:.0f}")

            detail = "; ".join(detail_parts) if detail_parts else "Lineage clean"

            lineage = CommitLineage(
                commit_sha=commit_sha,
                repo=repo,
                actor=actor,
                parent_shas=parent_shas,
                fork_origin=fork_origin,
                lineage_score=lineage_score,
                is_merge=is_merge,
                merge_from_fork=merge_from_fork,
                suspicious=suspicious,
                detail=detail,
            )

            logger.info(
                f"Commit {commit_sha} lineage: score={lineage_score:.0f}, "
                f"suspicious={suspicious}, from_fork={merge_from_fork}"
            )
            return lineage

        except Exception as e:
            logger.error(f"Error analyzing lineage for {commit_sha}: {e}")
            raise

    def _get_fork_metadata(self, fork_repo: str) -> Optional[ForkOrigin]:
        """
        Retrieve fork metadata from storage.

        Args:
            fork_repo: Fork repository identifier.

        Returns:
            ForkOrigin object if found; None otherwise.
        """
        try:
            fork_key = f"{self.REDIS_PREFIX}:forks:{fork_repo}"

            if self.redis_client:
                try:
                    data = self.redis_client.hgetall(fork_key)
                    if data:
                        return ForkOrigin(
                            repo=fork_repo,
                            fork_age_days=int(data.get(b"fork_age_days", b"0").decode()),
                            prior_contributions=self.get_contributor_score(
                                data.get(b"created_by", b"unknown").decode(), fork_repo
                            ),
                            created_by=data.get(b"created_by", b"unknown").decode(),
                            suspicious=False,
                            reason="",
                        )
                except Exception as e:
                    logger.warning(f"Redis fork retrieval failed: {e}")
                    return self._in_memory_forks.get(fork_repo)
            else:
                return self._in_memory_forks.get(fork_repo)

        except Exception as e:
            logger.error(f"Error retrieving fork metadata for {fork_repo}: {e}")

        return None

    def _is_suspicious_fork(self, fork_origin: ForkOrigin) -> tuple[bool, str]:
        """
        Determine if a fork origin is suspicious.

        Heuristics:
        - Fork < 2 days old AND zero prior contributions: HIGHLY suspicious
        - Fork < 7 days old: suspicious
        - Creator has < 3 prior contributions: moderately suspicious
        - Established fork with contributing account: trusted

        Args:
            fork_origin: ForkOrigin object to evaluate.

        Returns:
            Tuple of (is_suspicious, reason_string).
        """
        if fork_origin.fork_age_days is None:
            return False, "fork age unknown"

        if fork_origin.fork_age_days < 2 and fork_origin.prior_contributions == 0:
            return True, "brand-new fork with zero-contribution account"

        if fork_origin.fork_age_days < 7:
            return True, f"very new fork ({fork_origin.fork_age_days} days old)"

        if fork_origin.prior_contributions < 3:
            return True, f"fork creator has minimal history ({fork_origin.prior_contributions} contributions)"

        return False, "fork established with contributing account"

    def _score_fork_origin(self, fork: ForkOrigin) -> float:
        """
        Compute trust score for a fork origin.

        Scoring:
        - 90: Brand-new fork (<2 days) + zero contributions
        - 70: New fork (<7 days)
        - 50: Actor with <3 contributions
        - 20: Established fork (>7 days)
        - 0: Native (no fork)

        Args:
            fork: ForkOrigin object to score.

        Returns:
            Trust score from 0-100 (0 = most suspicious, 100 = most trusted).
        """
        if fork.fork_age_days is None:
            return 50  # Unknown

        if fork.fork_age_days < 2 and fork.prior_contributions == 0:
            return 10  # Highly suspicious

        if fork.fork_age_days < 7:
            return 30  # Suspicious

        if fork.prior_contributions < 3:
            return 50  # Moderately suspicious

        return 75  # Established fork

    def _score_lineage(self, fork_origin: Optional[ForkOrigin], actor: str, repo: str) -> float:
        """
        Compute overall lineage trust score.

        Combines fork origin score with contributor history.

        Args:
            fork_origin: Optional ForkOrigin object.
            actor: Committer username.
            repo: Repository identifier.

        Returns:
            Lineage score from 0-100 (higher = more trustworthy).
        """
        if fork_origin is None:
            # Native repository; score based on actor history
            contributions = self.get_contributor_score(actor, repo)
            if contributions == 0:
                return 60  # Unknown contributor
            elif contributions < 5:
                return 70  # New contributor
            else:
                return 90  # Established contributor
        else:
            # Forked repository
            fork_score = self._score_fork_origin(fork_origin)
            contrib_score = min(100, fork_origin.prior_contributions * 20)
            return (fork_score + contrib_score) / 2

    def get_fork_history(self, repo: str) -> list[dict]:
        """
        Retrieve recent fork events for a repository.

        Args:
            repo: Repository identifier.

        Returns:
            List of fork event dictionaries with metadata.
        """
        try:
            fork_key = f"{self.REDIS_PREFIX}:forks:{repo}"

            if self.redis_client:
                try:
                    data = self.redis_client.hgetall(fork_key)
                    if data:
                        return [
                            {
                                "fork": repo,
                                "parent": data.get(b"parent_repo", b"unknown").decode(),
                                "created_by": data.get(b"created_by", b"unknown").decode(),
                                "first_seen": data.get(b"first_seen", b"").decode(),
                            }
                        ]
                except Exception as e:
                    logger.warning(f"Redis fork history retrieval failed: {e}")
            else:
                if repo in self._in_memory_forks:
                    return [
                        {
                            "fork": repo,
                            "parent": self._in_memory_forks[repo].get("parent_repo", "unknown"),
                            "created_by": self._in_memory_forks[repo].get("created_by", "unknown"),
                            "first_seen": self._in_memory_forks[repo].get("first_seen", ""),
                        }
                    ]

        except Exception as e:
            logger.error(f"Error retrieving fork history for {repo}: {e}")

        return []

    def get_contributor_score(self, actor: str, repo: str) -> int:
        """
        Retrieve prior contribution count for an actor in a repository.

        Returns 0 for unknown/new contributors.

        Args:
            actor: Contributor username.
            repo: Repository identifier.

        Returns:
            Count of prior contributions (0 = unknown or new).
        """
        try:
            contrib_key = f"{self.REDIS_PREFIX}:contributions:{actor}:{repo}"

            if self.redis_client:
                try:
                    count = self.redis_client.get(contrib_key)
                    return int(count) if count else 0
                except Exception as e:
                    logger.warning(f"Redis contribution retrieval failed: {e}")
                    return self._in_memory_contributions.get((actor, repo), 0)
            else:
                return self._in_memory_contributions.get((actor, repo), 0)

        except Exception as e:
            logger.error(f"Error retrieving contributor score for {actor}/{repo}: {e}")
            return 0


def check_lineage_config() -> dict:
    """
    Verify LineageTracker configuration and Redis availability.

    Returns:
        Configuration dictionary with Redis availability status.
    """
    try:
        redis_available = False

        if redis:
            try:
                test_client = redis.Redis(host="localhost", port=6379, socket_connect_timeout=2, decode_responses=True)
                test_client.ping()
                redis_available = True
            except Exception:
                redis_available = False

        return {
            "redis_available": redis_available,
        }

    except Exception as e:
        logger.error(f"LineageTracker configuration check failed: {e}")
        return {
            "redis_available": False,
            "error": str(e),
        }
