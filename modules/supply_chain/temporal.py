"""
Per-actor behavioral baseline for git operation timing and anomaly detection.

This module builds behavioral profiles of developers' commit patterns,
tracking time-of-day, day-of-week, and velocity patterns. It detects
anomalies such as off-hours commits, weekend bursts, velocity spikes,
dormant account reactivation, and first-time commits from new actors.

Temporal anomalies may indicate account compromise or malicious activity.

Example:
    >>> detector = TemporalAnomalyDetector()
    >>> detector.record_commit("alice@example.com", datetime.now())
    >>> anomaly = detector.analyze("alice@example.com", datetime.now())
    >>> if anomaly and anomaly.score > 70:
    ...     print(f"Anomaly detected: {anomaly.anomaly_type}")
"""

import json
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import redis
except ImportError:
    redis = None

logger = logging.getLogger(__name__)


@dataclass
class CommitTemporalProfile:
    """Behavioral baseline for an actor's commit timing patterns.

    Attributes:
        actor: Email or identifier of the developer.
        hourly_dist: Distribution of commits by hour of day (0-23).
        dow_dist: Distribution of commits by day of week (0=Monday, 6=Sunday).
        total_commits: Total number of commits recorded for this actor.
        last_commit: ISO 8601 timestamp of the most recent commit.
        avg_daily_commits: Average number of commits per day.
    """
    actor: str
    hourly_dist: dict[int, int]
    dow_dist: dict[int, int]
    total_commits: int
    last_commit: str
    avg_daily_commits: float

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class TemporalAnomaly:
    """Detection record for an actor's commit timing anomaly.

    Attributes:
        actor: Email or identifier of the actor.
        commit_time: ISO 8601 timestamp of the anomalous commit.
        anomaly_type: Category of anomaly detected.
        score: Numeric anomaly score (0-100, higher=more anomalous).
        detail: Human-readable description of the anomaly.
    """
    actor: str
    commit_time: str
    anomaly_type: str
    score: float
    detail: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)


class TemporalAnomalyDetector:
    """Detects temporal anomalies in developer commit patterns via Redis.

    Maintains per-actor baselines for commit timing (hourly, day-of-week,
    velocity) and identifies deviations that may indicate compromise or
    malicious activity.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None) -> None:
        """Initialize the temporal anomaly detector.

        Args:
            redis_client: Optional redis.Redis instance. If not provided, attempts
                         to connect using REDIS_URL environment variable.
        """
        self.redis_client = redis_client

        if self.redis_client is None:
            try:
                redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("Connected to Redis for temporal anomaly detection")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. TemporalAnomalyDetector will operate in degraded mode.")
                self.redis_client = None

    def _profile_key(self, actor: str) -> str:
        """Generate Redis key for an actor's temporal profile."""
        return f"sc:temporal:{actor}"

    def _velocity_key(self, actor: str) -> str:
        """Generate Redis key for an actor's commit velocity tracking."""
        return f"sc:temporal:velocity:{actor}"

    def _load_profile(self, actor: str) -> Optional[CommitTemporalProfile]:
        """Load a profile from Redis."""
        if not self.redis_client:
            return None

        try:
            key = self._profile_key(actor)
            data = self.redis_client.get(key)
            if not data:
                return None

            profile_dict = json.loads(data)
            # Convert dict keys back to integers for hourly_dist and dow_dist
            profile_dict["hourly_dist"] = {int(k): v for k, v in profile_dict["hourly_dist"].items()}
            profile_dict["dow_dist"] = {int(k): v for k, v in profile_dict["dow_dist"].items()}
            return CommitTemporalProfile(**profile_dict)
        except Exception as e:
            logger.warning(f"Failed to load profile for {actor}: {e}")
            return None

    def _save_profile(self, profile: CommitTemporalProfile) -> None:
        """Save a profile to Redis."""
        if not self.redis_client:
            return

        try:
            key = self._profile_key(profile.actor)
            data = json.dumps(profile.to_dict())
            self.redis_client.set(key, data)
        except Exception as e:
            logger.error(f"Failed to save profile for {profile.actor}: {e}")

    def record_commit(self, actor: str, timestamp: datetime) -> None:
        """Record a commit and update the actor's behavioral profile.

        Updates the hourly distribution, day-of-week distribution, total count,
        last commit timestamp, and average daily rate.

        Args:
            actor: Email or identifier of the developer.
            timestamp: datetime object of when the commit was made.
        """
        if not self.redis_client:
            return

        try:
            # Load existing profile or create new one
            profile = self._load_profile(actor)
            if not profile:
                profile = CommitTemporalProfile(
                    actor=actor,
                    hourly_dist={},
                    dow_dist={},
                    total_commits=0,
                    last_commit=timestamp.isoformat(),
                    avg_daily_commits=0.0,
                )

            # Update distributions
            hour = timestamp.hour
            dow = timestamp.weekday()

            profile.hourly_dist[hour] = profile.hourly_dist.get(hour, 0) + 1
            profile.dow_dist[dow] = profile.dow_dist.get(dow, 0) + 1
            profile.total_commits += 1
            profile.last_commit = timestamp.isoformat()

            # Recalculate average daily commits
            # Estimate based on total commits and earliest activity
            if profile.total_commits > 1:
                first_commit = min(
                    datetime.fromisoformat(profile.last_commit),
                    datetime.now(timezone.utc)
                )
                days_active = (datetime.now(timezone.utc) - first_commit).days + 1
                profile.avg_daily_commits = profile.total_commits / max(days_active, 1)
            else:
                profile.avg_daily_commits = 1.0

            self._save_profile(profile)

            # Also record in velocity tracking (sorted set with timestamp score)
            velocity_key = self._velocity_key(actor)
            score = timestamp.timestamp()
            self.redis_client.zadd(velocity_key, {actor: score})

            logger.debug(f"Recorded commit for {actor}")
        except Exception as e:
            logger.error(f"Failed to record commit for {actor}: {e}")

    def _score_off_hours(self, hour: int, profile: CommitTemporalProfile) -> float:
        """Score off-hours commit anomaly.

        Returns 0 if the actor regularly commits at this hour, 80 if never,
        40 if rare (<5% of commits).

        Args:
            hour: Hour of day (0-23).
            profile: Actor's CommitTemporalProfile.

        Returns:
            Anomaly score 0-80.
        """
        if not profile.hourly_dist or profile.total_commits == 0:
            return 0.0

        commits_at_hour = profile.hourly_dist.get(hour, 0)
        pct_at_hour = commits_at_hour / profile.total_commits

        if commits_at_hour == 0:
            return 80.0
        if pct_at_hour < 0.05:
            return 40.0
        return 0.0

    def _score_velocity(self, actor: str, window_hours: int = 1) -> float:
        """Score commit velocity spike anomaly.

        Returns 0 if commits in window are ≤3/hour, 60 if >10/hour,
        90 if >25/hour.

        Args:
            actor: Developer identifier.
            window_hours: Time window to check (default 1 hour).

        Returns:
            Anomaly score 0-90.
        """
        if not self.redis_client:
            return 0.0

        try:
            velocity_key = self._velocity_key(actor)
            now = datetime.now(timezone.utc)
            cutoff = (now - timedelta(hours=window_hours)).timestamp()

            # Count commits in window
            count = self.redis_client.zcount(velocity_key, cutoff, now.timestamp())
            commits_per_hour = count / window_hours

            if commits_per_hour > 25:
                return 90.0
            if commits_per_hour > 10:
                return 60.0
            return 0.0
        except Exception as e:
            logger.debug(f"Failed to score velocity for {actor}: {e}")
            return 0.0

    def _score_dormant(self, profile: CommitTemporalProfile, now: datetime) -> float:
        """Score dormant account reactivation anomaly.

        Returns 0 if actor is active recently, 70 if no commits in >30 days,
        85 if >90 days.

        Args:
            profile: Actor's CommitTemporalProfile.
            now: Current datetime.

        Returns:
            Anomaly score 0-85.
        """
        if not profile.last_commit:
            return 0.0

        try:
            last_commit_time = datetime.fromisoformat(profile.last_commit)
            days_since = (now - last_commit_time).days

            if days_since > 90:
                return 85.0
            if days_since > 30:
                return 70.0
            return 0.0
        except Exception as e:
            logger.debug(f"Failed to score dormant status: {e}")
            return 0.0

    def analyze(self, actor: str, timestamp: datetime) -> Optional[TemporalAnomaly]:
        """Analyze a commit for temporal anomalies.

        Checks for off-hours commits, weekend bursts, velocity spikes,
        dormant account reactivation, and first-seen actors.

        Args:
            actor: Developer identifier.
            timestamp: datetime of the commit.

        Returns:
            TemporalAnomaly if an anomaly is detected, None otherwise.
        """
        profile = self._load_profile(actor)

        # First-seen actor
        if not profile:
            anomaly = TemporalAnomaly(
                actor=actor,
                commit_time=timestamp.isoformat(),
                anomaly_type="first_seen",
                score=25.0,
                detail=f"First commit recorded for actor {actor}",
            )
            logger.info(f"First-seen actor: {actor}")
            return anomaly

        # Off-hours check
        off_hours_score = self._score_off_hours(timestamp.hour, profile)
        if off_hours_score >= 40:
            hour_name = "midnight-6am" if timestamp.hour < 6 else f"{timestamp.hour}:00"
            anomaly = TemporalAnomaly(
                actor=actor,
                commit_time=timestamp.isoformat(),
                anomaly_type="off_hours",
                score=off_hours_score,
                detail=f"Commit at unusual hour ({hour_name}). Actor typically commits 9-17.",
            )
            logger.warning(f"Off-hours anomaly for {actor}: {anomaly.detail}")
            return anomaly

        # Velocity spike check
        velocity_score = self._score_velocity(actor, window_hours=1)
        if velocity_score >= 60:
            anomaly = TemporalAnomaly(
                actor=actor,
                commit_time=timestamp.isoformat(),
                anomaly_type="velocity_spike",
                score=velocity_score,
                detail=f"Unusually high commit rate (>10 commits/hour). Normal: {profile.avg_daily_commits:.1f}/day",
            )
            logger.warning(f"Velocity spike for {actor}: {anomaly.detail}")
            return anomaly

        # Dormant reactivation check
        dormant_score = self._score_dormant(profile, timestamp)
        if dormant_score >= 70:
            days = (timestamp - datetime.fromisoformat(profile.last_commit)).days
            anomaly = TemporalAnomaly(
                actor=actor,
                commit_time=timestamp.isoformat(),
                anomaly_type="dormant_resurface",
                score=dormant_score,
                detail=f"Account reactivation after {days} days of inactivity",
            )
            logger.warning(f"Dormant resurface for {actor}: {anomaly.detail}")
            return anomaly

        # Weekend burst check
        if timestamp.weekday() >= 5:  # Saturday or Sunday
            weekend_commits = profile.dow_dist.get(timestamp.weekday(), 0)
            if weekend_commits == 0 and profile.total_commits > 20:
                anomaly = TemporalAnomaly(
                    actor=actor,
                    commit_time=timestamp.isoformat(),
                    anomaly_type="weekend_burst",
                    score=45.0,
                    detail=f"Weekend commit from typically weekday-only actor",
                )
                logger.warning(f"Weekend burst for {actor}")
                return anomaly

        # No anomalies detected
        return None

    def get_profile(self, actor: str) -> Optional[CommitTemporalProfile]:
        """Retrieve the temporal profile for an actor.

        Args:
            actor: Developer identifier.

        Returns:
            CommitTemporalProfile if found, None otherwise.
        """
        return self._load_profile(actor)


def check_temporal_config() -> dict:
    """Verify temporal anomaly detector configuration.

    Returns a dict indicating Redis connectivity for temporal tracking.

    Returns:
        Dict with key:
            - redis_available: Boolean indicating if Redis is reachable.
    """
    redis_available = False

    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        redis_available = True
    except Exception as e:
        logger.debug(f"Redis check failed: {e}")

    return {
        "redis_available": redis_available,
    }
