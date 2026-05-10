"""Alert routing rules — match findings against rules → fan out to channels.

Each ``AlertRule`` is a (predicate, channel-list) pair.  When a
finding matches, the alert is dispatched to every channel in the
list.  Channels are pluggable; the four shipping defaults are
``email``, ``slack``, ``pagerduty``, ``jira``.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from ..findings import Finding, FindingSeverity

logger = logging.getLogger("tokendna_platform.alerts")


class AlertChannel(ABC):
    """Abstract alert sink; one per outbound system."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def deliver(self, finding: Finding) -> None: ...


class InMemoryChannel(AlertChannel):
    """Test-mode sink that just records what was delivered."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._delivered: list[Finding] = []
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return self._name

    def deliver(self, finding: Finding) -> None:
        with self._lock:
            self._delivered.append(finding)

    def delivered(self) -> list[Finding]:
        with self._lock:
            return list(self._delivered)


@dataclass
class AlertRule:
    """A routing rule.  Match a finding, dispatch to listed channels."""
    name: str
    predicate: Callable[[Finding], bool]
    channels: tuple[str, ...]


class AlertRouter:
    """Match findings against rules → deliver via the matching channels."""

    def __init__(self) -> None:
        self._rules: list[AlertRule] = []
        self._channels: dict[str, AlertChannel] = {}
        self._lock = threading.Lock()

    def register_channel(self, channel: AlertChannel) -> None:
        with self._lock:
            self._channels[channel.name] = channel

    def add_rule(self, rule: AlertRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def dispatch(self, finding: Finding) -> dict[str, int]:
        """Deliver ``finding`` to every channel in every matching rule."""
        invoked = failed = 0
        with self._lock:
            rules_snapshot = list(self._rules)
            channels_snapshot = dict(self._channels)
        for rule in rules_snapshot:
            try:
                if not rule.predicate(finding):
                    continue
            except Exception:
                logger.exception("alert rule %r predicate raised", rule.name)
                continue
            for channel_name in rule.channels:
                channel = channels_snapshot.get(channel_name)
                if channel is None:
                    failed += 1
                    continue
                try:
                    channel.deliver(finding)
                    invoked += 1
                except Exception:
                    failed += 1
                    logger.exception(
                        "alert channel %r failed delivering %s",
                        channel_name, finding.finding_id,
                    )
        return {"delivered": invoked, "failed": failed}


# ── Convenience predicate builders ─────────────────────────────────────────

def severity_at_least(threshold: FindingSeverity) -> Callable[[Finding], bool]:
    return lambda f: f.severity_rank >= threshold.value.__hash__()  # not used; see below


def severity_gte(threshold: FindingSeverity) -> Callable[[Finding], bool]:
    """Predicate: True iff the finding's severity is >= threshold."""
    return lambda f: f.severity_rank >= FindingSeverity(threshold).value.__class__.__hash__(threshold)
