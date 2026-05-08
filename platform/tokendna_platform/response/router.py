"""Response router — finding → action dispatch in enforce mode.

The router is the *only* place enforce-mode response actions fire.
Each `ResponseRule` is a (predicate, action-name-list) pair.  When a
finding matches, the listed actions are executed in registration order
and their `ResponseOutcome` records are returned to the caller for
audit logging.

Detect-mode customers never construct a `ResponseRouter`.  Enforce-
mode customers register actions explicitly so the audit trail is
unambiguous about which rules can take which steps.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable

from ..findings import Finding
from .actions import ResponseAction, ResponseOutcome

logger = logging.getLogger("tokendna_platform.response")


@dataclass
class ResponseRule:
    name: str
    predicate: Callable[[Finding], bool]
    actions: tuple[str, ...]


class ResponseRouter:
    """Match findings against rules → execute actions in registration order."""

    def __init__(self) -> None:
        self._rules: list[ResponseRule] = []
        self._actions: dict[str, ResponseAction] = {}
        self._lock = threading.Lock()

    def register_action(self, action: ResponseAction) -> None:
        with self._lock:
            self._actions[action.name] = action

    def add_rule(self, rule: ResponseRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def dispatch(self, finding: Finding) -> list[ResponseOutcome]:
        outcomes: list[ResponseOutcome] = []
        with self._lock:
            rules_snapshot = list(self._rules)
            actions_snapshot = dict(self._actions)
        for rule in rules_snapshot:
            try:
                if not rule.predicate(finding):
                    continue
            except Exception:
                logger.exception("response rule %r predicate raised", rule.name)
                continue
            for action_name in rule.actions:
                action = actions_snapshot.get(action_name)
                if action is None:
                    outcomes.append(ResponseOutcome(
                        action_name=action_name,
                        finding_id=finding.finding_id,
                        succeeded=False,
                        detail="action not registered",
                    ))
                    continue
                try:
                    outcomes.append(action.execute(finding))
                except Exception as exc:
                    logger.exception(
                        "response action %r raised on %s",
                        action_name, finding.finding_id,
                    )
                    outcomes.append(ResponseOutcome(
                        action_name=action_name,
                        finding_id=finding.finding_id,
                        succeeded=False,
                        detail=f"action raised: {exc}",
                    ))
        return outcomes
