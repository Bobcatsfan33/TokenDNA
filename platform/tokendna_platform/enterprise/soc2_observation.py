"""SOC 2 Type II observation-window evidence collector.

Type II reports certify that a control operated *over time* — not
just that it existed at a point in time.  The audit firm requires a
continuous evidence log proving the controls described in the SOC 2
description ran throughout the observation window (typically 6-12
months).

This module is the in-platform write-side of that evidence log.  It
records every operationally-relevant event (control activation,
finding generation, response action firing, configuration change)
into a hash-chained log so an auditor can verify integrity by
re-computing the chain.

The read-side (auditor export, evidence packaging) lands when the
existing ``modules/identity/compliance.py`` migrates here per the
disposition map.
"""
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 TokenDNA Inc.

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SOC2ObservationWindow:
    """Defines the audit's observation period."""
    tenant_id: str
    start: datetime
    end: datetime
    auditor: str       # firm name as it appears on the engagement letter

    @property
    def is_open(self) -> bool:
        return self.start <= datetime.now(timezone.utc) <= self.end


@dataclass(frozen=True)
class SOC2LogEntry:
    """One hash-chained record."""
    sequence: int
    timestamp: datetime
    control_id: str        # SOC 2 trust criterion: "CC6.1", "CC7.2", ...
    event_type: str        # "control_activated", "finding_generated", ...
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str


def _digest(seq: int, ts: datetime, control_id: str, event_type: str,
            payload: dict[str, Any], prev: str) -> str:
    canonical = json.dumps({
        "sequence":     seq,
        "timestamp":    ts.isoformat(),
        "control_id":   control_id,
        "event_type":   event_type,
        "payload":      payload,
        "previous_hash": prev,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class SOC2ObservationLog:
    """Append-only hash-chained log."""

    GENESIS_HASH = "0" * 64

    def __init__(self, window: SOC2ObservationWindow) -> None:
        self._window = window
        self._entries: list[SOC2LogEntry] = []
        self._lock = threading.Lock()

    @property
    def window(self) -> SOC2ObservationWindow:
        return self._window

    def record(
        self,
        *,
        control_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> SOC2LogEntry:
        ts = datetime.now(timezone.utc)
        body = dict(payload or {})
        with self._lock:
            seq = len(self._entries) + 1
            prev = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
            entry_hash = _digest(seq, ts, control_id, event_type, body, prev)
            entry = SOC2LogEntry(
                sequence=seq, timestamp=ts,
                control_id=control_id, event_type=event_type,
                payload=body, previous_hash=prev, entry_hash=entry_hash,
            )
            self._entries.append(entry)
            return entry

    def verify(self) -> bool:
        """Re-compute the chain; returns True iff every link is intact."""
        with self._lock:
            entries = list(self._entries)
        prev = self.GENESIS_HASH
        for e in entries:
            expected = _digest(e.sequence, e.timestamp, e.control_id,
                               e.event_type, e.payload, prev)
            if expected != e.entry_hash or e.previous_hash != prev:
                return False
            prev = e.entry_hash
        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def export(self) -> list[dict[str, Any]]:
        """Auditor export — JSON-safe representation of the chain."""
        with self._lock:
            return [
                {**asdict(e), "timestamp": e.timestamp.isoformat()}
                for e in self._entries
            ]
