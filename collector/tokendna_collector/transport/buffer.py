"""Local disk buffer for network outages.

When the connection to TokenDNA Cloud is unavailable, collected
``NormalizedEvent`` records spill to disk under
``CollectorConfig.buffer_path`` as a newline-delimited JSON file.

When the connection returns, the buffer drains in arrival order with
at-least-once delivery.  The collector tolerates duplicate events on
the cloud side (the ingestion layer dedupes by ``event_id``).

Design points:
  * One JSONL file per day, suffixed with ISO date.  Old files age out
    after ``max_age_days`` (default 7) so disk doesn't fill forever.
  * Append-only writes use ``os.O_APPEND`` for atomicity.
  * Reads stream line-by-line; nothing is loaded into memory all at once.
  * ``drain()`` deletes lines as they are successfully sent (rewritten
    to a temp file + atomic rename) so a crash mid-drain doesn't lose
    or duplicate events beyond the line boundary.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import dataclasses
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..schema import NormalizedEvent


def _serialize(event: NormalizedEvent) -> str:
    """JSON-encode a NormalizedEvent for the wire / disk."""
    d = dataclasses.asdict(event)
    # datetimes need to be strings on disk
    for k in ("timestamp", "received_at"):
        if isinstance(d.get(k), datetime):
            d[k] = d[k].isoformat()
    # enums also need string coercion (asdict gives back the enum value already
    # for str-Enum subclasses, but we coerce defensively)
    for k in ("event_category", "outcome"):
        v = d.get(k)
        if hasattr(v, "value"):
            d[k] = v.value
    return json.dumps(d, separators=(",", ":"), sort_keys=True)


def _deserialize(line: str) -> NormalizedEvent:
    """Decode one JSONL buffer line back into a NormalizedEvent."""
    raw = json.loads(line)
    data = dict(raw)
    if isinstance(data.get("timestamp"), str):
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
    if isinstance(data.get("received_at"), str):
        data["received_at"] = datetime.fromisoformat(data["received_at"])
    return NormalizedEvent(**data)


class LocalBuffer:
    """Append-only on-disk overflow buffer for the cloud transport."""

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        max_age_days: int = 7,
    ):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_age = timedelta(days=max_age_days)

    # ── Writes ──────────────────────────────────────────────────────────
    def append(self, event: NormalizedEvent) -> None:
        """O_APPEND-write one event to today's spool file."""
        line = _serialize(event) + "\n"
        target = self._spool_for(datetime.now(timezone.utc))
        # Open with O_APPEND so concurrent writers from multiple adapters
        # don't interleave at the byte level.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

    def append_many(self, events: Iterable[NormalizedEvent]) -> int:
        """Bulk write; returns count appended."""
        count = 0
        for event in events:
            self.append(event)
            count += 1
        return count

    # ── Reads + drain ───────────────────────────────────────────────────
    def iter_pending(self) -> Iterator[tuple[Path, str]]:
        """Yield (file, line) for every buffered event in arrival order.

        Caller is expected to call :meth:`drain_through` when a contiguous
        prefix of events has been successfully shipped.
        """
        for spool in sorted(self._dir.glob("events-*.jsonl")):
            with open(spool, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if line:
                        yield spool, line

    def drain_through(self, last_sent_line: str | None) -> int:
        """Remove every line up to and including ``last_sent_line`` from disk.

        Implementation: walks each spool file in order, skipping lines
        that are already-sent.  When the last_sent_line is hit, the
        remainder of that file is rewritten (atomically) and processing
        stops.  Earlier files with no more pending content are deleted.

        Returns the number of lines removed.
        """
        if last_sent_line is None:
            return 0
        removed = 0
        for spool in sorted(self._dir.glob("events-*.jsonl")):
            with open(spool, "r", encoding="utf-8") as f:
                lines = f.readlines()
            try:
                idx = lines.index(last_sent_line + "\n")
            except ValueError:
                # last_sent_line not in this file — entire file is
                # already-sent (it precedes the cursor) so delete it.
                spool.unlink(missing_ok=True)
                removed += len(lines)
                continue
            # Found cursor; rewrite remainder atomically and stop.
            removed += idx + 1
            remainder = lines[idx + 1 :]
            tmp = tempfile.NamedTemporaryFile(
                "w", delete=False, dir=str(self._dir),
                encoding="utf-8", prefix=".drain-", suffix=".tmp",
            )
            try:
                tmp.writelines(remainder)
                tmp.flush()
                os.fsync(tmp.fileno())
            finally:
                tmp.close()
            os.replace(tmp.name, spool)
            return removed
        return removed

    # ── Maintenance ─────────────────────────────────────────────────────
    def evict_old(self) -> int:
        """Delete spool files older than ``max_age_days``; returns # deleted."""
        cutoff = datetime.now(timezone.utc) - self._max_age
        deleted = 0
        for spool in self._dir.glob("events-*.jsonl"):
            try:
                date_str = spool.stem.removeprefix("events-")
                spool_date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if spool_date < cutoff:
                spool.unlink(missing_ok=True)
                deleted += 1
        return deleted

    # ── Internal ────────────────────────────────────────────────────────
    def _spool_for(self, when: datetime) -> Path:
        return self._dir / f"events-{when.date().isoformat()}.jsonl"
