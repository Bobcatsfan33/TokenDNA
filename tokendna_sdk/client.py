"""
Thin HTTP client with an offline buffer.

Why this exists
---------------
The SDK's wedge value is that ``@identified`` *cannot fail the user's
program*. If the TokenDNA API is unreachable, decorator calls must still
return; events get buffered (memory or disk) and a later ``Client.flush``
ships them. This module isolates that property.

Note: this avoids ``requests`` (or any third-party HTTP lib) so the SDK
stays dependency-free at install time. Production users can override
``Client._do_post`` to plug in their preferred HTTP stack.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from .config import SdkConfig, current_config

logger = logging.getLogger(__name__)


@dataclass
class BufferedEvent:
    path: str
    body: dict[str, Any]
    attempts: int = 0
    last_error: str | None = None


class OfflineBufferClient:
    """Stores events in memory (and optionally on disk). flush() calls
    a delegate to actually transmit them. Pluggable so tests can capture
    flushed events directly without HTTP."""

    def __init__(self, *, path: str = "", maxlen: int = 10_000):
        self._lock = threading.Lock()
        self._buffer: deque[BufferedEvent] = deque(maxlen=maxlen)
        self.path = path
        if self.path and os.path.exists(self.path):
            self._restore()

    def _restore(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    raw = line.strip()
                    if not raw:
                        continue
                    obj = json.loads(raw)
                    self._buffer.append(BufferedEvent(
                        path=obj["path"], body=obj["body"],
                        attempts=int(obj.get("attempts", 0)),
                        last_error=obj.get("last_error"),
                    ))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("offline buffer restore failed: %s", exc)

    def _persist(self) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                for ev in self._buffer:
                    fh.write(json.dumps({
                        "path": ev.path,
                        "body": ev.body,
                        "attempts": ev.attempts,
                        "last_error": ev.last_error,
                    }) + "\n")
        except OSError as exc:
            logger.warning("offline buffer persist failed: %s", exc)

    def append(self, ev: BufferedEvent) -> None:
        with self._lock:
            self._buffer.append(ev)
            self._persist()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def drain(self) -> Iterable[BufferedEvent]:
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
            self._persist()
        return items

    def reinject(self, items: Iterable[BufferedEvent]) -> None:
        """Push back items that failed during flush, keeping the buffer
        contract: nothing is lost, transient failures retry next time."""
        with self._lock:
            for ev in items:
                self._buffer.append(ev)
            self._persist()


class Client:
    """
    Pragmatic transport. POSTs JSON to ``{api_base}{path}`` with the
    standard X-API-Key header. Network failures push the event into the
    offline buffer.
    """

    def __init__(self, *, config: SdkConfig | None = None):
        self.config = config or current_config()
        self.buffer = OfflineBufferClient(path=self.config.offline_buffer_path)

    # Tests override this to capture without real HTTP.
    def _do_post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            return getattr(resp, "status", 200)

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if not self.config.enabled:
            return {"sent": False, "buffered": False, "reason": "sdk_disabled"}
        if not self.config.is_online():
            self.buffer.append(BufferedEvent(path=path, body=body))
            return {"sent": False, "buffered": True, "reason": "offline"}
        url = f"{self.config.api_base}{path}"
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key,
        }
        try:
            status = self._do_post(url, payload, headers)
            return {"sent": True, "buffered": False, "status": int(status)}
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self.buffer.append(
                BufferedEvent(path=path, body=body, attempts=1, last_error=str(exc))
            )
            return {"sent": False, "buffered": True, "reason": str(exc)}

    def flush(self) -> dict[str, Any]:
        """Try every buffered event once. Re-buffer the failures."""
        items = list(self.buffer.drain())
        sent = 0
        failed: list[BufferedEvent] = []
        for ev in items:
            url = f"{self.config.api_base}{ev.path}"
            payload = json.dumps(ev.body, separators=(",", ":")).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": self.config.api_key,
            }
            try:
                self._do_post(url, payload, headers)
                sent += 1
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                ev.attempts += 1
                ev.last_error = str(exc)
                failed.append(ev)
        if failed:
            self.buffer.reinject(failed)
        return {"sent": sent, "buffered": len(failed)}
