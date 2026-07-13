"""
Buffered event emitter.

This module sits between framework adapters (``integrations/langchain.py``
etc.) and the transport (:class:`tokendna_sdk.client.TokenDNAClient` or
:class:`tokendna_sdk.local.TokenDNALocalClient`). The wedge contract —
"never block the user, never raise" — lives here.

Mechanism
---------
- Events go onto an in-memory ``deque`` immediately. The caller returns
  in microseconds.
- A daemon thread wakes on a ~1 s tick or whenever the queue hits 50
  events, drains the queue, and ships the batch via the configured
  client. Failures get re-buffered on the client's own offline buffer.
- An ``atexit`` hook calls :func:`EventEmitter.flush` so we don't lose
  events on a clean shutdown. SIGKILL / hard crashes are out of scope —
  for that, configure ``offline_buffer_path`` in :mod:`config`.

The 50-event / 1-second numbers are deliberate: 1 s gives a useful
liveness signal in dashboards without spamming the network; 50 events
caps memory growth under a burst.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
from collections import deque
from typing import Any, Callable

logger = logging.getLogger(__name__)


DEFAULT_FLUSH_INTERVAL_S = 1.0
DEFAULT_FLUSH_THRESHOLD = 50
DEFAULT_MAX_QUEUE = 10_000


class EventEmitter:
    """Buffered event emitter with background flushing.

    Parameters
    ----------
    sender:
        Callable that takes a list of event dicts and ships them. Returns
        ``None`` on success; raises on transport failure (the emitter
        catches and re-queues). The transport is injected rather than
        imported so this module stays free of any client coupling.
    flush_interval_s:
        How often the background thread wakes to drain the queue.
    flush_threshold:
        Drain immediately once the queue reaches this many events.
    max_queue:
        Hard cap. When exceeded, the oldest events get dropped (with a
        single log line — the wedge never raises).
    """

    def __init__(
        self,
        sender: Callable[[list[dict[str, Any]]], None],
        *,
        flush_interval_s: float = DEFAULT_FLUSH_INTERVAL_S,
        flush_threshold: int = DEFAULT_FLUSH_THRESHOLD,
        max_queue: int = DEFAULT_MAX_QUEUE,
    ) -> None:
        self._sender = sender
        self._flush_interval_s = flush_interval_s
        self._flush_threshold = flush_threshold
        self._queue: deque[dict[str, Any]] = deque(maxlen=max_queue)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._dropped = 0
        self._thread: threading.Thread | None = None
        self._started = False

    # ── public API ────────────────────────────────────────────────────

    def start(self) -> None:
        """Idempotent start. Safe to call from multiple integrations."""
        with self._lock:
            if self._started:
                return
            self._started = True
            self._thread = threading.Thread(
                target=self._run, name="tokendna-emitter", daemon=True,
            )
            self._thread.start()
            # Register atexit once per emitter instance.
            atexit.register(self._on_exit)

    def emit(self, event: dict[str, Any]) -> None:
        """Enqueue an event. Never blocks longer than a deque append."""
        if not self._started:
            self.start()
        if len(self._queue) >= self._queue.maxlen:  # type: ignore[operator]
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 1000 == 0:
                logger.warning(
                    "tokendna_sdk event queue full — dropped %d events so far",
                    self._dropped,
                )
        self._queue.append(event)
        if len(self._queue) >= self._flush_threshold:
            self._wake.set()

    def flush(self, timeout_s: float = 5.0) -> int:
        """Drain pending events synchronously. Returns count sent.

        Used by tests and by the atexit hook. The background thread keeps
        running; flush() just races with it for the queue contents.
        """
        sent = 0
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            batch = self._drain()
            if not batch:
                return sent
            try:
                self._sender(batch)
                sent += len(batch)
            except Exception:  # noqa: BLE001
                # Re-queue at the front so order is preserved. We accept
                # that this is not lock-free against concurrent emit() —
                # those events just land after the retry batch.
                logger.debug("tokendna_sdk flush failed; re-queueing", exc_info=True)
                for ev in reversed(batch):
                    self._queue.appendleft(ev)
                return sent
        return sent

    def stop(self) -> None:
        """Stop the background thread. Primarily for tests."""
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._started = False

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def dropped_count(self) -> int:
        return self._dropped

    # ── internals ─────────────────────────────────────────────────────

    def _drain(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        while self._queue:
            try:
                items.append(self._queue.popleft())
            except IndexError:
                break
        return items

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=self._flush_interval_s)
            self._wake.clear()
            batch = self._drain()
            if not batch:
                continue
            try:
                self._sender(batch)
            except Exception:  # noqa: BLE001
                logger.debug("tokendna_sdk background send failed", exc_info=True)
                for ev in reversed(batch):
                    self._queue.appendleft(ev)
                # Brief backoff so we don't hot-loop on a persistent failure.
                time.sleep(min(self._flush_interval_s * 2, 5.0))

    def _on_exit(self) -> None:
        # Best-effort drain on interpreter shutdown.
        try:
            self.flush(timeout_s=2.0)
        except Exception:  # noqa: BLE001
            pass


__all__ = ["EventEmitter", "DEFAULT_FLUSH_INTERVAL_S", "DEFAULT_FLUSH_THRESHOLD"]
