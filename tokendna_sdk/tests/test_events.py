"""Tests for the buffered EventEmitter."""

from __future__ import annotations

import threading
import time

from tokendna_sdk.events import EventEmitter


def test_flush_sends_pending_events():
    captured: list[list[dict]] = []
    e = EventEmitter(sender=captured.append, flush_threshold=100)
    e.start()
    for i in range(10):
        e.emit({"i": i})
    sent = e.flush(timeout_s=1.0)
    assert sent == 10
    assert sum(len(b) for b in captured) == 10
    e.stop()


def test_threshold_triggers_background_flush():
    captured: list[list[dict]] = []
    e = EventEmitter(sender=captured.append, flush_threshold=5,
                      flush_interval_s=0.05)
    e.start()
    for i in range(5):
        e.emit({"i": i})
    # Wait briefly for the background thread to drain.
    for _ in range(50):
        if sum(len(b) for b in captured) >= 5:
            break
        time.sleep(0.02)
    assert sum(len(b) for b in captured) >= 5
    e.stop()


def test_sender_failure_re_queues_without_loss():
    calls = {"n": 0}
    captured: list[list[dict]] = []

    def flaky(batch):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("network down")
        captured.append(batch)

    e = EventEmitter(sender=flaky, flush_threshold=1000,
                      flush_interval_s=0.05)
    e.start()
    e.emit({"x": 1})
    # First flush fails (re-queued), second succeeds.
    e.flush(timeout_s=1.0)
    e.flush(timeout_s=1.0)
    assert calls["n"] >= 2
    flat = [ev for b in captured for ev in b]
    assert {"x": 1} in flat
    e.stop()


def test_queue_overflow_drops_with_counter():
    e = EventEmitter(sender=lambda b: None, max_queue=3, flush_threshold=999)
    e.start()
    # Stop the background drainer so we exercise the overflow path
    # deterministically.
    e.stop()
    e._started = True  # re-enable emit() but no thread
    for i in range(10):
        e.emit({"i": i})
    assert e.queue_size == 3
    assert e.dropped_count >= 1


def test_start_is_idempotent():
    e = EventEmitter(sender=lambda b: None)
    e.start()
    thread_id_a = e._thread.ident  # type: ignore[union-attr]
    e.start()
    thread_id_b = e._thread.ident  # type: ignore[union-attr]
    assert thread_id_a == thread_id_b
    e.stop()


def test_emit_is_thread_safe_under_concurrent_writers():
    captured: list[list[dict]] = []
    e = EventEmitter(sender=captured.append, flush_threshold=1000,
                      flush_interval_s=0.05)
    e.start()

    def writer(n):
        for i in range(n):
            e.emit({"i": i})

    threads = [threading.Thread(target=writer, args=(50,)) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    e.flush(timeout_s=2.0)
    total = sum(len(b) for b in captured)
    assert total == 8 * 50
    e.stop()
