"""
HTTP transport plus the high-level :class:`TokenDNAClient` façade.

Two layers live here:

* :class:`Client` — the low-level urllib transport with an offline
  buffer. Unchanged from v0.1.x for backward compat; the ``@tool``
  decorator still talks to it.
* :class:`TokenDNAClient` — the v0.2 façade that framework adapters
  use. Wraps :class:`Client` and adds the ``normalize`` / ``attest`` /
  ``verify`` / ``health`` methods plus an :class:`EventEmitter` for
  background batching.

The split keeps the wedge contract simple: low-level "POST and buffer
on failure" stays the same; the high-level surface evolves
independently.

Notes
-----
- Zero runtime deps — uses :mod:`urllib.request` only. Production users
  can override ``Client._do_post`` to plug in a different HTTP stack.
- Tests substitute their own ``_do_post`` or pass a stub client through
  the public constructor; nothing here reaches for a global singleton.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from .config import SdkConfig, current_config
from .events import EventEmitter
from .exceptions import (
    TokenDNAAttestationError,
    TokenDNAUnavailableError,
    TokenDNAVerificationError,
)
from .models import Attestation, PolicyVerdict, utc_now

logger = logging.getLogger(__name__)


@dataclass
class BufferedEvent:
    path: str
    body: dict[str, Any]
    attempts: int = 0
    last_error: str | None = None


class OfflineBufferClient:
    """In-memory (plus optional on-disk) FIFO of events that failed to
    transmit. Flushed by :meth:`Client.flush`. Pluggable so tests can
    capture flushed events without HTTP."""

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
        with self._lock:
            for ev in items:
                self._buffer.append(ev)
            self._persist()


class Client:
    """Low-level urllib transport. Backward-compatible with v0.1.x — the
    ``@tool`` decorator still calls ``post(path, body)`` on this.

    Network failures push the event into the offline buffer. The wedge
    contract (never raise) is enforced here; higher-level callers that
    *want* failures surfaced use :class:`TokenDNAClient`'s explicit
    methods, which translate this into typed exceptions.
    """

    def __init__(self, *, config: SdkConfig | None = None):
        self.config = config or current_config()
        self.buffer = OfflineBufferClient(path=self.config.offline_buffer_path)

    # Tests override this to capture without real HTTP.
    def _do_post(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            return (getattr(resp, "status", 200), resp.read() or b"")

    def _do_get(self, url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        req = urllib.request.Request(url, method="GET")
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            return (getattr(resp, "status", 200), resp.read() or b"")

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key,
            "User-Agent": "tokendna-sdk-python",
        }

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if not self.config.enabled:
            return {"sent": False, "buffered": False, "reason": "sdk_disabled"}
        if not self.config.is_online():
            self.buffer.append(BufferedEvent(path=path, body=body))
            return {"sent": False, "buffered": True, "reason": "offline"}
        url = f"{self.config.api_base}{path}"
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            status, _data = self._do_post(url, payload, self._headers())
            return {"sent": True, "buffered": False, "status": int(status)}
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self.buffer.append(
                BufferedEvent(path=path, body=body, attempts=1, last_error=str(exc))
            )
            return {"sent": False, "buffered": True, "reason": str(exc)}

    def post_with_response(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Like :meth:`post` but surfaces the response body. Used by
        :class:`TokenDNAClient` for synchronous calls (verify/attest)."""
        if not self.config.is_online():
            raise TokenDNAUnavailableError("SDK not configured for remote calls")
        url = f"{self.config.api_base}{path}"
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            status, raw = self._do_post(url, payload, self._headers())
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise TokenDNAUnavailableError(f"transport failed: {exc}") from exc
        if status >= 400:
            raise TokenDNAUnavailableError(f"server returned HTTP {status}")
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise TokenDNAUnavailableError(f"bad json from server: {exc}") from exc

    def get_with_response(self, path: str) -> dict[str, Any]:
        if not self.config.is_online():
            raise TokenDNAUnavailableError("SDK not configured for remote calls")
        url = f"{self.config.api_base}{path}"
        try:
            status, raw = self._do_get(url, self._headers())
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise TokenDNAUnavailableError(f"transport failed: {exc}") from exc
        if status >= 400:
            raise TokenDNAUnavailableError(f"server returned HTTP {status}")
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError as exc:
            raise TokenDNAUnavailableError(f"bad json from server: {exc}") from exc

    def flush(self) -> dict[str, Any]:
        """Try every buffered event once. Re-buffer the failures."""
        items = list(self.buffer.drain())
        sent = 0
        failed: list[BufferedEvent] = []
        for ev in items:
            url = f"{self.config.api_base}{ev.path}"
            payload = json.dumps(ev.body, separators=(",", ":")).encode("utf-8")
            try:
                self._do_post(url, payload, self._headers())
                sent += 1
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                ev.attempts += 1
                ev.last_error = str(exc)
                failed.append(ev)
        if failed:
            self.buffer.reinject(failed)
        return {"sent": sent, "buffered": len(failed)}


# ── High-level façade ────────────────────────────────────────────────────────

class TokenDNAClient:
    """The v0.2 high-level client used by framework adapters.

    Wraps a :class:`Client` for transport plus an :class:`EventEmitter`
    for background batching. Explicit verification calls (``verify``,
    ``attest``) raise typed exceptions on failure; fire-and-forget
    streams (``emit``) are silent.

    In local mode (no ``TOKENDNA_URL`` / ``TOKENDNA_API_BASE``), the
    :func:`tokendna_sdk.make_client` factory returns a
    :class:`tokendna_sdk.local.TokenDNALocalClient` instead — they share
    a duck-typed surface so callers can stay agnostic.
    """

    def __init__(self, *, config: SdkConfig | None = None,
                 transport: Client | None = None) -> None:
        self.config = config or current_config()
        self._transport = transport or Client(config=self.config)
        self._emitter = EventEmitter(sender=self._send_batch)

    @property
    def mode(self) -> str:
        return "remote"

    @property
    def emitter(self) -> EventEmitter:
        return self._emitter

    # ── parity with TokenDNALocalClient ───────────────────────────────

    def health(self) -> dict[str, Any]:
        try:
            data = self._transport.get_with_response("/health")
        except TokenDNAUnavailableError as exc:
            return {"status": "unreachable", "mode": "remote",
                    "error": str(exc), "api_base": self.config.api_base}
        return {"status": data.get("status", "ok"), "mode": "remote",
                "api_base": self.config.api_base, **{k: v for k, v in data.items()
                                                     if k != "status"}}

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Pass-through to the legacy transport for ``@tool``."""
        return self._transport.post(path, body)

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        """Fire-and-forget: ship a UIS-shaped event. Uses the buffered
        emitter so callers return immediately."""
        self._emitter.emit({"_path": "/api/uis/normalize", "_body": event})
        return {"normalized": True, "mode": "remote", "queued": True}

    def emit_batch(self, batch: list[dict[str, Any]]) -> None:
        """Compatibility shim — used by the local client; on remote
        we just hand each item to the transport directly."""
        for ev in batch:
            path = ev.pop("_path", "/api/uis/normalize")
            body = ev.pop("_body", ev)
            self._transport.post(path, body)

    def attest(self, agent_id: str, hops: list[dict[str, Any]],
               *, metadata: dict[str, Any] | None = None) -> Attestation:
        if not agent_id:
            raise TokenDNAAttestationError("agent_id required for attestation")
        body = {
            "agent_id": agent_id,
            "hops": list(hops),
            "metadata": dict(metadata or {}),
            "issued_at": utc_now(),
        }
        try:
            data = self._transport.post_with_response("/api/attest", body)
        except TokenDNAUnavailableError as exc:
            raise TokenDNAAttestationError(f"attest failed: {exc}") from exc
        receipt_id = data.get("receipt_id")
        if not receipt_id:
            raise TokenDNAAttestationError("server response missing receipt_id")
        return Attestation(
            receipt_id=receipt_id,
            agent_id=agent_id,
            issued_at=data.get("issued_at", utc_now()),
            hops=list(hops),
            signature=data.get("signature"),
            metadata=dict(metadata or {}),
        )

    def verify(self, agent_id: str, action: str,
               *, target: str = "", scope: list[str] | None = None,
               score: float = 0.0) -> PolicyVerdict:
        body = {
            "agent_id": agent_id,
            "action": action,
            "target": target,
            "scope": list(scope or []),
            "score": score,
        }
        try:
            data = self._transport.post_with_response("/api/verify", body)
        except TokenDNAUnavailableError as exc:
            raise TokenDNAVerificationError(f"verify transport failed: {exc}") from exc
        verdict = PolicyVerdict(
            decision=str(data.get("decision", "deny")),
            reason=str(data.get("reason", "")),
            message=str(data.get("message", "")),
            score=float(data.get("score", score)),
            metadata={k: v for k, v in data.items()
                      if k not in {"decision", "reason", "message", "score"}},
        )
        if verdict.decision == "deny":
            raise TokenDNAVerificationError(
                f"verify denied: {verdict.reason}", verdict=verdict,
            )
        return verdict

    def flush(self) -> int:
        """Synchronously flush the event emitter and the transport's
        offline buffer. Returns total events shipped."""
        sent = self._emitter.flush()
        sent += self._transport.flush().get("sent", 0)
        return sent

    # ── internals ─────────────────────────────────────────────────────

    def _send_batch(self, batch: list[dict[str, Any]]) -> None:
        for ev in batch:
            path = ev.get("_path", "/api/uis/normalize")
            body = ev.get("_body", ev)
            self._transport.post(path, body)


__all__ = ["Client", "TokenDNAClient", "OfflineBufferClient", "BufferedEvent"]
