"""
Local-only TokenDNA client.

When ``TOKENDNA_URL`` (or the legacy ``TOKENDNA_API_BASE``) is unset, the
SDK runs in "local mode": events are recorded to a JSONL file under
``~/.tokendna/`` and signed with a host-local HMAC key. No network calls
are made.

Why this exists
---------------
Local mode is the on-ramp. A developer running ``pip install
tokendna-sdk`` should see *something* useful — a JSONL audit trail, a
working ``tokendna verify`` command — without ever creating an account.
It also doubles as the test transport: integration tests for the
middleware can point at :class:`TokenDNALocalClient` instead of a mock.

Notes
-----
- The local HMAC key is generated on first use and stored at
  ``~/.tokendna/local.key`` with mode 0600. It is *not* a substitute for
  the server's signing key — it just lets us verify that local events
  weren't tampered with after recording.
- ``verify()`` always returns ``allow`` in local mode. Behavioral
  scoring still runs (see :mod:`_core.behavioral`) and surfaces the
  score on the verdict, but enforcement only happens in remote mode.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from .exceptions import TokenDNAAttestationError
from .models import Attestation, PolicyVerdict, utc_now

logger = logging.getLogger(__name__)


DEFAULT_LOCAL_ROOT = Path.home() / ".tokendna"
EVENTS_FILENAME = "events.jsonl"
KEY_FILENAME = "local.key"
BASELINES_FILENAME = "baselines.json"


def _ensure_root(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        # On some filesystems chmod is a no-op (Windows, network mounts).
        pass
    return root


def _load_or_create_key(root: Path) -> bytes:
    """Return the per-host HMAC key, creating it (0600) if missing."""
    key_path = root / KEY_FILENAME
    if key_path.exists():
        try:
            return key_path.read_bytes()
        except OSError as exc:
            logger.warning("tokendna_sdk local key unreadable, regenerating: %s", exc)
    key = secrets.token_bytes(32)
    # Write+chmod atomically-ish: write tmp, chmod, rename.
    tmp = key_path.with_suffix(".tmp")
    tmp.write_bytes(key)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(key_path)
    return key


class TokenDNALocalClient:
    """Local-mode replacement for :class:`TokenDNAClient`.

    Implements the same surface (``normalize``, ``attest``, ``verify``,
    ``health``, ``post``) so framework adapters and the event emitter
    don't care which one they're talking to.
    """

    def __init__(self, *, root: str | os.PathLike[str] | None = None) -> None:
        self._root = _ensure_root(Path(root) if root else DEFAULT_LOCAL_ROOT)
        self._key = _load_or_create_key(self._root)
        self._lock = threading.Lock()
        self._events_path = self._root / EVENTS_FILENAME
        self._baselines_path = self._root / BASELINES_FILENAME

    # ── parity with TokenDNAClient ────────────────────────────────────

    @property
    def mode(self) -> str:
        return "local"

    @property
    def root(self) -> Path:
        return self._root

    def health(self) -> dict[str, Any]:
        """Local mode is always healthy if the root dir is writable."""
        return {
            "status": "ok",
            "mode": "local",
            "root": str(self._root),
            "events_path": str(self._events_path),
        }

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """Compatibility shim for the legacy ``Client.post`` interface
        used by :func:`tokendna_sdk.decorators.tool`. Records the event
        and returns a sent-style envelope."""
        self._record({"path": path, "body": body, "type": "post"})
        return {"sent": True, "buffered": False, "status": 200, "mode": "local"}

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        """Persist a UIS-shaped event to the local JSONL log."""
        self._record({"type": "uis", "event": event})
        return {"normalized": True, "mode": "local"}

    def emit_batch(self, batch: list[dict[str, Any]]) -> None:
        """Bulk-record events from the emitter. One JSONL line per event."""
        if not batch:
            return
        with self._lock:
            with self._events_path.open("a", encoding="utf-8") as fh:
                for ev in batch:
                    fh.write(self._sign_line(ev) + "\n")

    def attest(self, agent_id: str, hops: list[dict[str, Any]],
               *, metadata: dict[str, Any] | None = None) -> Attestation:
        """Issue a local attestation receipt for a completed workflow."""
        if not agent_id:
            raise TokenDNAAttestationError("agent_id required for attestation")
        receipt_id = f"loc-{int(time.time() * 1000):x}-{secrets.token_hex(4)}"
        att = Attestation(
            receipt_id=receipt_id,
            agent_id=agent_id,
            issued_at=utc_now(),
            hops=list(hops),
            metadata=dict(metadata or {}),
        )
        att.signature = self._sign(json.dumps(att.to_dict(),
                                              sort_keys=True,
                                              separators=(",", ":"),
                                              default=str).encode("utf-8"))
        self._record({"type": "attestation", "attestation": att.to_dict()})
        return att

    def verify(self, agent_id: str, action: str,
               *, target: str = "", scope: list[str] | None = None,
               score: float = 0.0) -> PolicyVerdict:
        """Local-mode policy verify — always allow, but echo behavioral
        score so callers can opt in to soft enforcement."""
        verdict = PolicyVerdict(
            decision="allow",
            reason="local_mode",
            message=f"local mode: {agent_id} -> {action}",
            score=score,
            metadata={"target": target, "scope": list(scope or [])},
        )
        self._record({"type": "verdict", "verdict": verdict.to_dict()})
        return verdict

    # ── inspection / debugging ────────────────────────────────────────

    def read_events(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return recorded events (newest first). Used by
        ``tokendna status`` / ``tokendna replay``."""
        if not self._events_path.exists():
            return []
        lines = self._events_path.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, Any]] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if limit is not None and len(out) >= limit:
                break
        return out

    def verify_signature(self, signed_line: dict[str, Any]) -> bool:
        """Recompute the HMAC over a stored line's body and compare."""
        sig = signed_line.get("_sig")
        body = signed_line.get("_body")
        if not sig or body is None:
            return False
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             default=str).encode("utf-8")
        expected = self._sign(payload)
        return hmac.compare_digest(sig, expected)

    # ── internals ─────────────────────────────────────────────────────

    def _record(self, body: dict[str, Any]) -> None:
        with self._lock:
            with self._events_path.open("a", encoding="utf-8") as fh:
                fh.write(self._sign_line(body) + "\n")

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _sign_line(self, body: dict[str, Any]) -> str:
        body = {**body, "_ts": utc_now()}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"),
                             default=str).encode("utf-8")
        wrapped = {"_body": body, "_sig": self._sign(payload)}
        return json.dumps(wrapped, separators=(",", ":"), default=str)


__all__ = ["TokenDNALocalClient", "DEFAULT_LOCAL_ROOT"]
