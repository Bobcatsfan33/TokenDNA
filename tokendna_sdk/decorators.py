"""
``@identified`` and ``@tool`` — the actual wedge.

Design notes
------------
- ``@identified`` is a *class* decorator: it stamps every method call
  through a single dispatch path so middleware can inject UIS events
  uniformly. We deliberately avoid monkey-patching at module import
  time so the user retains control.
- ``@tool`` is a *method* decorator: it ships per-call attestation
  events and (when applicable) appends a hop to a workflow trace stored
  in a thread-local. That trace can be retrieved via
  ``get_agent_metadata`` for downstream workflow_attestation registration.
- Decorators never raise on transport failure. The original method's
  return value (or exception) is always passed through to the user.
"""

from __future__ import annotations

import functools
import inspect
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from .client import Client
from .config import current_config

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ── Per-thread workflow trace ─────────────────────────────────────────────────

_state = threading.local()


def _trace() -> list[dict[str, Any]]:
    if not hasattr(_state, "trace"):
        _state.trace = []
    return _state.trace


def _push_hop(hop: dict[str, Any]) -> None:
    _trace().append(hop)


def get_agent_metadata() -> dict[str, Any]:
    """
    Return the current thread's workflow trace as a list of hop dicts
    suitable for ``workflow_attestation.register_workflow``. Clears the
    trace after read so subsequent runs start clean.
    """
    hops = list(_trace())
    _state.trace = []
    return {"hops": hops}


# ── @identified — class decorator ─────────────────────────────────────────────

@dataclass
class _AgentMeta:
    agent_id: str
    scope: list[str] = field(default_factory=list)
    description: str = ""
    delegation_receipt_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def identified(
    agent_id: str,
    *,
    scope: list[str] | None = None,
    description: str = "",
    delegation_receipt_id: str | None = None,
    client: Client | None = None,
    **extra: Any,
) -> Callable[[type[T]], type[T]]:
    """
    Mark a class as an attested TokenDNA agent. After decoration::

        @identified("research-bot", scope=["docs:read"])
        class ResearchAgent: ...

    every instance carries ``__tokendna_meta__`` and every ``@tool``-marked
    method emits attestation events under that identity.

    The decorator is non-invasive: it does not modify methods, intercept
    __init__, or alter attribute lookup. ``@tool`` does the per-call work.
    """
    if not agent_id or not isinstance(agent_id, str):
        raise ValueError("agent_id must be a non-empty string")

    meta = _AgentMeta(
        agent_id=agent_id,
        scope=list(scope or []),
        description=description,
        delegation_receipt_id=delegation_receipt_id,
        extra=dict(extra),
    )
    bound_client = client

    def _wrap(cls: type[T]) -> type[T]:
        cls.__tokendna_meta__ = meta            # type: ignore[attr-defined]
        cls.__tokendna_client__ = bound_client  # type: ignore[attr-defined]
        return cls

    return _wrap


# ── @tool — method decorator ──────────────────────────────────────────────────

def _resolve_client(self_obj: Any, override: Client | None) -> Any:
    """Resolve which client to call. Duck-typed: any object with a
    ``post(path, body)`` method is acceptable so tests and downstream
    integrations can plug in their own transports without subclassing."""
    if override is not None:
        return override
    bound = getattr(type(self_obj), "__tokendna_client__", None)
    if bound is not None and hasattr(bound, "post"):
        return bound
    return Client(config=current_config())


def _resolve_meta(self_obj: Any) -> _AgentMeta | None:
    return getattr(type(self_obj), "__tokendna_meta__", None)


def tool(
    name: str | None = None,
    *,
    target: str | None = None,
    client: Client | None = None,
    capture_args: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorate a method on an ``@identified`` class. Each call:

      1. Pushes a hop {actor, action, target, metadata} onto the
         per-thread workflow trace.
      2. POSTs a UIS-shaped event to /api/uis/normalize via the SDK client
         (best-effort — network failures buffer locally and the call still
         returns the original method's value).
      3. Returns whatever the wrapped method returned. Exceptions raised by
         the wrapped method are re-raised verbatim.

    ``capture_args=False`` by default — silently dropping arguments avoids
    leaking secrets via instrumentation. Opt in for debugging only.
    """
    def _decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        action = name or fn.__name__

        @functools.wraps(fn)
        def _wrapper(self_obj: Any, *args: Any, **kwargs: Any) -> Any:
            meta = _resolve_meta(self_obj)
            if meta is None:
                # Class wasn't decorated with @identified — pass through
                # rather than crashing the caller's program.
                return fn(self_obj, *args, **kwargs)

            cli = _resolve_client(self_obj, client)
            cfg = cli.config
            call_id = uuid.uuid4().hex[:16]
            started = time.time()

            hop_meta: dict[str, Any] = {"call_id": call_id}
            if capture_args:
                # bind for stable rendering — drop self.
                try:
                    sig = inspect.signature(fn)
                    bound = sig.bind(self_obj, *args, **kwargs)
                    bound.apply_defaults()
                    hop_meta["arguments"] = {
                        k: repr(v) for k, v in list(bound.arguments.items())[1:]
                    }
                except (TypeError, ValueError):
                    pass

            hop = {
                "actor": meta.agent_id,
                "action": action,
                "target": target or "",
                "receipt_id": meta.delegation_receipt_id,
                "metadata": hop_meta,
            }
            _push_hop(hop)

            # Best-effort post; never block the caller longer than the
            # configured timeout.
            event = {
                "uis_version": "1.1",
                "event_id": f"sdk-{call_id}",
                "event_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00",
                                                 time.gmtime()),
                "identity": {
                    "entity_type": "machine",
                    "subject": meta.agent_id,
                    "tenant_id": cfg.tenant_id,
                    "tenant_name": cfg.tenant_id,
                    "machine_classification": "agent",
                    "agent_id": meta.agent_id,
                },
                "auth": {"method": "sdk", "mfa_asserted": False,
                         "protocol": "tokendna-sdk", "credential_strength": "standard"},
                "tool_call": {"action": action, "target": target or ""},
                "scope": list(meta.scope),
                "metadata": hop_meta,
            }
            try:
                cli.post("/api/uis/normalize", event)
            except Exception:  # noqa: BLE001
                # We promised: never raise from the wedge.
                logger.exception("tokendna_sdk emit failed (call_id=%s)", call_id)

            try:
                return fn(self_obj, *args, **kwargs)
            finally:
                hop["metadata"]["duration_ms"] = int((time.time() - started) * 1000)

        return _wrapper

    return _decorate
