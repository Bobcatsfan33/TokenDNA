"""
Shared verification / event-emission helpers used by every framework
adapter.

This module exists so the three middleware modules (LangChain, CrewAI,
AutoGen) can share the same "build a ToolCallEvent, ship it through
the emitter, optionally call client.verify()" pipeline without each
re-implementing the boilerplate.

Internal API only — nothing here is exported from the package root.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Union

from ..client import TokenDNAClient
from ..exceptions import TokenDNAVerificationError
from ..local import TokenDNALocalClient
from ..models import (
    ModelCallEvent,
    PolicyVerdict,
    ToolCallEvent,
    hash_args,
)

logger = logging.getLogger(__name__)


# Duck-typed union: either client exposes ``verify``, ``emit_batch``,
# ``post``, and the ``emitter`` attribute on the remote variant. We
# avoid a Protocol/ABC here to keep the SDK dep-free. ``Union[...]`` (not
# ``X | Y``) for Python 3.9 compatibility at runtime — the package
# targets >=3.9.
AnyClient = Union[TokenDNAClient, TokenDNALocalClient]


class Verifier:
    """Per-adapter helper: emit events, optionally enforce policy.

    Parameters
    ----------
    client:
        The active TokenDNA client (remote or local).
    agent_id:
        Stable identifier for the agent being instrumented.
    scope:
        Declared agent scope; passed into every verify call so the
        policy engine can reject out-of-scope tool calls.
    framework:
        Free-text label (``"langchain"`` / ``"crewai"`` / ``"autogen"``)
        carried on every event for downstream analytics.
    enforce:
        When True, ``record_tool_call`` calls ``client.verify`` and
        raises :class:`TokenDNAVerificationError` on deny. When False
        (default — match the wedge contract), verification still runs
        but only decorates the event with the verdict.
    session_id:
        Optional session identifier. If omitted a fresh one is generated
        on first use and reused across the verifier's lifetime.
    """

    def __init__(
        self,
        client: AnyClient,
        *,
        agent_id: str,
        scope: list[str] | None = None,
        framework: str = "plain",
        enforce: bool = False,
        session_id: str | None = None,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.scope = list(scope or [])
        self.framework = framework
        self.enforce = enforce
        self._session_id = session_id
        self._hops: list[dict[str, Any]] = []

    # ── public API ────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        if self._session_id is None:
            from ..models import new_session_id
            self._session_id = new_session_id()
        return self._session_id

    @property
    def hops(self) -> list[dict[str, Any]]:
        """Read-only view of the workflow trace built so far. Adapters
        forward this into :meth:`finish` to issue an attestation."""
        return list(self._hops)

    def record_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        *,
        target: str = "",
        duration_ms: int | None = None,
        score: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyVerdict | None:
        """Emit a :class:`ToolCallEvent` and (optionally) run policy.

        Returns the policy verdict when ``enforce=True`` *or* when the
        underlying client returned one without raising. Always emits the
        event regardless of policy outcome — denied calls are still
        valuable telemetry.
        """
        event = ToolCallEvent(
            agent_id=self.agent_id,
            tool_name=tool_name,
            tool_args_hash=hash_args(args),
            session_id=self.session_id,
            duration_ms=duration_ms,
            metadata={
                "framework": self.framework,
                "scope": list(self.scope),
                "target": target,
                **(metadata or {}),
            },
        )
        self._emit(event.to_dict(), path="/api/uis/normalize")
        self._hops.append({
            "actor": self.agent_id,
            "action": tool_name,
            "target": target,
            "metadata": {"session_id": self.session_id, **(metadata or {})},
        })

        verdict = self._maybe_verify(tool_name, target=target, score=score)
        if verdict is not None and verdict.decision == "deny" and self.enforce:
            raise TokenDNAVerificationError(
                f"tool '{tool_name}' denied by policy: {verdict.reason}",
                verdict=verdict,
            )
        return verdict

    def record_model_call(
        self,
        model: str,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        duration_ms: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = ModelCallEvent(
            agent_id=self.agent_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            session_id=self.session_id,
            duration_ms=duration_ms,
            metadata={"framework": self.framework, **(metadata or {})},
        )
        self._emit(event.to_dict(), path="/api/uis/normalize")

    def finish(self, *, metadata: dict[str, Any] | None = None) -> Any:
        """Issue an attestation for the accumulated hops.

        Adapters call this from their ``after_agent`` hook. Failures are
        logged but never raised — the wedge stays intact.
        """
        if not self._hops:
            return None
        try:
            return self.client.attest(self.agent_id, list(self._hops),
                                       metadata=metadata)
        except Exception:  # noqa: BLE001
            logger.debug("tokendna_sdk attest failed in finish()", exc_info=True)
            return None

    # ── helpers ───────────────────────────────────────────────────────

    def _emit(self, event: dict[str, Any], *, path: str) -> None:
        """Best-effort emit. Local client appends to JSONL; remote
        client queues via its EventEmitter."""
        try:
            if hasattr(self.client, "emitter") and self.client.emitter is not None:  # type: ignore[union-attr]
                # Remote: queue via emitter for batched send.
                self.client.emitter.emit({"_path": path, "_body": event})  # type: ignore[union-attr]
            else:
                # Local: direct write through normalize / post.
                self.client.post(path, event)
        except Exception:  # noqa: BLE001
            logger.debug("tokendna_sdk emit failed", exc_info=True)

    def _maybe_verify(
        self,
        tool_name: str,
        *,
        target: str,
        score: float,
    ) -> PolicyVerdict | None:
        try:
            return self.client.verify(
                self.agent_id, tool_name, target=target,
                scope=list(self.scope), score=score,
            )
        except TokenDNAVerificationError as exc:
            # The remote client raises on deny; surface the verdict to
            # the caller so it can decide whether to re-raise.
            if exc.verdict is not None and isinstance(exc.verdict, PolicyVerdict):
                return exc.verdict
            return PolicyVerdict(decision="deny", reason="verify_raised",
                                  message=str(exc))
        except Exception:  # noqa: BLE001
            logger.debug("tokendna_sdk verify failed; falling back to allow",
                         exc_info=True)
            return None


__all__ = ["Verifier", "AnyClient"]


def _instant_ms(start: float) -> int:
    """Tiny helper used by adapters to record per-call timing without
    pulling in a clock dependency."""
    return int((time.monotonic() - start) * 1000)
