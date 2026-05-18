"""
Native LangChain middleware for TokenDNA.

Install
-------
``pip install "tokendna-sdk[langchain]"``

Usage
-----
.. code-block:: python

    from langgraph.prebuilt import create_react_agent
    from tokendna_sdk.integrations.langchain import TokenDNAMiddleware

    agent = create_react_agent(
        model="gpt-4o",
        tools=[search_web, send_email],
        middleware=[
            TokenDNAMiddleware(
                agent_id="research-bot",
                scope=["web:read", "email:send"],
            ),
        ],
    )

Hooks implemented
-----------------
- ``wrap_model_call``  — records prompt + completion token counts
  and timing per LLM hop, queues a :class:`ModelCallEvent`.
- ``wrap_tool_call``   — records each tool invocation as a
  :class:`ToolCallEvent`, optionally calls ``client.verify`` to
  enforce policy, raises :class:`TokenDNAVerificationError` on
  deny when ``enforce=True``.
- ``after_agent``      — issues a workflow attestation receipt for
  the accumulated hops; updates the behavioral baseline.

Design notes
------------
- LangChain is imported lazily so the SDK install stays dependency-free.
- We accept either the new ``AgentMiddleware`` base (langchain ≥ 0.3
  middleware refactor) or a duck-typed fallback that just exposes the
  three hook methods. Older agents that don't use the middleware
  interface still work via the classic ``@identified`` + ``@tool``
  decorators — see ``tokendna_sdk.decorators``.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from .._core.behavioral import BaselineStore, score_session
from .._core.verifier import Verifier
from ..client import TokenDNAClient
from ..config import current_config
from ..exceptions import TokenDNAVerificationError
from ..local import TokenDNALocalClient

logger = logging.getLogger(__name__)


def _resolve_base_class() -> tuple[type, bool]:
    """Try to import the LangChain middleware base class.

    Returns ``(base, real)`` where ``real`` indicates whether we got
    the real LangChain class or our duck-typed stub. The middleware
    keeps working either way; tests that mock LangChain rely on this.
    """
    try:
        from langchain.agents.middleware import AgentMiddleware  # type: ignore
        return AgentMiddleware, True
    except Exception:  # noqa: BLE001
        try:
            from langchain.agents import AgentMiddleware  # type: ignore
            return AgentMiddleware, True
        except Exception:  # noqa: BLE001
            pass

    class _DuckMiddleware:
        """Stand-in for ``AgentMiddleware`` when LangChain is not
        installed. The hook methods are no-ops by default; subclasses
        override them just like the real base."""

    return _DuckMiddleware, False


_Base, _LANGCHAIN_AVAILABLE = _resolve_base_class()


class TokenDNAMiddleware(_Base):  # type: ignore[misc,valid-type]
    """Drop-in LangChain middleware for attested agent runs.

    Parameters
    ----------
    agent_id:
        Stable identifier for the agent. Required.
    scope:
        Declared scope (e.g. ``["web:read", "files:read"]``). Passed to
        the policy engine on every ``client.verify`` call.
    client:
        Pre-built TokenDNA client. If omitted, we call
        :func:`tokendna_sdk.make_client` so users get the right mode
        (remote/local) automatically.
    enforce:
        When True, denied tool calls raise
        :class:`TokenDNAVerificationError` and short-circuit the agent
        run. Default False — match the SDK's wedge contract (record,
        don't block).
    capture_args:
        When True, tool arguments are hashed into the event metadata.
        Default False to avoid leaking sensitive arguments.
    """

    middleware_name: str = "tokendna"
    framework: str = "langchain"

    def __init__(
        self,
        agent_id: str,
        *,
        scope: list[str] | None = None,
        client: Any | None = None,
        enforce: bool = False,
        capture_args: bool = False,
        agent_version: str = "0.0.0",
    ) -> None:
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        # super().__init__() works on either the real AgentMiddleware
        # base or our duck-typed stub.
        try:
            super().__init__()
        except TypeError:
            # LangChain's middleware sometimes requires kwargs; we don't
            # have any meaningful ones to pass so swallow the TypeError.
            pass
        self.agent_id = agent_id
        self.scope = list(scope or [])
        self.agent_version = agent_version
        self.capture_args = capture_args
        self._client = client or self._default_client()
        self._verifier = Verifier(
            self._client,
            agent_id=agent_id,
            scope=self.scope,
            framework=self.framework,
            enforce=enforce,
        )
        self._tool_calls: list[str] = []
        self._baseline = BaselineStore(self._baselines_path())

    # ── LangChain hooks ───────────────────────────────────────────────

    def wrap_model_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        """Wrap an LLM call. Records prompt + completion tokens if the
        response surfaces them."""
        start = time.monotonic()
        try:
            response = handler(request)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
        prompt_tokens, completion_tokens = _extract_token_counts(request, response)
        model = _extract_model_name(request, response)
        self._verifier.record_model_call(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            duration_ms=duration_ms,
        )
        return response

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_name, tool_args, target = _extract_tool_call(request)
        start = time.monotonic()
        score = score_session(
            self._baseline.get(self.agent_id), self._tool_calls,
        )
        # Verify BEFORE the call when enforcing — denied calls don't run.
        if self._verifier.enforce:
            self._verifier.record_tool_call(
                tool_name,
                args=tool_args if self.capture_args else None,
                target=target,
                score=score,
            )
            response = handler(request)
        else:
            try:
                response = handler(request)
            finally:
                duration_ms = int((time.monotonic() - start) * 1000)
                try:
                    self._verifier.record_tool_call(
                        tool_name,
                        args=tool_args if self.capture_args else None,
                        target=target,
                        duration_ms=duration_ms,
                        score=score,
                    )
                except TokenDNAVerificationError:
                    # Should never happen with enforce=False, but guard
                    # the wedge contract anyway.
                    logger.debug("verify raised in non-enforce mode")
        self._tool_calls.append(tool_name)
        return response

    def after_agent(self, state: Any) -> None:
        """Finalize: issue an attestation and roll the baseline."""
        try:
            self._verifier.finish(metadata={"langchain_state_keys":
                                            _state_keys(state)})
        finally:
            self._baseline.record_session(self.agent_id,
                                           list(self._tool_calls))
            self._tool_calls = []

    # Provide a couple of common LangChain hook aliases so older
    # versions can find at least one of them.
    after_model = wrap_model_call  # noqa: F811 — intentional alias

    # ── helpers ───────────────────────────────────────────────────────

    def _default_client(self) -> TokenDNAClient | TokenDNALocalClient:
        # Lazy import to break the package-level cycle.
        from .. import make_client
        return make_client()

    def _baselines_path(self):
        cfg = current_config()
        root = cfg.local_root or str((__import__("pathlib").Path.home() /
                                       ".tokendna"))
        return f"{root}/baselines.json"


# ── input adapters ────────────────────────────────────────────────────────────

def _extract_tool_call(request: Any) -> tuple[str, dict[str, Any], str]:
    """Extract (tool_name, args, target) from a LangChain tool-call request.

    LangChain has shifted this shape across versions; we accept the
    canonical v0.3 shape plus a couple of common older variants.
    """
    if request is None:
        return ("unknown", {}, "")
    if isinstance(request, dict):
        name = (request.get("name") or request.get("tool")
                or request.get("tool_name") or "unknown")
        args = (request.get("args") or request.get("arguments")
                or request.get("tool_input") or {})
        target = request.get("target") or ""
        if isinstance(args, str):
            args = {"_raw": args}
        return (str(name), dict(args) if isinstance(args, dict) else {"value": args},
                str(target))
    # Object with attributes (LangChain ToolCall).
    name = getattr(request, "name", None) or getattr(request, "tool",
                                                       None) or "unknown"
    args = (getattr(request, "args", None)
            or getattr(request, "arguments", None)
            or getattr(request, "tool_input", None)
            or {})
    target = getattr(request, "target", "") or ""
    if isinstance(args, str):
        args = {"_raw": args}
    return (str(name),
             dict(args) if isinstance(args, dict) else {"value": args},
             str(target))


def _extract_token_counts(request: Any, response: Any) -> tuple[int, int]:
    if response is None:
        return (0, 0)
    usage = (getattr(response, "usage_metadata", None)
             or getattr(response, "response_metadata", None)
             or getattr(response, "usage", None)
             or (response.get("usage") if isinstance(response, dict) else None))
    if not usage:
        return (0, 0)
    if isinstance(usage, dict):
        p = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
        c = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
        return (p, c)
    return (
        int(getattr(usage, "input_tokens", 0) or getattr(usage, "prompt_tokens", 0)),
        int(getattr(usage, "output_tokens", 0)
            or getattr(usage, "completion_tokens", 0)),
    )


def _extract_model_name(request: Any, response: Any) -> str:
    for candidate in (request, response):
        if isinstance(candidate, dict):
            v = candidate.get("model") or candidate.get("model_name")
            if v:
                return str(v)
        m = getattr(candidate, "model", None) or getattr(candidate, "model_name", None)
        if m:
            return str(m)
    return "unknown"


def _state_keys(state: Any) -> list[str]:
    if isinstance(state, dict):
        return sorted(state.keys())[:10]
    return []


__all__ = ["TokenDNAMiddleware"]
