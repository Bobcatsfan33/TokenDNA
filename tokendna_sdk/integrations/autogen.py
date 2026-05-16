"""
Native AutoGen middleware for TokenDNA.

Install
-------
``pip install "tokendna-sdk[autogen]"``

Usage
-----
.. code-block:: python

    from autogen import AssistantAgent
    from tokendna_sdk.integrations.autogen import TokenDNAAutoGenMiddleware

    agent = AssistantAgent(name="researcher", llm_config={...})
    middleware = TokenDNAAutoGenMiddleware(agent_id="research-bot",
                                            scope=["web:read"])
    middleware.attach(agent)   # wraps the agent's tool-call dispatch

How it works
------------
AutoGen exposes tools as registered Python callables on the agent
(``register_for_execution`` / ``register_function``). We monkey-patch
the registered function map at ``attach()`` time so each tool call
goes through the verifier first. The original callable is preserved
and re-installed by ``detach()``.

We deliberately patch *the registered function map*, not the agent
class — that means:

* AutoGen import is still lazy.
* Tests can attach to a plain ``object()`` that exposes a
  ``_function_map`` attribute, no AutoGen install required.
* Detaching restores the user's original callables exactly.
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable

from .._core.behavioral import BaselineStore, score_session
from .._core.verifier import Verifier
from ..config import current_config

logger = logging.getLogger(__name__)


class TokenDNAAutoGenMiddleware:
    """Attach to an AutoGen agent to record every tool invocation.

    Parameters mirror :class:`TokenDNAMiddleware`. After ``attach``
    every registered tool runs through the verifier before its body
    executes; failures during instrumentation are swallowed so the
    user's tool still gets its arguments. ``detach`` removes the
    instrumentation by restoring the original callables.
    """

    framework: str = "autogen"

    def __init__(
        self,
        agent_id: str,
        *,
        scope: list[str] | None = None,
        client: Any | None = None,
        enforce: bool = False,
        capture_args: bool = False,
    ) -> None:
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        self.agent_id = agent_id
        self.scope = list(scope or [])
        self.capture_args = capture_args
        self.enforce = enforce
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
        self._patched: list[tuple[Any, str, Callable[..., Any]]] = []

    # ── attach / detach ───────────────────────────────────────────────

    def attach(self, agent: Any) -> None:
        """Instrument the agent's registered tool functions in place.

        AutoGen stores callables in ``agent._function_map`` (newer
        versions) or ``agent.function_map`` (older). We patch whichever
        is present.
        """
        for attr in ("_function_map", "function_map"):
            fmap = getattr(agent, attr, None)
            if isinstance(fmap, dict):
                for name in list(fmap.keys()):
                    original = fmap[name]
                    if not callable(original):
                        continue
                    fmap[name] = self._wrap(name, original)
                    self._patched.append((fmap, name, original))
        if not self._patched:
            logger.debug("tokendna_sdk autogen attach: no tools found on agent %r",
                          agent)

    def detach(self) -> None:
        """Restore the original tool callables."""
        for fmap, name, original in self._patched:
            try:
                fmap[name] = original
            except Exception:  # noqa: BLE001
                logger.debug("tokendna_sdk autogen detach failed for %s", name)
        self._patched.clear()

    def finalize(self, *, metadata: dict[str, Any] | None = None) -> None:
        """Issue an attestation and roll the baseline. Call this when
        an agent run completes — AutoGen has no canonical hook so we
        leave it explicit."""
        try:
            self._verifier.finish(metadata=metadata)
        finally:
            self._baseline.record_session(self.agent_id,
                                           list(self._tool_calls))
            self._tool_calls = []

    # ── internals ─────────────────────────────────────────────────────

    def _wrap(self, name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs if self.capture_args else None
            start = time.monotonic()
            score = score_session(self._baseline.get(self.agent_id),
                                    self._tool_calls)
            # Pre-call verify when enforcing — denied calls never run.
            try:
                self._verifier.record_tool_call(
                    name,
                    args=tool_args,
                    duration_ms=None,
                    score=score,
                )
            except Exception:  # noqa: BLE001
                if self.enforce:
                    raise
                logger.debug("tokendna_sdk autogen pre-call emit failed",
                             exc_info=True)
            try:
                return fn(*args, **kwargs)
            finally:
                duration_ms = int((time.monotonic() - start) * 1000)
                self._tool_calls.append(name)
                # Send a follow-up event with the duration; cheap and
                # keeps the hop count honest.
                try:
                    self._verifier.record_tool_call(
                        name,
                        args=None,
                        duration_ms=duration_ms,
                        score=score,
                        metadata={"phase": "complete"},
                    )
                except Exception:  # noqa: BLE001
                    logger.debug("tokendna_sdk autogen post-call emit failed",
                                 exc_info=True)
        return _wrapped

    def _default_client(self) -> Any:
        from .. import make_client
        return make_client()

    def _baselines_path(self) -> str:
        cfg = current_config()
        root = cfg.local_root or str((__import__("pathlib").Path.home() /
                                       ".tokendna"))
        return f"{root}/baselines.json"


__all__ = ["TokenDNAAutoGenMiddleware"]
