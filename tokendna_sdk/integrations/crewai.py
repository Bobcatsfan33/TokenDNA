"""
Native CrewAI callback for TokenDNA.

Install
-------
``pip install "tokendna-sdk[crewai]"``

Usage
-----
.. code-block:: python

    from crewai import Crew, Agent, Task
    from tokendna_sdk.integrations.crewai import TokenDNACrewCallback

    crew = Crew(
        agents=[...],
        tasks=[...],
        step_callback=TokenDNACrewCallback(agent_id="research-crew",
                                            scope=["docs:read"]),
    )

CrewAI's callback surface accepts either a callable or an object with
``__call__``/``on_step``-style methods depending on version. The
callback class implemented here is callable and exposes both
``on_tool_start``/``on_tool_end``/``on_finish`` hooks for newer
versions and ``__call__`` for the classic ``step_callback`` slot.

The class never imports ``crewai`` itself — it duck-types whatever
shape CrewAI hands it. That keeps the SDK install zero-deps and lets
users adopt without pinning a specific CrewAI version.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from .._core.behavioral import BaselineStore, score_session
from .._core.verifier import Verifier
from ..config import current_config

logger = logging.getLogger(__name__)


class TokenDNACrewCallback:
    """CrewAI step callback that records tool calls and emits
    attestations.

    Parameters mirror :class:`TokenDNAMiddleware`. CrewAI invokes
    callbacks at task boundaries (``__call__``) and — in newer versions
    — at tool-call boundaries. We support both: every recognised event
    shape records a hop; unrecognised shapes log at DEBUG and are
    otherwise ignored to keep the wedge contract.
    """

    framework: str = "crewai"

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
        self._call_start: dict[str, float] = {}

    # ── classic step_callback entrypoint ──────────────────────────────

    def __call__(self, step: Any) -> None:
        """Invoked by CrewAI after every step. ``step`` shape depends on
        the CrewAI version; we accept dicts and arbitrary objects."""
        info = _unpack_step(step)
        if info.get("tool"):
            self._record_tool(info)

    # ── newer CrewAI tool-hook surface ────────────────────────────────

    def on_tool_start(self, tool_name: str, tool_input: Any = None,
                       **_: Any) -> None:
        self._call_start[tool_name] = time.monotonic()

    def on_tool_end(self, tool_name: str, output: Any = None,
                     **kwargs: Any) -> None:
        start = self._call_start.pop(tool_name, time.monotonic())
        duration_ms = int((time.monotonic() - start) * 1000)
        args = kwargs.get("tool_input") if self.capture_args else None
        score = score_session(self._baseline.get(self.agent_id),
                                self._tool_calls)
        try:
            self._verifier.record_tool_call(
                tool_name,
                args=args if isinstance(args, dict) else None,
                duration_ms=duration_ms,
                score=score,
            )
        except Exception:  # noqa: BLE001
            logger.debug("tokendna_sdk crewai on_tool_end emit failed",
                         exc_info=True)
        self._tool_calls.append(tool_name)

    def on_finish(self, result: Any = None, **_: Any) -> None:
        try:
            self._verifier.finish(metadata={"crewai_result_present": result is not None})
        finally:
            self._baseline.record_session(self.agent_id,
                                           list(self._tool_calls))
            self._tool_calls = []

    # ── helpers ───────────────────────────────────────────────────────

    def _record_tool(self, info: dict[str, Any]) -> None:
        tool_name = str(info.get("tool", "unknown"))
        args = info.get("tool_input") if self.capture_args else None
        target = str(info.get("target") or "")
        score = score_session(self._baseline.get(self.agent_id),
                                self._tool_calls)
        try:
            self._verifier.record_tool_call(
                tool_name,
                args=args if isinstance(args, dict) else None,
                target=target,
                score=score,
            )
        except Exception:  # noqa: BLE001
            logger.debug("tokendna_sdk crewai __call__ emit failed", exc_info=True)
        self._tool_calls.append(tool_name)

    def _default_client(self) -> Any:
        from .. import make_client
        return make_client()

    def _baselines_path(self) -> str:
        cfg = current_config()
        root = cfg.local_root or str((__import__("pathlib").Path.home() /
                                       ".tokendna"))
        return f"{root}/baselines.json"


def _unpack_step(step: Any) -> dict[str, Any]:
    """Normalize CrewAI's per-step payload into a dict.

    Versions seen in the wild:
      - dict with ``"tool"`` / ``"tool_input"`` / ``"result"``
      - dataclass-style object with ``.tool`` / ``.tool_input``
      - bare string (raw thought) — we ignore those
    """
    if isinstance(step, dict):
        return step
    if step is None or isinstance(step, str):
        return {}
    return {
        "tool": getattr(step, "tool", None) or getattr(step, "tool_name", None),
        "tool_input": getattr(step, "tool_input", None) or getattr(step, "arguments", None),
        "result": getattr(step, "result", None) or getattr(step, "output", None),
        "target": getattr(step, "target", "") or "",
    }


__all__ = ["TokenDNACrewCallback"]
