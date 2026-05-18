"""
MCP (Model Context Protocol) tool-call interceptor.

What this gives you
-------------------
A thin proxy that sits between an MCP client (Claude Desktop, an
agent, etc.) and one or more upstream MCP servers. Every tool call
flowing through the proxy is:

1. Stamped with an agent identity + scope.
2. Recorded as a :class:`ToolCallEvent` via the configured
   :class:`tokendna_sdk.client.TokenDNAClient` /
   :class:`TokenDNALocalClient`.
3. Optionally enforced against a chain-pattern allowlist (e.g. flag
   ``read_file -> send_email`` exfil shapes via
   :func:`tokendna_sdk._core.behavioral.detect_chain`).
4. Scored against the per-agent behavioral baseline.

Install
-------
``pip install "tokendna-sdk[mcp]"``

Usage — programmatic
--------------------

.. code-block:: python

    from tokendna_sdk.integrations.mcp import TokenDNAMCPProxy

    proxy = TokenDNAMCPProxy(
        agent_id="claude-desktop",
        scope=["filesystem:read", "web:fetch"],
        deny_chains=[["read_file", "send_email"],
                      ["read_secret", "post_url"]],
    )
    response = proxy.handle_tool_call({
        "name": "read_file",
        "arguments": {"path": "/etc/passwd"},
    }, upstream=upstream_fn)

Usage — wrapper
---------------

.. code-block:: python

    from tokendna_sdk.integrations.mcp import secure_mcp_server

    @secure_mcp_server(agent_id="claude-desktop",
                       scope=["filesystem:read"])
    def my_mcp_server(request): ...

The function returned by ``secure_mcp_server`` looks identical to the
original — same signature, same return type — but every call goes
through the proxy first.

Design
------
- No MCP server dependency at import time. The ``mcp`` package is
  imported lazily inside the optional ``run_server`` helper; the
  proxy itself is pure stdlib + the SDK core.
- The proxy is *advisory* by default. ``enforce=True`` makes denied
  chains raise :class:`TokenDNAVerificationError`; otherwise the
  proxy emits and lets the call proceed.
- We hash arguments before emitting so the proxy doesn't leak
  secrets via instrumentation. Opt in via ``capture_args=True`` for
  debugging (don't ship that to production).
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable

from .._core.behavioral import BaselineStore, detect_chain, score_session
from .._core.verifier import Verifier
from ..config import current_config
from ..exceptions import TokenDNAVerificationError
from ..models import PolicyVerdict

logger = logging.getLogger(__name__)


class TokenDNAMCPProxy:
    """Wrap MCP tool-call dispatch with TokenDNA telemetry + policy.

    Parameters mirror the LangChain middleware adapter, plus:

    deny_chains:
        List of ordered tool-name patterns to flag. Each pattern is
        matched as a bounded-gap subsequence against the recent tool
        history; matches are emitted with ``decision="deny"`` and (when
        ``enforce=True``) raise :class:`TokenDNAVerificationError`.
    max_chain_gap:
        Tolerance for ``deny_chains`` matching — how many unrelated
        tool calls may appear between consecutive pattern elements
        before we give up. Default 3.
    """

    framework: str = "mcp"

    def __init__(
        self,
        *,
        agent_id: str,
        scope: list[str] | None = None,
        client: Any | None = None,
        enforce: bool = False,
        capture_args: bool = False,
        deny_chains: list[list[str]] | None = None,
        max_chain_gap: int = 3,
    ) -> None:
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        self.agent_id = agent_id
        self.scope = list(scope or [])
        self.capture_args = capture_args
        self.enforce = enforce
        self.deny_chains = [list(p) for p in (deny_chains or [])]
        self.max_chain_gap = max_chain_gap
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

    # ── public surface ────────────────────────────────────────────────

    def handle_tool_call(
        self,
        request: dict[str, Any],
        *,
        upstream: Callable[[dict[str, Any]], Any] | None = None,
    ) -> Any:
        """Run one MCP tool call through the proxy.

        Parameters
        ----------
        request:
            A dict shaped like ``{"name": "...", "arguments": {...}}``
            — the canonical MCP tool-call envelope.
        upstream:
            Optional callable invoked to actually execute the tool. If
            omitted, the proxy just records and returns ``None``.

        Returns whatever ``upstream`` returned. Raises
        :class:`TokenDNAVerificationError` when ``enforce=True`` and
        the call hits a deny chain or the underlying client denies it.
        """
        name = str(request.get("name") or request.get("tool") or "unknown")
        args = request.get("arguments") or request.get("args") or {}
        target = str(request.get("target") or "")

        # Chain-pattern check happens BEFORE we record the call so the
        # event metadata can carry the verdict.
        chain_verdict = self._chain_verdict(name)
        score = max(
            score_session(self._baseline.get(self.agent_id),
                            self._tool_calls + [name]),
            chain_verdict.score if chain_verdict else 0.0,
        )

        try:
            self._verifier.record_tool_call(
                name,
                args=args if self.capture_args else None,
                target=target,
                score=score,
                metadata=({"chain_match": chain_verdict.reason}
                          if chain_verdict else {}),
            )
        except TokenDNAVerificationError:
            # Server-side deny; surface it.
            raise

        if chain_verdict and chain_verdict.decision == "deny" and self.enforce:
            raise TokenDNAVerificationError(
                f"mcp chain denied: {chain_verdict.reason}",
                verdict=chain_verdict,
            )

        self._tool_calls.append(name)

        if upstream is None:
            return None
        start = time.monotonic()
        try:
            return upstream(request)
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                self._verifier.record_tool_call(
                    name,
                    args=None,
                    target=target,
                    duration_ms=duration_ms,
                    score=score,
                    metadata={"phase": "complete"},
                )
            except Exception:  # noqa: BLE001
                logger.debug("tokendna_sdk mcp post-call emit failed",
                             exc_info=True)

    def finish(self, *, metadata: dict[str, Any] | None = None) -> Any:
        """Issue an attestation receipt for the proxy's accumulated hops."""
        try:
            return self._verifier.finish(metadata=metadata)
        finally:
            self._baseline.record_session(self.agent_id,
                                           list(self._tool_calls))
            self._tool_calls = []

    # ── helpers ───────────────────────────────────────────────────────

    def _chain_verdict(self, next_tool: str) -> PolicyVerdict | None:
        if not self.deny_chains:
            return None
        history = self._tool_calls + [next_tool]
        for pattern in self.deny_chains:
            if detect_chain(history, pattern, max_gap=self.max_chain_gap):
                reason = "chain:" + "->".join(pattern)
                return PolicyVerdict(
                    decision="deny",
                    reason=reason,
                    message=f"deny chain matched: {reason}",
                    score=1.0,
                )
        return None

    def _default_client(self) -> Any:
        from .. import make_client
        return make_client()

    def _baselines_path(self) -> str:
        cfg = current_config()
        root = cfg.local_root or str((__import__("pathlib").Path.home() /
                                       ".tokendna"))
        return f"{root}/baselines.json"


# ── secure_mcp_server decorator ───────────────────────────────────────────────

def secure_mcp_server(
    *,
    agent_id: str,
    scope: list[str] | None = None,
    client: Any | None = None,
    enforce: bool = False,
    capture_args: bool = False,
    deny_chains: list[list[str]] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps an MCP server handler with the proxy.

    The decorated function must accept the canonical
    ``{"name": ..., "arguments": ...}`` MCP tool-call dict and return
    the tool result. The proxy is *per-server* — every request
    routed through this handler shares one identity and one baseline.

    .. code-block:: python

        @secure_mcp_server(agent_id="claude-desktop",
                           scope=["filesystem:read"])
        def server(request):
            return run_tool(request)
    """
    proxy = TokenDNAMCPProxy(
        agent_id=agent_id,
        scope=scope,
        client=client,
        enforce=enforce,
        capture_args=capture_args,
        deny_chains=deny_chains,
    )

    def _decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def _wrapped(request: dict[str, Any], *a: Any, **kw: Any) -> Any:
            def _upstream(req: dict[str, Any]) -> Any:
                return fn(req, *a, **kw)
            return proxy.handle_tool_call(request, upstream=_upstream)
        _wrapped.tokendna_proxy = proxy  # type: ignore[attr-defined]
        return _wrapped

    return _decorate


__all__ = ["TokenDNAMCPProxy", "secure_mcp_server"]
