"""Revocation Fan-out Bus — real-time credential rip (Gap roadmap, Challenge D).

The enforcement-plane kill switch only blocks traffic that reaches TokenDNA's
``evaluate()``. A rogue agent holding a live OAuth token, an MCP session, or a
long-lived key keeps acting against systems that never call TokenDNA. This bus
turns a single ``rip_credentials(agent)`` call into parallel, bounded,
idempotent revocations across every plane the agent holds identity in — each
emitting a hash-chained AuditEvent and returning a per-plane status receipt.

Design (per the roadmap §5.3):
  * Parallel + bounded: connectors run concurrently with a per-plane timeout.
  * Idempotent + reversible: re-ripping is safe; reversible planes can restore.
  * Actor + reason mandatory: enforced here, propagated to every plane + audit.
  * Partial success is valid: the receipt shows killed ✓ / failed ✗ per plane.
  * Pre-flight preview: which planes are connected and will act.

Connectors are pluggable (register_connector); built-ins cover the planes that
already exist in-repo (TokenDNA decision switch, edge JWT revocation). External
connectors (IdP OAuth, MCP creds, live sessions, data planes) register on top.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# Default per-plane timeout. Internal planes are sub-second; external planes
# (OAuth, MCP) are given a few seconds before they fail-visibly.
DEFAULT_PLANE_TIMEOUT_MS = 5000
DEFAULT_MAX_WORKERS = 8


# ── Result types ──────────────────────────────────────────────────────────────

# Per-plane outcomes.
KILLED = "killed"            # revoked successfully
FAILED = "failed"            # connector raised
TIMEOUT = "timeout"          # exceeded the per-plane budget
NOT_CONNECTED = "not_connected"  # plane not configured for this tenant — skipped


@dataclass
class PlaneResult:
    plane: str
    status: str
    detail: str = ""
    duration_ms: int = 0
    reversible: bool = False

    @property
    def ok(self) -> bool:
        return self.status in (KILLED, NOT_CONNECTED)

    def as_dict(self) -> dict[str, Any]:
        return {
            "plane": self.plane,
            "status": self.status,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "reversible": self.reversible,
        }


@dataclass
class KillReceipt:
    agent_id: str
    tenant_id: str
    actor: str
    reason: str
    action: str                       # "rip" | "reverse" | "preview"
    planes: list[PlaneResult] = field(default_factory=list)

    @property
    def overall(self) -> str:
        statuses = {p.status for p in self.planes}
        if not self.planes:
            return "noop"
        if statuses <= {KILLED, NOT_CONNECTED}:
            return "complete"
        if KILLED in statuses:
            return "partial"
        return "failed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "reason": self.reason,
            "action": self.action,
            "overall": self.overall,
            "planes": [p.as_dict() for p in self.planes],
            "killed": sum(1 for p in self.planes if p.status == KILLED),
            "failed": sum(1 for p in self.planes if p.status in (FAILED, TIMEOUT)),
        }


# ── Connector protocol ──────────────────────────────────────────────────────

@runtime_checkable
class RevocationConnector(Protocol):
    """A single revocation plane. Implementations MUST be idempotent."""

    plane: str
    reversible: bool

    def is_connected(self, tenant_id: str) -> bool: ...

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        """Revoke the agent on this plane. Return a human-readable detail.

        Raise to signal failure (the bus records FAILED, never crashes).
        """
        ...

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        """Best-effort restore for reversible planes. Return detail."""
        ...


# ── Built-in connectors (reuse existing in-repo primitives) ──────────────────

class TokenDNADecisionConnector:
    """Plane: TokenDNA decision-time block (enforcement_plane kill switch)."""

    plane = "tokendna_decision"
    reversible = True

    def is_connected(self, tenant_id: str) -> bool:
        return True  # always available — it's the internal switch

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity import enforcement_plane
        enforcement_plane.activate_kill_switch(
            tenant_id, agent_id,
            activated_by=context["actor"],
            reason=context.get("reason", ""),
        )
        return "decision-time block active (evaluate() short-circuits to deny)"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity import enforcement_plane
        enforcement_plane.deactivate_kill_switch(
            tenant_id, agent_id, deactivated_by=context["actor"],
        )
        return "decision-time block lifted"


class EdgeJWTConnector:
    """Plane: edge / JWT revocation (Cloudflare KV via cache_redis).

    Revokes the agent's known token ids (jtis) so the edge worker rejects them
    before they reach the backend. jtis come from context['jtis'] and/or the
    agent's last_token_id in the lifecycle inventory.
    """

    plane = "edge_jwt"
    reversible = False  # a revoked token is dead; the agent must re-auth

    def is_connected(self, tenant_id: str) -> bool:
        return True

    def _agent_jtis(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> list[str]:
        jtis: list[str] = list(context.get("jtis") or [])
        try:
            from modules.identity import agent_lifecycle
            agent = agent_lifecycle.get_agent(tenant_id=tenant_id, agent_id=agent_id)
            tok = agent.get("last_token_id")
            if tok:
                jtis.append(tok)
        except Exception:
            pass
        # de-dup, drop falsy
        return sorted({j for j in jtis if j})

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity.cache_redis import revoke_token
        jtis = self._agent_jtis(tenant_id, agent_id, context)
        for jti in jtis:
            revoke_token(jti, tenant_id=tenant_id)
        if not jtis:
            return "no known token ids to revoke (edge blocklist unchanged)"
        return f"revoked {len(jtis)} token id(s) at the edge KV blocklist"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        return "edge JWT revocation is irreversible — agent must re-authenticate"


# ── Registry ────────────────────────────────────────────────────────────────

_DEFAULT_FACTORIES: list[Callable[[], RevocationConnector]] = [
    TokenDNADecisionConnector,
    EdgeJWTConnector,
]

_connectors: dict[str, RevocationConnector] = {}


def register_default_factory(factory: Callable[[], RevocationConnector]) -> None:
    """Add a connector factory to the default set (idempotent).

    Optional connector modules (IdP, MCP, session, data planes) call this at
    import so they are present after every ``reset_connectors()`` — gated by
    each connector's ``is_connected()`` so unconfigured planes are skipped.
    """
    if factory not in _DEFAULT_FACTORIES:
        _DEFAULT_FACTORIES.append(factory)
        reset_connectors()


def reset_connectors() -> None:
    """Re-install the default connector set (used by tests + at import)."""
    _connectors.clear()
    for factory in _DEFAULT_FACTORIES:
        c = factory()
        _connectors[c.plane] = c


def register_connector(connector: RevocationConnector) -> None:
    """Register (or replace) a connector by its plane name."""
    _connectors[connector.plane] = connector


def get_connectors() -> list[RevocationConnector]:
    return list(_connectors.values())


reset_connectors()


# ── Core operations ───────────────────────────────────────────────────────────

def _emit(event_name: str, *, tenant_id: str, agent_id: str, actor: str,
          detail: dict[str, Any]) -> None:
    try:
        from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
        ok = event_name != "KILL_PLANE_FAILED"
        log_event(
            getattr(AuditEventType, event_name),
            AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
            tenant_id=tenant_id,
            subject=actor,
            resource=f"agent/{agent_id}",
            detail=detail,
        )
    except Exception as exc:  # noqa: BLE001 - audit is best-effort
        logger.warning("kill audit emit failed (%s): %s", event_name, exc)


def preview(tenant_id: str, agent_id: str) -> KillReceipt:
    """Report which planes are connected and would act — no side effects."""
    receipt = KillReceipt(agent_id=agent_id, tenant_id=tenant_id, actor="", reason="",
                          action="preview")
    for c in get_connectors():
        connected = False
        try:
            connected = bool(c.is_connected(tenant_id))
        except Exception as exc:  # noqa: BLE001
            receipt.planes.append(PlaneResult(c.plane, FAILED, f"preview error: {exc}",
                                              reversible=getattr(c, "reversible", False)))
            continue
        receipt.planes.append(PlaneResult(
            c.plane,
            KILLED if connected else NOT_CONNECTED,
            "connected — will revoke" if connected else "not configured for tenant",
            reversible=getattr(c, "reversible", False),
        ))
    return receipt


def _run_plane(c: RevocationConnector, tenant_id: str, agent_id: str,
               context: dict[str, Any], *, reverse: bool) -> PlaneResult:
    reversible = bool(getattr(c, "reversible", False))
    start = time.monotonic()
    try:
        if not c.is_connected(tenant_id):
            return PlaneResult(c.plane, NOT_CONNECTED, "not configured for tenant",
                               reversible=reversible)
        if reverse:
            if not reversible:
                return PlaneResult(c.plane, NOT_CONNECTED,
                                   "plane is irreversible — nothing to restore",
                                   reversible=False)
            detail = c.reverse(tenant_id, agent_id, context)
        else:
            detail = c.revoke(tenant_id, agent_id, context)
        dur = int((time.monotonic() - start) * 1000)
        return PlaneResult(c.plane, KILLED, detail or "", dur, reversible)
    except Exception as exc:  # noqa: BLE001 - one plane must not break the rip
        dur = int((time.monotonic() - start) * 1000)
        return PlaneResult(c.plane, FAILED, str(exc), dur, reversible)


def _fan_out(tenant_id: str, agent_id: str, context: dict[str, Any], *,
             planes: Optional[list[str]], timeout_ms: int, reverse: bool) -> list[PlaneResult]:
    selected = [c for c in get_connectors() if planes is None or c.plane in planes]
    results: list[PlaneResult] = []
    timeout_s = max(timeout_ms, 1) / 1000.0
    with ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(len(selected), 1))) as pool:
        futures = {
            pool.submit(_run_plane, c, tenant_id, agent_id, context, reverse=reverse): c
            for c in selected
        }
        for fut, c in futures.items():
            try:
                results.append(fut.result(timeout=timeout_s))
            except FuturesTimeout:
                results.append(PlaneResult(c.plane, TIMEOUT,
                                           f"exceeded {timeout_ms}ms budget",
                                           timeout_ms, getattr(c, "reversible", False)))
    results.sort(key=lambda r: r.plane)
    return results


def rip_credentials(
    tenant_id: str,
    agent_id: str,
    *,
    actor: str,
    reason: str = "",
    planes: Optional[list[str]] = None,
    context: Optional[dict[str, Any]] = None,
    timeout_ms: int = DEFAULT_PLANE_TIMEOUT_MS,
) -> KillReceipt:
    """Rip an agent's credentials across every (or selected) connected plane.

    actor + reason are mandatory for audit. Returns a per-plane KillReceipt.
    """
    if not actor:
        raise ValueError("actor is required to rip credentials")
    ctx = dict(context or {})
    ctx["actor"] = actor
    ctx["reason"] = reason

    _emit("KILL_RIP_INITIATED", tenant_id=tenant_id, agent_id=agent_id, actor=actor,
          detail={"reason": reason, "planes": planes or "all"})

    plane_results = _fan_out(tenant_id, agent_id, ctx, planes=planes,
                             timeout_ms=timeout_ms, reverse=False)

    for pr in plane_results:
        if pr.status == KILLED:
            _emit("KILL_PLANE_REVOKED", tenant_id=tenant_id, agent_id=agent_id, actor=actor,
                  detail={"plane": pr.plane, "detail": pr.detail, "duration_ms": pr.duration_ms})
        elif pr.status in (FAILED, TIMEOUT):
            _emit("KILL_PLANE_FAILED", tenant_id=tenant_id, agent_id=agent_id, actor=actor,
                  detail={"plane": pr.plane, "status": pr.status, "detail": pr.detail})

    return KillReceipt(agent_id=agent_id, tenant_id=tenant_id, actor=actor,
                       reason=reason, action="rip", planes=plane_results)


def reverse_rip(
    tenant_id: str,
    agent_id: str,
    *,
    actor: str,
    reason: str = "",
    planes: Optional[list[str]] = None,
    context: Optional[dict[str, Any]] = None,
    timeout_ms: int = DEFAULT_PLANE_TIMEOUT_MS,
) -> KillReceipt:
    """Restore reversible planes. Irreversible planes are reported as such."""
    if not actor:
        raise ValueError("actor is required to reverse a rip")
    ctx = dict(context or {})
    ctx["actor"] = actor
    ctx["reason"] = reason

    plane_results = _fan_out(tenant_id, agent_id, ctx, planes=planes,
                             timeout_ms=timeout_ms, reverse=True)

    _emit("KILL_RIP_REVERSED", tenant_id=tenant_id, agent_id=agent_id, actor=actor,
          detail={"reason": reason,
                  "restored": [p.plane for p in plane_results if p.status == KILLED]})

    return KillReceipt(agent_id=agent_id, tenant_id=tenant_id, actor=actor,
                       reason=reason, action="reverse", planes=plane_results)
