"""Per-MCP-call SIEM schema + vendor mappings (Gap roadmap Epic 4.2 / B2).

The NSA MCP advisory calls for standardized audit logging of every tool
invocation. This module defines TokenDNA's canonical per-MCP-call event and maps
it to the three SIEMs that matter: Elastic (ECS — the competitive counter named
in the advisory), Splunk (HEC), and Microsoft Sentinel (Log Analytics). Raw tool
params are never exported — only a sha256 hash.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

SUPPORTED_SIEM_TARGETS = ("ecs", "splunk", "sentinel", "canonical")

# Canonical field set (documented via canonical_schema()).
_CANONICAL_FIELDS = {
    "event_id": "str", "timestamp": "iso8601", "tenant_id": "str",
    "agent_id": "str", "session_id": "str", "mcp_server": "str", "tool_name": "str",
    "action": "str", "outcome": "allow|flag|block", "blocked": "bool",
    "risk_score": "float", "reasons": "list[str]", "params_hash": "sha256",
    "inspector_used": "bool", "correlation_id": "str",
}


def canonical_schema() -> dict[str, Any]:
    return {"action": "mcp.tool_call", "fields": dict(_CANONICAL_FIELDS),
            "targets": list(SUPPORTED_SIEM_TARGETS)}


def _params_hash(params: Any) -> str:
    raw = json.dumps(params, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


def normalize_mcp_call(enforcement: dict[str, Any]) -> dict[str, Any]:
    """Map a gateway enforcement record to the canonical per-MCP-call event."""
    outcome = enforcement.get("outcome", "allow")
    return {
        "event_id": enforcement.get("enforcement_id", ""),
        "timestamp": enforcement.get("created_at") or datetime.now(timezone.utc).isoformat(),
        "tenant_id": enforcement.get("tenant_id", ""),
        "agent_id": enforcement.get("agent_id", ""),
        "session_id": enforcement.get("session_id", ""),
        "mcp_server": enforcement.get("server_id", ""),
        "tool_name": enforcement.get("tool_name", ""),
        "action": "mcp.tool_call",
        "outcome": outcome,
        "blocked": bool(enforcement.get("blocked", outcome == "block")),
        "risk_score": float(enforcement.get("risk_score", 0.0)),
        "reasons": list(enforcement.get("reasons", []) or []),
        "params_hash": _params_hash(enforcement.get("params", {})),
        "inspector_used": bool(enforcement.get("inspector_used", False)),
        "correlation_id": enforcement.get("correlation_id") or enforcement.get("session_id", ""),
    }


# ── Vendor mappings ───────────────────────────────────────────────────────────

def to_ecs(event: dict[str, Any]) -> dict[str, Any]:
    """Elastic Common Schema (ECS) document."""
    return {
        "@timestamp": event["timestamp"],
        "ecs": {"version": "8.11"},
        "event": {
            "id": event["event_id"],
            "action": event["action"],
            "kind": "event",
            "category": ["intrusion_detection"],
            "type": ["denied"] if event["blocked"] else ["allowed"],
            "outcome": "failure" if event["blocked"] else "success",
            "risk_score": event["risk_score"],
            "reason": "; ".join(event["reasons"]),
        },
        "user": {"id": event["agent_id"]},
        "organization": {"id": event["tenant_id"]},
        "service": {"name": event["mcp_server"], "type": "mcp"},
        "labels": {
            "tokendna_tool": event["tool_name"],
            "tokendna_session_id": event["session_id"],
            "tokendna_blocked": event["blocked"],
            "tokendna_params_hash": event["params_hash"],
            "tokendna_inspector_used": event["inspector_used"],
        },
        "trace": {"id": event["correlation_id"]},
        "message": f"MCP tool call {event['tool_name']} on {event['mcp_server']} -> {event['outcome']}",
    }


def to_splunk(event: dict[str, Any]) -> dict[str, Any]:
    """Splunk HTTP Event Collector (HEC) envelope with a flat event payload."""
    return {
        "time": _epoch(event["timestamp"]),
        "source": "tokendna",
        "sourcetype": "tokendna:mcp:call",
        "event": {
            "event_id": event["event_id"],
            "action": event["action"],
            "tenant_id": event["tenant_id"],
            "agent_id": event["agent_id"],
            "session_id": event["session_id"],
            "mcp_server": event["mcp_server"],
            "tool_name": event["tool_name"],
            "outcome": event["outcome"],
            "blocked": event["blocked"],
            "risk_score": event["risk_score"],
            "reasons": event["reasons"],
            "params_hash": event["params_hash"],
            "inspector_used": event["inspector_used"],
            "correlation_id": event["correlation_id"],
        },
    }


def to_sentinel(event: dict[str, Any]) -> dict[str, Any]:
    """Microsoft Sentinel / Log Analytics custom-log record (PascalCase)."""
    return {
        "TimeGenerated": event["timestamp"],
        "EventId": event["event_id"],
        "Action": event["action"],
        "TenantId": event["tenant_id"],
        "AgentId": event["agent_id"],
        "SessionId": event["session_id"],
        "McpServer": event["mcp_server"],
        "ToolName": event["tool_name"],
        "Outcome": event["outcome"],
        "Blocked": event["blocked"],
        "RiskScore": event["risk_score"],
        "Reasons": event["reasons"],
        "ParamsHash": event["params_hash"],
        "InspectorUsed": event["inspector_used"],
        "CorrelationId": event["correlation_id"],
    }


_MAPPERS = {"ecs": to_ecs, "splunk": to_splunk, "sentinel": to_sentinel}


def export_event(event: dict[str, Any], target: str) -> dict[str, Any]:
    """Render a canonical event for a target SIEM ('canonical' = passthrough)."""
    target = target.lower()
    if target == "canonical":
        return event
    mapper = _MAPPERS.get(target)
    if mapper is None:
        raise ValueError(f"unsupported SIEM target '{target}'; supported: {', '.join(SUPPORTED_SIEM_TARGETS)}")
    return mapper(event)


def export_mcp_calls(*, tenant_id: str, target: str = "ecs", limit: int = 100,
                     session_id: str | None = None) -> list[dict[str, Any]]:
    """Pull recent gateway enforcements and render them for a SIEM target."""
    from modules.identity import mcp_gateway
    enforcements = mcp_gateway.list_enforcements(tenant_id, session_id=session_id, limit=limit)
    return [export_event(normalize_mcp_call(e), target) for e in enforcements]
