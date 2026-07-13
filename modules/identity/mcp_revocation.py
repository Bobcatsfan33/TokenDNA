"""MCP credential revocation connector for the kill switch (Epic 2.2 / B4).

On kill, the gateway revokes the agent's brokered MCP credentials, disables its
tool grants, and closes its open MCP sessions — so a rogue agent loses its MCP
reach immediately, not just at TokenDNA's decision point.
"""
from __future__ import annotations

from typing import Any

from modules.identity import mcp_gateway, revocation_bus


class MCPCredentialConnector:
    plane = "mcp"
    reversible = False  # credentials are pulled; tool grants must be re-granted

    def is_connected(self, tenant_id: str) -> bool:
        # The gateway is an internal plane — always available. revoke() reports
        # "nothing to revoke" when the agent holds no MCP grants.
        return True

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        result = mcp_gateway.revoke_agent_mcp(
            tenant_id=tenant_id, agent_id=agent_id, revoked_by=context["actor"],
        )
        c, g, s = (result["credentials_revoked"], result["tool_grants_disabled"],
                   result["sessions_closed"])
        if not (c or g or s):
            return "no MCP credentials, tool grants, or sessions for agent"
        return f"mcp: revoked {c} credential(s), disabled {g} tool grant(s), closed {s} session(s)"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        return "MCP credentials were pulled — tool grants must be re-issued"


revocation_bus.register_default_factory(MCPCredentialConnector)
