"""Trust-graph revocation connector for the kill switch (P2.1).

The other planes stop the agent acting. This one makes the containment *legible*:
an operator staring at a blast-radius graph needs the node at the centre of it to
show as already contained, and the incident feed needs to record that containment
happened. On kill, the agent's node is marked revoked and a CRITICAL
AGENT_CREDENTIALS_REVOKED anomaly is raised.

Reversible: the mark is an annotation, so reversing a rip lifts it.
"""
from __future__ import annotations

from typing import Any

from modules.identity import revocation_bus


class TrustGraphConnector:
    plane = "trust_graph"
    reversible = True

    def is_connected(self, tenant_id: str) -> bool:
        return True  # internal plane — the graph is always present

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity import trust_graph

        marked = trust_graph.mark_agent_revoked(
            tenant_id, agent_id,
            actor=context["actor"],
            reason=context.get("reason", ""),
        )
        if not marked:
            return "agent not present in the trust graph — nothing to mark"
        return "agent node marked revoked; AGENT_CREDENTIALS_REVOKED anomaly raised"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity import trust_graph

        cleared = trust_graph.clear_agent_revoked(
            tenant_id, agent_id, actor=context["actor"],
        )
        if not cleared:
            return "agent not present in the trust graph — nothing to clear"
        return "revocation mark lifted from the agent node"


revocation_bus.register_default_factory(TrustGraphConnector)
