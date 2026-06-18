"""Live-session kill connector for the kill switch (Gap roadmap Epic 2.3)."""
from __future__ import annotations

from typing import Any

from modules.identity import revocation_bus, session_registry


class LiveSessionConnector:
    plane = "live_sessions"
    reversible = False  # a terminated session is dead; the agent must reconnect

    def is_connected(self, tenant_id: str) -> bool:
        return True  # internal plane — always available

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        res = session_registry.terminate_agent_sessions(
            tenant_id, agent_id, terminated_by=context["actor"],
        )
        n = res["sessions_terminated"]
        return f"terminated {n} live session(s)" if n else "no live sessions for agent"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        return "terminated sessions cannot be restored — agent must reconnect"


revocation_bus.register_default_factory(LiveSessionConnector)
