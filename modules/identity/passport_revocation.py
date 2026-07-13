"""Passport revocation connector for the kill switch (P2.1).

The passport is the agent's credential of record — the thing a verifier checks
to answer "is this a legitimate agent identity?". Ripping the decision switch,
the edge JWT, the IdP token, MCP credentials and live sessions still leaves an
ISSUED passport behind, and an ISSUED passport says the agent is trustworthy.
Any verifier holding it — including TokenDNA's own verify path — keeps saying
yes. This connector closes that gap: on kill, every passport the agent holds
that still confers trust is revoked, with the kill reason recorded on it.
"""
from __future__ import annotations

from typing import Any

from modules.identity import revocation_bus

# Only these statuses confer trust; PENDING/EXPIRED passports are already inert.
_TRUST_CONFERRING = ("ISSUED", "APPROVED")


class PassportConnector:
    plane = "passport"
    reversible = False  # a revoked passport is dead — re-issue requires re-attestation

    def is_connected(self, tenant_id: str) -> bool:
        return True  # internal plane — the passport store is always present

    def revoke(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        from modules.identity import passport

        reason = context.get("reason") or "credential rip"
        revoked = 0
        already = 0

        for p in passport.list_passports(tenant_id=tenant_id, agent_id=agent_id,
                                         limit=200):
            if p.status == passport.PassportStatus.REVOKED:
                already += 1
                continue
            if p.status.name not in _TRUST_CONFERRING:
                continue
            passport.revoke_passport(p.passport_id, f"kill switch: {reason}")
            revoked += 1

        if revoked:
            suffix = f" ({already} already revoked)" if already else ""
            return f"revoked {revoked} passport(s){suffix}"
        if already:
            return f"passport(s) already revoked ({already}) — idempotent no-op"
        return "no active passports for agent"

    def reverse(self, tenant_id: str, agent_id: str, context: dict[str, Any]) -> str:
        return "a revoked passport is irreversible — re-issue requires re-attestation"


revocation_bus.register_default_factory(PassportConnector)
