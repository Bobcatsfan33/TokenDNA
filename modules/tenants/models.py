"""
TokenDNA — Tenant models
Tenants are the top-level billing/isolation unit (a company or team).
Each tenant has one or more API keys. Keys are stored hashed; raw values
are shown exactly once at creation time.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Plan(str, Enum):
    FREE       = "free"        # 10k events/month, 1 user
    STARTER    = "starter"     # 100k events/month, 5 users
    PRO        = "pro"         # 1M events/month, unlimited users
    ENTERPRISE = "enterprise"  # unlimited, SLA, SAML SSO


@dataclass
class Tenant:
    id:         str
    name:       str
    plan:       Plan
    is_active:  bool
    created_at: datetime
    # optional contact info
    owner_email: str = ""

    @staticmethod
    def new(name: str, owner_email: str = "", plan: Plan = Plan.FREE) -> "Tenant":
        return Tenant(
            id=str(uuid.uuid4()),
            name=name,
            plan=plan,
            is_active=True,
            created_at=datetime.utcnow(),
            owner_email=owner_email,
        )


@dataclass
class ApiKey:
    """
    Represents one API key belonging to a tenant.
    `key_hash` is SHA-256(raw_key) — the raw key is NEVER stored.
    The prefix (first 8 chars) is stored in plaintext for display/lookup.
    """
    id:         str
    tenant_id:  str
    name:       str          # human label e.g. "production", "ci-pipeline"
    key_prefix: str          # first 8 chars of raw key, for display
    key_hash:   str          # SHA-256 of raw key
    is_active:  bool
    created_at: datetime
    last_used:  datetime | None = None

    # ── class helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def generate(tenant_id: str, name: str) -> tuple["ApiKey", str]:
        """
        Generate a new key. Returns (ApiKey record, raw_key).
        Caller must show raw_key to the user — it will not be recoverable.
        """
        raw    = "tdna_" + secrets.token_urlsafe(32)   # ~43 chars of entropy
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        record = ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            key_prefix=raw[:12],
            key_hash=hashed,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        return record, raw

    @staticmethod
    def hash(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()


@dataclass
class TenantContext:
    """Injected into every authenticated request."""
    tenant_id:  str
    tenant_name: str
    plan:       Plan
    api_key_id: str
