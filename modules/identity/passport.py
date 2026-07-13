"""
TokenDNA -- Cross-Vendor Agent Identity Passport (Sprint 3-1)

An Agent Identity Passport is a signed, portable bundle that encodes:
  - Agent identity (agent_id, owner_org, agent_dna_fingerprint)
  - Attestation scope (what the agent is permitted to do)
  - Issuer metadata (who issued, when, with what key)
  - Validity window (not_before / not_after)
  - Revocation URL (where to check live status)

Passports are issued by the TokenDNA Trust Authority, cryptographically
signed (HMAC-SHA256 over canonical JSON — no external PKI required), and
verified by any party with access to the verification endpoint.

Passport IDs follow the format: tdn-pass-<uuid4>

Cross-vendor integration playbooks are provided for:
  - AWS Bedrock agents
  - Azure OpenAI
  - Anthropic API
  - OpenAI API

Revenue model: separate SKU, per-passport issuance pricing.
ADR: docs/adr/ADR-006-agent-identity-passport.md
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

from modules.storage.pg_connection import AdaptedCursor, get_db_conn


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PASSPORT_SIGNING_SECRET = os.getenv(
    "PASSPORT_SIGNING_SECRET",
    "tokendna-passport-dev-secret-change-in-production",
)
_PASSPORT_VALIDITY_DAYS = int(os.getenv("PASSPORT_VALIDITY_DAYS", "90"))
_PASSPORT_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")
_PASSPORT_ISSUER_URL = os.getenv(
    "PASSPORT_ISSUER_URL", "https://trust.tokendna.io"
)

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PassportStatus(str, Enum):
    PENDING = "pending"       # Evidence submitted, awaiting approval
    APPROVED = "approved"     # Approved, ready for issuance
    ISSUED = "issued"         # Active, signed passport delivered
    REVOKED = "revoked"       # Revoked by operator
    EXPIRED = "expired"       # Past not_after timestamp


class VendorPlatform(str, Enum):
    AWS_BEDROCK = "aws_bedrock"
    AZURE_OPENAI = "azure_openai"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PassportSubject:
    """Identity of the agent the passport is issued for."""
    agent_id: str
    owner_org: str
    display_name: str
    agent_dna_fingerprint: str
    model_fingerprint: str | None = None


@dataclass
class PassportScope:
    """What the agent is permitted to do."""
    permissions: list[str]          # e.g. ["read:data", "write:events"]
    resource_patterns: list[str]    # e.g. ["arn:aws:bedrock:*", "openai://gpt-4*"]
    delegation_depth: int = 0       # max chain depth (0 = leaf, no delegation)
    custom_claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class PassportIssuer:
    """Who issued the passport."""
    issuer_id: str
    issuer_name: str
    issuer_url: str
    key_id: str
    issued_by: str     # operator user who approved


@dataclass
class Passport:
    """The complete, signed Agent Identity Passport artifact."""
    passport_id: str
    subject: PassportSubject
    scope: PassportScope
    issuer: PassportIssuer
    not_before: str      # ISO-8601 UTC
    not_after: str       # ISO-8601 UTC
    revocation_url: str
    status: PassportStatus
    signature: str       # HMAC-SHA256 over canonical JSON of the unsigned payload
    created_at: str
    issued_at: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    tenant_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "passport_id": self.passport_id,
            "subject": asdict(self.subject),
            "scope": asdict(self.scope),
            "issuer": asdict(self.issuer),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "revocation_url": self.revocation_url,
            "status": self.status.value,
            "signature": self.signature,
            "created_at": self.created_at,
            "issued_at": self.issued_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "tenant_id": self.tenant_id,
        }
        return d

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        return (
            self.status == PassportStatus.ISSUED
            and self.not_before <= now <= self.not_after
        )

    def trust_score(self) -> float:
        """Return a 0.0–1.0 trust score based on scope and validity."""
        if not self.is_valid():
            return 0.0
        # Start at 0.5, reduce for wide scope, boost for narrow scope
        base = 0.5
        perm_count = len(self.scope.permissions)
        pattern_count = len(self.scope.resource_patterns)
        delegation = self.scope.delegation_depth

        # Narrow scope = higher trust
        scope_penalty = min(perm_count * 0.03 + pattern_count * 0.02, 0.2)
        delegation_penalty = min(delegation * 0.05, 0.15)
        score = base - scope_penalty - delegation_penalty + 0.15  # issuer bonus
        return max(0.0, min(1.0, round(score, 3)))


# ---------------------------------------------------------------------------
# Evidence submission (pre-issuance)
# ---------------------------------------------------------------------------


@dataclass
class EvidenceBundle:
    """Operator-submitted evidence package for passport issuance."""
    evidence_id: str
    passport_id: str
    tenant_id: str
    submitted_by: str
    submitted_at: str
    evidence_type: str   # "attestation_record" | "audit_log" | "manual" | "api_key_proof"
    evidence_ref: str    # attestation_id or free-text reference
    notes: str | None = None
    status: str = "pending"  # pending | accepted | rejected


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sign_passport(payload: dict[str, Any]) -> str:
    """HMAC-SHA256 over canonical JSON of the passport payload (minus signature field)."""
    msg = _canonical_json(payload).encode("utf-8")
    secret = _PASSPORT_SIGNING_SECRET.encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def _verify_signature(payload: dict[str, Any], signature: str) -> bool:
    expected = _sign_passport(payload)
    return hmac.compare_digest(expected, signature)


def _unsigned_payload(passport: Passport) -> dict[str, Any]:
    """Extract the payload that was signed (excludes signature field)."""
    d = passport.to_dict()
    d.pop("signature", None)
    return d


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------


@contextmanager
def _cursor():
    """Yield an AdaptedCursor backed by the configured DB backend."""
    with get_db_conn(db_path=_PASSPORT_DB_PATH) as conn:
        yield AdaptedCursor(conn.cursor())


def init_passport_db() -> None:
    """Create passport and evidence tables (idempotent).

    Directory creation and PRAGMA configuration are handled by
    ``get_db_conn()``; no manual setup required here.
    """
    with _cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passports (
                passport_id      TEXT PRIMARY KEY,
                tenant_id        TEXT NOT NULL,
                agent_id         TEXT NOT NULL,
                owner_org        TEXT NOT NULL,
                display_name     TEXT NOT NULL,
                agent_dna_fp     TEXT NOT NULL,
                model_fp         TEXT,
                permissions      TEXT NOT NULL,  -- JSON list
                resource_patterns TEXT NOT NULL, -- JSON list
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                custom_claims    TEXT NOT NULL DEFAULT '{}',
                issuer_id        TEXT NOT NULL,
                issuer_name      TEXT NOT NULL,
                issuer_url       TEXT NOT NULL,
                key_id           TEXT NOT NULL,
                issued_by        TEXT NOT NULL,
                not_before       TEXT NOT NULL,
                not_after        TEXT NOT NULL,
                revocation_url   TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                signature        TEXT NOT NULL DEFAULT '',
                created_at       TEXT NOT NULL,
                issued_at        TEXT,
                revoked_at       TEXT,
                revocation_reason TEXT
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_passports_tenant_agent
                ON passports (tenant_id, agent_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_passports_status
                ON passports (status)
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passport_evidence (
                evidence_id   TEXT PRIMARY KEY,
                passport_id   TEXT NOT NULL,
                tenant_id     TEXT NOT NULL,
                submitted_by  TEXT NOT NULL,
                submitted_at  TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_ref  TEXT NOT NULL,
                notes         TEXT,
                status        TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (passport_id) REFERENCES passports(passport_id)
            )
        """)


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _row_to_passport(row: Any) -> Passport:
    subject = PassportSubject(
        agent_id=row["agent_id"],
        owner_org=row["owner_org"],
        display_name=row["display_name"],
        agent_dna_fingerprint=row["agent_dna_fp"],
        model_fingerprint=row["model_fp"],
    )
    scope = PassportScope(
        permissions=json.loads(row["permissions"]),
        resource_patterns=json.loads(row["resource_patterns"]),
        delegation_depth=row["delegation_depth"],
        custom_claims=json.loads(row["custom_claims"]),
    )
    issuer = PassportIssuer(
        issuer_id=row["issuer_id"],
        issuer_name=row["issuer_name"],
        issuer_url=row["issuer_url"],
        key_id=row["key_id"],
        issued_by=row["issued_by"],
    )
    return Passport(
        passport_id=row["passport_id"],
        subject=subject,
        scope=scope,
        issuer=issuer,
        not_before=row["not_before"],
        not_after=row["not_after"],
        revocation_url=row["revocation_url"],
        status=PassportStatus(row["status"]),
        signature=row["signature"],
        created_at=row["created_at"],
        issued_at=row["issued_at"],
        revoked_at=row["revoked_at"],
        revocation_reason=row["revocation_reason"],
        tenant_id=row["tenant_id"],
    )


def _row_to_evidence(row: Any) -> EvidenceBundle:
    return EvidenceBundle(
        evidence_id=row["evidence_id"],
        passport_id=row["passport_id"],
        tenant_id=row["tenant_id"],
        submitted_by=row["submitted_by"],
        submitted_at=row["submitted_at"],
        evidence_type=row["evidence_type"],
        evidence_ref=row["evidence_ref"],
        notes=row["notes"],
        status=row["status"],
    )


def _insert_passport(passport: Passport) -> None:
    with _cursor() as cur:
        cur.execute("""
            INSERT INTO passports (
                passport_id, tenant_id, agent_id, owner_org, display_name,
                agent_dna_fp, model_fp, permissions, resource_patterns,
                delegation_depth, custom_claims, issuer_id, issuer_name,
                issuer_url, key_id, issued_by, not_before, not_after,
                revocation_url, status, signature, created_at, issued_at,
                revoked_at, revocation_reason
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            passport.passport_id,
            passport.tenant_id,
            passport.subject.agent_id,
            passport.subject.owner_org,
            passport.subject.display_name,
            passport.subject.agent_dna_fingerprint,
            passport.subject.model_fingerprint,
            json.dumps(passport.scope.permissions),
            json.dumps(passport.scope.resource_patterns),
            passport.scope.delegation_depth,
            json.dumps(passport.scope.custom_claims),
            passport.issuer.issuer_id,
            passport.issuer.issuer_name,
            passport.issuer.issuer_url,
            passport.issuer.key_id,
            passport.issuer.issued_by,
            passport.not_before,
            passport.not_after,
            passport.revocation_url,
            passport.status.value,
            passport.signature,
            passport.created_at,
            passport.issued_at,
            passport.revoked_at,
            passport.revocation_reason,
        ))


def _update_passport_status(
    passport_id: str,
    status: PassportStatus,
    *,
    signature: str | None = None,
    issued_at: str | None = None,
    revoked_at: str | None = None,
    revocation_reason: str | None = None,
) -> None:
    with _cursor() as cur:
        cur.execute("""
            UPDATE passports SET status=?, signature=COALESCE(?,signature),
                issued_at=COALESCE(?,issued_at), revoked_at=COALESCE(?,revoked_at),
                revocation_reason=COALESCE(?,revocation_reason)
            WHERE passport_id=?
        """, (status.value, signature, issued_at, revoked_at, revocation_reason,
              passport_id))


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def request_passport(
    *,
    tenant_id: str,
    agent_id: str,
    owner_org: str,
    display_name: str,
    agent_dna_fingerprint: str,
    permissions: list[str],
    resource_patterns: list[str],
    requested_by: str,
    model_fingerprint: str | None = None,
    delegation_depth: int = 0,
    custom_claims: dict[str, Any] | None = None,
    validity_days: int | None = None,
) -> Passport:
    """
    Submit a passport issuance request. The passport is created in PENDING state.
    An operator must approve it before it can be issued.
    """
    init_passport_db()
    validity = validity_days or _PASSPORT_VALIDITY_DAYS
    now = datetime.now(timezone.utc)
    passport_id = f"tdn-pass-{uuid.uuid4()}"
    key_id = f"tdn-key-{hashlib.sha256(passport_id.encode()).hexdigest()[:16]}"

    subject = PassportSubject(
        agent_id=agent_id,
        owner_org=owner_org,
        display_name=display_name,
        agent_dna_fingerprint=agent_dna_fingerprint,
        model_fingerprint=model_fingerprint,
    )
    scope = PassportScope(
        permissions=permissions,
        resource_patterns=resource_patterns,
        delegation_depth=delegation_depth,
        custom_claims=custom_claims or {},
    )
    issuer = PassportIssuer(
        issuer_id="tokendna-trust-authority",
        issuer_name="TokenDNA Trust Authority",
        issuer_url=_PASSPORT_ISSUER_URL,
        key_id=key_id,
        issued_by=requested_by,
    )
    revocation_url = f"{_PASSPORT_ISSUER_URL}/passport/{passport_id}/status"

    passport = Passport(
        passport_id=passport_id,
        subject=subject,
        scope=scope,
        issuer=issuer,
        not_before=now.isoformat(),
        not_after=(now + timedelta(days=validity)).isoformat(),
        revocation_url=revocation_url,
        status=PassportStatus.PENDING,
        signature="",  # unsigned until issued
        created_at=now.isoformat(),
        tenant_id=tenant_id,
    )
    _insert_passport(passport)
    return passport


def approve_passport(passport_id: str) -> Passport:
    """Advance a PENDING passport to APPROVED state."""
    passport = get_passport(passport_id)
    if passport is None:
        raise ValueError(f"Passport {passport_id} not found")
    if passport.status != PassportStatus.PENDING:
        raise ValueError(
            f"Cannot approve passport in status {passport.status.value}"
        )
    _update_passport_status(passport_id, PassportStatus.APPROVED)
    passport.status = PassportStatus.APPROVED
    return passport


def issue_passport(passport_id: str) -> Passport:
    """
    Issue an APPROVED passport: sign it and set status to ISSUED.
    The signature is HMAC-SHA256 over the canonical JSON payload.
    """
    passport = get_passport(passport_id)
    if passport is None:
        raise ValueError(f"Passport {passport_id} not found")
    if passport.status != PassportStatus.APPROVED:
        raise ValueError(
            f"Cannot issue passport in status {passport.status.value}"
        )
    now = datetime.now(timezone.utc).isoformat()
    passport.status = PassportStatus.ISSUED
    passport.issued_at = now
    unsigned = _unsigned_payload(passport)
    signature = _sign_passport(unsigned)
    passport.signature = signature
    _update_passport_status(
        passport_id,
        PassportStatus.ISSUED,
        signature=signature,
        issued_at=now,
    )
    return passport


def revoke_passport(passport_id: str, reason: str) -> Passport:
    """Revoke an ISSUED or APPROVED passport."""
    passport = get_passport(passport_id)
    if passport is None:
        raise ValueError(f"Passport {passport_id} not found")
    if passport.status not in (PassportStatus.ISSUED, PassportStatus.APPROVED):
        raise ValueError(
            f"Cannot revoke passport in status {passport.status.value}"
        )
    now = datetime.now(timezone.utc).isoformat()
    _update_passport_status(
        passport_id,
        PassportStatus.REVOKED,
        revoked_at=now,
        revocation_reason=reason,
    )
    passport.status = PassportStatus.REVOKED
    passport.revoked_at = now
    passport.revocation_reason = reason
    return passport


def verify_passport(passport_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Verify a passport bundle submitted by a third party.

    Returns:
      {
        "valid": bool,
        "trust_score": float,
        "passport_id": str,
        "status": str,
        "reason": str | None,
        "subject": {...},
        "scope": {...},
        "not_after": str,
      }
    """
    init_passport_db()

    passport_id = passport_dict.get("passport_id", "")
    if not passport_id:
        return _invalid("missing passport_id")

    # Check DB record (authoritative status)
    stored = get_passport(passport_id)
    if stored is None:
        return _invalid("passport not found in registry")

    if stored.status == PassportStatus.REVOKED:
        return _invalid(
            f"passport revoked: {stored.revocation_reason or 'no reason given'}"
        )

    # Check expiry
    now = datetime.now(timezone.utc).isoformat()
    if stored.not_after < now:
        return _invalid("passport expired")
    if stored.not_before > now:
        return _invalid("passport not yet valid")

    if stored.status != PassportStatus.ISSUED:
        return _invalid(f"passport not in issued state: {stored.status.value}")

    # Verify signature from submitted payload
    submitted_sig = passport_dict.get("signature", "")
    check_payload = {k: v for k, v in passport_dict.items() if k != "signature"}
    if not _verify_signature(check_payload, submitted_sig):
        return _invalid("signature verification failed")

    trust_score = stored.trust_score()
    return {
        "valid": True,
        "trust_score": trust_score,
        "passport_id": passport_id,
        "status": stored.status.value,
        "reason": None,
        "subject": asdict(stored.subject),
        "scope": asdict(stored.scope),
        "not_after": stored.not_after,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return {
        "valid": False,
        "trust_score": 0.0,
        "passport_id": None,
        "status": "invalid",
        "reason": reason,
        "subject": None,
        "scope": None,
        "not_after": None,
    }


# ---------------------------------------------------------------------------
# Evidence submission
# ---------------------------------------------------------------------------


def submit_evidence(
    *,
    passport_id: str,
    tenant_id: str,
    submitted_by: str,
    evidence_type: str,
    evidence_ref: str,
    notes: str | None = None,
) -> EvidenceBundle:
    """Attach an evidence bundle to a pending passport."""
    init_passport_db()
    now = datetime.now(timezone.utc).isoformat()
    evidence_id = f"ev-{uuid.uuid4()}"
    bundle = EvidenceBundle(
        evidence_id=evidence_id,
        passport_id=passport_id,
        tenant_id=tenant_id,
        submitted_by=submitted_by,
        submitted_at=now,
        evidence_type=evidence_type,
        evidence_ref=evidence_ref,
        notes=notes,
    )
    with _cursor() as cur:
        cur.execute("""
            INSERT INTO passport_evidence
                (evidence_id, passport_id, tenant_id, submitted_by, submitted_at,
                 evidence_type, evidence_ref, notes, status)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            bundle.evidence_id, bundle.passport_id, bundle.tenant_id,
            bundle.submitted_by, bundle.submitted_at, bundle.evidence_type,
            bundle.evidence_ref, bundle.notes, bundle.status,
        ))
    return bundle


def list_evidence(passport_id: str) -> list[EvidenceBundle]:
    init_passport_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT * FROM passport_evidence WHERE passport_id=? ORDER BY submitted_at DESC
        """, (passport_id,))
        return [_row_to_evidence(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def get_passport(passport_id: str) -> Passport | None:
    init_passport_db()
    with _cursor() as cur:
        cur.execute("SELECT * FROM passports WHERE passport_id=?", (passport_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return _row_to_passport(row)


def list_passports(
    tenant_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[Passport]:
    init_passport_db()
    clauses: list[str] = []
    params: list[Any] = []
    if tenant_id:
        clauses.append("tenant_id=?")
        params.append(tenant_id)
    if agent_id:
        clauses.append("agent_id=?")
        params.append(agent_id)
    if status:
        clauses.append("status=?")
        params.append(status)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(min(limit, 200))
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM passports {where} ORDER BY created_at DESC LIMIT ?",
            params,
        )
        return [_row_to_passport(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Cross-vendor integration playbooks
# ---------------------------------------------------------------------------


def get_integration_playbook(vendor: str) -> dict[str, Any]:
    """
    Return an integration playbook for the specified vendor.
    Raises ValueError for unknown vendors.
    """
    try:
        platform = VendorPlatform(vendor)
    except ValueError:
        supported = [v.value for v in VendorPlatform]
        raise ValueError(
            f"Unknown vendor '{vendor}'. Supported: {supported}"
        )

    playbooks: dict[VendorPlatform, dict[str, Any]] = {
        VendorPlatform.AWS_BEDROCK: _playbook_aws_bedrock(),
        VendorPlatform.AZURE_OPENAI: _playbook_azure_openai(),
        VendorPlatform.ANTHROPIC: _playbook_anthropic(),
        VendorPlatform.OPENAI: _playbook_openai(),
    }
    return playbooks[platform]


def list_integration_playbooks() -> list[dict[str, Any]]:
    """Return summary list of all available integration playbooks."""
    return [
        {
            "vendor": v.value,
            "display_name": _vendor_display_name(v),
            "status": "available",
        }
        for v in VendorPlatform
    ]


def _vendor_display_name(v: VendorPlatform) -> str:
    names = {
        VendorPlatform.AWS_BEDROCK: "AWS Bedrock",
        VendorPlatform.AZURE_OPENAI: "Azure OpenAI",
        VendorPlatform.ANTHROPIC: "Anthropic API",
        VendorPlatform.OPENAI: "OpenAI API",
    }
    return names[v]


def _playbook_aws_bedrock() -> dict[str, Any]:
    return {
        "vendor": "aws_bedrock",
        "display_name": "AWS Bedrock",
        "overview": (
            "Attach the TokenDNA passport JWT to every Bedrock InvokeAgent call "
            "via the X-TokenDNA-Passport header. Use an AWS Lambda authorizer to "
            "validate the passport before forwarding to Bedrock."
        ),
        "steps": [
            {
                "step": 1,
                "title": "Issue a passport for your Bedrock agent",
                "description": (
                    "Call POST /api/passport/request with the Bedrock agent ARN as "
                    "agent_id and 'bedrock:invoke' in permissions. Wait for operator "
                    "approval, then call POST /api/passport/{id}/issue."
                ),
                "code_sample": (
                    "import requests\n"
                    "resp = requests.post('https://your-tokendna/api/passport/request', json={\n"
                    "    'agent_id': 'arn:aws:bedrock:us-east-1:123456789012:agent/ABCD1234',\n"
                    "    'owner_org': 'your-org',\n"
                    "    'display_name': 'My Bedrock Agent',\n"
                    "    'agent_dna_fingerprint': '<fingerprint>',\n"
                    "    'permissions': ['bedrock:invoke', 'bedrock:retrieve'],\n"
                    "    'resource_patterns': ['arn:aws:bedrock:*'],\n"
                    "    'requested_by': 'ops-team',\n"
                    "}, headers={'X-Tenant-ID': 'your-tenant'})"
                ),
            },
            {
                "step": 2,
                "title": "Embed passport in Bedrock API calls",
                "description": (
                    "Retrieve the issued passport JSON and base64-encode it. "
                    "Attach to each InvokeAgent/InvokeModel call via custom headers "
                    "or the sessionAttributes field."
                ),
                "code_sample": (
                    "import base64, json, boto3\n"
                    "passport_b64 = base64.b64encode(json.dumps(passport_dict).encode()).decode()\n"
                    "client = boto3.client('bedrock-agent-runtime')\n"
                    "client.invoke_agent(\n"
                    "    agentId='ABCD1234',\n"
                    "    agentAliasId='TSTALIASID',\n"
                    "    sessionId='session-001',\n"
                    "    inputText='your prompt here',\n"
                    "    sessionState={'sessionAttributes': {'tokendna_passport': passport_b64}}\n"
                    ")"
                ),
            },
            {
                "step": 3,
                "title": "Lambda authorizer validates passport",
                "description": (
                    "Deploy a Lambda authorizer that extracts the passport from "
                    "sessionAttributes and calls POST /verify on your TokenDNA "
                    "endpoint before allowing the agent invocation."
                ),
                "code_sample": (
                    "# lambda_authorizer.py\n"
                    "import json, base64, requests\n"
                    "def handler(event, context):\n"
                    "    passport_b64 = event['sessionAttributes'].get('tokendna_passport', '')\n"
                    "    passport = json.loads(base64.b64decode(passport_b64))\n"
                    "    result = requests.post('https://your-tokendna/api/passport/verify',\n"
                    "                          json=passport).json()\n"
                    "    if not result['valid'] or result['trust_score'] < 0.5:\n"
                    "        raise Exception('Unauthorized')\n"
                    "    return {'principalId': passport['subject']['agent_id'], 'policyDocument': allow_policy()}"
                ),
            },
        ],
        "permissions_reference": ["bedrock:invoke", "bedrock:retrieve", "bedrock:list"],
        "resource_pattern_examples": [
            "arn:aws:bedrock:us-east-1:*:agent/*",
            "arn:aws:bedrock:*:*:knowledge-base/*",
        ],
        "docs_url": "https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html",
    }


def _playbook_azure_openai() -> dict[str, Any]:
    return {
        "vendor": "azure_openai",
        "display_name": "Azure OpenAI",
        "overview": (
            "Attach the TokenDNA passport to Azure OpenAI calls via a custom "
            "HTTP header or APIM policy. Use Azure API Management to enforce "
            "passport validation before routing to Azure OpenAI."
        ),
        "steps": [
            {
                "step": 1,
                "title": "Issue a passport for your Azure OpenAI deployment",
                "description": (
                    "Use the Azure OpenAI deployment endpoint as resource_pattern. "
                    "Include 'openai:chat.completions' and 'openai:embeddings' in permissions."
                ),
                "code_sample": (
                    "resp = requests.post('https://your-tokendna/api/passport/request', json={\n"
                    "    'agent_id': 'azure-oai-agent-001',\n"
                    "    'owner_org': 'contoso',\n"
                    "    'display_name': 'Contoso GPT-4 Agent',\n"
                    "    'agent_dna_fingerprint': '<fingerprint>',\n"
                    "    'permissions': ['openai:chat.completions'],\n"
                    "    'resource_patterns': ['https://*.openai.azure.com/*'],\n"
                    "    'requested_by': 'platform-team',\n"
                    "}, headers={'X-Tenant-ID': 'contoso'})"
                ),
            },
            {
                "step": 2,
                "title": "Add APIM inbound policy for passport validation",
                "description": (
                    "In Azure API Management, add a send-request inbound policy "
                    "that forwards the X-TokenDNA-Passport header to your TokenDNA "
                    "verify endpoint and rejects calls with invalid passports."
                ),
                "code_sample": (
                    "<inbound>\n"
                    "  <send-request mode='new' response-variable-name='passportCheck'>\n"
                    "    <set-url>https://your-tokendna/api/passport/verify</set-url>\n"
                    "    <set-method>POST</set-method>\n"
                    "    <set-header name='Content-Type' exists-action='override'><value>application/json</value></set-header>\n"
                    "    <set-body>@(context.Request.Headers.GetValueOrDefault('X-TokenDNA-Passport','{}'))</set-body>\n"
                    "  </send-request>\n"
                    "  <choose>\n"
                    "    <when condition=\"@(((IResponse)context.Variables['passportCheck']).Body.As<JObject>()['valid'].Value<bool>() == false)\">\n"
                    "      <return-response><set-status code='403' reason='Invalid Passport'/></return-response>\n"
                    "    </when>\n"
                    "  </choose>\n"
                    "</inbound>"
                ),
            },
        ],
        "permissions_reference": [
            "openai:chat.completions", "openai:embeddings", "openai:fine_tuning",
        ],
        "resource_pattern_examples": [
            "https://*.openai.azure.com/openai/deployments/gpt-4/*",
        ],
        "docs_url": "https://learn.microsoft.com/azure/ai-services/openai/",
    }


def _playbook_anthropic() -> dict[str, Any]:
    return {
        "vendor": "anthropic",
        "display_name": "Anthropic API",
        "overview": (
            "Attach the TokenDNA passport as a base64-encoded custom HTTP header "
            "when calling the Anthropic Messages API. Use a lightweight proxy or "
            "middleware to validate before forwarding to api.anthropic.com."
        ),
        "steps": [
            {
                "step": 1,
                "title": "Issue a passport for your Anthropic agent",
                "description": (
                    "Set resource_patterns to 'anthropic://claude-*' and include "
                    "'anthropic:messages' and 'anthropic:batches' in permissions."
                ),
                "code_sample": (
                    "resp = requests.post('https://your-tokendna/api/passport/request', json={\n"
                    "    'agent_id': 'claude-agent-prod-001',\n"
                    "    'owner_org': 'your-org',\n"
                    "    'display_name': 'Production Claude Agent',\n"
                    "    'agent_dna_fingerprint': '<fingerprint>',\n"
                    "    'permissions': ['anthropic:messages', 'anthropic:batches'],\n"
                    "    'resource_patterns': ['anthropic://claude-*'],\n"
                    "    'requested_by': 'platform-team',\n"
                    "}, headers={'X-Tenant-ID': 'your-tenant'})"
                ),
            },
            {
                "step": 2,
                "title": "Attach passport in Anthropic SDK calls",
                "description": (
                    "Pass the passport as a base64-encoded extra header. The proxy "
                    "extracts and validates before forwarding."
                ),
                "code_sample": (
                    "import anthropic, base64, json\n"
                    "client = anthropic.Anthropic(api_key='your-key')\n"
                    "passport_b64 = base64.b64encode(json.dumps(passport_dict).encode()).decode()\n"
                    "message = client.messages.create(\n"
                    "    model='claude-opus-4-6',\n"
                    "    max_tokens=1024,\n"
                    "    messages=[{'role': 'user', 'content': 'Hello'}],\n"
                    "    extra_headers={'X-TokenDNA-Passport': passport_b64},\n"
                    ")"
                ),
            },
            {
                "step": 3,
                "title": "Validation proxy (FastAPI example)",
                "description": "Thin proxy that validates the passport before forwarding to Anthropic.",
                "code_sample": (
                    "# proxy.py\n"
                    "from fastapi import FastAPI, Request, HTTPException\n"
                    "import httpx, base64, json, requests\n"
                    "app = FastAPI()\n"
                    "@app.post('/v1/messages')\n"
                    "async def proxy_messages(request: Request):\n"
                    "    raw = request.headers.get('X-TokenDNA-Passport', '')\n"
                    "    try:\n"
                    "        passport = json.loads(base64.b64decode(raw))\n"
                    "    except Exception:\n"
                    "        raise HTTPException(403, 'Missing or invalid passport')\n"
                    "    result = requests.post('https://your-tokendna/api/passport/verify',\n"
                    "                          json=passport).json()\n"
                    "    if not result['valid']:\n"
                    "        raise HTTPException(403, result['reason'])\n"
                    "    # forward to Anthropic\n"
                    "    async with httpx.AsyncClient() as client:\n"
                    "        body = await request.body()\n"
                    "        r = await client.post('https://api.anthropic.com/v1/messages',\n"
                    "                              content=body, headers=dict(request.headers))\n"
                    "        return r.json()"
                ),
            },
        ],
        "permissions_reference": ["anthropic:messages", "anthropic:batches", "anthropic:models"],
        "resource_pattern_examples": [
            "anthropic://claude-opus-*",
            "anthropic://claude-sonnet-*",
            "anthropic://claude-haiku-*",
        ],
        "docs_url": "https://docs.anthropic.com/en/api/getting-started",
    }


def _playbook_openai() -> dict[str, Any]:
    return {
        "vendor": "openai",
        "display_name": "OpenAI API",
        "overview": (
            "Attach the TokenDNA passport as a base64-encoded HTTP header when "
            "calling the OpenAI API. Use an nginx/Envoy sidecar or FastAPI proxy "
            "to validate passports before forwarding to api.openai.com."
        ),
        "steps": [
            {
                "step": 1,
                "title": "Issue a passport for your OpenAI agent",
                "description": (
                    "Set resource_patterns to 'openai://gpt-*' and include "
                    "'openai:chat.completions' and 'openai:embeddings' in permissions."
                ),
                "code_sample": (
                    "resp = requests.post('https://your-tokendna/api/passport/request', json={\n"
                    "    'agent_id': 'gpt4-production-agent',\n"
                    "    'owner_org': 'your-org',\n"
                    "    'display_name': 'Production GPT-4 Agent',\n"
                    "    'agent_dna_fingerprint': '<fingerprint>',\n"
                    "    'permissions': ['openai:chat.completions', 'openai:embeddings'],\n"
                    "    'resource_patterns': ['openai://gpt-4*', 'openai://text-embedding-*'],\n"
                    "    'requested_by': 'platform-team',\n"
                    "}, headers={'X-Tenant-ID': 'your-tenant'})"
                ),
            },
            {
                "step": 2,
                "title": "Attach passport in OpenAI SDK calls",
                "description": "Use the extra_headers parameter to attach the passport.",
                "code_sample": (
                    "import openai, base64, json\n"
                    "client = openai.OpenAI(api_key='your-key')\n"
                    "passport_b64 = base64.b64encode(json.dumps(passport_dict).encode()).decode()\n"
                    "response = client.chat.completions.create(\n"
                    "    model='gpt-4o',\n"
                    "    messages=[{'role': 'user', 'content': 'Hello'}],\n"
                    "    extra_headers={'X-TokenDNA-Passport': passport_b64},\n"
                    ")"
                ),
            },
            {
                "step": 3,
                "title": "Envoy sidecar filter (production)",
                "description": (
                    "For high-throughput deployments, use an Envoy ext_authz filter "
                    "pointing at your TokenDNA verification gRPC service."
                ),
                "code_sample": (
                    "# envoy.yaml (partial)\n"
                    "http_filters:\n"
                    "- name: envoy.filters.http.ext_authz\n"
                    "  typed_config:\n"
                    "    '@type': type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz\n"
                    "    grpc_service:\n"
                    "      envoy_grpc:\n"
                    "        cluster_name: tokendna_authz\n"
                    "    include_peer_certificate: true\n"
                    "    metadata_context_namespaces:\n"
                    "    - tokendna.passport"
                ),
            },
        ],
        "permissions_reference": [
            "openai:chat.completions", "openai:embeddings", "openai:assistants",
            "openai:fine_tuning", "openai:images",
        ],
        "resource_pattern_examples": [
            "openai://gpt-4*",
            "openai://gpt-3.5*",
            "openai://text-embedding-3-*",
        ],
        "docs_url": "https://platform.openai.com/docs/api-reference",
    }
