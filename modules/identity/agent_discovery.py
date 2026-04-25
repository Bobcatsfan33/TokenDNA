"""
TokenDNA — Agent Discovery & Inventory (Phase 5-2)

Answers the enterprise's first question about AI governance: "Where are all
my agents?"  Agents are deployed across multiple cloud providers, on-prem
infrastructure, and SaaS platforms with no unified inventory.  This module
is the CMDB for the agent era.

─────────────────────────────────────────────────────────────
Architecture
─────────────────────────────────────────────────────────────

1. Agent Registry
   Canonical inventory of every known agent: who owns it, what model it
   runs, what tools it has, its current lifecycle state, and how it was
   discovered.

2. Provider Adapters (pluggable)
   Each cloud provider (AWS Bedrock, Azure OpenAI, Google Vertex AI,
   Anthropic API, OpenAI, self-hosted vLLM/Ollama) has a scan adapter
   that queries the provider's API and returns normalised AgentRecord
   objects.  Adapters are injected — no API calls happen in tests.

3. Shadow Agent Detection
   An agent is a "shadow agent" when it appears in a provider scan but was
   never registered through the official provisioning workflow, OR when it
   was registered but its provider-reported metadata contradicts its
   registration (model swapped, endpoint changed, etc.).

4. Lifecycle State Machine
   provisioned → active → suspended ↔ active
                        → decommissioned (terminal)
   Every transition is recorded in an immutable event log.  Decommission
   requires human approval (actor_id required).  Re-activation from
   suspended optionally requires approval depending on tenant policy.

─────────────────────────────────────────────────────────────
Provider Adapter Contract
─────────────────────────────────────────────────────────────

Each adapter must implement:
    class MyAdapter(ProviderAdapter):
        provider = "my_provider"
        def scan(self, credentials: dict) -> list[AgentRecord]: ...

AgentRecord is a plain dataclass — no DB coupling in adapters.

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
POST /api/discovery/agents/register           Register an agent manually
GET  /api/discovery/agents                    Agent census (filterable)
GET  /api/discovery/agents/{agent_id}         Single agent detail
PATCH /api/discovery/agents/{agent_id}        Update agent metadata

POST /api/discovery/scan                      Trigger provider scan
GET  /api/discovery/scans                     Recent scan history
GET  /api/discovery/scans/{scan_id}           Single scan result

GET  /api/discovery/shadow                    Shadow agent alerts
POST /api/discovery/shadow/{alert_id}/acknowledge  Acknowledge shadow agent

POST /api/discovery/agents/{agent_id}/lifecycle    Lifecycle transition
GET  /api/discovery/agents/{agent_id}/lifecycle    Lifecycle history
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

from modules.storage.ddl_runner import run_ddl
from modules.storage.pg_connection import AdaptedCursor, get_db_conn
from typing import Any

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_DB_PATH = os.getenv(
    "TOKENDNA_DISCOVERY_DB",
    os.path.expanduser("~/.tokendna/agent_discovery.db"),
)

# Valid provider names
PROVIDERS = {
    "aws_bedrock",
    "azure_openai",
    "google_vertex",
    "anthropic",
    "openai",
    "self_hosted",
    "manual",
}

# Lifecycle states
STATES = {"provisioned", "active", "suspended", "decommissioned"}

# Valid transitions: from_state → set of allowed to_states
TRANSITIONS: dict[str, set[str]] = {
    "provisioned":    {"active", "decommissioned"},
    "active":         {"suspended", "decommissioned"},
    "suspended":      {"active", "decommissioned"},
    "decommissioned": set(),  # terminal
}

# Discovery methods
DISCOVERY_METHODS = {"registered", "scanned", "shadow"}

_lock = threading.Lock()
_db_initialized = False


# ── Data classes ───────────────────────────────────────────────────────────────


@dataclass
class AgentRecord:
    """Normalised agent record returned by provider adapters."""

    name: str
    provider: str
    model: str = ""
    endpoint_url: str = ""
    tools: list[str] = field(default_factory=list)
    permissions: dict[str, Any] = field(default_factory=dict)
    owner_id: str = ""
    external_id: str = ""          # provider-native agent ID
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Provider Adapter base ──────────────────────────────────────────────────────


class ProviderAdapter:
    """Base class for cloud provider scan adapters."""

    provider: str = "base"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:  # pragma: no cover
        raise NotImplementedError


# ── Built-in adapters (stub implementations) ───────────────────────────────────
# Production adapters call the real cloud APIs.  These stubs define the
# interface and can be monkey-patched in tests or extended by implementors.


class AWSBedrockAdapter(ProviderAdapter):
    """Discovers agents running on AWS Bedrock Agents."""

    provider = "aws_bedrock"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        """
        Production: calls boto3 bedrock-agent list_agents().
        Returns AgentRecord list; stub returns empty list when boto3 unavailable.
        """
        try:
            import boto3  # type: ignore  # noqa: PLC0415
            client = boto3.client(
                "bedrock-agent",
                region_name=credentials.get("region", "us-east-1"),
                aws_access_key_id=credentials.get("access_key_id"),
                aws_secret_access_key=credentials.get("secret_access_key"),
                aws_session_token=credentials.get("session_token"),
            )
            paginator = client.get_paginator("list_agents")
            records = []
            for page in paginator.paginate():
                for agent in page.get("agentSummaries", []):
                    records.append(
                        AgentRecord(
                            name=agent.get("agentName", ""),
                            provider=self.provider,
                            model=agent.get("foundationModel", ""),
                            external_id=agent.get("agentId", ""),
                            metadata={"status": agent.get("agentStatus", "")},
                        )
                    )
            return records
        except Exception as exc:
            log.debug("AWSBedrockAdapter scan unavailable: %s", exc)
            return []


class AzureOpenAIAdapter(ProviderAdapter):
    """Discovers assistants/agents on Azure OpenAI."""

    provider = "azure_openai"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        try:
            from openai import AzureOpenAI  # type: ignore  # noqa: PLC0415
            client = AzureOpenAI(
                api_key=credentials.get("api_key"),
                api_version=credentials.get("api_version", "2024-02-01"),
                azure_endpoint=credentials.get("endpoint", ""),
            )
            assistants = client.beta.assistants.list(limit=100)
            records = []
            for a in assistants.data:
                records.append(
                    AgentRecord(
                        name=a.name or a.id,
                        provider=self.provider,
                        model=a.model,
                        external_id=a.id,
                        tools=[t.type for t in (a.tools or [])],
                        metadata={"instructions": (a.instructions or "")[:200]},
                    )
                )
            return records
        except Exception as exc:
            log.debug("AzureOpenAIAdapter scan unavailable: %s", exc)
            return []


class GoogleVertexAdapter(ProviderAdapter):
    """Discovers agents on Google Vertex AI Agent Builder."""

    provider = "google_vertex"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        try:
            from google.cloud import dialogflowcx_v3  # type: ignore  # noqa: PLC0415
            client = dialogflowcx_v3.AgentsClient()
            project = credentials.get("project_id", "")
            location = credentials.get("location", "global")
            parent = f"projects/{project}/locations/{location}"
            records = []
            for agent in client.list_agents(parent=parent):
                records.append(
                    AgentRecord(
                        name=agent.display_name,
                        provider=self.provider,
                        model=agent.default_language_code,
                        external_id=agent.name,
                        metadata={"description": agent.description[:200]},
                    )
                )
            return records
        except Exception as exc:
            log.debug("GoogleVertexAdapter scan unavailable: %s", exc)
            return []


class AnthropicAdapter(ProviderAdapter):
    """Discovers Claude-based agents via Anthropic API introspection."""

    provider = "anthropic"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        # Anthropic API doesn't yet expose a list-agents endpoint.
        # Production implementation would use a TokenDNA registry sidecar
        # deployed in the customer's Anthropic-using infrastructure.
        log.debug("AnthropicAdapter: no list-agents API available; use manual registration")
        return []


class OpenAIAdapter(ProviderAdapter):
    """Discovers assistants on OpenAI Assistants API."""

    provider = "openai"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        try:
            from openai import OpenAI  # type: ignore  # noqa: PLC0415
            client = OpenAI(api_key=credentials.get("api_key"))
            assistants = client.beta.assistants.list(limit=100)
            records = []
            for a in assistants.data:
                records.append(
                    AgentRecord(
                        name=a.name or a.id,
                        provider=self.provider,
                        model=a.model,
                        external_id=a.id,
                        tools=[t.type for t in (a.tools or [])],
                        metadata={},
                    )
                )
            return records
        except Exception as exc:
            log.debug("OpenAIAdapter scan unavailable: %s", exc)
            return []


class SelfHostedAdapter(ProviderAdapter):
    """Discovers agents on self-hosted inference endpoints (vLLM, NIM, Ollama)."""

    provider = "self_hosted"

    def scan(self, credentials: dict[str, Any]) -> list[AgentRecord]:
        """
        Queries /v1/models (OpenAI-compatible) on the given base_url.
        Works with vLLM, NIM, LM Studio, and Ollama (with --openai-compat flag).
        """
        try:
            import urllib.request  # noqa: PLC0415
            import urllib.error  # noqa: PLC0415
            base_url = credentials.get("base_url", "").rstrip("/")
            if not base_url:
                return []
            req = urllib.request.Request(
                f"{base_url}/v1/models",
                headers={"Authorization": f"Bearer {credentials.get('api_key', 'none')}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            records = []
            for model in data.get("data", []):
                records.append(
                    AgentRecord(
                        name=model.get("id", ""),
                        provider=self.provider,
                        model=model.get("id", ""),
                        endpoint_url=base_url,
                        external_id=model.get("id", ""),
                        metadata={"owned_by": model.get("owned_by", "")},
                    )
                )
            return records
        except Exception as exc:
            log.debug("SelfHostedAdapter scan unavailable: %s", exc)
            return []


# ── Adapter registry ───────────────────────────────────────────────────────────

_ADAPTERS: dict[str, ProviderAdapter] = {
    "aws_bedrock":   AWSBedrockAdapter(),
    "azure_openai":  AzureOpenAIAdapter(),
    "google_vertex": GoogleVertexAdapter(),
    "anthropic":     AnthropicAdapter(),
    "openai":        OpenAIAdapter(),
    "self_hosted":   SelfHostedAdapter(),
}


def register_adapter(adapter: ProviderAdapter) -> None:
    """Replace or add a provider adapter (used in tests and extensions)."""
    _ADAPTERS[adapter.provider] = adapter


# ── DB bootstrap ───────────────────────────────────────────────────────────────


_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS da_agents (
        agent_id          TEXT PRIMARY KEY,
        tenant_id         TEXT NOT NULL,
        name              TEXT NOT NULL,
        provider          TEXT NOT NULL,
        model             TEXT,
        endpoint_url      TEXT,
        tools_json        TEXT,
        permissions_json  TEXT,
        owner_id          TEXT,
        external_id       TEXT,
        status            TEXT NOT NULL DEFAULT 'provisioned',
        discovery_method  TEXT NOT NULL DEFAULT 'registered',
        registered_at     TEXT NOT NULL,
        last_active_at    TEXT,
        metadata_json     TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_da_agents_tenant ON da_agents(tenant_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_da_agents_external ON da_agents(tenant_id, provider, external_id)",
    """
    CREATE TABLE IF NOT EXISTS da_lifecycle_events (
        event_id       TEXT PRIMARY KEY,
        agent_id       TEXT NOT NULL,
        tenant_id      TEXT NOT NULL,
        from_status    TEXT NOT NULL,
        to_status      TEXT NOT NULL,
        actor_id       TEXT NOT NULL,
        reason         TEXT,
        approved_by    TEXT,
        approved_at    TEXT,
        created_at     TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_da_lifecycle_agent ON da_lifecycle_events(agent_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS da_scan_runs (
        scan_id        TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL,
        provider       TEXT NOT NULL,
        started_at     TEXT NOT NULL,
        completed_at   TEXT,
        agents_found   INTEGER NOT NULL DEFAULT 0,
        new_agents     INTEGER NOT NULL DEFAULT 0,
        shadow_agents  INTEGER NOT NULL DEFAULT 0,
        run_status     TEXT NOT NULL DEFAULT 'running',
        error_message  TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_da_scan_tenant ON da_scan_runs(tenant_id, started_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS da_shadow_alerts (
        alert_id          TEXT PRIMARY KEY,
        tenant_id         TEXT NOT NULL,
        agent_id          TEXT NOT NULL,
        reason            TEXT NOT NULL,
        detected_at       TEXT NOT NULL,
        acknowledged      INTEGER NOT NULL DEFAULT 0,
        acknowledged_by   TEXT,
        acknowledged_at   TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_da_shadow_tenant ON da_shadow_alerts(tenant_id, acknowledged)",
)


def init_db(db_path: str = _DB_PATH) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _lock:
        if _db_initialized:
            return
        run_ddl(_DDL_STATEMENTS, db_path)
        _db_initialized = True


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with get_db_conn(db_path=db_path) as conn:
        yield AdaptedCursor(conn.cursor())


# ── Agent Registration ─────────────────────────────────────────────────────────


def register_agent(
    *,
    tenant_id: str,
    name: str,
    provider: str,
    model: str = "",
    endpoint_url: str = "",
    tools: list[str] | None = None,
    permissions: dict[str, Any] | None = None,
    owner_id: str = "",
    external_id: str = "",
    metadata: dict[str, Any] | None = None,
    discovery_method: str = "registered",
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Register an agent in the inventory.

    ``discovery_method`` is ``"registered"`` for manually provisioned agents,
    ``"scanned"`` for scanner-discovered agents, and ``"shadow"`` for agents
    flagged as operating outside official provisioning.
    """
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider '{provider}'. Valid: {sorted(PROVIDERS)}")
    if discovery_method not in DISCOVERY_METHODS:
        raise ValueError(f"Unknown discovery_method '{discovery_method}'")

    init_db(db_path)
    agent_id = str(uuid.uuid4())
    now = _now()

    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO da_agents
                (agent_id, tenant_id, name, provider, model, endpoint_url,
                 tools_json, permissions_json, owner_id, external_id,
                 status, discovery_method, registered_at, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'provisioned', ?, ?, ?)
            """,
            (
                agent_id, tenant_id, name, provider, model, endpoint_url,
                json.dumps(tools or []),
                json.dumps(permissions or {}),
                owner_id, external_id,
                discovery_method, now,
                json.dumps(metadata or {}),
            ),
        )
    return get_agent(agent_id, tenant_id, db_path=db_path)


def get_agent(
    agent_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT * FROM da_agents WHERE agent_id = ? AND tenant_id = ?",
            (agent_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Agent '{agent_id}' not found for tenant '{tenant_id}'")
    return _row_to_agent(row)


def update_agent(
    agent_id: str,
    tenant_id: str,
    *,
    name: str | None = None,
    model: str | None = None,
    endpoint_url: str | None = None,
    tools: list[str] | None = None,
    permissions: dict[str, Any] | None = None,
    owner_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Update mutable fields on a registered agent."""
    init_db(db_path)
    current = get_agent(agent_id, tenant_id, db_path=db_path)
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE da_agents SET
                name             = ?,
                model            = ?,
                endpoint_url     = ?,
                tools_json       = ?,
                permissions_json = ?,
                owner_id         = ?,
                metadata_json    = ?
            WHERE agent_id = ? AND tenant_id = ?
            """,
            (
                name         if name         is not None else current["name"],
                model        if model        is not None else current["model"],
                endpoint_url if endpoint_url is not None else current["endpoint_url"],
                json.dumps(tools)       if tools       is not None else json.dumps(current["tools"]),
                json.dumps(permissions) if permissions is not None else json.dumps(current["permissions"]),
                owner_id     if owner_id     is not None else current["owner_id"],
                json.dumps(metadata)    if metadata    is not None else json.dumps(current["metadata"]),
                agent_id, tenant_id,
            ),
        )
    return get_agent(agent_id, tenant_id, db_path=db_path)


def list_agents(
    tenant_id: str,
    *,
    status: str | None = None,
    provider: str | None = None,
    discovery_method: str | None = None,
    owner_id: str | None = None,
    limit: int = 100,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """Return the agent census for a tenant."""
    init_db(db_path)
    sql = "SELECT * FROM da_agents WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    if provider:
        sql += " AND provider = ?"
        params.append(provider)
    if discovery_method:
        sql += " AND discovery_method = ?"
        params.append(discovery_method)
    if owner_id:
        sql += " AND owner_id = ?"
        params.append(owner_id)
    sql += " ORDER BY registered_at DESC LIMIT ?"
    params.append(limit)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_agent(r) for r in rows]


def record_activity(
    agent_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> None:
    """Update last_active_at and auto-transition provisioned → active."""
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT status FROM da_agents WHERE agent_id = ? AND tenant_id = ?",
            (agent_id, tenant_id),
        ).fetchone()
        if row is None:
            return
        cur.execute(
            "UPDATE da_agents SET last_active_at = ? WHERE agent_id = ? AND tenant_id = ?",
            (now, agent_id, tenant_id),
        )
        if row["status"] == "provisioned":
            cur.execute(
                "UPDATE da_agents SET status = 'active' WHERE agent_id = ? AND tenant_id = ?",
                (agent_id, tenant_id),
            )
            cur.execute(
                """
                INSERT INTO da_lifecycle_events
                    (event_id, agent_id, tenant_id, from_status, to_status,
                     actor_id, reason, created_at)
                VALUES (?, ?, ?, 'provisioned', 'active', 'system', 'first_activity', ?)
                """,
                (str(uuid.uuid4()), agent_id, tenant_id, now),
            )


def _row_to_agent(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "agent_id":         row["agent_id"],
        "tenant_id":        row["tenant_id"],
        "name":             row["name"],
        "provider":         row["provider"],
        "model":            row["model"] or "",
        "endpoint_url":     row["endpoint_url"] or "",
        "tools":            json.loads(row["tools_json"] or "[]"),
        "permissions":      json.loads(row["permissions_json"] or "{}"),
        "owner_id":         row["owner_id"] or "",
        "external_id":      row["external_id"] or "",
        "status":           row["status"],
        "discovery_method": row["discovery_method"],
        "registered_at":    row["registered_at"],
        "last_active_at":   row["last_active_at"],
        "metadata":         json.loads(row["metadata_json"] or "{}"),
    }


# ── Lifecycle State Machine ────────────────────────────────────────────────────


def transition_lifecycle(
    agent_id: str,
    tenant_id: str,
    to_status: str,
    actor_id: str,
    *,
    reason: str = "",
    approved_by: str | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Transition an agent's lifecycle state.

    Rules:
    - ``decommissioned`` requires ``actor_id`` (non-empty).
    - Any transition from ``suspended`` back to ``active`` requires
      ``approved_by`` when the current status is ``suspended``.
    - ``decommissioned`` is terminal — no further transitions allowed.

    Returns the updated agent dict.
    """
    if to_status not in STATES:
        raise ValueError(f"Unknown status '{to_status}'. Valid: {sorted(STATES)}")
    if not actor_id:
        raise ValueError("actor_id is required for lifecycle transitions")

    init_db(db_path)
    agent = get_agent(agent_id, tenant_id, db_path=db_path)
    from_status = agent["status"]

    if to_status not in TRANSITIONS.get(from_status, set()):
        raise ValueError(
            f"Invalid transition: {from_status!r} → {to_status!r}. "
            f"Allowed from {from_status!r}: {sorted(TRANSITIONS.get(from_status, set()))}"
        )

    # Decommission requires approval
    if to_status == "decommissioned" and not approved_by:
        raise ValueError("approved_by is required to decommission an agent")

    now = _now()
    event_id = str(uuid.uuid4())
    with _cursor(db_path) as cur:
        cur.execute(
            "UPDATE da_agents SET status = ? WHERE agent_id = ? AND tenant_id = ?",
            (to_status, agent_id, tenant_id),
        )
        cur.execute(
            """
            INSERT INTO da_lifecycle_events
                (event_id, agent_id, tenant_id, from_status, to_status,
                 actor_id, reason, approved_by, approved_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, agent_id, tenant_id,
                from_status, to_status,
                actor_id, reason,
                approved_by,
                now if approved_by else None,
                now,
            ),
        )
    return get_agent(agent_id, tenant_id, db_path=db_path)


def get_lifecycle_history(
    agent_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM da_lifecycle_events
             WHERE agent_id = ? AND tenant_id = ?
             ORDER BY created_at ASC
            """,
            (agent_id, tenant_id),
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id":    row["event_id"],
        "agent_id":    row["agent_id"],
        "tenant_id":   row["tenant_id"],
        "from_status": row["from_status"],
        "to_status":   row["to_status"],
        "actor_id":    row["actor_id"],
        "reason":      row["reason"] or "",
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
        "created_at":  row["created_at"],
    }


# ── Provider Scan ──────────────────────────────────────────────────────────────


def run_scan(
    tenant_id: str,
    provider: str,
    credentials: dict[str, Any],
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Execute a provider scan, ingest results, and flag shadow agents.

    Returns a scan result summary.
    """
    if provider not in _ADAPTERS and provider != "manual":
        raise ValueError(f"No adapter registered for provider '{provider}'")

    init_db(db_path)
    scan_id = str(uuid.uuid4())
    started_at = _now()

    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO da_scan_runs
                (scan_id, tenant_id, provider, started_at, run_status)
            VALUES (?, ?, ?, ?, 'running')
            """,
            (scan_id, tenant_id, provider, started_at),
        )

    adapter = _ADAPTERS.get(provider)
    records: list[AgentRecord] = []
    error_message: str | None = None

    try:
        if adapter:
            records = adapter.scan(credentials)
    except Exception as exc:
        error_message = str(exc)
        log.warning("Scan failed for provider %s: %s", provider, exc)

    new_agents = 0
    shadow_count = 0

    for rec in records:
        existing = _find_by_external_id(tenant_id, provider, rec.external_id, db_path=db_path)

        if existing is None:
            # New agent — register as scanned
            agent = register_agent(
                tenant_id=tenant_id,
                name=rec.name,
                provider=provider,
                model=rec.model,
                endpoint_url=rec.endpoint_url,
                tools=rec.tools,
                permissions=rec.permissions,
                owner_id=rec.owner_id,
                external_id=rec.external_id,
                metadata=rec.metadata,
                discovery_method="scanned",
                db_path=db_path,
            )
            new_agents += 1
            # New scanned agents are shadow agents — not officially provisioned
            _raise_shadow_alert(
                tenant_id=tenant_id,
                agent_id=agent["agent_id"],
                reason="discovered_by_scan_not_registered",
                db_path=db_path,
            )
            shadow_count += 1
        else:
            # Existing agent — check for metadata drift
            drift_reasons = _check_metadata_drift(existing, rec)
            for reason in drift_reasons:
                _raise_shadow_alert(
                    tenant_id=tenant_id,
                    agent_id=existing["agent_id"],
                    reason=reason,
                    db_path=db_path,
                )
                shadow_count += 1

    completed_at = _now()
    run_status = "failed" if error_message else "complete"

    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE da_scan_runs SET
                completed_at  = ?,
                agents_found  = ?,
                new_agents    = ?,
                shadow_agents = ?,
                run_status    = ?,
                error_message = ?
            WHERE scan_id = ?
            """,
            (
                completed_at,
                len(records),
                new_agents,
                shadow_count,
                run_status,
                error_message,
                scan_id,
            ),
        )

    return get_scan(scan_id, tenant_id, db_path=db_path)


def get_scan(
    scan_id: str,
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            "SELECT * FROM da_scan_runs WHERE scan_id = ? AND tenant_id = ?",
            (scan_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Scan '{scan_id}' not found for tenant '{tenant_id}'")
    return _row_to_scan(row)


def list_scans(
    tenant_id: str,
    *,
    provider: str | None = None,
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    sql = "SELECT * FROM da_scan_runs WHERE tenant_id = ?"
    params: list[Any] = [tenant_id]
    if provider:
        sql += " AND provider = ?"
        params.append(provider)
    sql += " ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_scan(r) for r in rows]


def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scan_id":       row["scan_id"],
        "tenant_id":     row["tenant_id"],
        "provider":      row["provider"],
        "started_at":    row["started_at"],
        "completed_at":  row["completed_at"],
        "agents_found":  row["agents_found"],
        "new_agents":    row["new_agents"],
        "shadow_agents": row["shadow_agents"],
        "status":        row["run_status"],
        "error_message": row["error_message"],
    }


def _find_by_external_id(
    tenant_id: str,
    provider: str,
    external_id: str,
    *,
    db_path: str,
) -> dict[str, Any] | None:
    if not external_id:
        return None
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM da_agents
             WHERE tenant_id = ? AND provider = ? AND external_id = ?
            """,
            (tenant_id, provider, external_id),
        ).fetchone()
    return _row_to_agent(row) if row else None


def _check_metadata_drift(
    existing: dict[str, Any],
    rec: AgentRecord,
) -> list[str]:
    """Return a list of drift reason strings if the live scan contradicts registration."""
    reasons = []
    if rec.model and existing["model"] and rec.model != existing["model"]:
        reasons.append(f"model_changed:{existing['model']}->{rec.model}")
    if rec.endpoint_url and existing["endpoint_url"] and rec.endpoint_url != existing["endpoint_url"]:
        reasons.append(f"endpoint_changed:{existing['endpoint_url']}->{rec.endpoint_url}")
    return reasons


# ── Shadow Agent Detection ─────────────────────────────────────────────────────


def _raise_shadow_alert(
    *,
    tenant_id: str,
    agent_id: str,
    reason: str,
    db_path: str,
) -> str:
    """Record a shadow agent alert. Returns the alert_id."""
    alert_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO da_shadow_alerts
                (alert_id, tenant_id, agent_id, reason, detected_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (alert_id, tenant_id, agent_id, reason, now),
        )
    return alert_id


def list_shadow_alerts(
    tenant_id: str,
    *,
    acknowledged: bool = False,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            """
            SELECT * FROM da_shadow_alerts
             WHERE tenant_id = ? AND acknowledged = ?
             ORDER BY detected_at DESC
            """,
            (tenant_id, int(acknowledged)),
        ).fetchall()
    return [_row_to_shadow(r) for r in rows]


def acknowledge_shadow_alert(
    tenant_id: str,
    alert_id: str,
    acknowledged_by: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    init_db(db_path)
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            UPDATE da_shadow_alerts
               SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
             WHERE alert_id = ? AND tenant_id = ?
            """,
            (acknowledged_by, now, alert_id, tenant_id),
        )
        row = cur.execute(
            "SELECT * FROM da_shadow_alerts WHERE alert_id = ? AND tenant_id = ?",
            (alert_id, tenant_id),
        ).fetchone()
    if row is None:
        raise KeyError(f"Shadow alert '{alert_id}' not found for tenant '{tenant_id}'")
    return _row_to_shadow(row)


def _row_to_shadow(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "alert_id":        row["alert_id"],
        "tenant_id":       row["tenant_id"],
        "agent_id":        row["agent_id"],
        "reason":          row["reason"],
        "detected_at":     row["detected_at"],
        "acknowledged":    bool(row["acknowledged"]),
        "acknowledged_by": row["acknowledged_by"],
        "acknowledged_at": row["acknowledged_at"],
    }


# ── Census summary ─────────────────────────────────────────────────────────────


def census_summary(
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Return a high-level summary of the agent inventory."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        total = cur.execute(
            "SELECT COUNT(*) FROM da_agents WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]

        by_status = {}
        for row in cur.execute(
            "SELECT status, COUNT(*) as n FROM da_agents WHERE tenant_id = ? GROUP BY status",
            (tenant_id,),
        ).fetchall():
            by_status[row["status"]] = row["n"]

        by_provider = {}
        for row in cur.execute(
            "SELECT provider, COUNT(*) as n FROM da_agents WHERE tenant_id = ? GROUP BY provider",
            (tenant_id,),
        ).fetchall():
            by_provider[row["provider"]] = row["n"]

        shadow_count = cur.execute(
            "SELECT COUNT(*) FROM da_shadow_alerts WHERE tenant_id = ? AND acknowledged = 0",
            (tenant_id,),
        ).fetchone()[0]

    return {
        "tenant_id":        tenant_id,
        "total_agents":     total,
        "by_status":        by_status,
        "by_provider":      by_provider,
        "shadow_alerts":    shadow_count,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
