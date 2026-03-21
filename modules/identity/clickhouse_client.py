"""
TokenDNA -- ClickHouse event store.

tenant_id is a first-class column so every query can be scoped to one
customer without needing separate databases or tables per tenant.
"""

import logging
from typing import Optional

from config import (
    CLICKHOUSE_DB,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_PORT,
    CLICKHOUSE_SECURE,
    CLICKHOUSE_USER,
)

logger = logging.getLogger(__name__)
_client = None


def _get_client():
    global _client
    if _client is None:
        try:
            import clickhouse_connect
            _client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASSWORD,
                database=CLICKHOUSE_DB,
                secure=CLICKHOUSE_SECURE,
                connect_timeout=5,
                send_receive_timeout=10,
            )
            _ensure_schema(_client)
            logger.info("ClickHouse connected: %s:%s/%s", CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DB)
        except Exception as e:
            logger.warning("ClickHouse connection failed: %s", e)
            _client = None
    return _client


def _ensure_schema(client) -> None:
    client.command(f"""
        CREATE TABLE IF NOT EXISTS {CLICKHOUSE_DB}.sessions (
            timestamp         DateTime64(3)  DEFAULT now64(),
            request_id        String,
            tenant_id         String,
            user_id           String,
            device_hash       String,
            ip_hash           String,
            country           FixedString(2),
            asn               String,
            ua_os             String,
            ua_browser        String,
            is_mobile         Bool,
            ml_score          Int32,
            threat_penalty    Int32,
            graph_penalty     Int32,
            final_score       Int32,
            tier              String,
            reasons           Array(String),
            is_tor            Bool,
            is_datacenter     Bool,
            is_vpn            Bool,
            abuse_score       Int32,
            impossible_travel Bool,
            branching         Bool
        )
        ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (tenant_id, user_id, timestamp)
        TTL timestamp + INTERVAL 90 DAY
        SETTINGS index_granularity = 8192
    """)

    # Non-destructive migration: add tenant_id to existing tables that predate v2.1
    try:
        client.command(f"""
            ALTER TABLE {CLICKHOUSE_DB}.sessions
            ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT '_global_'
        """)
    except Exception:
        pass   # column already exists or DDL not supported -- harmless


def is_available() -> bool:
    try:
        c = _get_client()
        if c is None:
            return False
        c.command("SELECT 1")
        return True
    except Exception:
        return False


def insert_event(
    request_id: str,
    user_id: str,
    dna: dict,
    score_breakdown,
    threat_context=None,
    graph_result=None,
    tenant_id: str = "_global_",
) -> None:
    """
    Insert a session event.  Fails silently so a ClickHouse outage
    never blocks authentication.
    """
    client = _get_client()
    if client is None:
        return

    try:
        tc = threat_context
        gr = graph_result
        client.insert(
            f"{CLICKHOUSE_DB}.sessions",
            [[
                request_id,
                tenant_id,
                user_id,
                dna.get("device", ""),
                dna.get("ip", ""),
                dna.get("country", "XX"),
                dna.get("asn", "unknown"),
                dna.get("ua_os", "Other"),
                dna.get("ua_browser", "Other"),
                bool(dna.get("is_mobile", False)),
                int(score_breakdown.ml_score),
                int(score_breakdown.threat_penalty),
                int(score_breakdown.graph_penalty),
                int(score_breakdown.final_score),
                str(score_breakdown.tier.value),
                list(score_breakdown.reasons),
                bool(tc.is_tor        if tc else False),
                bool(tc.is_datacenter if tc else False),
                bool(tc.is_vpn        if tc else False),
                int(tc.abuse_score    if tc else 0),
                bool(gr.impossible_travel if gr else False),
                bool(gr.branching         if gr else False),
            ]],
            column_names=[
                "request_id", "tenant_id", "user_id",
                "device_hash", "ip_hash", "country", "asn",
                "ua_os", "ua_browser", "is_mobile",
                "ml_score", "threat_penalty", "graph_penalty",
                "final_score", "tier", "reasons",
                "is_tor", "is_datacenter", "is_vpn", "abuse_score",
                "impossible_travel", "branching",
            ],
        )
    except Exception as e:
        logger.warning("ClickHouse insert_event failed: %s", e)


def query_recent_events(tenant_id: str, limit: int = 50) -> list[dict]:
    """
    Return the most recent session events for a tenant.
    Used by the dashboard /api/events endpoint.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        result = client.query(
            f"""
            SELECT
                toString(timestamp) AS ts,
                request_id, user_id, country, asn,
                final_score, tier,
                is_tor, is_datacenter, is_vpn,
                impossible_travel, branching, reasons
            FROM {CLICKHOUSE_DB}.sessions
            WHERE tenant_id = %(tid)s
            ORDER BY timestamp DESC
            LIMIT %(lim)s
            """,
            parameters={"tid": tenant_id, "lim": limit},
        )
        cols = result.column_names
        return [dict(zip(cols, row)) for row in result.result_rows]
    except Exception as e:
        logger.warning("query_recent_events failed: %s", e)
        return []


def query_hourly_volume(tenant_id: str, hours: int = 24) -> list[dict]:
    """
    Return per-hour event counts bucketed by tier for the last N hours.
    Powers the volume chart on the dashboard.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        result = client.query(
            f"""
            SELECT
                toStartOfHour(timestamp) AS hour,
                countIf(tier = 'ALLOW')   AS allow,
                countIf(tier = 'STEP_UP') AS step_up,
                countIf(tier = 'BLOCK')   AS block,
                countIf(tier = 'REVOKE')  AS revoke
            FROM {CLICKHOUSE_DB}.sessions
            WHERE tenant_id = %(tid)s
              AND timestamp >= now() - INTERVAL %(h)s HOUR
            GROUP BY hour
            ORDER BY hour ASC
            """,
            parameters={"tid": tenant_id, "h": hours},
        )
        cols = result.column_names
        return [dict(zip(cols, row)) for row in result.result_rows]
    except Exception as e:
        logger.warning("query_hourly_volume failed: %s", e)
        return []


def query_threat_breakdown(tenant_id: str) -> dict:
    """Return counts of each threat signal type for the past 24 hours."""
    client = _get_client()
    if client is None:
        return {}
    try:
        result = client.query(
            f"""
            SELECT
                countIf(is_tor)            AS tor,
                countIf(impossible_travel) AS impossible_travel,
                countIf(is_datacenter)     AS datacenter,
                countIf(is_vpn)            AS vpn,
                countIf(branching)         AS branching,
                countIf(abuse_score > 0)   AS abuseipdb
            FROM {CLICKHOUSE_DB}.sessions
            WHERE tenant_id = %(tid)s
              AND timestamp >= now() - INTERVAL 24 HOUR
            """,
            parameters={"tid": tenant_id},
        )
        row  = result.first_row
        cols = result.column_names
        return dict(zip(cols, row)) if row else {}
    except Exception as e:
        logger.warning("query_threat_breakdown failed: %s", e)
        return {}
