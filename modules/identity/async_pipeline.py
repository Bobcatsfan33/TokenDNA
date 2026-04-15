"""
TokenDNA -- Async event pipeline.
Offloads ClickHouse inserts to a thread pool so they never block requests.
"""
import asyncio
import logging

from modules.identity import clickhouse_client

logger = logging.getLogger(__name__)


async def process_event(
    request_id: str,
    user_id: str,
    dna: dict,
    score_breakdown,
    threat_context=None,
    graph_result=None,
    tenant_id: str = "_global_",
    uis_narrative=None,
) -> None:
    try:
        await asyncio.to_thread(
            clickhouse_client.insert_event,
            request_id,
            user_id,
            dna,
            score_breakdown,
            threat_context,
            graph_result,
            tenant_id,
            uis_narrative,
        )
    except Exception as e:
        logger.warning("async_pipeline.process_event failed: %s", e)
