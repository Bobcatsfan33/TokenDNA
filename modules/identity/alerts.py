"""
TokenDNA — Risk-adaptive alerting and response actions.

Alert tiers map to response actions:
    STEP_UP → trigger MFA challenge (no alert sent unless challenge fails)
    BLOCK   → Slack + SIEM webhook alert
    REVOKE  → Slack + SIEM webhook alert + token revocation

All webhook URLs and secrets come from environment variables (config.py).
SIEM webhooks are HMAC-signed with SIEM_WEBHOOK_SECRET if set.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import requests

from config import (
    MFA_CHALLENGE_URL,
    SLACK_WEBHOOK_URL,
    SIEM_WEBHOOK_URL,
    SIEM_WEBHOOK_SECRET,
    TOKEN_REVOKE_URL,
    TOKEN_REVOKE_SECRET,
)

logger = logging.getLogger(__name__)


# ── HMAC signing for SIEM webhook ─────────────────────────────────────────────

def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


# ── Low-level senders ─────────────────────────────────────────────────────────

async def _post(url: str, body: dict, headers: Optional[dict] = None) -> bool:
    if not url:
        return False
    try:
        payload_bytes = json.dumps(body).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        resp = await asyncio.to_thread(
            requests.post, url, data=payload_bytes, headers=hdrs, timeout=8
        )
        if not resp.ok:
            logger.warning(f"POST to {url} returned {resp.status_code}")
        return resp.ok
    except Exception as e:
        logger.warning(f"POST to {url} failed: {e}")
        return False


async def _send_slack(message: str) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    await _post(SLACK_WEBHOOK_URL, {"text": message})


async def _send_siem(payload: dict) -> None:
    if not SIEM_WEBHOOK_URL:
        return
    headers: dict = {}
    if SIEM_WEBHOOK_SECRET:
        payload_bytes = json.dumps(payload).encode("utf-8")
        sig = _sign_payload(payload_bytes, SIEM_WEBHOOK_SECRET)
        headers["X-TokenDNA-Signature"] = f"sha256={sig}"
    await _post(SIEM_WEBHOOK_URL, payload, headers)


async def _trigger_mfa_challenge(user_id: str, request_id: str) -> bool:
    if not MFA_CHALLENGE_URL:
        logger.warning("MFA_CHALLENGE_URL not configured — step-up auth skipped.")
        return False
    return await _post(MFA_CHALLENGE_URL, {
        "user_id":    user_id,
        "request_id": request_id,
        "reason":     "tokendna_step_up",
        "timestamp":  time.time(),
    })


async def _revoke_token_remote(jti: str, user_id: str) -> bool:
    if not TOKEN_REVOKE_URL:
        return False
    headers: dict = {}
    if TOKEN_REVOKE_SECRET:
        payload_bytes = json.dumps({"jti": jti}).encode("utf-8")
        sig = _sign_payload(payload_bytes, TOKEN_REVOKE_SECRET)
        headers["X-TokenDNA-Signature"] = f"sha256={sig}"
    return await _post(TOKEN_REVOKE_URL, {
        "jti":       jti,
        "user_id":   user_id,
        "reason":    "tokendna_revoke",
        "timestamp": time.time(),
    }, headers)


# ── Alert payload builder ─────────────────────────────────────────────────────

def _build_alert(
    user_id: str,
    request_id: str,
    score_breakdown: dict,
    dna: dict,
    threat_context: Optional[dict],
    graph_result: Optional[dict],
) -> dict:
    return {
        "source":      "TokenDNA",
        "timestamp":   time.time(),
        "request_id":  request_id,
        "user_id":     user_id,
        "tier":        score_breakdown.get("tier"),
        "final_score": score_breakdown.get("final_score"),
        "reasons":     score_breakdown.get("reasons", []),
        "dna": {
            "country":    dna.get("country"),
            "asn":        dna.get("asn"),
            "ua_os":      dna.get("ua_os"),
            "ua_browser": dna.get("ua_browser"),
            "is_mobile":  dna.get("is_mobile"),
        },
        "threat":  threat_context or {},
        "graph":   graph_result or {},
    }


def _slack_message(user_id: str, score_breakdown: dict, dna: dict) -> str:
    tier  = score_breakdown.get("tier", "unknown").upper()
    score = score_breakdown.get("final_score", 0)
    reasons = ", ".join(score_breakdown.get("reasons", []))
    emoji = "🚨" if tier == "REVOKE" else "⚠️"
    return (
        f"{emoji} *TokenDNA {tier} Alert*\n"
        f"• User: `{user_id}`\n"
        f"• Score: `{score}/100`\n"
        f"• Reasons: `{reasons}`\n"
        f"• Country: `{dna.get('country')}` · ASN: `{dna.get('asn')}`\n"
        f"• Device: `{dna.get('ua_os')} / {dna.get('ua_browser')}`"
    )


# ── Public dispatch ───────────────────────────────────────────────────────────

async def handle_step_up(
    user_id: str,
    request_id: str,
) -> bool:
    """Trigger an MFA challenge. Returns True if challenge was dispatched."""
    logger.info(f"Step-up MFA triggered for {user_id} (request {request_id})")
    return await _trigger_mfa_challenge(user_id, request_id)


async def handle_block(
    user_id: str,
    request_id: str,
    score_breakdown: dict,
    dna: dict,
    threat_context: Optional[dict] = None,
    graph_result: Optional[dict] = None,
) -> None:
    """Send alerts for a BLOCK-tier event."""
    logger.warning(f"BLOCK: user={user_id} score={score_breakdown.get('final_score')}")
    alert = _build_alert(user_id, request_id, score_breakdown, dna, threat_context, graph_result)
    await asyncio.gather(
        _send_slack(_slack_message(user_id, score_breakdown, dna)),
        _send_siem(alert),
    )


async def handle_revoke(
    user_id: str,
    request_id: str,
    jti: str,
    score_breakdown: dict,
    dna: dict,
    threat_context: Optional[dict] = None,
    graph_result: Optional[dict] = None,
) -> None:
    """Send alerts and revoke token for a REVOKE-tier event."""
    logger.error(f"REVOKE: user={user_id} score={score_breakdown.get('final_score')} jti={jti}")
    alert = _build_alert(user_id, request_id, score_breakdown, dna, threat_context, graph_result)
    alert["jti"] = jti
    await asyncio.gather(
        _send_slack(_slack_message(user_id, score_breakdown, dna)),
        _send_siem(alert),
        _revoke_token_remote(jti, user_id),
    )
