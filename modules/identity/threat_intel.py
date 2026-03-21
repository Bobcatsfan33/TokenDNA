"""
TokenDNA — Threat Intelligence enrichment.  (NEW MODULE)

Enriches an IP address with threat context from multiple sources:

  1. Tor exit nodes   — Tor Project bulk exit list (refreshed periodically)
  2. Datacenter IPs   — Detects AWS, GCP, Azure, and generic hosting ASNs
  3. VPN/Proxy heuristics — Common VPN ASN prefixes and hosting patterns
  4. AbuseIPDB        — Crowdsourced abuse confidence score (optional API key)

All checks are designed to be fast (Redis-cached) and fail-open: if a check
cannot be completed, it does not block the request — it contributes zero
penalty to the risk score.
"""

import logging
import threading
import time
from typing import Optional

import requests

from config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_MIN_CONFIDENCE,
    REDIS_GEO_TTL,
    TOR_REFRESH_INTERVAL,
)

logger = logging.getLogger(__name__)


# ── Tor exit node list ────────────────────────────────────────────────────────

_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_tor_exits: set = set()
_tor_last_refresh: float = 0.0
_tor_lock = threading.Lock()


def _refresh_tor_list() -> None:
    global _tor_exits, _tor_last_refresh
    try:
        resp = requests.get(_TOR_LIST_URL, timeout=10)
        resp.raise_for_status()
        new_exits = {
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        with _tor_lock:
            _tor_exits = new_exits
            _tor_last_refresh = time.time()
        logger.info(f"Tor exit list refreshed: {len(new_exits)} exits loaded.")
    except Exception as e:
        logger.warning(f"Failed to refresh Tor exit list: {e}")


def _ensure_tor_list() -> None:
    if time.time() - _tor_last_refresh > TOR_REFRESH_INTERVAL:
        thread = threading.Thread(target=_refresh_tor_list, daemon=True)
        thread.start()
        # On first call, wait briefly so we have data
        if _tor_last_refresh == 0.0:
            thread.join(timeout=8)


def is_tor_exit(ip: str) -> bool:
    """Return True if the IP is a known Tor exit node."""
    _ensure_tor_list()
    with _tor_lock:
        return ip in _tor_exits


# ── Datacenter / hosting IP detection ────────────────────────────────────────

# Well-known cloud/hosting ASN prefixes.  These are public information.
_DATACENTER_ASN_PREFIXES = (
    "AS16509",  # Amazon AWS
    "AS14618",  # Amazon AWS (older)
    "AS15169",  # Google Cloud
    "AS19527",  # Google Cloud
    "AS8075",   # Microsoft Azure
    "AS20940",  # Akamai
    "AS13335",  # Cloudflare
    "AS14061",  # DigitalOcean
    "AS63949",  # Linode (Akamai)
    "AS16276",  # OVHcloud
    "AS24940",  # Hetzner
    "AS46484",  # Vultr
    "AS35540",  # Vultr
    "AS62567",  # DigitalOcean
    "AS60068",  # CDN77
    "AS136907", # Huawei Cloud
)

_HOSTING_KEYWORDS = ("hosting", "datacenter", "data center", "cloud", "server",
                     "vps", "colocation", "colo", "dedicated")


def is_datacenter_ip(asn: str, isp: str = "") -> bool:
    """Return True if the ASN or ISP name looks like a cloud/hosting provider."""
    asn_upper = (asn or "").upper()
    if any(asn_upper.startswith(dc) for dc in _DATACENTER_ASN_PREFIXES):
        return True
    isp_lower = (isp or "").lower()
    return any(kw in isp_lower for kw in _HOSTING_KEYWORDS)


# ── VPN / proxy heuristic ────────────────────────────────────────────────────

_VPN_KEYWORDS = ("vpn", "proxy", "anonymizer", "anonymous", "hide", "tunnel",
                 "mullvad", "nordvpn", "expressvpn", "protonvpn", "pia ",
                 "private internet", "torguard", "windscribe", "surfshark",
                 "cyberghost", "ipvanish")


def is_vpn_or_proxy(isp: str = "", org: str = "") -> bool:
    """Heuristic: return True if the ISP/org name suggests a VPN or proxy."""
    combined = (f"{isp} {org}").lower()
    return any(kw in combined for kw in _VPN_KEYWORDS)


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def get_abuse_score(ip: str, redis_client=None) -> int:
    """
    Query AbuseIPDB for the abuse confidence score (0–100).
    Returns 0 if no API key configured or the lookup fails.
    Results are cached in Redis for 24 hours.
    """
    if not ABUSEIPDB_API_KEY:
        return 0

    cache_key = f"abuseipdb:{ip}"
    if redis_client is not None:
        try:
            cached = redis_client.get(cache_key)
            if cached is not None:
                return int(cached)
        except Exception:
            pass

    try:
        resp = requests.get(
            _ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        resp.raise_for_status()
        score = int(resp.json().get("data", {}).get("abuseConfidenceScore", 0))

        if redis_client is not None:
            try:
                redis_client.setex(cache_key, 86400, str(score))
            except Exception:
                pass

        return score
    except Exception as e:
        logger.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return 0


# ── Unified threat context ────────────────────────────────────────────────────

class ThreatContext:
    """Aggregated threat intelligence for a single IP."""

    __slots__ = ("ip", "is_tor", "is_datacenter", "is_vpn", "abuse_score", "flags")

    def __init__(
        self,
        ip: str,
        is_tor: bool = False,
        is_datacenter: bool = False,
        is_vpn: bool = False,
        abuse_score: int = 0,
    ):
        self.ip = ip
        self.is_tor = is_tor
        self.is_datacenter = is_datacenter
        self.is_vpn = is_vpn
        self.abuse_score = abuse_score
        self.flags: list[str] = []
        if is_tor:          self.flags.append("tor_exit")
        if is_datacenter:   self.flags.append("datacenter")
        if is_vpn:          self.flags.append("vpn_proxy")
        if abuse_score >= ABUSEIPDB_MIN_CONFIDENCE:
            self.flags.append(f"abuse:{abuse_score}")

    @property
    def is_suspicious(self) -> bool:
        return bool(self.flags)

    def to_dict(self) -> dict:
        return {
            "is_tor":        self.is_tor,
            "is_datacenter": self.is_datacenter,
            "is_vpn":        self.is_vpn,
            "abuse_score":   self.abuse_score,
            "flags":         self.flags,
        }


def enrich(ip: str, asn: str = "", isp: str = "", redis_client=None) -> ThreatContext:
    """
    Run all threat intel checks for an IP and return a ThreatContext.

    Designed to be fast: Tor and AbuseIPDB are Redis-cached; datacenter/VPN
    checks are in-process lookups with no network calls.
    """
    return ThreatContext(
        ip=ip,
        is_tor=is_tor_exit(ip),
        is_datacenter=is_datacenter_ip(asn, isp),
        is_vpn=is_vpn_or_proxy(isp),
        abuse_score=get_abuse_score(ip, redis_client),
    )
