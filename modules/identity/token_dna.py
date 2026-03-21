"""
TokenDNA — Session fingerprint ("DNA") generation.

A DNA is a compact, versioned record of the network/device signals present on
a given request.  All sensitive values are hashed with SHA-256 (not MD5) so
that the stored fingerprint cannot be reversed to recover the original IP or
User-Agent, while still enabling exact-match comparisons.

DNA schema v2:
    version  : int          schema version for migration compatibility
    device   : str          SHA-256(User-Agent)
    ip       : str          SHA-256(IP address)
    country  : str          ISO-3166-1 alpha-2 country code
    asn      : str          ASN string (e.g. "AS15169")
    ua_os    : str          extracted OS family   (Windows / macOS / Linux / iOS / Android / Other)
    ua_browser: str         extracted browser family (Chrome / Firefox / Safari / Edge / Other)
    is_mobile : bool        true when request is from a mobile user agent
"""

import hashlib
import hmac
import os
import re
from typing import Optional

# ── HMAC key for privacy-preserving IP/UA hashing ────────────────────────────
# Plain SHA-256 of an IPv4 address is reversible (rainbow table over 4B addrs).
# HMAC-SHA256 with a platform secret prevents reversal even with full DB access.
# Set DNA_HMAC_KEY in production (load from AWS Secrets Manager or Vault).
# FedRAMP SC-28 / privacy requirement.
_DNA_HMAC_KEY: bytes = os.getenv("DNA_HMAC_KEY", "").encode() or b"dev-only-insecure-key"


# ── Schema version — bump when DNA structure changes ─────────────────────────
DNA_VERSION = 2


# ── User-Agent parsing helpers ────────────────────────────────────────────────

_OS_PATTERNS = [
    (re.compile(r"Windows", re.I),  "Windows"),
    (re.compile(r"Macintosh|Mac OS X", re.I), "macOS"),
    (re.compile(r"Android", re.I),  "Android"),
    (re.compile(r"iPhone|iPad|iPod", re.I), "iOS"),
    (re.compile(r"Linux", re.I),    "Linux"),
    (re.compile(r"CrOS", re.I),     "ChromeOS"),
]

_BROWSER_PATTERNS = [
    (re.compile(r"Edg/|Edge/", re.I),    "Edge"),
    (re.compile(r"Chrome/", re.I),       "Chrome"),
    (re.compile(r"Firefox/", re.I),      "Firefox"),
    (re.compile(r"Safari/", re.I),       "Safari"),
    (re.compile(r"OPR/|Opera/", re.I),   "Opera"),
    (re.compile(r"curl/", re.I),         "curl"),
    (re.compile(r"python-requests", re.I), "requests"),
]

_MOBILE_RE = re.compile(r"Mobile|Android|iPhone|iPad|iPod", re.I)


def _extract_os(ua: str) -> str:
    for pattern, name in _OS_PATTERNS:
        if pattern.search(ua):
            return name
    return "Other"


def _extract_browser(ua: str) -> str:
    for pattern, name in _BROWSER_PATTERNS:
        if pattern.search(ua):
            return name
    return "Other"


def _is_mobile(ua: str) -> bool:
    return bool(_MOBILE_RE.search(ua))


# ── Hashing ───────────────────────────────────────────────────────────────────

def _sha256(val: str) -> str:
    """HMAC-SHA256(val, platform_key) → first 32 hex chars.

    Using HMAC-SHA256 instead of plain SHA-256 prevents rainbow table
    reversal of IP addresses (the 32-bit IPv4 space is fully enumerable).
    Truncation to 32 chars preserves uniqueness for comparison while
    keeping stored fingerprints compact.

    FedRAMP SC-28 / IL6 privacy requirement.
    """
    return hmac.new(
        _DNA_HMAC_KEY,
        val.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


# ── Public API ────────────────────────────────────────────────────────────────

def generate_dna(
    user_agent: str,
    ip: str,
    country: str,
    asn: str,
) -> dict:
    """
    Build a versioned DNA fingerprint from request signals.

    Args:
        user_agent: HTTP User-Agent header value
        ip:         Client IP address (IPv4 or IPv6)
        country:    ISO-3166-1 alpha-2 country code from GeoIP
        asn:        Autonomous System Number string (e.g. "AS15169")

    Returns:
        DNA dict ready for scoring, caching, or ClickHouse insertion.
    """
    ua = user_agent.strip() if user_agent else ""
    ip = ip.strip() if ip else ""
    country = (country or "XX").upper()[:2]
    asn = (asn or "unknown").upper()

    return {
        "version":    DNA_VERSION,
        "device":     _sha256(ua) if ua else "unknown",
        "ip":         _sha256(ip) if ip else "unknown",
        "country":    country,
        "asn":        asn,
        "ua_os":      _extract_os(ua),
        "ua_browser": _extract_browser(ua),
        "is_mobile":  _is_mobile(ua),
    }


def dna_matches(a: dict, b: dict) -> bool:
    """True if two DNA records represent the same device on the same network."""
    return (
        a.get("device") == b.get("device")
        and a.get("ip") == b.get("ip")
        and a.get("country") == b.get("country")
        and a.get("asn") == b.get("asn")
    )


def migrate_dna(dna: dict) -> dict:
    """Upgrade a v1 DNA (abbreviated keys) to v2 (descriptive keys)."""
    version = dna.get("version", 1)
    if version >= DNA_VERSION:
        return dna
    if version == 1:
        return {
            "version":    DNA_VERSION,
            "device":     dna.get("d", "unknown"),
            "ip":         dna.get("i", "unknown"),
            "country":    dna.get("c", "XX"),
            "asn":        dna.get("a", "unknown"),
            "ua_os":      "Other",
            "ua_browser": "Other",
            "is_mobile":  False,
        }
    return dna
