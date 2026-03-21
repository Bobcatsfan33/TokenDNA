"""
TokenDNA — GeoIP intelligence.

Resolves an IP address to country code, ASN, city, and lat/lon for use in
DNA fingerprinting and impossible-travel detection.

Provider priority:
  1. MaxMind GeoLite2 (offline, fast, accurate — set GEOIP_PROVIDER=maxmind)
  2. ip-api.com       (online, free for non-commercial — default)

Results are cached in Redis to avoid repeated lookups.
"""

import logging
from typing import Optional

import requests

from config import (
    GEOIP_PROVIDER,
    GEOIP_TIMEOUT,
    MAXMIND_DB_PATH,
    REDIS_GEO_TTL,
)

logger = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

class GeoResult:
    __slots__ = ("country", "asn", "city", "lat", "lon", "isp", "raw")

    def __init__(
        self,
        country: str = "XX",
        asn: str = "unknown",
        city: str = "unknown",
        lat: float = 0.0,
        lon: float = 0.0,
        isp: str = "unknown",
        raw: Optional[dict] = None,
    ):
        self.country = country.upper()[:2] if country else "XX"
        self.asn = asn or "unknown"
        self.city = city or "unknown"
        self.lat = lat
        self.lon = lon
        self.isp = isp or "unknown"
        self.raw = raw or {}

    def to_dict(self) -> dict:
        return {
            "country": self.country,
            "asn":     self.asn,
            "city":    self.city,
            "lat":     self.lat,
            "lon":     self.lon,
            "isp":     self.isp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GeoResult":
        return cls(
            country=d.get("country", "XX"),
            asn=d.get("asn", "unknown"),
            city=d.get("city", "unknown"),
            lat=float(d.get("lat", 0.0)),
            lon=float(d.get("lon", 0.0)),
            isp=d.get("isp", "unknown"),
        )

    @classmethod
    def unknown(cls) -> "GeoResult":
        """Safe fallback for private/loopback IPs or lookup failures."""
        return cls()


# ── Private IP detection ──────────────────────────────────────────────────────

import ipaddress

def _is_private(ip: str) -> bool:
    """Return True for loopback, link-local, and RFC-1918 addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ── ip-api.com provider ───────────────────────────────────────────────────────

_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,as,org"


def _lookup_ipapi(ip: str) -> GeoResult:
    try:
        resp = requests.get(
            _IPAPI_URL.format(ip=ip),
            timeout=GEOIP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            logger.warning(f"ip-api.com returned non-success for {ip}: {data.get('message')}")
            return GeoResult.unknown()

        # ASN comes back as e.g. "AS15169 Google LLC" — take first token
        asn_raw = data.get("as", "unknown")
        asn = asn_raw.split()[0] if asn_raw else "unknown"

        return GeoResult(
            country=data.get("countryCode", "XX"),
            asn=asn,
            city=data.get("city", "unknown"),
            lat=float(data.get("lat", 0.0)),
            lon=float(data.get("lon", 0.0)),
            isp=data.get("isp", "unknown"),
            raw=data,
        )
    except Exception as e:
        logger.warning(f"ip-api.com lookup failed for {ip}: {e}")
        return GeoResult.unknown()


# ── MaxMind GeoLite2 provider ─────────────────────────────────────────────────

def _lookup_maxmind(ip: str) -> GeoResult:
    try:
        import geoip2.database  # type: ignore
        with geoip2.database.Reader(MAXMIND_DB_PATH) as reader:
            city_resp = reader.city(ip)
            asn_path = MAXMIND_DB_PATH.replace("City", "ASN")
            asn_str = "unknown"
            try:
                with geoip2.database.Reader(asn_path) as asn_reader:
                    asn_resp = asn_reader.asn(ip)
                    asn_str = f"AS{asn_resp.autonomous_system_number}"
            except Exception:
                pass

            return GeoResult(
                country=city_resp.country.iso_code or "XX",
                asn=asn_str,
                city=city_resp.city.name or "unknown",
                lat=float(city_resp.location.latitude or 0.0),
                lon=float(city_resp.location.longitude or 0.0),
                isp=city_resp.traits.isp or "unknown",
            )
    except ImportError:
        logger.warning("geoip2 library not installed — falling back to ip-api.com")
        return _lookup_ipapi(ip)
    except Exception as e:
        logger.warning(f"MaxMind lookup failed for {ip}: {e}")
        return GeoResult.unknown()


# ── Public API ────────────────────────────────────────────────────────────────

def lookup(ip: str, redis_client=None) -> GeoResult:
    """
    Resolve an IP to a GeoResult, using Redis cache when available.

    Args:
        ip:           IPv4 or IPv6 address string
        redis_client: Optional redis.Redis instance for caching.
                      If None, performs a live lookup on every call.

    Returns:
        GeoResult with country, ASN, city, coordinates, and ISP.
    """
    if not ip or _is_private(ip):
        return GeoResult.unknown()

    cache_key = f"geo:{ip}"

    # ── Try cache first ───────────────────────────────────────────────────────
    if redis_client is not None:
        try:
            import json
            cached = redis_client.get(cache_key)
            if cached:
                return GeoResult.from_dict(json.loads(cached))
        except Exception as e:
            logger.debug(f"Redis geo cache read failed: {e}")

    # ── Live lookup ───────────────────────────────────────────────────────────
    result = (
        _lookup_maxmind(ip)
        if GEOIP_PROVIDER == "maxmind"
        else _lookup_ipapi(ip)
    )

    # ── Cache result ──────────────────────────────────────────────────────────
    if redis_client is not None:
        try:
            import json
            redis_client.setex(cache_key, REDIS_GEO_TTL, json.dumps(result.to_dict()))
        except Exception as e:
            logger.debug(f"Redis geo cache write failed: {e}")

    return result
