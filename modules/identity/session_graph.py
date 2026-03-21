"""
TokenDNA — Session graph with impossible travel detection.  (ENHANCED)

Tracks per-user session history in Redis and detects two attack patterns:

  1. Session branching  — token used simultaneously from too many distinct
                          devices (lateral movement / credential sharing)

  2. Impossible travel  — token used from two locations that are physically
                          too far apart given the time elapsed between requests
                          (e.g. New York → London in 15 minutes = impossible)

Both checks store only what's needed (device hashes + geo coordinates +
timestamps) and cap history to a rolling window to control Redis memory.
"""

import json
import logging
import math
import time
from typing import Optional

from modules.identity.cache_redis import get_redis
from config import REDIS_PROFILE_TTL
from config import (
    BRANCHING_DEVICE_THRESHOLD,
    MAX_TRAVEL_SPEED_KMH,
    REDIS_PROFILE_TTL,
)

logger = logging.getLogger(__name__)

_MAX_EVENTS = 100   # rolling cap per user


def _key(user_id: str) -> str:
    return f"session_graph:{user_id}"


# ── Haversine distance formula ────────────────────────────────────────────────

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km between two lat/lon points."""
    R = 6371.0  # Earth radius km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi  = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── Data model ────────────────────────────────────────────────────────────────

class SessionEvent:
    __slots__ = ("device", "ip_hash", "country", "asn", "lat", "lon", "ts")

    def __init__(self, device: str, ip_hash: str, country: str, asn: str,
                 lat: float, lon: float, ts: float):
        self.device   = device
        self.ip_hash  = ip_hash
        self.country  = country
        self.asn      = asn
        self.lat      = lat
        self.lon      = lon
        self.ts       = ts

    def to_dict(self) -> dict:
        return {
            "device":  self.device,
            "ip_hash": self.ip_hash,
            "country": self.country,
            "asn":     self.asn,
            "lat":     self.lat,
            "lon":     self.lon,
            "ts":      self.ts,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionEvent":
        return cls(
            device=d.get("device", ""),
            ip_hash=d.get("ip_hash", ""),
            country=d.get("country", "XX"),
            asn=d.get("asn", "unknown"),
            lat=float(d.get("lat", 0.0)),
            lon=float(d.get("lon", 0.0)),
            ts=float(d.get("ts", 0.0)),
        )

    @classmethod
    def from_dna_and_geo(cls, dna: dict, geo=None) -> "SessionEvent":
        lat = float(getattr(geo, "lat", 0.0) if geo else 0.0)
        lon = float(getattr(geo, "lon", 0.0) if geo else 0.0)
        return cls(
            device=dna.get("device", ""),
            ip_hash=dna.get("ip", ""),
            country=dna.get("country", "XX"),
            asn=dna.get("asn", "unknown"),
            lat=lat,
            lon=lon,
            ts=time.time(),
        )


# ── Redis-backed graph ────────────────────────────────────────────────────────

def add_event(user_id: str, dna: dict, geo=None, redis=None) -> None:
    """Append a session event to the user's graph history (capped at _MAX_EVENTS)."""
    try:
        event = SessionEvent.from_dna_and_geo(dna, geo)
        r = redis if redis is not None else get_redis()
        key = f"graph:{user_id}"
        r.lpush(key, json.dumps(event.to_dict()))
        r.ltrim(key, 0, _MAX_EVENTS - 1)
        r.expire(key, REDIS_PROFILE_TTL)
    except Exception as e:
        logger.warning(f"add_event failed for {user_id}: {e}")


def _load_events(user_id: str, redis=None) -> list[SessionEvent]:
    try:
        r = redis if redis is not None else get_redis()
        raw = r.lrange(f"graph:{user_id}", 0, _MAX_EVENTS - 1)
        return [SessionEvent.from_dict(json.loads(item)) for item in raw]
    except Exception as e:
        logger.warning(f"_load_events failed for {user_id}: {e}")
        return []


# ── Detection checks ──────────────────────────────────────────────────────────

class GraphAnomalyResult:
    __slots__ = ("branching", "impossible_travel", "details")

    def __init__(self):
        self.branching: bool = False
        self.impossible_travel: bool = False
        self.details: dict = {}

    @property
    def has_anomaly(self) -> bool:
        return self.branching or self.impossible_travel

    def to_dict(self) -> dict:
        return {
            "branching":         self.branching,
            "impossible_travel": self.impossible_travel,
            "details":           self.details,
        }


def detect_anomalies(user_id: str, current_dna: dict, current_geo=None, redis=None) -> GraphAnomalyResult:
    """
    Run branching and impossible-travel checks against the session graph.

    Args:
        user_id:     Authenticated user identifier
        current_dna: DNA record for the current request
        current_geo: GeoResult for the current request (optional but recommended)

    Returns:
        GraphAnomalyResult with flags and detail payload for alerting.
    """
    result = GraphAnomalyResult()
    events = _load_events(user_id, redis=redis)

    if not events:
        return result  # No history yet — nothing to compare

    # ── 1. Session branching ──────────────────────────────────────────────────
    unique_devices = {e.device for e in events}
    unique_devices.add(current_dna.get("device", ""))
    if len(unique_devices) > BRANCHING_DEVICE_THRESHOLD:
        result.branching = True
        result.details["branching"] = {
            "unique_devices": len(unique_devices),
            "threshold": BRANCHING_DEVICE_THRESHOLD,
        }

    # ── 2. Impossible travel ──────────────────────────────────────────────────
    if current_geo and hasattr(current_geo, "lat"):
        now_lat = current_geo.lat
        now_lon = current_geo.lon
        now_ts  = time.time()

        # Compare against the most recent event that has non-zero coordinates
        for prev in events:
            if prev.lat == 0.0 and prev.lon == 0.0:
                continue
            # Skip if same device (no travel needed — it's the same machine)
            if prev.device == current_dna.get("device"):
                continue

            elapsed_h = (now_ts - prev.ts) / 3600.0
            if elapsed_h <= 0:
                continue

            dist_km = _haversine_km(prev.lat, prev.lon, now_lat, now_lon)
            speed_kmh = dist_km / elapsed_h

            if speed_kmh > MAX_TRAVEL_SPEED_KMH and dist_km > 100:
                result.impossible_travel = True
                result.details["impossible_travel"] = {
                    "distance_km":     round(dist_km, 1),
                    "elapsed_minutes": round(elapsed_h * 60, 1),
                    "speed_kmh":       round(speed_kmh, 1),
                    "prev_country":    prev.country,
                    "curr_country":    current_dna.get("country", "XX"),
                    "max_allowed_kmh": MAX_TRAVEL_SPEED_KMH,
                }
                break  # one confirmed impossible event is enough

    return result
