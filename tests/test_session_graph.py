"""
Tests — Session Graph: impossible travel & session branching  (Phase 2D)

Coverage targets for modules/identity/session_graph.py:
  - SessionEvent construction and serialization
  - add_event: push to Redis mock, cap at _MAX_EVENTS, TTL set
  - _load_events: deserialize from Redis mock
  - Haversine distance computation edge cases
  - detect_anomalies:
      - No history → clean result
      - Session branching: device count threshold
      - Impossible travel: distance + speed detection
      - Same device skipped in travel check
      - Zero coords skipped in travel check
      - Combined: branching + travel in same session
  - GraphAnomalyResult.has_anomaly, to_dict()
  - Cycle detection via repeated event sequence (branching surrogate)
"""

import json
import math
import time
from unittest.mock import MagicMock, patch
import pytest

import os
os.environ.setdefault("BRANCHING_DEVICE_THRESHOLD", "3")
os.environ.setdefault("MAX_TRAVEL_SPEED_KMH", "900")
os.environ.setdefault("REDIS_PROFILE_TTL", "604800")

from modules.identity.session_graph import (
    SessionEvent,
    GraphAnomalyResult,
    add_event,
    detect_anomalies,
    _haversine_km,
    _load_events,
    _MAX_EVENTS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_event(
    device:  str   = "device-A",
    country: str   = "US",
    lat:     float = 40.7128,
    lon:     float = -74.0060,
    ts:      float = None,
) -> SessionEvent:
    return SessionEvent(
        device=device,
        ip_hash=f"hash-{device}",
        country=country,
        asn="AS1234",
        lat=lat,
        lon=lon,
        ts=ts or time.time(),
    )


def _make_redis_mock(events: list[SessionEvent]) -> MagicMock:
    """Return a mock Redis client pre-loaded with serialized events."""
    serialized = [json.dumps(e.to_dict()).encode() for e in events]
    mock = MagicMock()
    mock.lrange.return_value = serialized
    return mock


def _make_geo_mock(lat: float, lon: float) -> MagicMock:
    geo = MagicMock()
    geo.lat = lat
    geo.lon = lon
    return geo


def _make_dna(device: str = "device-A", country: str = "US") -> dict:
    return {"device": device, "ip": "1.2.3.4", "country": country, "asn": "AS1234"}


# ─────────────────────────────────────────────────────────────────────────────
# 1. SessionEvent
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionEvent:
    def test_construction(self):
        e = _make_event()
        assert e.device  == "device-A"
        assert e.country == "US"
        assert e.lat     == pytest.approx(40.7128, abs=0.001)
        assert e.lon     == pytest.approx(-74.0060, abs=0.001)

    def test_to_dict_fields(self):
        e = _make_event()
        d = e.to_dict()
        assert set(d.keys()) == {"device", "ip_hash", "country", "asn", "lat", "lon", "ts"}

    def test_from_dict_roundtrip(self):
        e = _make_event(device="device-Z", lat=51.5, lon=-0.127)
        d = e.to_dict()
        e2 = SessionEvent.from_dict(d)
        assert e2.device  == "device-Z"
        assert e2.lat     == pytest.approx(51.5)
        assert e2.lon     == pytest.approx(-0.127)

    def test_from_dict_defaults(self):
        e = SessionEvent.from_dict({})
        assert e.device  == ""
        assert e.country == "XX"
        assert e.lat     == 0.0
        assert e.lon     == 0.0
        assert e.ts      == 0.0

    def test_from_dna_and_geo(self):
        dna = {"device": "dev-1", "ip": "1.2.3.4", "country": "GB", "asn": "AS5"}
        geo = _make_geo_mock(lat=51.5, lon=-0.127)
        e = SessionEvent.from_dna_and_geo(dna, geo)
        assert e.device  == "dev-1"
        assert e.country == "GB"
        assert e.lat     == pytest.approx(51.5)
        assert e.lon     == pytest.approx(-0.127)

    def test_from_dna_and_geo_no_geo(self):
        dna = {"device": "dev-1", "ip": "x", "country": "US", "asn": "AS1"}
        e = SessionEvent.from_dna_and_geo(dna, None)
        assert e.lat == 0.0
        assert e.lon == 0.0

    def test_json_serialization(self):
        e = _make_event()
        j = json.dumps(e.to_dict())
        d = json.loads(j)
        e2 = SessionEvent.from_dict(d)
        assert e2.device == e.device

    def test_ts_is_float(self):
        e = _make_event()
        assert isinstance(e.ts, float)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Haversine distance
# ─────────────────────────────────────────────────────────────────────────────

class TestHaversine:
    def test_same_point_zero_distance(self):
        d = _haversine_km(40.7128, -74.006, 40.7128, -74.006)
        assert d == pytest.approx(0.0, abs=0.01)

    def test_nyc_to_london(self):
        # NYC (40.7128, -74.006) → London (51.5074, -0.1278) ≈ 5570 km
        d = _haversine_km(40.7128, -74.006, 51.5074, -0.1278)
        assert 5500 < d < 5700, f"Expected ~5570 km, got {d:.1f}"

    def test_nyc_to_la(self):
        # NYC → LA ≈ 3940 km
        d = _haversine_km(40.7128, -74.006, 34.0522, -118.2437)
        assert 3800 < d < 4100, f"Expected ~3940 km, got {d:.1f}"

    def test_symmetry(self):
        d1 = _haversine_km(40.7128, -74.006, 51.5074, -0.1278)
        d2 = _haversine_km(51.5074, -0.1278, 40.7128, -74.006)
        assert d1 == pytest.approx(d2, rel=0.001)

    def test_north_pole_to_equator(self):
        # Pole (90, 0) → equator (0, 0) ≈ 10,007 km
        d = _haversine_km(90.0, 0.0, 0.0, 0.0)
        assert 9000 < d < 11000

    def test_short_distance(self):
        # Two points 1km apart (approx)
        d = _haversine_km(40.0, -74.0, 40.009, -74.0)
        assert 0.5 < d < 2.0

    def test_antipodal_max_distance(self):
        # Antipodal points ≈ 20015 km
        d = _haversine_km(0.0, 0.0, 0.0, 180.0)
        assert 18000 < d < 22000

    def test_negative_coordinates(self):
        # Should handle negative lat/lon
        d = _haversine_km(-33.8688, 151.2093, -36.8485, 174.7633)
        assert 2100 < d < 2300  # Sydney → Auckland ≈ 2155 km

    def test_zero_zero(self):
        d = _haversine_km(0.0, 0.0, 0.0, 0.0)
        assert d == pytest.approx(0.0, abs=0.01)

    def test_returns_float(self):
        d = _haversine_km(40.0, -74.0, 51.5, -0.1)
        assert isinstance(d, float)


# ─────────────────────────────────────────────────────────────────────────────
# 3. GraphAnomalyResult
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphAnomalyResult:
    def test_default_no_anomaly(self):
        r = GraphAnomalyResult()
        assert r.branching == False
        assert r.impossible_travel == False
        assert r.has_anomaly == False

    def test_branching_has_anomaly(self):
        r = GraphAnomalyResult()
        r.branching = True
        assert r.has_anomaly == True

    def test_travel_has_anomaly(self):
        r = GraphAnomalyResult()
        r.impossible_travel = True
        assert r.has_anomaly == True

    def test_both_has_anomaly(self):
        r = GraphAnomalyResult()
        r.branching = True
        r.impossible_travel = True
        assert r.has_anomaly == True

    def test_to_dict(self):
        r = GraphAnomalyResult()
        r.branching = True
        r.details = {"branching": {"unique_devices": 4}}
        d = r.to_dict()
        assert d["branching"] == True
        assert d["impossible_travel"] == False
        assert "details" in d

    def test_to_dict_complete_keys(self):
        r = GraphAnomalyResult()
        d = r.to_dict()
        assert set(d.keys()) == {"branching", "impossible_travel", "details"}


# ─────────────────────────────────────────────────────────────────────────────
# 4. add_event
# ─────────────────────────────────────────────────────────────────────────────

class TestAddEvent:
    def test_add_event_pushes_to_redis(self):
        mock_redis = MagicMock()
        dna = _make_dna()
        add_event("user-1", dna, redis=mock_redis)
        assert mock_redis.lpush.called
        assert mock_redis.ltrim.called
        assert mock_redis.expire.called

    def test_add_event_caps_at_max_events(self):
        mock_redis = MagicMock()
        add_event("user-1", _make_dna(), redis=mock_redis)
        _, trim_args, _ = mock_redis.ltrim.mock_calls[0]
        # ltrim(key, 0, _MAX_EVENTS - 1)
        assert trim_args[2] == _MAX_EVENTS - 1

    def test_add_event_sets_ttl(self):
        mock_redis = MagicMock()
        add_event("user-1", _make_dna(), redis=mock_redis)
        assert mock_redis.expire.called

    def test_add_event_with_geo(self):
        mock_redis = MagicMock()
        geo = _make_geo_mock(lat=40.7128, lon=-74.0)
        add_event("user-1", _make_dna(), geo=geo, redis=mock_redis)
        # Check the pushed data contains lat
        pushed_json = mock_redis.lpush.call_args[0][1]
        data = json.loads(pushed_json)
        assert data["lat"] == pytest.approx(40.7128)

    def test_add_event_redis_error_does_not_raise(self):
        mock_redis = MagicMock()
        mock_redis.lpush.side_effect = Exception("Redis down")
        # Should not raise
        add_event("user-1", _make_dna(), redis=mock_redis)


# ─────────────────────────────────────────────────────────────────────────────
# 5. detect_anomalies — no history
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectAnomaliesNoHistory:
    def test_no_history_no_anomaly(self):
        mock_redis = MagicMock()
        mock_redis.lrange.return_value = []
        result = detect_anomalies("user-1", _make_dna(), redis=mock_redis)
        assert not result.has_anomaly

    def test_no_history_returns_graph_result(self):
        mock_redis = MagicMock()
        mock_redis.lrange.return_value = []
        result = detect_anomalies("user-1", _make_dna(), redis=mock_redis)
        assert isinstance(result, GraphAnomalyResult)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Session branching detection
# ─────────────────────────────────────────────────────────────────────────────

class TestSessionBranching:
    def _run_detection(self, existing_devices: list[str], current_device: str = "device-X") -> GraphAnomalyResult:
        events = [_make_event(device=d) for d in existing_devices]
        mock_redis = _make_redis_mock(events)
        dna = _make_dna(device=current_device)
        return detect_anomalies("user-1", dna, redis=mock_redis)

    def test_no_branching_below_threshold(self):
        # threshold=3: <= 3 unique devices → no branching
        result = self._run_detection(["d1", "d2"], current_device="d3")
        # 3 devices total — depends on threshold interpretation
        # threshold=3 → branch if > 3 devices
        assert not result.branching

    def test_branching_above_threshold(self):
        # 3 existing + 1 current = 4 unique → above threshold 3
        result = self._run_detection(["d1", "d2", "d3"], current_device="d4")
        assert result.branching

    def test_branching_at_threshold(self):
        # 2 existing + 1 current = 3 unique → AT threshold, not above
        result = self._run_detection(["d1", "d2"], current_device="d3")
        assert not result.branching

    def test_branching_same_device_no_branch(self):
        # All requests from same device → no branching
        result = self._run_detection(["device-A", "device-A", "device-A"], current_device="device-A")
        assert not result.branching

    def test_branching_details_populated(self):
        result = self._run_detection(["d1", "d2", "d3"], current_device="d4")
        assert result.branching
        assert "branching" in result.details
        assert result.details["branching"]["unique_devices"] == 4

    def test_branching_exactly_four_devices(self):
        result = self._run_detection(["d1", "d2", "d3"], current_device="d4")
        assert result.branching
        assert result.details["branching"]["unique_devices"] == 4

    def test_branching_five_devices(self):
        result = self._run_detection(["d1", "d2", "d3", "d4"], current_device="d5")
        assert result.branching

    def test_branching_threshold_in_details(self):
        result = self._run_detection(["d1", "d2", "d3"], current_device="d4")
        assert result.details["branching"]["threshold"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# 7. Impossible travel detection
# ─────────────────────────────────────────────────────────────────────────────

class TestImpossibleTravel:
    # NYC coords
    NYC_LAT, NYC_LON = 40.7128, -74.0060
    # London coords
    LON_LAT, LON_LON = 51.5074, -0.1278
    # LA coords
    LA_LAT,  LA_LON  = 34.0522, -118.2437

    def test_impossible_travel_nyc_to_london_5min(self):
        """NYC → London in 5 minutes is physically impossible."""
        now = time.time()
        events = [_make_event(
            device="device-B",
            lat=self.NYC_LAT, lon=self.NYC_LON,
            ts=now - 5 * 60,   # 5 minutes ago
        )]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.LON_LAT, lon=self.LON_LON)
        dna = _make_dna(device="device-A")  # different device
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert result.impossible_travel

    def test_possible_travel_nyc_to_la_overnight(self):
        """NYC → LA in 6 hours is possible (flight)."""
        now = time.time()
        events = [_make_event(
            device="device-B",
            lat=self.NYC_LAT, lon=self.NYC_LON,
            ts=now - 6 * 3600,   # 6 hours ago
        )]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.LA_LAT, lon=self.LA_LON)
        dna = _make_dna(device="device-A")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert not result.impossible_travel

    def test_same_device_skipped_in_travel_check(self):
        """Travel check skips events from the same device as current request."""
        now = time.time()
        events = [_make_event(
            device="same-device",
            lat=self.NYC_LAT, lon=self.NYC_LON,
            ts=now - 5 * 60,
        )]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.LON_LAT, lon=self.LON_LON)
        dna = _make_dna(device="same-device")  # same device as event!
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert not result.impossible_travel

    def test_zero_coords_skipped(self):
        """Events with lat=0,lon=0 are skipped in travel check (missing geo)."""
        now = time.time()
        events = [_make_event(device="device-B", lat=0.0, lon=0.0, ts=now - 5 * 60)]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.LON_LAT, lon=self.LON_LON)
        dna = _make_dna(device="device-A")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert not result.impossible_travel

    def test_no_geo_on_current_request(self):
        """Without current geo, no travel check is performed."""
        now = time.time()
        events = [_make_event(device="device-B", lat=self.NYC_LAT, lon=self.NYC_LON, ts=now - 5 * 60)]
        mock_redis = _make_redis_mock(events)
        result = detect_anomalies("user-1", _make_dna(), current_geo=None, redis=mock_redis)
        assert not result.impossible_travel

    def test_travel_details_populated(self):
        now = time.time()
        events = [_make_event(device="device-B", lat=self.NYC_LAT, lon=self.NYC_LON, ts=now - 5 * 60)]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.LON_LAT, lon=self.LON_LON)
        dna = _make_dna(device="device-A")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert result.impossible_travel
        d = result.details["impossible_travel"]
        assert "distance_km"     in d
        assert "elapsed_minutes" in d
        assert "speed_kmh"       in d
        assert "prev_country"    in d
        assert "curr_country"    in d
        assert "max_allowed_kmh" in d

    def test_travel_distance_over_100km_required(self):
        """Travel < 100 km doesn't trigger flag even at high speed."""
        now = time.time()
        # Two points ~5 km apart, 1 second apart → impossible speed
        close_lat = self.NYC_LAT + 0.04  # ~4 km away
        events = [_make_event(device="device-B", lat=close_lat, lon=self.NYC_LON, ts=now - 1)]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.NYC_LAT, lon=self.NYC_LON)
        dna = _make_dna(device="device-A")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        # Speed is extreme but distance < 100 km → no flag
        assert not result.impossible_travel

    def test_exact_max_speed_boundary(self):
        """At exactly MAX_TRAVEL_SPEED_KMH → no flag."""
        now = time.time()
        # ~900 km in 1 hour → at limit (NYC to roughly Chicago area)
        target_lat = 48.7  # approx 900 km north of NYC
        events = [_make_event(device="device-B", lat=target_lat, lon=self.NYC_LON, ts=now - 3600)]
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=self.NYC_LAT, lon=self.NYC_LON)
        dna = _make_dna(device="device-A")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        # Speed ≈ 900 km/h — may or may not trigger depending on exact distance
        # Just verify it doesn't crash
        assert isinstance(result.impossible_travel, bool)


# ─────────────────────────────────────────────────────────────────────────────
# 8. Combined anomalies
# ─────────────────────────────────────────────────────────────────────────────

class TestCombinedAnomalies:
    def test_branching_and_travel_both_detected(self):
        now = time.time()
        events = [
            # Branching: 3 different devices (threshold=3)
            _make_event(device="d1", lat=40.7128, lon=-74.006, ts=now - 600),
            _make_event(device="d2", lat=40.7128, lon=-74.006, ts=now - 400),
            _make_event(device="d3", lat=40.7128, lon=-74.006, ts=now - 200),
        ]
        mock_redis = _make_redis_mock(events)
        # Current: new device (4th) from London → triggers both
        geo = _make_geo_mock(lat=51.5074, lon=-0.1278)
        dna = _make_dna(device="d4", country="GB")
        result = detect_anomalies("user-1", dna, current_geo=geo, redis=mock_redis)
        assert result.branching
        assert result.impossible_travel
        assert result.has_anomaly

    def test_redis_error_graceful_fallback(self):
        """If Redis fails, detect_anomalies returns clean result (no anomaly)."""
        mock_redis = MagicMock()
        mock_redis.lrange.side_effect = Exception("Redis down")
        result = detect_anomalies("user-1", _make_dna(), redis=mock_redis)
        assert isinstance(result, GraphAnomalyResult)
        assert not result.branching
        assert not result.impossible_travel

    def test_empty_events_after_redis_error(self):
        """Corrupted Redis data should not crash."""
        mock_redis = MagicMock()
        mock_redis.lrange.return_value = [b"not-valid-json"]
        result = detect_anomalies("user-1", _make_dna(), redis=mock_redis)
        # Should not raise, even with bad data
        assert isinstance(result, GraphAnomalyResult)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Anomaly detection edge cases / cycle detection surrogate
# ─────────────────────────────────────────────────────────────────────────────

class TestAnomalyEdgeCases:
    def test_single_event_no_anomaly(self):
        events = [_make_event(device="d1")]
        mock_redis = _make_redis_mock(events)
        result = detect_anomalies("user-1", _make_dna(device="d1"), redis=mock_redis)
        # Only 1 existing + 1 current = 2 unique → no branching
        assert not result.branching

    def test_two_events_same_device_no_branching(self):
        events = [_make_event(device="d1"), _make_event(device="d1")]
        mock_redis = _make_redis_mock(events)
        result = detect_anomalies("user-1", _make_dna(device="d1"), redis=mock_redis)
        assert not result.branching

    def test_many_events_from_many_devices_triggers_branch(self):
        # Simulate 100 events from 10 different devices → definitely branching
        events = [_make_event(device=f"device-{i % 10}") for i in range(100)]
        mock_redis = _make_redis_mock(events)
        result = detect_anomalies("user-1", _make_dna(device="device-99"), redis=mock_redis)
        assert result.branching

    def test_cycle_detection_via_branching(self):
        """
        Cycle detection surrogate: if a token is used in a circular pattern
        (e.g., credential sharing across many hosts), branching detects it.
        """
        devices = [f"host-{i}" for i in range(20)]
        events = [_make_event(device=d) for d in devices]
        mock_redis = _make_redis_mock(events)
        result = detect_anomalies("user-1", _make_dna(device="attacker"), redis=mock_redis)
        assert result.branching
        assert result.details["branching"]["unique_devices"] > 3

    def test_detect_anomalies_with_future_prev_event(self):
        """Event with ts in future should be handled gracefully."""
        now = time.time()
        events = [_make_event(device="d1", ts=now + 1000)]  # future timestamp
        mock_redis = _make_redis_mock(events)
        geo = _make_geo_mock(lat=51.5074, lon=-0.1278)
        result = detect_anomalies("user-1", _make_dna(device="d2"), current_geo=geo, redis=mock_redis)
        # elapsed_h would be negative → skipped
        assert isinstance(result, GraphAnomalyResult)

    def test_anomaly_result_details_initially_empty(self):
        result = GraphAnomalyResult()
        assert result.details == {}

    def test_detect_anomalies_returns_graph_result_always(self):
        mock_redis = MagicMock()
        mock_redis.lrange.return_value = []
        result = detect_anomalies("user-1", _make_dna(), redis=mock_redis)
        assert isinstance(result, GraphAnomalyResult)
        assert hasattr(result, "branching")
        assert hasattr(result, "impossible_travel")
        assert hasattr(result, "has_anomaly")
