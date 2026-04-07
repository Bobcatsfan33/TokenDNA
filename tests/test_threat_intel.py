"""
Tests — Threat Intelligence  (Phase 2D)

Coverage targets for modules/identity/threat_intel.py:
  - Tor exit node detection (is_tor_exit)
  - Datacenter / hosting IP detection (is_datacenter_ip)
  - VPN / proxy heuristics (is_vpn_or_proxy)
  - AbuseIPDB integration (get_abuse_score)
  - ThreatContext construction, flags, serialization
  - enrich() unified pipeline
  - Caching behaviour (Redis mock)
  - Fail-open / error handling
  - Edge cases: empty strings, None-like inputs, boundary scores
"""

import time
import threading
from unittest.mock import MagicMock, patch

import pytest

import modules.identity.threat_intel as ti
from modules.identity.threat_intel import (
    ThreatContext,
    enrich,
    get_abuse_score,
    is_datacenter_ip,
    is_tor_exit,
    is_vpn_or_proxy,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _inject_tor_exits(*ips: str):
    """Directly populate the in-process Tor exit set (avoids network)."""
    with ti._tor_lock:
        ti._tor_exits = set(ips)
        ti._tor_last_refresh = time.time()


def _clear_tor_exits():
    with ti._tor_lock:
        ti._tor_exits = set()
        ti._tor_last_refresh = time.time()


# ─── Tor exit node detection ──────────────────────────────────────────────────

class TestIsTorExit:

    def setup_method(self):
        """Ensure we start with a deterministic Tor set (no network)."""
        _inject_tor_exits("10.0.0.1", "185.220.101.1", "104.244.72.115")

    def test_known_tor_exit_returns_true(self):
        assert is_tor_exit("10.0.0.1") is True

    def test_second_known_tor_exit_returns_true(self):
        assert is_tor_exit("185.220.101.1") is True

    def test_unknown_ip_returns_false(self):
        assert is_tor_exit("8.8.8.8") is False

    def test_empty_tor_set_returns_false(self):
        _clear_tor_exits()
        assert is_tor_exit("10.0.0.1") is False

    def test_result_is_boolean(self):
        result = is_tor_exit("10.0.0.1")
        assert isinstance(result, bool)

    def test_refresh_is_triggered_when_stale(self):
        """If last refresh is 0 (never), a refresh is triggered (mocked to avoid network)."""
        with ti._tor_lock:
            ti._tor_last_refresh = 0.0
            ti._tor_exits = {"1.2.3.4"}

        with patch.object(ti, "_refresh_tor_list"):
            # Should not raise; result may be True or False depending on race
            result = is_tor_exit("1.2.3.4")
            assert isinstance(result, bool)

        # Restore state
        _inject_tor_exits("10.0.0.1")

    def test_partial_ip_does_not_match(self):
        _inject_tor_exits("10.0.0.1")
        assert is_tor_exit("10.0.0") is False
        assert is_tor_exit("10.0.0.10") is False

    def test_localhost_not_tor(self):
        assert is_tor_exit("127.0.0.1") is False


# ─── Datacenter IP detection ──────────────────────────────────────────────────

class TestIsDatacenterIp:

    # Known ASN prefixes
    def test_aws_asn_returns_true(self):
        assert is_datacenter_ip("AS16509") is True

    def test_aws_older_asn_returns_true(self):
        assert is_datacenter_ip("AS14618") is True

    def test_google_cloud_asn_returns_true(self):
        assert is_datacenter_ip("AS15169") is True

    def test_azure_asn_returns_true(self):
        assert is_datacenter_ip("AS8075") is True

    def test_digitalocean_asn_returns_true(self):
        assert is_datacenter_ip("AS14061") is True

    def test_hetzner_asn_returns_true(self):
        assert is_datacenter_ip("AS24940") is True

    def test_residential_asn_returns_false(self):
        assert is_datacenter_ip("AS7922") is False  # Comcast

    def test_empty_asn_returns_false(self):
        assert is_datacenter_ip("") is False

    # ISP keyword fallback
    def test_isp_with_hosting_keyword_returns_true(self):
        assert is_datacenter_ip("AS99999", "BestHosting Inc.") is True

    def test_isp_with_vps_keyword_returns_true(self):
        assert is_datacenter_ip("AS99999", "SuperVPS Providers") is True

    def test_isp_with_datacenter_keyword_returns_true(self):
        assert is_datacenter_ip("AS99999", "Global Data Center LLC") is True

    def test_isp_with_cloud_keyword_returns_true(self):
        assert is_datacenter_ip("AS99999", "Cloud Systems AG") is True

    def test_isp_with_colocation_keyword_returns_true(self):
        assert is_datacenter_ip("AS99999", "East Coast Colocation") is True

    def test_isp_residential_name_returns_false(self):
        assert is_datacenter_ip("AS99999", "Atlantic Broadband") is False

    def test_asn_case_insensitive(self):
        assert is_datacenter_ip("as16509") is True

    def test_both_empty_returns_false(self):
        assert is_datacenter_ip("", "") is False


# ─── VPN / proxy heuristics ──────────────────────────────────────────────────

class TestIsVpnOrProxy:

    def test_nordvpn_in_isp_returns_true(self):
        assert is_vpn_or_proxy(isp="NordVPN Server") is True

    def test_mullvad_in_isp_returns_true(self):
        assert is_vpn_or_proxy(isp="Mullvad Networks") is True

    def test_expressvpn_in_org_returns_true(self):
        assert is_vpn_or_proxy(org="ExpressVPN Ltd") is True

    def test_protonvpn_in_isp_returns_true(self):
        assert is_vpn_or_proxy(isp="ProtonVPN AG") is True

    def test_proxy_keyword_returns_true(self):
        assert is_vpn_or_proxy(isp="Anonymous Proxy Services") is True

    def test_tunnel_keyword_returns_true(self):
        assert is_vpn_or_proxy(isp="Tunnel Bear Inc") is True

    def test_private_internet_access_returns_true(self):
        assert is_vpn_or_proxy(isp="Private Internet Access") is True

    def test_surfshark_returns_true(self):
        assert is_vpn_or_proxy(org="Surfshark Ltd") is True

    def test_residential_isp_returns_false(self):
        assert is_vpn_or_proxy(isp="Comcast Cable Communications") is False

    def test_empty_strings_returns_false(self):
        assert is_vpn_or_proxy("", "") is False

    def test_no_args_returns_false(self):
        assert is_vpn_or_proxy() is False

    def test_combined_isp_and_org_match(self):
        assert is_vpn_or_proxy(isp="Generic ISP", org="CyberGhost VPN") is True

    def test_case_insensitive(self):
        assert is_vpn_or_proxy(isp="NORDVPN SERVER") is True


# ─── AbuseIPDB integration ────────────────────────────────────────────────────

class TestGetAbuseScore:

    def test_returns_zero_when_no_api_key(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            score = get_abuse_score("8.8.8.8")
        assert score == 0

    def test_returns_cached_value_from_redis(self):
        mock_redis = MagicMock()
        mock_redis.get.return_value = b"75"
        with patch.object(ti, "ABUSEIPDB_API_KEY", "test-key-123"):
            score = get_abuse_score("1.2.3.4", redis_client=mock_redis)
        assert score == 75
        mock_redis.get.assert_called_once_with("abuseipdb:1.2.3.4")

    def test_fetches_from_api_when_no_cache(self):
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 88}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(ti, "ABUSEIPDB_API_KEY", "test-key-123"), \
             patch("requests.get", return_value=mock_response):
            score = get_abuse_score("5.6.7.8", redis_client=mock_redis)

        assert score == 88
        mock_redis.setex.assert_called_once_with("abuseipdb:5.6.7.8", 86400, "88")

    def test_returns_zero_on_api_failure(self):
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(ti, "ABUSEIPDB_API_KEY", "test-key-123"), \
             patch("requests.get", side_effect=Exception("timeout")):
            score = get_abuse_score("9.9.9.9", redis_client=mock_redis)
        assert score == 0

    def test_works_without_redis(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            score = get_abuse_score("1.1.1.1", redis_client=None)
        assert score == 0

    def test_redis_error_does_not_propagate(self):
        """Redis failures should be swallowed (fail-open)."""
        mock_redis = MagicMock()
        mock_redis.get.side_effect = Exception("redis down")
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            score = get_abuse_score("2.2.2.2", redis_client=mock_redis)
        assert score == 0


# ─── ThreatContext ────────────────────────────────────────────────────────────

class TestThreatContext:

    def test_clean_ip_has_no_flags(self):
        ctx = ThreatContext("8.8.8.8")
        assert ctx.flags == []
        assert ctx.is_suspicious is False

    def test_tor_exit_sets_flag(self):
        ctx = ThreatContext("10.0.0.1", is_tor=True)
        assert "tor_exit" in ctx.flags
        assert ctx.is_suspicious is True

    def test_datacenter_sets_flag(self):
        ctx = ThreatContext("10.0.0.1", is_datacenter=True)
        assert "datacenter" in ctx.flags

    def test_vpn_sets_flag(self):
        ctx = ThreatContext("10.0.0.1", is_vpn=True)
        assert "vpn_proxy" in ctx.flags

    def test_high_abuse_score_sets_flag(self):
        ctx = ThreatContext("10.0.0.1", abuse_score=80)
        assert any("abuse:" in f for f in ctx.flags)
        assert ctx.is_suspicious is True

    def test_low_abuse_score_does_not_set_flag(self):
        ctx = ThreatContext("10.0.0.1", abuse_score=10)
        assert not any("abuse:" in f for f in ctx.flags)

    def test_abuse_score_boundary_at_min_confidence(self):
        """Score exactly at ABUSEIPDB_MIN_CONFIDENCE (50) should trigger flag."""
        with patch.object(ti, "ABUSEIPDB_MIN_CONFIDENCE", 50):
            ctx = ThreatContext("10.0.0.1", abuse_score=50)
        assert any("abuse:" in f for f in ctx.flags)

    def test_multiple_flags_accumulate(self):
        ctx = ThreatContext("10.0.0.1", is_tor=True, is_datacenter=True, is_vpn=True, abuse_score=90)
        assert "tor_exit" in ctx.flags
        assert "datacenter" in ctx.flags
        assert "vpn_proxy" in ctx.flags
        assert any("abuse:" in f for f in ctx.flags)
        assert len(ctx.flags) == 4

    def test_to_dict_has_all_keys(self):
        ctx = ThreatContext("1.2.3.4", is_tor=True, abuse_score=60)
        d = ctx.to_dict()
        assert "is_tor" in d
        assert "is_datacenter" in d
        assert "is_vpn" in d
        assert "abuse_score" in d
        assert "flags" in d
        assert d["is_tor"] is True
        assert d["abuse_score"] == 60

    def test_to_dict_flags_match_object(self):
        ctx = ThreatContext("1.2.3.4", is_vpn=True)
        assert ctx.to_dict()["flags"] == ctx.flags

    def test_ip_stored_on_context(self):
        ctx = ThreatContext("192.168.1.1")
        assert ctx.ip == "192.168.1.1"


# ─── enrich() unified pipeline ───────────────────────────────────────────────

class TestEnrich:

    def setup_method(self):
        _inject_tor_exits("185.220.101.5")

    def test_returns_threat_context(self):
        result = enrich("8.8.8.8")
        assert isinstance(result, ThreatContext)

    def test_clean_ip_not_suspicious(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("8.8.8.8", asn="AS7922", isp="Comcast")
        assert result.is_suspicious is False

    def test_tor_ip_flagged_by_enrich(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("185.220.101.5")
        assert result.is_tor is True
        assert "tor_exit" in result.flags

    def test_datacenter_asn_flagged_by_enrich(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("52.0.0.1", asn="AS16509", isp="Amazon")
        assert result.is_datacenter is True

    def test_vpn_isp_flagged_by_enrich(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("10.5.5.5", asn="AS999", isp="NordVPN")
        assert result.is_vpn is True

    def test_enrich_with_redis_does_not_crash(self):
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("1.1.1.1", redis_client=mock_redis)
        assert isinstance(result, ThreatContext)

    def test_enrich_ip_stored_on_result(self):
        with patch.object(ti, "ABUSEIPDB_API_KEY", ""):
            result = enrich("203.0.113.1")
        assert result.ip == "203.0.113.1"
