"""
TokenDNA — Attribution Engine  (v2.6.0)
========================================
Builds attacker profiles, campaign clusters, kill-chain mappings, and IOC
lists from Token Trap hits, Preflight Gate decisions, and session events.

This module provides the intelligence layer that converts raw telemetry into
operator-actionable threat attribution:

  AttackerProfile  — single IP's activity across all trap hits
  Campaign         — correlated profiles sharing ASN / infrastructure
  IOC              — indicator of compromise (IP, ASN, User-Agent)
  AttributionSummary — full data payload for the Attribution Dashboard

MITRE ATT&CK mapping
────────────────────
  initial-access     T1078  (Valid Accounts), T1190 (Public-Facing App)
  credential-access  T1552  (Unsecured Credentials), T1110 (Brute Force)
  collection         T1530  (Data from Cloud Storage)
  lateral-movement   T1021  (Remote Services)
  defense-evasion    T1090  (Proxy), T1078.004 (Cloud Accounts)
  exfiltration       T1048  (Exfiltration over Alt Protocol)

NIST 800-53 Rev5: SI-3 · IR-4 · SC-26 · AU-2 · RA-3 · PM-16
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kill-chain label → MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

_LABEL_TO_KILL_CHAIN: Dict[str, Tuple[str, List[str]]] = {
    # trap label      (kill-chain stage,       techniques)
    "aws-cred-file":  ("credential-access",   ["T1552.001", "T1078.004"]),
    "api-key-leak":   ("credential-access",   ["T1552", "T1078"]),
    "env-file":       ("credential-access",   ["T1552.001"]),
    "git-history":    ("credential-access",   ["T1552", "T1213"]),
    "s3-backup":      ("collection",          ["T1530"]),
    "ci-cd-secret":   ("credential-access",   ["T1552.004"]),
    "k8s-token":      ("credential-access",   ["T1528", "T1552"]),
    "insider-test":   ("privilege-escalation",["T1068", "T1078.003"]),
    "default":        ("initial-access",      ["T1078", "T1190"]),
}

_SIGNAL_TO_KILL_CHAIN: Dict[str, Tuple[str, str]] = {
    # preflight signal    (stage,                  technique)
    "impossible_travel":  ("lateral-movement",    "T1078"),
    "credential_stuffing":("credential-access",   "T1110"),
    "new_device":         ("defense-evasion",     "T1078.004"),
    "threat_intel":       ("defense-evasion",     "T1090"),
    "velocity":           ("credential-access",   "T1110.003"),
    "hvip_policy":        ("privilege-escalation","T1068"),
    "ml_anomaly":         ("initial-access",      "T1078"),
    "global_block":       ("initial-access",      "T1078"),
}

_KILL_CHAIN_ORDER = [
    "initial-access",
    "credential-access",
    "privilege-escalation",
    "lateral-movement",
    "collection",
    "exfiltration",
    "defense-evasion",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackerProfile:
    """Aggregated activity record for a single attacker IP."""
    profile_id:          str
    ip:                  str
    asn:                 Optional[str]
    country:             Optional[str]
    hit_count:           int
    first_seen:          str   # ISO-8601 UTC
    last_seen:           str
    token_age_avg_s:     float  # avg seconds between trap issuance and hit
    trap_labels:         List[str]           # which trap types were hit
    user_agents:         List[str]           # distinct UAs observed
    uids_targeted:       List[str]           # identities attacked
    real_tokens_revoked: int
    kill_chain_stages:   List[str]           # detected stages
    mitre_techniques:    List[str]
    iocs:               List[str]            # IP, ASN string refs
    confidence:         float                # 0.0 – 1.0 attribution confidence

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Campaign:
    """Correlated group of attacker profiles sharing infrastructure (ASN)."""
    campaign_id:    str
    asn:            str
    country:        Optional[str]
    attacker_ips:   List[str]
    total_hits:     int
    first_seen:     str
    last_seen:      str
    trap_labels:    List[str]       # all trap labels triggered
    kill_chain_stages: List[str]
    mitre_techniques:  List[str]
    confidence:     float
    description:    str             # human-readable campaign summary

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IOC:
    """Indicator of Compromise extracted from attribution data."""
    ioc_type:    str    # "ip" | "asn" | "user_agent" | "uid"
    value:       str
    confidence:  float  # 0.0 – 1.0
    hit_count:   int
    first_seen:  str
    last_seen:   str
    context:     str    # brief description for analyst

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttributionSummary:
    """
    Full attribution data payload for the Attribution Dashboard API.
    Aggregates trap hits, campaigns, kill-chain staging, and IOC list.
    """
    generated_at:          str
    window_hours:          int           # analysis window

    # Top-line KPIs
    total_trap_hits:       int
    unique_attacker_ips:   int
    active_campaigns:      int
    real_tokens_revoked:   int

    # Geo + infra distribution
    top_countries:         List[dict]   # [{country, hits, pct}]
    top_asns:              List[dict]   # [{asn, hits, pct}]

    # Kill-chain + MITRE
    kill_chain_distribution: Dict[str, int]   # stage → hit count
    mitre_techniques:      List[dict]         # [{technique, count, stage}]

    # Hit timeline (last 30 days, daily buckets)
    daily_hits:            List[dict]         # [{date, hits, tokens_revoked}]

    # Attacker profiles and campaigns
    attacker_profiles:     List[dict]
    campaigns:             List[dict]

    # IOC list (filtered by confidence ≥ 0.5)
    ioc_list:              List[dict]

    # Preflight gate stats (ALLOW/ENRICH/STEP_UP/DENY + signal breakdown)
    preflight_stats:       Dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "generated_at":           self.generated_at,
            "window_hours":           self.window_hours,
            "kpis": {
                "total_trap_hits":      self.total_trap_hits,
                "unique_attacker_ips":  self.unique_attacker_ips,
                "active_campaigns":     self.active_campaigns,
                "real_tokens_revoked":  self.real_tokens_revoked,
            },
            "geo":                    self.top_countries,
            "asns":                   self.top_asns,
            "kill_chain":             self.kill_chain_distribution,
            "mitre":                  self.mitre_techniques,
            "daily_hits":             self.daily_hits,
            "attacker_profiles":      self.attacker_profiles,
            "campaigns":              self.campaigns,
            "iocs":                   self.ioc_list,
            "preflight_stats":        self.preflight_stats,
        }


# ---------------------------------------------------------------------------
# Attribution Engine
# ---------------------------------------------------------------------------

class AttributionEngine:
    """
    Builds attacker profiles and campaigns from Token Trap and Preflight data.

    All data is read-only from Redis / in-memory stores — no writes.
    """

    def build_profiles(self, hits: List[dict]) -> List[AttackerProfile]:
        """Cluster raw trap hit dicts into per-IP attacker profiles."""
        ip_hits: Dict[str, List[dict]] = defaultdict(list)
        for h in hits:
            ip = h.get("attacker_ip", "unknown")
            ip_hits[ip].append(h)

        profiles: List[AttackerProfile] = []
        for ip, ip_hit_list in ip_hits.items():
            profile = self._build_single_profile(ip, ip_hit_list)
            profiles.append(profile)

        # Sort by hit_count descending
        profiles.sort(key=lambda p: p.hit_count, reverse=True)
        return profiles

    def _build_single_profile(self, ip: str, hits: List[dict]) -> AttackerProfile:
        timestamps = []
        for h in hits:
            try:
                timestamps.append(
                    datetime.fromisoformat(h.get("hit_at", "")).timestamp()
                )
            except Exception:
                pass

        # Aggregate fields
        asn_ctr     = Counter(h.get("attacker_asn") for h in hits if h.get("attacker_asn"))
        country_ctr = Counter(h.get("attacker_country") for h in hits if h.get("attacker_country"))
        ua_set      = list(dict.fromkeys(h.get("attacker_ua", "") for h in hits if h.get("attacker_ua")))[:5]
        uid_set     = list(dict.fromkeys(h.get("uid", "") for h in hits if h.get("uid")))
        labels      = list(dict.fromkeys(h.get("label", "default") for h in hits))
        total_revoked = sum(int(h.get("real_tokens_revoked", 0)) for h in hits)

        ages = [float(h.get("token_age_seconds", 0)) for h in hits]
        age_avg = sum(ages) / len(ages) if ages else 0.0

        asn     = asn_ctr.most_common(1)[0][0] if asn_ctr else None
        country = country_ctr.most_common(1)[0][0] if country_ctr else None

        # Kill chain + MITRE from trap labels
        stages:     List[str] = []
        techniques: List[str] = []
        for label in labels:
            entry = _LABEL_TO_KILL_CHAIN.get(label, _LABEL_TO_KILL_CHAIN["default"])
            if entry[0] not in stages:
                stages.append(entry[0])
            for t in entry[1]:
                if t not in techniques:
                    techniques.append(t)

        # IOC refs
        iocs: List[str] = [f"ip:{ip}"]
        if asn:
            iocs.append(f"asn:{asn}")

        # Confidence heuristic: more hits + recent = higher confidence
        hit_score  = min(len(hits) / 5, 1.0)      # 5+ hits → 1.0
        recency    = 1.0 if timestamps and (time.time() - max(timestamps)) < 86400 * 7 else 0.6
        confidence = round((hit_score * 0.6 + recency * 0.4), 2)

        first_seen = min(h.get("hit_at", "") for h in hits)
        last_seen  = max(h.get("hit_at", "") for h in hits)

        return AttackerProfile(
            profile_id=str(uuid.uuid5(uuid.NAMESPACE_URL, ip)),
            ip=ip,
            asn=asn,
            country=country,
            hit_count=len(hits),
            first_seen=first_seen,
            last_seen=last_seen,
            token_age_avg_s=round(age_avg, 1),
            trap_labels=labels,
            user_agents=ua_set,
            uids_targeted=uid_set,
            real_tokens_revoked=total_revoked,
            kill_chain_stages=stages,
            mitre_techniques=techniques,
            iocs=iocs,
            confidence=confidence,
        )

    def detect_campaigns(self, profiles: List[AttackerProfile]) -> List[Campaign]:
        """
        Cluster profiles sharing the same ASN into campaigns.
        Campaigns with only one IP and one hit are low-confidence opportunistic noise.
        """
        asn_profiles: Dict[str, List[AttackerProfile]] = defaultdict(list)
        for p in profiles:
            key = p.asn or f"unknown_asn_{p.ip}"
            asn_profiles[key].append(p)

        campaigns: List[Campaign] = []
        for asn, asn_profile_list in asn_profiles.items():
            if len(asn_profile_list) == 1 and asn_profile_list[0].hit_count < 3:
                continue  # skip low-signal singletons

            all_hits   = sum(p.hit_count for p in asn_profile_list)
            all_ips    = [p.ip for p in asn_profile_list]
            all_labels = list(dict.fromkeys(
                l for p in asn_profile_list for l in p.trap_labels
            ))
            all_stages = list(dict.fromkeys(
                s for p in asn_profile_list for s in p.kill_chain_stages
            ))
            all_tech   = list(dict.fromkeys(
                t for p in asn_profile_list for t in p.mitre_techniques
            ))

            countries  = Counter(p.country for p in asn_profile_list if p.country)
            country    = countries.most_common(1)[0][0] if countries else None

            first_seen = min(p.first_seen for p in asn_profile_list if p.first_seen)
            last_seen  = max(p.last_seen  for p in asn_profile_list if p.last_seen)

            conf = min(
                0.4 + len(asn_profile_list) * 0.15 + min(all_hits / 20, 0.3),
                1.0
            )
            conf = round(conf, 2)

            label_str  = ", ".join(all_labels[:3])
            stage_str  = " → ".join(
                s for s in _KILL_CHAIN_ORDER if s in all_stages
            ) or "unknown"
            description = (
                f"{len(asn_profile_list)} attacker IP(s) from ASN {asn} "
                f"({country or 'unknown country'}) targeting {label_str} credentials. "
                f"Kill chain: {stage_str}."
            )

            campaigns.append(Campaign(
                campaign_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"campaign:{asn}")),
                asn=asn,
                country=country,
                attacker_ips=all_ips,
                total_hits=all_hits,
                first_seen=first_seen,
                last_seen=last_seen,
                trap_labels=all_labels,
                kill_chain_stages=all_stages,
                mitre_techniques=all_tech,
                confidence=conf,
                description=description,
            ))

        campaigns.sort(key=lambda c: c.total_hits, reverse=True)
        return campaigns

    def build_iocs(
        self, profiles: List[AttackerProfile], min_confidence: float = 0.3
    ) -> List[IOC]:
        """Extract IOC list from attacker profiles."""
        iocs: List[IOC] = []
        seen: set = set()

        for p in profiles:
            if p.confidence < min_confidence:
                continue

            # IP IOC
            if p.ip not in seen:
                seen.add(p.ip)
                iocs.append(IOC(
                    ioc_type  = "ip",
                    value     = p.ip,
                    confidence= p.confidence,
                    hit_count = p.hit_count,
                    first_seen= p.first_seen,
                    last_seen = p.last_seen,
                    context   = (
                        f"Attacker IP from {p.country or '?'} "
                        f"(ASN {p.asn or '?'}), {p.hit_count} trap hit(s), "
                        f"targeting: {', '.join(p.trap_labels[:2])}"
                    ),
                ))

            # ASN IOC
            if p.asn:
                asn_key = f"asn:{p.asn}"
                if asn_key not in seen:
                    seen.add(asn_key)
                    iocs.append(IOC(
                        ioc_type  = "asn",
                        value     = p.asn,
                        confidence= min(p.confidence + 0.1, 1.0),
                        hit_count = p.hit_count,
                        first_seen= p.first_seen,
                        last_seen = p.last_seen,
                        context   = f"ASN used by attacker IP {p.ip} ({p.country or '?'})",
                    ))

            # User-Agent IOC (only suspicious ones)
            for ua in p.user_agents[:2]:
                if ua and "python" in ua.lower() or "curl" in ua.lower() or "go-http" in ua.lower():
                    ua_key = f"ua:{ua[:80]}"
                    if ua_key not in seen:
                        seen.add(ua_key)
                        iocs.append(IOC(
                            ioc_type  = "user_agent",
                            value     = ua[:120],
                            confidence= 0.5,
                            hit_count = p.hit_count,
                            first_seen= p.first_seen,
                            last_seen = p.last_seen,
                            context   = f"Automated UA from attacker IP {p.ip}",
                        ))

        iocs.sort(key=lambda i: (i.confidence, i.hit_count), reverse=True)
        return iocs

    def build_kill_chain_distribution(
        self, profiles: List[AttackerProfile]
    ) -> Dict[str, int]:
        dist: Dict[str, int] = {stage: 0 for stage in _KILL_CHAIN_ORDER}
        for p in profiles:
            for stage in p.kill_chain_stages:
                if stage in dist:
                    dist[stage] += p.hit_count
        return dist

    def build_mitre_summary(self, profiles: List[AttackerProfile]) -> List[dict]:
        tech_counter: Counter = Counter()
        tech_stage: Dict[str, str] = {}
        for p in profiles:
            for t in p.mitre_techniques:
                tech_counter[t] += p.hit_count
            for label in p.trap_labels:
                entry = _LABEL_TO_KILL_CHAIN.get(label, _LABEL_TO_KILL_CHAIN["default"])
                for t in entry[1]:
                    tech_stage[t] = entry[0]

        return [
            {"technique": t, "count": c, "stage": tech_stage.get(t, "unknown")}
            for t, c in tech_counter.most_common(15)
        ]

    def build_daily_hits(self, hits: List[dict], days: int = 30) -> List[dict]:
        """Bucket trap hits into daily counts for the timeline chart."""
        from datetime import timedelta, date

        buckets: Dict[str, dict] = {}
        today = datetime.now(timezone.utc).date()
        for i in range(days):
            d = (today - timedelta(days=days - 1 - i)).isoformat()
            buckets[d] = {"date": d, "hits": 0, "tokens_revoked": 0}

        for h in hits:
            try:
                d = h.get("hit_at", "")[:10]
                if d in buckets:
                    buckets[d]["hits"] += 1
                    buckets[d]["tokens_revoked"] += int(h.get("real_tokens_revoked", 0))
            except Exception:
                pass

        return list(buckets.values())


# ---------------------------------------------------------------------------
# Preflight stats helpers (reads Redis, falls back to empty)
# ---------------------------------------------------------------------------

def _get_preflight_stats(tenant_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Read preflight gate decision stats from Redis.
    Keys written by preflight.py _store_gate_stats() hook (added in v2.6).
    """
    try:
        from modules.identity.cache_redis import get_redis
        r = get_redis()

        decisions = {"allow": 0, "enrich": 0, "step_up": 0, "deny": 0}
        signals:   Dict[str, int] = {}

        pattern = "preflight:decisions:*"
        for key in r.scan_iter(pattern, count=100):
            try:
                raw = r.hgetall(key)
                for k, v in raw.items():
                    dk = k.decode() if isinstance(k, bytes) else k
                    dv = int(v.decode() if isinstance(v, bytes) else v)
                    if dk in decisions:
                        decisions[dk] += dv
            except Exception:
                pass

        pattern = "preflight:signals:*"
        for key in r.scan_iter(pattern, count=100):
            try:
                raw = r.hgetall(key)
                for k, v in raw.items():
                    sk = k.decode() if isinstance(k, bytes) else k
                    sv = int(v.decode() if isinstance(v, bytes) else v)
                    signals[sk] = signals.get(sk, 0) + sv
            except Exception:
                pass

        total_decisions = sum(decisions.values()) or 1

        return {
            "decisions":     decisions,
            "total":         sum(decisions.values()),
            "decision_pcts": {
                k: round(v / total_decisions * 100, 1)
                for k, v in decisions.items()
            },
            "top_signals": [
                {"signal": s, "count": c}
                for s, c in sorted(signals.items(), key=lambda x: -x[1])[:10]
            ],
        }

    except Exception as e:
        logger.debug("Preflight stats unavailable: %s", e)
        return {
            "decisions": {"allow": 0, "enrich": 0, "step_up": 0, "deny": 0},
            "total": 0,
            "decision_pcts": {"allow": 0, "enrich": 0, "step_up": 0, "deny": 0},
            "top_signals": [],
        }


# ---------------------------------------------------------------------------
# Public convenience function
# ---------------------------------------------------------------------------

def build_attribution_summary(
    window_hours: int = 168,   # 7 days default
    hits_limit:   int = 500,
) -> AttributionSummary:
    """
    Build a complete AttributionSummary from live trap hit data.
    Called by GET /api/attribution in the API layer.
    """
    # Pull raw hits from token trap store
    try:
        from modules.defense.token_trap import recent_trap_hits
        raw_hits = recent_trap_hits(limit=hits_limit)
    except Exception as e:
        logger.error("Could not fetch trap hits: %s", e)
        raw_hits = []

    engine = AttributionEngine()

    # Filter to window
    cutoff = time.time() - (window_hours * 3600)
    windowed_hits: List[dict] = []
    for h in raw_hits:
        try:
            ts = datetime.fromisoformat(h.get("hit_at", "")).timestamp()
            if ts >= cutoff:
                windowed_hits.append(h)
        except Exception:
            windowed_hits.append(h)  # include if timestamp unparseable

    profiles   = engine.build_profiles(windowed_hits)
    campaigns  = engine.detect_campaigns(profiles)
    iocs       = engine.build_iocs(profiles)

    # Aggregates
    country_ctr = Counter(p.country for p in profiles if p.country)
    asn_ctr     = Counter(p.asn for p in profiles if p.asn)
    total_hits  = sum(p.hit_count for p in profiles)

    top_countries = [
        {"country": c, "hits": n, "pct": round(n / max(total_hits, 1) * 100, 1)}
        for c, n in country_ctr.most_common(10)
    ]
    top_asns = [
        {"asn": a, "hits": n, "pct": round(n / max(total_hits, 1) * 100, 1)}
        for a, n in asn_ctr.most_common(10)
    ]

    kill_chain_dist = engine.build_kill_chain_distribution(profiles)
    mitre_summary   = engine.build_mitre_summary(profiles)
    daily_hits      = engine.build_daily_hits(windowed_hits)
    preflight_stats = _get_preflight_stats()

    total_revoked   = sum(p.real_tokens_revoked for p in profiles)

    return AttributionSummary(
        generated_at          = datetime.now(timezone.utc).isoformat(),
        window_hours          = window_hours,
        total_trap_hits       = total_hits,
        unique_attacker_ips   = len(profiles),
        active_campaigns      = len(campaigns),
        real_tokens_revoked   = total_revoked,
        top_countries         = top_countries,
        top_asns              = top_asns,
        kill_chain_distribution = kill_chain_dist,
        mitre_techniques      = mitre_summary,
        daily_hits            = daily_hits,
        attacker_profiles     = [p.to_dict() for p in profiles[:50]],
        campaigns             = [c.to_dict() for c in campaigns[:20]],
        ioc_list              = [i.to_dict() for i in iocs[:200]],
        preflight_stats       = preflight_stats,
    )
