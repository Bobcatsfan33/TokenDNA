"""
Tests — TokenDNA Machine Identity Stack

Coverage:
  - MachineFingerprint construction and signal extraction
  - BehavioralBaseline update and stat computation
  - AnomalyDetector: TLS change, geo change, timing outlier, error spike
  - HardwareAttestationHook: NullHook + TPMHook stubs
  - MachineKeyManager: generate, rotate, expire, invalidate
  - MachineIdentityManager: register, verify (clean + anomaly), auto-revoke, rotate keys
"""

import time
import threading
import pytest

from modules.identity.machine_identity import (
    AnomalyDetector,
    AnomalyType,
    AttestationResult,
    BehavioralBaseline,
    MachineFingerprint,
    MachineIdentityManager,
    MachineIdentityStore,
    MachineKeyManager,
    MachineStatus,
    NullAttestationHook,
    TPMAttestationHook,
    get_machine_identity_manager,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fp(
    ja3="abc123",
    ja4="",
    country="US",
    asn="AS15169",
    ua="Mozilla/5.0",
    path="/api/verify",
    method="POST",
    is_error=False,
    ts=None,
    platform_id="linux-x64",
):
    return MachineFingerprint(
        ja3_hash=ja3,
        ja4_hash=ja4,
        country=country,
        asn=asn,
        user_agent=ua,
        api_path=path,
        method=method,
        is_error=is_error,
        timestamp=ts or time.time(),
        platform_id=platform_id,
    )


def _prime_baseline(baseline: BehavioralBaseline, n=15, country="US", asn="AS15169"):
    """Pump enough samples to establish baseline."""
    base_ts = time.time() - n * 60
    for i in range(n):
        fp = _fp(country=country, asn=asn, ts=base_ts + i * 60)
        baseline.update(fp)


# ── MachineFingerprint ────────────────────────────────────────────────────────

class TestMachineFingerprint:
    def test_tls_signature_prefers_ja4(self):
        fp = _fp(ja3="ja3val", ja4="ja4val")
        assert fp.tls_signature() == "ja4val"

    def test_tls_signature_falls_back_to_ja3(self):
        fp = _fp(ja3="ja3val", ja4="")
        assert fp.tls_signature() == "ja3val"

    def test_tls_signature_unknown_when_empty(self):
        fp = _fp(ja3="", ja4="")
        assert fp.tls_signature() == "unknown"

    def test_geo_signature(self):
        fp = _fp(country="DE", asn="AS3320")
        assert fp.geo_signature() == "DE:AS3320"

    def test_to_dict_no_hw_attest(self):
        fp = _fp()
        fp.hw_attest = b"secret_attestation_bytes"
        d = fp.to_dict()
        assert "hw_attest" not in d
        assert "tls_signature" in d


# ── BehavioralBaseline ────────────────────────────────────────────────────────

class TestBehavioralBaseline:
    def test_not_established_initially(self):
        baseline = BehavioralBaseline()
        assert not baseline.is_established
        assert baseline.sample_count == 0

    def test_established_after_min_samples(self):
        baseline = BehavioralBaseline()
        _prime_baseline(baseline)
        assert baseline.is_established

    def test_error_rate_all_errors(self):
        baseline = BehavioralBaseline()
        for i in range(20):
            baseline.update(_fp(is_error=True))
        assert baseline.error_rate() == 1.0

    def test_error_rate_no_errors(self):
        baseline = BehavioralBaseline()
        for i in range(20):
            baseline.update(_fp(is_error=False))
        assert baseline.error_rate() == 0.0

    def test_inter_arrival_stats(self):
        baseline = BehavioralBaseline()
        base = time.time()
        for i in range(20):
            baseline.update(_fp(ts=base + i * 60.0))
        mean, stdev = baseline.inter_arrival_stats()
        assert 55 <= mean <= 65        # ~60s intervals
        assert stdev < 1               # very consistent

    def test_country_set_tracking(self):
        baseline = BehavioralBaseline()
        baseline.update(_fp(country="US"))
        baseline.update(_fp(country="US"))
        baseline.update(_fp(country="GB"))
        assert "US" in baseline.known_countries()
        assert "GB" in baseline.known_countries()
        assert "DE" not in baseline.known_countries()

    def test_max_samples_respected(self):
        baseline = BehavioralBaseline()
        for i in range(BehavioralBaseline.MAX_SAMPLES + 50):
            baseline.update(_fp())
        assert len(baseline._timestamps) == BehavioralBaseline.MAX_SAMPLES


# ── AnomalyDetector ───────────────────────────────────────────────────────────

class TestAnomalyDetector:
    def setup_method(self):
        self.detector = AnomalyDetector()

    def _make_baseline(self, country="US", asn="AS15169"):
        b = BehavioralBaseline()
        _prime_baseline(b, n=15, country=country, asn=asn)
        return b

    def test_clean_fingerprint_no_anomalies(self):
        baseline = self._make_baseline()
        fp = _fp(ja3="abc123", country="US", asn="AS15169")
        anomalies = self.detector.check(baseline, fp, "abc123", "US:AS15169")
        assert anomalies == []

    def test_tls_change_detected(self):
        baseline = self._make_baseline()
        fp = _fp(ja3="DIFFERENT_TLS", country="US")
        anomalies = self.detector.check(baseline, fp, "abc123", "US:AS15169")
        types = [a[0] for a in anomalies]
        assert AnomalyType.TLS_CHANGE in types

    def test_geo_change_detected(self):
        baseline = self._make_baseline(country="US")
        fp = _fp(ja3="abc123", country="CN", asn="AS4837")
        anomalies = self.detector.check(baseline, fp, "abc123", "US:AS15169")
        types = [a[0] for a in anomalies]
        assert AnomalyType.GEO_CHANGE in types

    def test_no_anomaly_before_baseline_established(self):
        baseline = BehavioralBaseline()  # only 2 samples
        baseline.update(_fp())
        baseline.update(_fp())
        fp = _fp(ja3="TOTALLY_DIFFERENT")
        # baseline not established — no anomalies flagged
        anomalies = self.detector.check(baseline, fp, "abc123", "US:AS15169")
        assert anomalies == []

    def test_error_spike_detected(self):
        baseline = self._make_baseline()
        # Prime error window with many errors
        for _ in range(80):
            baseline._error_window.append(1)
        fp = _fp(ja3="abc123", country="US", is_error=True)
        anomalies = self.detector.check(baseline, fp, "abc123", "US:AS15169")
        types = [a[0] for a in anomalies]
        assert AnomalyType.ERROR_SPIKE in types


# ── HardwareAttestationHook ────────────────────────────────────────────────────

class TestHardwareAttestationHooks:
    def test_null_hook_always_passes(self):
        hook = NullAttestationHook()
        ok, detail = hook.verify("mid_abc", None)
        assert ok
        assert "null" in hook.name()

    def test_null_hook_with_blob(self):
        hook = NullAttestationHook()
        ok, _ = hook.verify("mid_abc", b"some_blob")
        assert ok

    def test_tpm_hook_no_blob_fails(self):
        hook = TPMAttestationHook(aik_pem=None)
        ok, detail = hook.verify("mid_abc", None)
        assert not ok
        assert "no_attestation_blob" in detail

    def test_tpm_hook_no_aik_dev_pass(self):
        hook = TPMAttestationHook(aik_pem=None)
        ok, detail = hook.verify("mid_abc", b"fake_quote")
        assert ok                           # dev mode: no AIK → accept
        assert "dev_accept" in detail


# ── MachineKeyManager ─────────────────────────────────────────────────────────

class TestMachineKeyManager:
    def setup_method(self):
        self.mgr = MachineKeyManager()

    def test_generate_keypair_returns_pem(self):
        kp = self.mgr.generate_keypair("mid_test")
        assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----") or "PUBLIC KEY" in kp.public_key_pem
        assert kp.fingerprint

    def test_get_public_key_returns_pem(self):
        self.mgr.generate_keypair("mid_test2")
        pub = self.mgr.get_public_key("mid_test2")
        assert pub is not None
        assert "KEY" in pub

    def test_rotate_replaces_keypair(self):
        kp1 = self.mgr.generate_keypair("mid_rotate")
        kp2 = self.mgr.rotate_keypair("mid_rotate")
        assert kp2.issued_at >= kp1.issued_at

    def test_expired_key_returns_none(self):
        self.mgr.generate_keypair("mid_expired", ttl=0)  # TTL=0 → instant expiry
        # Not strictly expired after 0s due to float precision — check with tiny ttl
        self.mgr.generate_keypair("mid_expired2", ttl=-1)
        result = self.mgr.get_public_key("mid_expired2")
        # With ttl=-1 it expires immediately
        assert result is None

    def test_invalidate_removes_key(self):
        self.mgr.generate_keypair("mid_del")
        self.mgr.invalidate("mid_del")
        assert self.mgr.get_public_key("mid_del") is None

    def test_is_expired_unknown_machine(self):
        assert self.mgr.is_expired("nonexistent_mid") is True


# ── MachineIdentityManager ────────────────────────────────────────────────────

class TestMachineIdentityManager:
    def setup_method(self):
        self.mgr = MachineIdentityManager(auto_revoke_on_anomaly=True)

    def _register_and_prime(self, fp=None):
        fp = fp or _fp()
        machine_id = self.mgr.register(fp)
        # Prime baseline to established state
        base = self.mgr._store.baseline(machine_id)
        _prime_baseline(base)
        return machine_id

    def test_register_returns_machine_id(self):
        fp = _fp()
        mid = self.mgr.register(fp)
        assert mid.startswith("mid_")

    def test_register_same_machine_same_id(self):
        fp = _fp()
        id1 = self.mgr.register(fp)
        id2 = self.mgr.register(fp)
        assert id1 == id2

    def test_verify_unknown_machine_fails(self):
        result = self.mgr.verify("mid_nonexistent", _fp())
        assert not result.verified
        assert "not_registered" in result.reason

    def test_verify_clean_machine_passes(self):
        mid = self._register_and_prime()
        fp_clean = _fp(ja3="abc123", country="US", asn="AS15169")
        result = self.mgr.verify(mid, fp_clean)
        assert result.verified
        assert not result.auto_revoked

    def test_verify_tls_change_auto_revokes(self):
        fp = _fp(ja3="original_tls")
        mid = self.mgr.register(fp)
        # Force record to have the original TLS
        record = self.mgr._store.get(mid)
        record.tls_signature = "original_tls"
        self.mgr._store.put(record)
        _prime_baseline(self.mgr._store.baseline(mid))

        fp_bad = _fp(ja3="ATTACKER_TLS", country="US")
        result = self.mgr.verify(mid, fp_bad)
        assert result.anomaly_detected
        assert AnomalyType.TLS_CHANGE.value in result.anomaly_types
        assert result.auto_revoked

    def test_revoke_marks_machine_revoked(self):
        mid = self._register_and_prime()
        self.mgr.revoke(mid, reason="test_revoke")
        status = self.mgr.get_status(mid)
        assert status["status"] == MachineStatus.REVOKED.value
        assert "test_revoke" in status["revoke_reason"]

    def test_verify_revoked_machine_fails(self):
        mid = self._register_and_prime()
        self.mgr.revoke(mid, reason="test")
        result = self.mgr.verify(mid, _fp())
        assert not result.verified
        assert "revoked" in result.reason

    def test_rotate_keys_updates_public_key(self):
        mid = self._register_and_prime()
        kp = self.mgr.rotate_keys(mid)
        assert kp is not None
        record = self.mgr._store.get(mid)
        assert record.public_key_pem == kp.public_key_pem

    def test_rotate_keys_revoked_returns_none(self):
        mid = self._register_and_prime()
        self.mgr.revoke(mid, reason="test")
        result = self.mgr.rotate_keys(mid)
        assert result is None

    def test_get_status_returns_dict(self):
        mid = self._register_and_prime()
        status = self.mgr.get_status(mid)
        assert status["machine_id"] == mid
        assert status["baseline_ready"] is True

    def test_get_status_unknown_returns_none(self):
        assert self.mgr.get_status("mid_unknown") is None

    def test_list_machines(self):
        mid = self._register_and_prime()
        # Force active status
        record = self.mgr._store.get(mid)
        record.status = MachineStatus.ACTIVE
        self.mgr._store.put(record)
        machines = self.mgr.list_machines()
        assert mid in machines


# ── Singleton ─────────────────────────────────────────────────────────────────

class TestSingleton:
    def test_singleton_returns_same_instance(self):
        m1 = get_machine_identity_manager()
        m2 = get_machine_identity_manager()
        assert m1 is m2

    def test_singleton_is_manager(self):
        assert isinstance(get_machine_identity_manager(), MachineIdentityManager)


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_register(self):
        mgr = MachineIdentityManager()
        ids = []
        lock = threading.Lock()

        def register():
            mid = mgr.register(_fp(platform_id="platform-concurrent", ua="concurrent-ua"))
            with lock:
                ids.append(mid)

        threads = [threading.Thread(target=register) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should get the same machine_id (same fingerprint signals)
        assert len(set(ids)) == 1
