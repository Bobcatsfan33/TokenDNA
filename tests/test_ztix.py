"""
Tests — TokenDNA ZTIX Engine (Zero Trust Identity Exchange)

Coverage:
  - JWT sign/verify helpers
  - JTIReplayCache: mark_used, is_used, eviction
  - CapabilityPolicy: allow, deny, assurance level enforcement
  - ZTIXEngine.exchange: happy path, policy denial, empty caps, missing fields
  - ZTIXEngine.verify_token: valid, expired, replayed, wrong target, bad sig
  - ZTIXEngine.revoke_token: manual revocation
  - Source identity abstraction: sub_handle and mid_handle are opaque
  - Assurance level evaluation
  - Singleton
"""

import time
import threading
import pytest

from modules.ztix.engine import (
    CapabilityPolicy,
    JTIReplayCache,
    ZTIXCapabilityToken,
    ZTIXEngine,
    ZTIXError,
    ZTIXPolicyError,
    ZTIXRequest,
    ZTIXResult,
    ZTIXTokenError,
    _jwt_sign,
    _jwt_verify,
    get_ztix_engine,
)

TEST_KEY = b"test-signing-key-for-unit-tests"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _req(
    subject_id="user@example.com",
    machine_id="mid_abc123",
    capabilities=None,
    scope="aegis:findings:read",
    target="aegis-api",
    dna_hash="abc123dna",
    assurance=1,
    ttl=300,
):
    return ZTIXRequest(
        subject_id=subject_id,
        machine_id=machine_id,
        capabilities=capabilities or ["read:findings"],
        scope=scope,
        target=target,
        dna_hash=dna_hash,
        assurance=assurance,
        ttl=ttl,
    )


def _engine():
    return ZTIXEngine(signing_key=TEST_KEY)


# ── JWT helpers ───────────────────────────────────────────────────────────────

class TestJWTHelpers:
    def test_sign_verify_roundtrip(self):
        payload = {"foo": "bar", "num": 42}
        token = _jwt_sign(payload, TEST_KEY)
        recovered = _jwt_verify(token, TEST_KEY)
        assert recovered["foo"] == "bar"
        assert recovered["num"] == 42

    def test_wrong_key_raises(self):
        token = _jwt_sign({"x": 1}, TEST_KEY)
        with pytest.raises(ZTIXTokenError, match="invalid_signature"):
            _jwt_verify(token, b"wrong_key")

    def test_malformed_token_raises(self):
        with pytest.raises(ZTIXTokenError, match="malformed"):
            _jwt_verify("not.a.real.jwt.with.extra.dots", TEST_KEY)

    def test_three_parts_required(self):
        with pytest.raises(ZTIXTokenError):
            _jwt_verify("only.two", TEST_KEY)


# ── JTIReplayCache ─────────────────────────────────────────────────────────────

class TestJTIReplayCache:
    def test_unused_jti_not_in_cache(self):
        cache = JTIReplayCache()
        assert not cache.is_used("jti_abc")

    def test_used_jti_detected(self):
        cache = JTIReplayCache()
        cache.mark_used("jti_abc", time.time() + 300)
        assert cache.is_used("jti_abc")

    def test_expired_jti_evicted(self):
        cache = JTIReplayCache()
        cache.mark_used("jti_expired", time.time() - 1)   # already expired
        cache.mark_used("jti_fresh", time.time() + 300)   # triggers eviction
        assert not cache.is_used("jti_expired")
        assert cache.is_used("jti_fresh")

    def test_count(self):
        cache = JTIReplayCache()
        cache.mark_used("jti_1", time.time() + 300)
        cache.mark_used("jti_2", time.time() + 300)
        assert cache.count() >= 2


# ── CapabilityPolicy ──────────────────────────────────────────────────────────

class TestCapabilityPolicy:
    def test_known_cap_at_right_assurance(self):
        policy = CapabilityPolicy()
        ok, reason = policy.allowed(["read:findings"], assurance=1)
        assert ok

    def test_known_cap_insufficient_assurance(self):
        policy = CapabilityPolicy()
        ok, reason = policy.allowed(["admin:keys"], assurance=1)
        assert not ok
        assert "insufficient_assurance" in reason

    def test_unknown_cap_denied(self):
        policy = CapabilityPolicy()
        ok, reason = policy.allowed(["unknown:operation"], assurance=3)
        assert not ok
        assert "unknown_capability" in reason

    def test_multiple_caps_all_must_pass(self):
        policy = CapabilityPolicy()
        ok, reason = policy.allowed(["read:findings", "admin:keys"], assurance=2)
        assert not ok    # admin:keys needs level 3

    def test_multiple_caps_all_pass(self):
        policy = CapabilityPolicy()
        ok, _ = policy.allowed(["read:findings", "tokendna:verify"], assurance=1)
        assert ok

    def test_custom_registry(self):
        policy = CapabilityPolicy(registry={"custom:op": 2})
        ok, _ = policy.allowed(["custom:op"], assurance=2)
        assert ok
        ok2, r2 = policy.allowed(["custom:op"], assurance=1)
        assert not ok2


# ── ZTIXEngine.exchange ───────────────────────────────────────────────────────

class TestZTIXEngineExchange:
    def setup_method(self):
        self.engine = _engine()

    def test_exchange_happy_path(self):
        result = self.engine.exchange(_req())
        assert result.success
        assert result.token
        assert result.jti.startswith("ztix_")
        assert result.expires_at > time.time()
        assert result.assurance >= 1

    def test_exchange_with_dna_elevates_assurance(self):
        req = _req(dna_hash="valid_dna_hash", assurance=2)
        result = self.engine.exchange(req)
        assert result.success
        assert result.assurance == 2

    def test_exchange_empty_capabilities_fails(self):
        # Build request directly to bypass _req() default-fill
        req = ZTIXRequest(
            subject_id="user@example.com",
            machine_id="mid_abc",
            capabilities=[],
            scope="test",
            target="test",
        )
        result = self.engine.exchange(req)
        assert not result.success
        assert "empty_capability" in result.error

    def test_exchange_missing_subject_fails(self):
        result = self.engine.exchange(_req(subject_id=""))
        assert not result.success
        assert "missing" in result.error

    def test_exchange_missing_machine_fails(self):
        result = self.engine.exchange(_req(machine_id=""))
        assert not result.success

    def test_exchange_policy_denied(self):
        result = self.engine.exchange(_req(capabilities=["admin:keys"], assurance=1))
        assert not result.success
        assert "policy_denied" in result.error

    def test_exchange_ttl_capped(self):
        result = self.engine.exchange(_req(ttl=999999))
        assert result.success
        assert (result.expires_at - time.time()) <= 3600 + 5   # max TTL + small buffer

    def test_exchange_result_has_scope_and_target(self):
        result = self.engine.exchange(_req(scope="test:scope", target="test-service"))
        assert result.scope == "test:scope"
        assert result.target == "test-service"


# ── ZTIXEngine.verify_token ───────────────────────────────────────────────────

class TestZTIXEngineVerify:
    def setup_method(self):
        self.engine = _engine()

    def test_verify_valid_token(self):
        result = self.engine.exchange(_req())
        cap_token = self.engine.verify_token(result.token)
        assert isinstance(cap_token, ZTIXCapabilityToken)
        assert "read:findings" in cap_token.capabilities
        assert not cap_token.is_expired()

    def test_verify_with_target_match(self):
        result = self.engine.exchange(_req(target="aegis-api"))
        cap = self.engine.verify_token(result.token, expected_target="aegis-api")
        assert cap.target == "aegis-api"

    def test_verify_with_target_mismatch_raises(self):
        result = self.engine.exchange(_req(target="aegis-api"))
        with pytest.raises(ZTIXTokenError, match="target_mismatch"):
            self.engine.verify_token(result.token, expected_target="wrong-service")

    def test_verify_expired_token_raises(self):
        # Issue token that expires immediately (ttl=0 is capped to 1, so use direct jwt)
        payload = {
            "jti": "ztix_expiredtest",
            "iss": "ztix.tokendna",
            "sub": "sub_x",
            "mid": "mid_x",
            "cap": ["read:findings"],
            "scp": "test",
            "tgt": "test",
            "iat": int(time.time()) - 100,
            "exp": int(time.time()) - 1,    # already expired
            "aml": 1,
            "dna": "",
            "sig": "ignored",
        }
        token = _jwt_sign(payload, TEST_KEY)
        with pytest.raises(ZTIXTokenError, match="expired"):
            self.engine.verify_token(token)

    def test_verify_wrong_issuer_raises(self):
        payload = {
            "jti": "ztix_wrongiss",
            "iss": "evil.com",
            "sub": "sub_x",
            "mid": "mid_x",
            "cap": ["read:findings"],
            "scp": "test",
            "tgt": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "aml": 1,
            "dna": "",
            "sig": "x",
        }
        token = _jwt_sign(payload, TEST_KEY)
        with pytest.raises(ZTIXTokenError, match="invalid_issuer"):
            self.engine.verify_token(token)

    def test_verify_bad_signature_raises(self):
        result = self.engine.exchange(_req())
        # Tamper with the token
        parts = result.token.split(".")
        parts[2] = parts[2][:-4] + "XXXX"
        bad_token = ".".join(parts)
        with pytest.raises(ZTIXTokenError):
            self.engine.verify_token(bad_token)

    def test_verify_replay_rejected(self):
        result = self.engine.exchange(_req())
        # First verify succeeds
        self.engine.verify_token(result.token)
        # Second verify should be rejected (replay)
        with pytest.raises(ZTIXTokenError, match="already_used"):
            self.engine.verify_token(result.token)


# ── ZTIXEngine.revoke_token ───────────────────────────────────────────────────

class TestZTIXEngineRevoke:
    def test_revoke_prevents_verify(self):
        engine = _engine()
        result = engine.exchange(_req())
        engine.revoke_token(result.jti, result.expires_at)
        with pytest.raises(ZTIXTokenError, match="already_used"):
            engine.verify_token(result.token)


# ── Source identity abstraction ───────────────────────────────────────────────

class TestSourceIdentityAbstraction:
    def test_sub_handle_not_original_id(self):
        engine = _engine()
        result = engine.exchange(_req(subject_id="real-user@company.com"))
        cap = engine.verify_token(result.token)
        # Target sees opaque handle, never the real subject_id
        assert cap.sub_handle != "real-user@company.com"
        assert cap.sub_handle.startswith("sub_")

    def test_mid_handle_not_original_id(self):
        engine = _engine()
        result = engine.exchange(_req(machine_id="mid_secret123"))
        cap = engine.verify_token(result.token)
        assert cap.mid_handle != "mid_secret123"
        assert cap.mid_handle.startswith("mid_")

    def test_different_subjects_different_handles(self):
        engine = _engine()
        r1 = engine.exchange(_req(subject_id="user_a@example.com"))
        r2 = engine.exchange(_req(subject_id="user_b@example.com"))
        c1 = engine.verify_token(r1.token)
        c2 = engine.verify_token(r2.token)
        assert c1.sub_handle != c2.sub_handle

    def test_same_subject_same_handle(self):
        engine = _engine()
        r1 = engine.exchange(_req(subject_id="stable@example.com"))
        r2 = engine.exchange(_req(subject_id="stable@example.com"))
        # Handle is HMAC-deterministic — same subject → same handle
        assert r1.success and r2.success
        # We can verify indirectly through the handle field
        c1 = engine.verify_token(r1.token)
        c2 = engine.verify_token(r2.token)
        assert c1.sub_handle == c2.sub_handle


# ── ZTIXCapabilityToken ───────────────────────────────────────────────────────

class TestZTIXCapabilityToken:
    def test_has_capability_true(self):
        cap = ZTIXCapabilityToken(
            jti="j", sub_handle="s", mid_handle="m",
            capabilities=["read:findings", "aegis:read"],
            scope="test", target="t", issued_at=time.time(),
            expires_at=time.time() + 300, assurance=1,
        )
        assert cap.has_capability("read:findings")
        assert not cap.has_capability("admin:keys")

    def test_is_expired_future(self):
        cap = ZTIXCapabilityToken(
            jti="j", sub_handle="s", mid_handle="m", capabilities=[],
            scope="", target="", issued_at=time.time(),
            expires_at=time.time() + 300, assurance=1,
        )
        assert not cap.is_expired()

    def test_is_expired_past(self):
        cap = ZTIXCapabilityToken(
            jti="j", sub_handle="s", mid_handle="m", capabilities=[],
            scope="", target="", issued_at=time.time(),
            expires_at=time.time() - 1, assurance=1,
        )
        assert cap.is_expired()

    def test_to_dict_no_raw_jwt(self):
        cap = ZTIXCapabilityToken(
            jti="j", sub_handle="s", mid_handle="m", capabilities=["read:findings"],
            scope="test", target="t", issued_at=time.time(),
            expires_at=time.time() + 300, assurance=1,
            raw_jwt="verylongrawjwtstring",
        )
        d = cap.to_dict()
        assert "raw_jwt" not in d


# ── Singleton ─────────────────────────────────────────────────────────────────

class TestSingleton:
    def test_singleton_same_instance(self):
        e1 = get_ztix_engine()
        e2 = get_ztix_engine()
        assert e1 is e2


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_exchange(self):
        engine = _engine()
        results = []
        lock = threading.Lock()

        def do_exchange():
            r = engine.exchange(_req())
            with lock:
                results.append(r)

        threads = [threading.Thread(target=do_exchange) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r.success for r in results)
        # All JTIs must be unique
        jtis = [r.jti for r in results]
        assert len(set(jtis)) == 20
