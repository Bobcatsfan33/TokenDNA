"""
Tests — TokenDNA Agent Identity Chaining + Delegation Graph

Coverage:
  - DelegationAssertion: canonical, sign, verify, expiry, revoke
  - AgentIdentity: effective_capabilities, depth, earliest_expiry, validity
  - DelegationGraph: add, get, by_delegatee, by_delegator, revoke, counts
  - AgentIdentityChainer.create_root: basic creation and signing
  - AgentIdentityChainer.delegate: happy path, depth limit, capability overgrant, TTL attenuation
  - AgentIdentityChainer.build_chain: single hop, multi-hop, missing chain
  - AgentIdentityChainer.verify_chain: valid chain, bad sig, expired, revoked, depth mismatch, capability overgrant
  - AgentIdentityChainer.revoke: blocks downstream verification
  - AgentIdentityChainer.audit_trail: history by agent
  - AgentIdentityChainer.trace_to_root: full path
  - Singleton
"""

import time
import threading
import pytest

from modules.ztix.agent_identity import (
    AgentIdentity,
    AgentIdentityChainer,
    ChainCapabilityError,
    ChainDepthError,
    ChainError,
    ChainExpiredError,
    ChainRevokedError,
    ChainSignatureError,
    DelegationAssertion,
    DelegationGraph,
    _sign_assertion,
    _verify_assertion_sig,
    get_agent_identity_chainer,
)

TEST_KEY = b"test-chain-key-for-unit-tests"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _chainer(max_depth=5):
    return AgentIdentityChainer(signing_key=TEST_KEY, max_depth=max_depth)


def _root(chainer, agent_id="orchestrator", caps=None, ttl=3600):
    return chainer.create_root(
        agent_id=agent_id,
        capabilities=caps or ["read:findings", "write:scan"],
        scope="aegis:*",
        purpose="test_root",
        ttl=ttl,
    )


def _identity_from_root(chainer, root_assertion):
    """Build AgentIdentity with just the root assertion."""
    return AgentIdentity(agent_id=root_assertion.delegatee_id, chain=[root_assertion])


# ── DelegationAssertion ───────────────────────────────────────────────────────

class TestDelegationAssertion:
    def test_canonical_is_deterministic(self):
        chainer = _chainer()
        a = _root(chainer)
        c1 = a.canonical()
        c2 = a.canonical()
        assert c1 == c2

    def test_canonical_changes_with_id(self):
        chainer = _chainer()
        a1 = _root(chainer, agent_id="agent_a")
        a2 = _root(chainer, agent_id="agent_b")
        assert a1.canonical() != a2.canonical()

    def test_signature_present(self):
        chainer = _chainer()
        a = _root(chainer)
        assert a.signature
        assert len(a.signature) == 64    # HMAC-SHA256 hex

    def test_verify_sig_correct_key(self):
        chainer = _chainer()
        a = _root(chainer)
        assert _verify_assertion_sig(a, TEST_KEY)

    def test_verify_sig_wrong_key_fails(self):
        chainer = _chainer()
        a = _root(chainer)
        assert not _verify_assertion_sig(a, b"wrong_key")

    def test_not_expired_by_default(self):
        chainer = _chainer()
        a = _root(chainer)
        assert not a.is_expired()
        assert a.is_valid()

    def test_expired(self):
        chainer = _chainer()
        a = _root(chainer, ttl=0)    # TTL=0 → expires at now (may be in the past)
        # Force expires_at to past
        a.expires_at = time.time() - 1
        assert a.is_expired()
        assert not a.is_valid()

    def test_revoked(self):
        chainer = _chainer()
        a = _root(chainer)
        a.revoked = True
        assert not a.is_valid()

    def test_to_dict_includes_validity(self):
        chainer = _chainer()
        a = _root(chainer)
        d = a.to_dict()
        assert "is_valid" in d
        assert "is_expired" in d
        assert d["is_valid"] is True


# ── AgentIdentity ─────────────────────────────────────────────────────────────

class TestAgentIdentity:
    def test_root_id(self):
        chainer = _chainer()
        root = _root(chainer, agent_id="orch")
        identity = _identity_from_root(chainer, root)
        assert identity.root_id == AgentIdentityChainer.ROOT_OPERATOR

    def test_depth_single(self):
        chainer = _chainer()
        root = _root(chainer)
        identity = _identity_from_root(chainer, root)
        assert identity.depth == 1

    def test_effective_capabilities_single(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings", "write:scan"])
        identity = _identity_from_root(chainer, root)
        assert sorted(identity.effective_capabilities) == ["read:findings", "write:scan"]

    def test_effective_capabilities_intersection(self):
        # Chain: root gives [A, B, C] → sub-agent gets [A, B] → only A, B effective
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings", "write:scan", "aegis:read"])
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub_agent", ["read:findings", "write:scan"])
        identity = AgentIdentity(agent_id="sub_agent", chain=[root, sub])
        assert sorted(identity.effective_capabilities) == ["read:findings", "write:scan"]

    def test_is_valid_all_valid(self):
        chainer = _chainer()
        root = _root(chainer)
        identity = _identity_from_root(chainer, root)
        assert identity.is_valid()

    def test_is_valid_one_expired(self):
        chainer = _chainer()
        root = _root(chainer)
        root.expires_at = time.time() - 1
        identity = _identity_from_root(chainer, root)
        assert not identity.is_valid()

    def test_earliest_expiry(self):
        chainer = _chainer()
        root = _root(chainer, ttl=1000)
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub_agent", ["read:findings"], ttl=500)
        identity = AgentIdentity(agent_id="sub_agent", chain=[root, sub])
        exp = identity.earliest_expiry()
        # Should be sub's expiry (500s), not root's (1000s)
        assert exp < time.time() + 600

    def test_to_dict(self):
        chainer = _chainer()
        root = _root(chainer)
        identity = _identity_from_root(chainer, root)
        d = identity.to_dict()
        assert d["agent_id"] == root.delegatee_id
        assert d["depth"] == 1
        assert "chain" in d


# ── DelegationGraph ───────────────────────────────────────────────────────────

class TestDelegationGraph:
    def test_add_and_get(self):
        chainer = _chainer()
        graph = DelegationGraph()
        a = _root(chainer)
        graph.add(a)
        assert graph.get(a.assertion_id) is a

    def test_get_nonexistent(self):
        graph = DelegationGraph()
        assert graph.get("nonexistent") is None

    def test_by_delegatee(self):
        chainer = _chainer()
        graph = chainer._graph
        a = _root(chainer, agent_id="orch1")
        assertions = graph.assertions_for_delegatee("orch1")
        assert a in assertions

    def test_by_delegator(self):
        chainer = _chainer()
        graph = chainer._graph
        root = _root(chainer, agent_id="orch")
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub", ["read:findings"])
        delegated_by_orch = graph.assertions_by_delegator("orch")
        assert sub in delegated_by_orch

    def test_revoke(self):
        chainer = _chainer()
        graph = chainer._graph
        a = _root(chainer)
        graph.revoke(a.assertion_id, reason="test_revoke")
        assert graph.get(a.assertion_id).revoked is True

    def test_revoke_nonexistent_returns_false(self):
        graph = DelegationGraph()
        assert graph.revoke("nonexistent") is False

    def test_count(self):
        chainer = _chainer()
        _root(chainer, agent_id="a1")
        _root(chainer, agent_id="a2")
        assert chainer._graph.count() >= 2


# ── AgentIdentityChainer ──────────────────────────────────────────────────────

class TestAgentIdentityChainerCreateRoot:
    def test_creates_root_assertion(self):
        chainer = _chainer()
        a = _root(chainer)
        assert a.depth == 0
        assert a.parent_id is None
        assert a.signature

    def test_root_in_graph(self):
        chainer = _chainer()
        a = _root(chainer)
        assert chainer._graph.get(a.assertion_id) is a

    def test_root_ttl_capped(self):
        chainer = _chainer()
        a = chainer.create_root("orch", ["read:findings"], ttl=999999)
        remaining = a.expires_at - time.time()
        assert remaining <= 86400 + 5   # CHAIN_MAX_TTL + buffer


class TestAgentIdentityChainerDelegate:
    def test_delegate_happy_path(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings", "write:scan"])
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub_agent", ["read:findings"])
        # root is depth=0, sub-agent delegation is depth=1
        assert sub.depth == 1
        assert sub.delegatee_id == "sub_agent"
        assert "read:findings" in sub.capabilities

    def test_delegate_depth_limit(self):
        chainer = _chainer(max_depth=1)
        root = _root(chainer, caps=["read:findings"])
        root_identity = _identity_from_root(chainer, root)
        # root is depth=0; first delegation is depth=1 which equals max=1 — allowed
        sub = chainer.delegate(root_identity, "sub_agent", ["read:findings"])
        assert sub.depth == 1
        # Second delegation would be depth=2 > max=1 — should raise
        sub_identity = AgentIdentity(agent_id="sub_agent", chain=[root, sub])
        with pytest.raises(ChainDepthError):
            chainer.delegate(sub_identity, "sub_sub", ["read:findings"])

    def test_delegate_capability_overgrant_raises(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings"])
        root_identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainCapabilityError):
            chainer.delegate(root_identity, "sub", ["read:findings", "write:scan"])

    def test_delegate_ttl_limited_by_parent(self):
        chainer = _chainer()
        root = _root(chainer, ttl=100)
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub", ["read:findings"], ttl=9999)
        remaining = sub.expires_at - time.time()
        assert remaining <= 100 + 2   # capped by parent's remaining TTL

    def test_delegate_invalid_chain_raises(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings"])
        root.revoked = True
        root_identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainExpiredError):
            chainer.delegate(root_identity, "sub", ["read:findings"])

    def test_delegate_creates_parent_id_link(self):
        chainer = _chainer()
        root = _root(chainer)
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub", ["read:findings"])
        assert sub.parent_id == root.assertion_id


class TestAgentIdentityChainerBuildChain:
    def test_build_chain_single_hop(self):
        chainer = _chainer()
        root = _root(chainer, agent_id="orch")
        identity = chainer.build_chain("orch")
        assert identity is not None
        assert identity.agent_id == "orch"
        assert identity.depth == 1

    def test_build_chain_multi_hop(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings", "write:scan"])
        root_identity = _identity_from_root(chainer, root)
        sub1 = chainer.delegate(root_identity, "sub1", ["read:findings", "write:scan"])
        sub1_identity = AgentIdentity(agent_id="sub1", chain=[root, sub1])
        chainer.delegate(sub1_identity, "sub2", ["read:findings"])

        identity = chainer.build_chain("sub2")
        assert identity is not None
        assert identity.agent_id == "sub2"
        assert identity.depth == 3   # 3 assertions in chain: root, sub1, sub2

    def test_build_chain_unknown_agent_returns_none(self):
        chainer = _chainer()
        assert chainer.build_chain("unknown_agent") is None

    def test_build_chain_all_revoked_returns_none(self):
        chainer = _chainer()
        root = _root(chainer, agent_id="orch2")
        chainer._graph.revoke(root.assertion_id)
        result = chainer.build_chain("orch2")
        assert result is None


class TestAgentIdentityChainerVerifyChain:
    def test_verify_valid_chain(self):
        chainer = _chainer()
        root = _root(chainer)
        identity = _identity_from_root(chainer, root)
        chainer.verify_chain(identity)  # should not raise

    def test_verify_empty_chain_raises(self):
        chainer = _chainer()
        identity = AgentIdentity(agent_id="orch", chain=[])
        with pytest.raises(ChainError, match="empty_chain"):
            chainer.verify_chain(identity)

    def test_verify_bad_sig_raises(self):
        chainer = _chainer()
        root = _root(chainer)
        root.signature = "badsig" + "0" * 58   # tamper
        identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainSignatureError):
            chainer.verify_chain(identity)

    def test_verify_expired_assertion_raises(self):
        chainer = _chainer()
        root = _root(chainer)
        root.expires_at = time.time() - 1
        root.signature = _sign_assertion(root, TEST_KEY)   # re-sign with correct exp
        identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainExpiredError):
            chainer.verify_chain(identity)

    def test_verify_revoked_assertion_raises(self):
        chainer = _chainer()
        root = _root(chainer)
        root.revoked = True
        identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainRevokedError):
            chainer.verify_chain(identity)

    def test_verify_depth_mismatch_raises(self):
        chainer = _chainer()
        root = _root(chainer)
        root.depth = 99   # wrong depth; re-sign
        root.signature = _sign_assertion(root, TEST_KEY)
        identity = _identity_from_root(chainer, root)
        with pytest.raises(ChainError, match="depth_mismatch"):
            chainer.verify_chain(identity)

    def test_verify_chain_break_raises(self):
        chainer = _chainer()
        root = _root(chainer, caps=["read:findings"])
        root_identity = _identity_from_root(chainer, root)
        sub = chainer.delegate(root_identity, "sub_agent", ["read:findings"])
        # Tamper: put a different agent's assertion in the chain
        root2 = _root(chainer, agent_id="unrelated_orch", caps=["read:findings"])
        # root2.delegatee_id != sub.delegator_id (which is "orchestrator")
        bad_identity = AgentIdentity(agent_id="sub_agent", chain=[root2, sub])
        with pytest.raises((ChainCapabilityError, ChainError)):
            chainer.verify_chain(bad_identity)


class TestAgentIdentityChainerRevoke:
    def test_revoke_blocks_verify(self):
        chainer = _chainer()
        root = _root(chainer)
        identity = _identity_from_root(chainer, root)
        chainer.revoke(root.assertion_id, reason="test_revoke")
        with pytest.raises(ChainRevokedError):
            chainer.verify_chain(identity)

    def test_revoke_returns_true(self):
        chainer = _chainer()
        root = _root(chainer)
        assert chainer.revoke(root.assertion_id) is True

    def test_revoke_nonexistent_returns_false(self):
        chainer = _chainer()
        assert chainer.revoke("nonexistent_id") is False


class TestAgentIdentityChainerAuditTrail:
    def test_audit_trail_as_delegatee(self):
        chainer = _chainer()
        _root(chainer, agent_id="orch_audit")
        trail = chainer.audit_trail("orch_audit")
        assert len(trail) >= 1
        assert any(a["delegatee_id"] == "orch_audit" for a in trail)

    def test_audit_trail_as_delegator(self):
        chainer = _chainer()
        root = _root(chainer, agent_id="orch_del", caps=["read:findings"])
        root_identity = _identity_from_root(chainer, root)
        chainer.delegate(root_identity, "sub_audit", ["read:findings"])
        trail = chainer.audit_trail("orch_del")
        assert any(a["delegator_id"] == "orch_del" for a in trail)

    def test_audit_trail_empty_for_unknown(self):
        chainer = _chainer()
        assert chainer.audit_trail("unknown_agent") == []

    def test_audit_trail_sorted_by_time(self):
        chainer = _chainer()
        _root(chainer, agent_id="orch_sort")
        trail = chainer.audit_trail("orch_sort")
        times = [a["issued_at"] for a in trail]
        assert times == sorted(times)


class TestTraceToRoot:
    def test_trace_single_hop(self):
        chainer = _chainer()
        _root(chainer, agent_id="orch_trace")
        path = chainer.trace_to_root("orch_trace")
        assert path[0] == AgentIdentityChainer.ROOT_OPERATOR
        assert path[-1] == "orch_trace"

    def test_trace_unknown_agent(self):
        chainer = _chainer()
        path = chainer.trace_to_root("ghost_agent")
        assert path == ["ghost_agent"]


# ── Singleton ─────────────────────────────────────────────────────────────────

class TestSingleton:
    def test_same_instance(self):
        c1 = get_agent_identity_chainer()
        c2 = get_agent_identity_chainer()
        assert c1 is c2


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_create_root(self):
        chainer = _chainer()
        assertions = []
        lock = threading.Lock()

        def create():
            a = chainer.create_root(f"agent_{id(threading.current_thread())}", ["read:findings"])
            with lock:
                assertions.append(a)

        threads = [threading.Thread(target=create) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(assertions) == 20
        ids = [a.assertion_id for a in assertions]
        assert len(set(ids)) == 20
