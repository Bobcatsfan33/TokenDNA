"""
TokenDNA — Agent Identity Chaining + Delegation Graph  (v2.11.0)

Cryptographically linked identity chains for AI agents that spawn sub-agents.
Every action in an agentic pipeline can be traced back to the root orchestrator.

Design
------
When an AI agent (orchestrator) delegates work to a sub-agent, it issues a
DelegationAssertion — a signed record that says:
  "I (<delegator_id>) delegate capability <cap> to <delegatee_id> for <purpose>
   scoped to <scope>, valid until <exp>, revocable at <assertion_id>"

The sub-agent carries a chain of assertions. Any action it takes is traceable
through that chain to the root orchestrator.

Key properties:
  - Cryptographic binding: each assertion is HMAC-signed by the delegator
  - Auditability: full chain is available for forensic inspection
  - TTL-scoped: assertions expire; sub-agents cannot outlive their parent grant
  - Revocable: each assertion has a unique ID that can be revoked
  - Capability attenuation: sub-agents cannot grant more than they received
    (delegated capabilities must be a subset of delegator's capabilities)
  - Depth limiting: configurable max chain depth prevents infinite sub-delegation

Data model:
  DelegationAssertion  — single signed delegation record
  AgentIdentity        — current chain of assertions for an agent
  DelegationGraph      — full graph of all active delegations (in-process store)
  AgentIdentityChainer — top-level API: delegate, verify_chain, revoke, audit_trail

NIST 800-53 Rev5:
  IA-2   Identification and Authentication
  AC-2   Account Management (agent lifecycle)
  AC-3   Access Enforcement (capability attenuation)
  AU-2   Auditable Events (full chain audit trail)
  AU-9   Protection of Audit Information
  IR-4   Incident Response (chain tracing for forensics)
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

CHAIN_SIGNING_KEY: bytes = os.getenv("CHAIN_SIGNING_KEY", "").encode() or b"dev-chain-key-change-in-prod"
CHAIN_MAX_DEPTH   = int(os.getenv("CHAIN_MAX_DEPTH", "8"))
CHAIN_DEFAULT_TTL = int(os.getenv("CHAIN_DEFAULT_TTL", "3600"))       # 1 hour
CHAIN_MAX_TTL     = int(os.getenv("CHAIN_MAX_TTL", "86400"))           # 24 hours


# ── Errors ─────────────────────────────────────────────────────────────────────


class ChainError(Exception):
    """Base error for agent identity chain operations."""


class ChainSignatureError(ChainError):
    """Assertion signature verification failed."""


class ChainExpiredError(ChainError):
    """Assertion or chain has expired."""


class ChainDepthError(ChainError):
    """Delegation chain depth limit exceeded."""


class ChainCapabilityError(ChainError):
    """Attempted to delegate capability not held by delegator."""


class ChainRevokedError(ChainError):
    """Assertion or chain has been revoked."""


# ── DelegationAssertion ────────────────────────────────────────────────────────


@dataclass
class DelegationAssertion:
    """
    A single signed delegation record.

    Fields:
      assertion_id   — unique ID (nonce)
      delegator_id   — agent making the delegation
      delegatee_id   — agent receiving the delegation
      capabilities   — capabilities being delegated (subset of delegator's)
      scope          — resource scope for this delegation
      purpose        — human-readable reason for delegation
      issued_at      — Unix epoch
      expires_at     — Unix epoch (hard expiry; delegatee stops working after this)
      depth          — depth in the chain (root=0, root→A=1, root→A→B=2, ...)
      parent_id      — assertion_id of the parent assertion (None for root delegation)
      signature      — HMAC-SHA256 of canonical form of above fields
      revoked        — set to True when manually revoked (in-place mutation is OK)
      revoke_reason  — why it was revoked
    """
    assertion_id: str
    delegator_id: str
    delegatee_id: str
    capabilities: list
    scope:        str
    purpose:      str
    issued_at:    float
    expires_at:   float
    depth:        int
    parent_id:    Optional[str]
    signature:    str
    revoked:      bool = False
    revoke_reason: Optional[str] = None

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    def canonical(self) -> str:
        """Canonical string for signature computation (deterministic)."""
        return json.dumps({
            "assertion_id": self.assertion_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "capabilities": sorted(self.capabilities),
            "scope":        self.scope,
            "purpose":      self.purpose,
            "issued_at":    self.issued_at,
            "expires_at":   self.expires_at,
            "depth":        self.depth,
            "parent_id":    self.parent_id,
        }, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["is_expired"] = self.is_expired()
        d["is_valid"]   = self.is_valid()
        return d


def _sign_assertion(assertion: DelegationAssertion, key: bytes) -> str:
    """Compute HMAC-SHA256 of the assertion's canonical form."""
    return hmac.new(key, assertion.canonical().encode(), hashlib.sha256).hexdigest()


def _verify_assertion_sig(assertion: DelegationAssertion, key: bytes) -> bool:
    """Verify the assertion's signature."""
    expected = _sign_assertion(assertion, key)
    return hmac.compare_digest(expected, assertion.signature)


# ── AgentIdentity ──────────────────────────────────────────────────────────────


@dataclass
class AgentIdentity:
    """
    The full delegation chain for one agent.

    chain[0]     = root assertion (granted by the root orchestrator or a human operator)
    chain[-1]    = this agent's direct grant
    agent_id     = the agent this identity belongs to
    root_id      = the root orchestrator (chain[0].delegator_id)
    """
    agent_id:    str
    chain:       list   # list of DelegationAssertion

    @property
    def root_id(self) -> Optional[str]:
        if self.chain:
            return self.chain[0].delegator_id
        return None

    @property
    def depth(self) -> int:
        return len(self.chain)

    @property
    def effective_capabilities(self) -> list:
        """Capabilities at the tip of the chain (intersection of all grants)."""
        if not self.chain:
            return []
        caps = set(self.chain[0].capabilities)
        for assertion in self.chain[1:]:
            caps = caps.intersection(assertion.capabilities)
        return sorted(caps)

    @property
    def effective_scope(self) -> str:
        """Scope at the tip — most specific (last) assertion's scope."""
        if not self.chain:
            return ""
        return self.chain[-1].scope

    def is_valid(self) -> bool:
        """All assertions in chain must be valid (not expired, not revoked)."""
        return all(a.is_valid() for a in self.chain)

    def earliest_expiry(self) -> float:
        """Effective expiry = earliest expiry in the chain."""
        if not self.chain:
            return 0.0
        return min(a.expires_at for a in self.chain)

    def to_dict(self) -> dict:
        return {
            "agent_id":               self.agent_id,
            "root_id":                self.root_id,
            "depth":                  self.depth,
            "effective_capabilities": self.effective_capabilities,
            "effective_scope":        self.effective_scope,
            "is_valid":               self.is_valid(),
            "earliest_expiry":        self.earliest_expiry(),
            "chain":                  [a.to_dict() for a in self.chain],
        }


# ── Delegation Graph ───────────────────────────────────────────────────────────


class DelegationGraph:
    """
    In-process store for the full delegation graph.

    Stores:
      assertions  — all DelegationAssertions by assertion_id
      by_delegatee — assertion_ids grouped by delegatee_id
      by_delegator — assertion_ids grouped by delegator_id
    """

    def __init__(self):
        self._assertions: dict[str, DelegationAssertion] = {}
        self._by_delegatee: dict[str, list] = {}
        self._by_delegator: dict[str, list] = {}
        self._lock = threading.Lock()

    def add(self, assertion: DelegationAssertion) -> None:
        with self._lock:
            self._assertions[assertion.assertion_id] = assertion
            self._by_delegatee.setdefault(assertion.delegatee_id, []).append(assertion.assertion_id)
            self._by_delegator.setdefault(assertion.delegator_id, []).append(assertion.assertion_id)

    def get(self, assertion_id: str) -> Optional[DelegationAssertion]:
        with self._lock:
            return self._assertions.get(assertion_id)

    def assertions_for_delegatee(self, agent_id: str) -> list:
        with self._lock:
            ids = self._by_delegatee.get(agent_id, [])
            return [self._assertions[aid] for aid in ids if aid in self._assertions]

    def assertions_by_delegator(self, agent_id: str) -> list:
        with self._lock:
            ids = self._by_delegator.get(agent_id, [])
            return [self._assertions[aid] for aid in ids if aid in self._assertions]

    def revoke(self, assertion_id: str, reason: str = "manual") -> bool:
        with self._lock:
            assertion = self._assertions.get(assertion_id)
            if assertion is None:
                return False
            assertion.revoked = True
            assertion.revoke_reason = reason
            return True

    def all_assertions(self) -> list:
        with self._lock:
            return list(self._assertions.values())

    def count(self) -> int:
        with self._lock:
            return len(self._assertions)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for a in self._assertions.values() if a.is_valid())


# ── Agent Identity Chainer ─────────────────────────────────────────────────────


class AgentIdentityChainer:
    """
    Top-level API for agent identity chaining and delegation.

    create_root(agent_id, capabilities, scope, ttl) → DelegationAssertion
      Creates a root delegation (issued by an operator/human principal).

    delegate(delegator_identity, delegatee_id, capabilities, scope, purpose, ttl)
      → DelegationAssertion
      Issues a signed delegation from one agent to another.
      Enforces capability attenuation and depth limits.

    build_chain(delegatee_id) → AgentIdentity
      Reconstructs the full chain for an agent from the graph.

    verify_chain(identity) → None (raises on invalid)
      Verifies all signatures and validity in a chain.

    revoke(assertion_id, reason) → bool
      Revokes a specific assertion (and all downstream chains are invalidated).

    audit_trail(agent_id) → list[dict]
      Returns full auditable history for an agent_id.
    """

    ROOT_OPERATOR = "__root_operator__"

    def __init__(
        self,
        signing_key: bytes = CHAIN_SIGNING_KEY,
        graph: Optional[DelegationGraph] = None,
        max_depth: int = CHAIN_MAX_DEPTH,
    ):
        self._key      = signing_key
        self._graph    = graph or DelegationGraph()
        self._max_depth = max_depth

    def create_root(
        self,
        agent_id: str,
        capabilities: list,
        scope: str = "*",
        purpose: str = "root_delegation",
        ttl: int = CHAIN_DEFAULT_TTL,
        operator_id: str = ROOT_OPERATOR,
    ) -> DelegationAssertion:
        """
        Create a root delegation from an operator to an orchestrator agent.
        This is the anchor of the chain.
        """
        ttl = min(max(ttl, 1), CHAIN_MAX_TTL)
        now = time.time()

        assertion = DelegationAssertion(
            assertion_id=f"da_{secrets.token_hex(16)}",
            delegator_id=operator_id,
            delegatee_id=agent_id,
            capabilities=sorted(capabilities),
            scope=scope,
            purpose=purpose,
            issued_at=now,
            expires_at=now + ttl,
            depth=0,
            parent_id=None,
            signature="",
        )
        assertion.signature = _sign_assertion(assertion, self._key)
        self._graph.add(assertion)

        logger.info(
            "[Chain] Root delegation: op=%s → agent=%s caps=%s depth=0 id=%s",
            operator_id, agent_id, capabilities, assertion.assertion_id,
        )
        return assertion

    def delegate(
        self,
        delegator_identity: AgentIdentity,
        delegatee_id: str,
        capabilities: list,
        scope: str = "",
        purpose: str = "",
        ttl: int = CHAIN_DEFAULT_TTL,
    ) -> DelegationAssertion:
        """
        Delegate a subset of capabilities from an agent to a sub-agent.

        Raises:
          ChainDepthError     — if delegation would exceed max depth
          ChainCapabilityError — if delegatee requests more than delegator holds
          ChainExpiredError   — if delegator chain is already expired
          ChainRevokedError   — if any assertion in delegator's chain is revoked
        """
        if not delegator_identity.is_valid():
            raise ChainExpiredError("delegator_chain_invalid_or_expired")

        # Depth of the new assertion = tip assertion's depth + 1
        tip_depth = delegator_identity.chain[-1].depth if delegator_identity.chain else 0
        new_depth = tip_depth + 1
        if new_depth > self._max_depth:
            raise ChainDepthError(
                f"chain_depth_exceeded: depth={new_depth} max={self._max_depth}"
            )

        # Capability attenuation: delegatee gets only subset of delegator's effective caps
        delegator_caps = set(delegator_identity.effective_capabilities)
        requested_caps = set(capabilities)
        if not requested_caps.issubset(delegator_caps):
            excess = requested_caps - delegator_caps
            raise ChainCapabilityError(
                f"capability_overgrant: agent={delegator_identity.agent_id} "
                f"requested={sorted(excess)} not_held={sorted(excess)}"
            )

        # TTL: delegatee TTL must not exceed delegator's remaining TTL
        delegator_remaining = delegator_identity.earliest_expiry() - time.time()
        effective_ttl = min(min(ttl, CHAIN_MAX_TTL), max(0, delegator_remaining))
        if effective_ttl <= 0:
            raise ChainExpiredError("delegator_ttl_already_expired")

        effective_scope = scope or delegator_identity.effective_scope
        parent_id = delegator_identity.chain[-1].assertion_id if delegator_identity.chain else None
        now = time.time()

        assertion = DelegationAssertion(
            assertion_id=f"da_{secrets.token_hex(16)}",
            delegator_id=delegator_identity.agent_id,
            delegatee_id=delegatee_id,
            capabilities=sorted(capabilities),
            scope=effective_scope,
            purpose=purpose or f"delegation_from_{delegator_identity.agent_id}",
            issued_at=now,
            expires_at=now + effective_ttl,
            depth=new_depth,
            parent_id=parent_id,
            signature="",
        )
        assertion.signature = _sign_assertion(assertion, self._key)
        self._graph.add(assertion)

        logger.info(
            "[Chain] Delegation: %s → %s caps=%s scope=%s depth=%d id=%s",
            delegator_identity.agent_id, delegatee_id, capabilities,
            effective_scope, new_depth, assertion.assertion_id,
        )
        return assertion

    def build_chain(self, delegatee_id: str) -> Optional[AgentIdentity]:
        """
        Reconstruct the chain for an agent.

        Finds the most recent valid assertion for the agent and walks up
        to the root via parent_id links.
        """
        assertions = self._graph.assertions_for_delegatee(delegatee_id)
        if not assertions:
            return None

        # Pick the most recently issued non-revoked assertion
        valid_assertions = [a for a in assertions if not a.revoked]
        if not valid_assertions:
            return None
        tip = max(valid_assertions, key=lambda a: a.issued_at)

        # Walk up the chain via parent_id
        chain = [tip]
        current = tip
        while current.parent_id is not None:
            parent = self._graph.get(current.parent_id)
            if parent is None:
                logger.warning("[Chain] Missing parent assertion %s", current.parent_id)
                break
            chain.insert(0, parent)
            current = parent

        return AgentIdentity(agent_id=delegatee_id, chain=chain)

    def verify_chain(self, identity: AgentIdentity) -> None:
        """
        Fully verify an agent identity chain.

        Checks:
          1. All assertions have valid signatures
          2. No assertion is expired
          3. No assertion is revoked
          4. Depth ordering is consistent
          5. Capability attenuation: each link is a subset of previous

        Raises appropriate ChainError on any violation.
        """
        if not identity.chain:
            raise ChainError("empty_chain")

        prev_caps = None
        for i, assertion in enumerate(identity.chain):
            # 1. Signature
            if not _verify_assertion_sig(assertion, self._key):
                raise ChainSignatureError(
                    f"invalid_signature: assertion_id={assertion.assertion_id} depth={i}"
                )

            # 2. Expiry
            if assertion.is_expired():
                raise ChainExpiredError(
                    f"expired_assertion: assertion_id={assertion.assertion_id}"
                )

            # 3. Revocation
            if assertion.revoked:
                raise ChainRevokedError(
                    f"revoked_assertion: assertion_id={assertion.assertion_id} "
                    f"reason={assertion.revoke_reason}"
                )

            # 4. Depth
            if assertion.depth != i:
                raise ChainError(
                    f"depth_mismatch: expected={i} got={assertion.depth} "
                    f"assertion_id={assertion.assertion_id}"
                )

            # 5. Capability attenuation
            if prev_caps is not None:
                current_caps = set(assertion.capabilities)
                if not current_caps.issubset(prev_caps):
                    excess = current_caps - prev_caps
                    raise ChainCapabilityError(
                        f"capability_overgrant: assertion_id={assertion.assertion_id} "
                        f"excess={sorted(excess)}"
                    )
            prev_caps = set(assertion.capabilities)

        # 6. Delegatee of each assertion must match delegator of next
        for i in range(len(identity.chain) - 1):
            curr = identity.chain[i]
            next_ = identity.chain[i + 1]
            if curr.delegatee_id != next_.delegator_id:
                raise ChainError(
                    f"chain_break: chain[{i}].delegatee={curr.delegatee_id} "
                    f"!= chain[{i+1}].delegator={next_.delegator_id}"
                )

    def revoke(self, assertion_id: str, reason: str = "manual") -> bool:
        """
        Revoke an assertion. All downstream chains that include this assertion
        will fail verify_chain() since the assertion is marked revoked.
        """
        revoked = self._graph.revoke(assertion_id, reason)
        if revoked:
            logger.info("[Chain] Revoked assertion: id=%s reason=%s", assertion_id, reason)
        return revoked

    def audit_trail(self, agent_id: str) -> list:
        """
        Return full auditable history for an agent_id.
        Includes all assertions where the agent was delegatee or delegator,
        sorted by issued_at.

        NIST AU-2: Auditable Events — every delegation is traceable.
        """
        as_delegatee = self._graph.assertions_for_delegatee(agent_id)
        as_delegator = self._graph.assertions_by_delegator(agent_id)

        # Deduplicate
        seen = set()
        all_assertions = []
        for a in as_delegatee + as_delegator:
            if a.assertion_id not in seen:
                seen.add(a.assertion_id)
                all_assertions.append(a)

        all_assertions.sort(key=lambda a: a.issued_at)
        return [a.to_dict() for a in all_assertions]

    def trace_to_root(self, agent_id: str) -> list:
        """
        Return the path from agent_id to the root orchestrator.

        Returns: list of agent_ids [root_operator, orchestrator, ..., agent_id]
        """
        identity = self.build_chain(agent_id)
        if identity is None:
            return [agent_id]
        path = [identity.chain[0].delegator_id]
        for assertion in identity.chain:
            path.append(assertion.delegatee_id)
        return path

    def graph_stats(self) -> dict:
        return {
            "total_assertions": self._graph.count(),
            "active_assertions": self._graph.active_count(),
            "max_depth": self._max_depth,
        }


# ── Module-level singleton ─────────────────────────────────────────────────────

_default_chainer: Optional[AgentIdentityChainer] = None
_chainer_lock = threading.Lock()


def get_agent_identity_chainer() -> AgentIdentityChainer:
    """Return (or lazily create) the module-level AgentIdentityChainer singleton."""
    global _default_chainer
    if _default_chainer is None:
        with _chainer_lock:
            if _default_chainer is None:
                _default_chainer = AgentIdentityChainer()
    return _default_chainer
