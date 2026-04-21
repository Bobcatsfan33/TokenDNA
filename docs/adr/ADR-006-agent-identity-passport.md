# ADR-006 — Cross-Vendor Agent Identity Passport

**Status:** Accepted  
**Sprint:** 3-1 (Weeks 13-14)  
**Date:** 2026-04-17  
**Author:** Forge (TokenDNA engineering)

---

## Context

As AI agents proliferate across cloud platforms (AWS Bedrock, Azure OpenAI, Anthropic, OpenAI), there is no portable, vendor-neutral way to assert an agent's identity, permitted scope, and trust lineage to a third party. Every integration today is bespoke.

TokenDNA already has:
- A 4D attestation model (WHO/WHAT/HOW/WHY)
- A Trust Authority for key management
- Attestation certificates and drift detection

What is missing is a **portable artifact** that encodes all of this into a self-describing, cryptographically verifiable bundle that cross-vendor integrations can validate without a live call to the issuer for every operation.

---

## Decision

Introduce the **Agent Identity Passport** (`modules/identity/passport.py`), a signed portable bundle that captures:

| Field | Purpose |
|-------|---------|
| `subject` | Agent identity (agent_id, owner_org, DNA fingerprint, model fingerprint) |
| `scope` | Permissions, resource patterns, delegation depth, custom claims |
| `issuer` | TokenDNA Trust Authority key reference + issuing operator |
| `validity window` | `not_before` / `not_after` (ISO-8601 UTC) |
| `revocation_url` | Public endpoint for live status check |
| `signature` | HMAC-SHA256 over canonical JSON |

### Passport ID Format

`tdn-pass-<uuid4>` — universally unique, no collision risk.

### Lifecycle State Machine

```
PENDING → APPROVED → ISSUED → REVOKED
            ↓
          REVOKED (early revocation)
```

- **PENDING**: Evidence submitted, awaiting operator approval. Unsigned.
- **APPROVED**: Operator review complete. Still unsigned. Ready for issuance.
- **ISSUED**: Signed by Trust Authority. Valid for cross-vendor presentation.
- **REVOKED**: Invalidated by operator (key compromise, scope change, expiry of trust relationship).
- **EXPIRED**: Derived at query time from `not_after`; not a stored state.

### Cryptographic Approach

HMAC-SHA256 over canonical JSON (sorted keys, no whitespace) of the passport payload minus the `signature` field. No external PKI dependency for the MVP — the signing secret is environment-configured.

**Rationale:** Full asymmetric signing (RSA/ECDSA) with a public key registry is the target for Sprint 3-2+. HMAC is sufficient for Phase 3 design-partner deployments where the verifier trusts the TokenDNA endpoint and only needs to confirm the passport wasn't tampered with in transit.

### Trust Score

`Passport.trust_score()` returns a 0.0–1.0 float:
- Base: 0.5
- Penalty for wide permission scope (−0.03 per permission, capped at −0.20)
- Penalty for wide resource patterns (−0.02 per pattern, capped with above)
- Penalty for delegation depth (−0.05 per hop, capped at −0.15)
- Issuer bonus: +0.15 for TokenDNA-issued passports
- Floor: 0.0 for invalid/revoked/expired passports

### Evidence Submission

Before a passport is approved, operators upload evidence bundles (`passport_evidence` table) linking the passport to:
- An attestation record
- An audit log entry
- A manual review record
- An API key ownership proof

Evidence is advisory — approval is still an explicit operator action.

### Verification Endpoint

`POST /api/passport/verify` is **unauthenticated** by design. Third-party integrators embed a call to this endpoint in their Lambda authorizer, APIM policy, or Envoy ext_authz filter. The endpoint:

1. Looks up the passport by ID in the registry (authoritative status)
2. Checks revocation and expiry
3. Verifies the HMAC signature over the submitted payload
4. Returns `{"valid": bool, "trust_score": float, ...}`

The revocation URL embedded in each passport (`/api/passport/{id}/status`) also supports lightweight status checks that don't require submitting the full bundle.

---

## Cross-Vendor Integration Playbooks

Four playbooks are provided in `passport.py` and exposed via API:

| Vendor | Integration Pattern | Key Touchpoint |
|--------|--------------------|--------------------|
| AWS Bedrock | `sessionAttributes` + Lambda authorizer | `invoke_agent` sessionState |
| Azure OpenAI | APIM inbound policy | `send-request` policy |
| Anthropic | `extra_headers` + FastAPI proxy | `X-TokenDNA-Passport` header |
| OpenAI | `extra_headers` + Envoy ext_authz | `X-TokenDNA-Passport` header |

All playbooks follow the same pattern: attach → validate → forward.

---

## API Surface

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/passport/request` | Tenant | Submit issuance request |
| POST | `/api/passport/{id}/approve` | ADMIN | Approve PENDING passport |
| POST | `/api/passport/{id}/issue` | ADMIN | Issue (sign) APPROVED passport |
| POST | `/api/passport/{id}/revoke` | ADMIN | Revoke ISSUED/APPROVED passport |
| POST | `/api/passport/verify` | None | Verify passport bundle (open) |
| GET | `/api/passport/{id}` | Tenant | Retrieve passport by ID |
| GET | `/api/passport/{id}/status` | None | Revocation check (open) |
| GET | `/api/passports` | ANALYST | List passports with filters |
| POST | `/api/passport/{id}/evidence` | Tenant | Submit evidence bundle |
| GET | `/api/passport/{id}/evidence` | ANALYST | List evidence for passport |
| GET | `/api/passport/integrations/playbooks` | None | List available playbooks |
| GET | `/api/passport/integrations/playbook/{vendor}` | None | Get vendor playbook detail |

---

## GTM Positioning

- **Separate SKU**: Per-passport issuance pricing (not bundled with base attestation).
- **Design partner targeting**: Any organization running agents across ≥2 cloud AI vendors is the primary buyer.
- **Demo arc**: Issue a passport for a Bedrock agent, verify it via a Lambda authorizer, show the revocation flow → 5-minute live demo that closes design-partner conversations.

---

## Consequences

**Positive:**
- Portable, auditable agent identity across vendors without vendor lock-in
- Open verification endpoint enables third-party trust without TokenDNA integration overhead
- Evidence workflow supports compliance use cases (SOC 2, NIST AI RMF)
- Separate SKU creates upsell path beyond base attestation

**Neutral:**
- HMAC approach couples verifiers to the TokenDNA endpoint for secret validation — acceptable for MVP, migrates to asymmetric signing in Sprint 3-2+
- Delegation depth tracking is advisory, not enforced at runtime (runtime enforcement is a Phase 4 item)

**Negative:**
- Passport validity window is static at issuance; dynamic scope narrowing requires reissuance (by design — immutable artifacts are simpler to audit)

---

## Alternatives Considered

### W3C Verifiable Credentials
Full VC compliance adds significant implementation complexity (DID resolution, JSON-LD context) with no Phase 3 customer demand. The passport format is intentionally VC-compatible in structure so we can wrap it later.

### JWTs
Standard JWT libraries would work but add a dependency and constrain the payload structure. Our canonical JSON + HMAC is functionally equivalent for this use case and keeps the codebase self-contained.

### Client-side signature verification
Would eliminate the verification endpoint call but requires distributing public keys to every verifier. Too complex for Phase 3. Revisit with asymmetric signing in Phase 4.

---

## Related

- ADR-001: TokenDNA Identity Backbone Architecture
- ADR-002: UIS Schema Evolution Strategy (Sprint 1-1)
- ADR-003: UIS Trust Graph Design (Sprint 1-2, planned)
- Sprint 3-2: Verifier Reputation Network (upgrades static trust scores to dynamic)
- Sprint 4-1: Attestation Portability Package (open-sources passport format as a spec)
