# TokenDNA Engineering Handoff Guide

## Purpose

This document is a full handoff for continuing TokenDNA’s identity-first product strategy and six-slice moat expansion implementation. It is written so an engineer can continue without original author context.

---

## Current Strategic Direction (Implemented in Code)

TokenDNA is being built as:

1. **Open protocol + OSS distribution layer**
   - UIS schema/protocol endpoints
   - protocol adapters
   - CLI onboarding and integration adapters

2. **Managed trust/enforcement layer**
   - attestation lifecycle
   - certificate lifecycle + revocation
   - transparency log
   - runtime drift + ABAC enforcement

3. **Moat expansion layer**
   - cross-tenant anonymized threat intelligence feed
   - compliance evidence automation
   - auditable deterministic policy outcomes

---

## What Was Added In This Iteration (Six Slices)

### Slice 1 — Trust authority as verification network

Files:
- `modules/identity/trust_authority.py`
- `modules/identity/certificate_transparency.py`
- `modules/identity/attestation_certificates.py` (extended)
- `api.py` (certificate lifecycle + transparency endpoints)

Implemented:
- Pluggable signer abstraction with software/HSM backend switch:
  - `ATTESTATION_KEY_BACKEND=software|hsm`
  - HS256 default, RS256 path if RSA keys present
- Certificate lifecycle fields:
  - `signature_alg`, `ca_key_id`, `status`, `revoked_at`, `revocation_reason`
- Certificate transparency-style append-only log:
  - hash-chained entries
  - per-entry Merkle root
  - log integrity verification endpoint
- Runtime certificate revocation/status verification in `/secure`.

APIs:
- `GET /api/agent/certificates`
- `POST /api/agent/certificates/revoke`
- `GET /api/agent/certificates/transparency-log`
- `GET /api/agent/certificates/transparency-log/verify`

---

### Slice 2 — Data network effects

Files:
- `modules/identity/network_intel.py`
- `modules/identity/scoring.py` (extended)
- `api.py` (`/secure` + intel endpoints)

Implemented:
- Cross-tenant anonymized signal aggregation store.
- Runtime penalty assessment from observed signals.
- Auto-record high-risk runtime signals when request tier is BLOCK/REVOKE.
- Threat intel feed endpoints and TAXII-style export.

APIs:
- `GET /api/threat-intel/feed`
- `GET /api/intel/feed`
- `POST /api/intel/record`
- `POST /api/intel/assess`
- `GET /api/intel/feed/taxii`

---

### Slice 3 — UIS/attestation protocol standardization

Files:
- `modules/identity/uis_protocol.py`
- `api.py`
- `bin/tokendna-cli.py`

Implemented:
- Explicit UIS field set specification payload.
- Adapter inputs/contracts for OIDC/SAML/OAuth-introspection/SPIFFE/MCP.
- Adapter-based normalization endpoint.
- Attestation protocol spec endpoint.
- OSS CLI onboarding for UIS spec + normalization.

APIs:
- `GET /api/uis/spec`
- `POST /api/uis/adapters/normalize`
- `GET /api/attestation/spec`
- `GET /api/oss/onboarding`

CLI:
- `python3 bin/tokendna-cli.py uis-spec`
- `python3 bin/tokendna-cli.py normalize ...`

---

### Slice 4 — Deep runtime enforcement

Files:
- `modules/identity/abac.py`
- `api.py` (`/secure` policy path + explicit ABAC evaluation endpoint)

Implemented:
- Deterministic attestation-aware ABAC decision engine:
  - risk-tier checks
  - certificate validity checks
  - drift checks
  - scope checks
- Inline `/secure` policy actioning:
  - allow / step_up / block
  - auditable policy trace

API:
- `POST /api/abac/evaluate`

---

### Slice 5 — Compliance automation moat

Files:
- `modules/identity/compliance.py`
- `api.py`

Implemented:
- Framework control maps for:
  - DISA STIG
  - FedRAMP
  - eMASS
- Evidence package generation from live platform telemetry counts:
  - UIS events
  - attestations/certs/revocations
  - drift events
  - threat signals
- Persistent package storage and retrieval.

APIs:
- `GET /api/compliance/frameworks`
- `GET /api/compliance/controls/{framework}`
- `POST /api/compliance/evidence/generate`
- `GET /api/compliance/evidence/packages`

---

### Slice 6 — OSS distribution + integrations

Files:
- `bin/tokendna-cli.py`
- `modules/integrations/siem_taxii.py`
- `modules/integrations/idp_events.py`
- `modules/integrations/__init__.py`
- `api.py`

Implemented:
- OSS onboarding endpoint and CLI.
- STIX/TAXII feed bundle conversion for SIEM/SOAR ingestion.
- IdP event adapters (Okta + Entra) into UIS flow.
- Integrations catalog endpoint for developers/partners.

APIs:
- `POST /api/integrations/idp/normalize`
- `GET /api/integrations/catalog`

---

## Runtime/Platform Flow (How It Works Now)

1. `/secure` computes behavioral + threat + session graph score.
2. Network-intel feed penalties are applied in scoring.
3. UIS event is normalized and persisted.
4. For agent requests (`x-agent-id`):
   - fetch latest attestation baseline
   - optionally verify certificate (`x-agent-certificate-id`)
   - compute drift
   - persist drift events
   - evaluate ABAC policy and enforce outcome
5. High-risk outcomes feed anonymized network-intel data.
6. Cert issuance/revocation writes transparency log entries.

---

## Environment/Config Inputs Added

Primary new env vars:
- `ATTESTATION_CA_ALG` (`HS256`/`RS256`)
- `ATTESTATION_CA_PRIVATE_KEY_PEM`
- `ATTESTATION_CA_PUBLIC_KEY_PEM`
- `ATTESTATION_CA_SECRET`
- `ATTESTATION_CA_KEY_ID`
- `ATTESTATION_KEY_BACKEND` (`software`/`hsm`)
- `NETWORK_INTEL_HASH_SALT`
- `DATA_DB_PATH`

---

## Recommended Next Steps (If Continuing Tomorrow)

### P0 (next)
1. Replace `MockHSMTrustSigner` with real KMS/HSM adapters (AWS KMS, CloudHSM, Azure Key Vault HSM).
2. Add pagination/cursor APIs for:
   - transparency log
   - intel feed
   - drift events
3. Add signature verification against historical key IDs (`ca_key_id`) to support key rotation windows.

### P1
1. Edge enforcement parity:
   - mirror cert+attestation checks in Cloudflare Worker for early-block SLO.
2. Policy-as-code:
   - externalized ABAC rules with versioning and signed policy bundles.
3. Compliance outputs:
   - machine-readable eMASS export packages
   - evidence attestation signatures.

### P2
1. True standards publication:
   - publish UIS/attestation versioned schema docs in repo
   - add migration guide and compatibility tests.
2. Ecosystem SDKs:
   - JS/Python SDK wrappers for UIS and attestation APIs.

---

## Engineering Guardrails

1. Keep runtime enforcement deterministic and auditable (no opaque policy decisions).
2. Keep open protocol layers stable and backwards compatible.
3. Keep proprietary moat in data, trust authority operations, and managed enforcement.
4. Every new security decision path must emit audit and explainable policy trace.

---

## Quick “Pick Up Where Left Off” Checklist

1. Pull branch and install deps:
   - `python3 -m pip install -r requirements.txt pytest`
2. Run tests:
   - `python3 -m pytest -q`
3. Inspect key modules:
   - `modules/identity/trust_authority.py`
   - `modules/identity/certificate_transparency.py`
   - `modules/identity/network_intel.py`
   - `modules/identity/abac.py`
   - `modules/identity/compliance.py`
   - `modules/identity/uis_protocol.py`
4. Validate endpoint behavior in `api.py` around:
   - certificate lifecycle + transparency
   - `/secure` enforcement path
   - intel/compliance/integration endpoints

---

## Intent Summary

The product intent is to make TokenDNA the **identity trust substrate for agentic systems**:
- open protocol for distribution,
- managed trust authority for revenue,
- data network effects for widening moat,
- deterministic runtime enforcement for enterprise trust.

