# TokenDNA — Runtime Risk Engine for Agentic AI

**Federal procurement summary · v1.0 · 2026-04**

> Existing identity vendors verify *that* an AI agent authenticated.
> TokenDNA verifies *whether the action is what the agent claims it is*,
> *whether the chain of actions is consistent with the agent's intent*, and
> *whether the cross-organization handshake has authority to act* — at
> runtime, in <100 ms, with FIPS 140-2 Level 3 cryptographic foundation.

---

## Three RSA 2026 gaps TokenDNA closes

| # | Gap                                            | What no major vendor catches today                                                                          | TokenDNA control                                                                                                  |
|---|------------------------------------------------|-------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| 1 | **Agent self-modification of policy**          | An agent silently expands its own permission scope mid-session; IAM policy unchanged.                       | `policy_guard` `CONST-01`: BLOCK any action whose subject equals its actor; `POLICY_SCOPE_MODIFICATION` (CRITICAL) anomaly written to the trust graph. |
| 2 | **Silent permission drift**                    | Tools allowed last quarter for one purpose are now called for another; auth event identical, behavior 3× different. | `permission_drift` baseline + growth-factor detector; `PERMISSION_WEIGHT_DRIFT` (HIGH) on >2× scope expansion without an attestation event. |
| 3 | **MCP chain-pattern attacks**                  | `read_file → send_email` — each call individually allowed, the chain is exfiltration.                       | `mcp_inspector` bounded-gap subsequence matcher; `MCP_CHAIN_PATTERN_MATCHED` with confidence; BLOCKs the second call before dispatch. |

---

## NIST 800-53 Rev 5 control mapping (excerpt)

| Control      | Coverage                                                                                                |
|--------------|--------------------------------------------------------------------------------------------------------|
| **AC-3**     | ABAC enforcement on every agent action with auditable trace.                                            |
| **AC-6 (5)** | High-Value Identity Profiles (HVIP) for OWNER/ADMIN identities; least-privilege via attestation scope.  |
| **AU-2 / AU-12** | Hash-chained certificate transparency log; OSCAL/eMASS evidence package generator.                  |
| **AU-9**     | Tamper-evident Merkle log; verifiable per-tenant integrity.                                             |
| **IA-2 (1) / IA-2 (6)** | MFA assertion enforcement on all privileged identities in IL5 mode.                          |
| **IA-3**     | Machine identity attestation records signed by KMS / CloudHSM CMK.                                      |
| **IA-5 (1)** | Cryptographic token binding (RFC 9449 DPoP); short-lived attestation certs with revocation.            |
| **IA-7**     | FIPS 140-2 algorithm enforcement; HS256/SHA-1/MD5/RC4 blocked at JWT verification.                     |
| **SC-13**    | FIPS 140-2 mode runtime enforcement; FATAL startup gate in IL5/IL6.                                     |
| **SC-28**    | AES-256-GCM data-at-rest encryption (application-level + transparent disk).                             |
| **SI-4**     | Continuous drift monitoring + anonymized cross-tenant threat-intel feed.                                |

---

## Architecture (deployment options)

```
              ┌───────────────────────────────────────────────────────┐
              │                  Cloudflare Workers                   │
              │  JWT + DPoP + cert-revocation cache + drift cache     │
              │  (FedRAMP Mod / High-friendly external surface)       │
              └───────────────────┬───────────────────────────────────┘
                                  │ mTLS (internal CA / Vault PKI / ACM-PCA)
                                  ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │                       FastAPI / uvicorn                             │
   │  policy_guard · policy_advisor · trust_graph · mcp_inspector        │
   │  attestation_certificates · workflow_attestation · federation       │
   │  compliance_posture · blast_radius · permission_drift               │
   └──────────────┬─────────────────────────┬────────────────────────────┘
                  │ mTLS                    │ mTLS
                  ▼                         ▼
        ┌─────────────────┐       ┌──────────────────────┐
        │  Postgres 16    │       │  Redis 7 (Sentinel/  │
        │  (TDE / EBS at  │       │   Cluster)           │
        │   rest)         │       └──────────────────────┘
        └─────────────────┘
                  ▲
                  │  KMS Sign / Verify (FIPS-2)
                  │  CloudHSM Sign / Verify (FIPS-3)  ◄── IL5
                  │
        ┌─────────────────┐
        │  Trust Authority│
        │  CA private key │
        │  NEVER leaves   │
        │  the boundary   │
        └─────────────────┘
```

**Deployment footprint**

| Mode             | Where it runs                                       | Customers                                  |
|------------------|-----------------------------------------------------|--------------------------------------------|
| SaaS multi-tenant| TokenDNA-managed Cloudflare + AWS                   | Commercial / FedRAMP Mod                   |
| Hosted single-tenant | TokenDNA-managed but isolated VPC + KMS        | FedRAMP High                               |
| On-prem          | Customer-managed Kubernetes (Helm chart shipped)    | DoD IL4-IL6, ITAR, sovereign cloud         |
| Hybrid edge      | Cloudflare-hosted enforcement + customer backend    | Mixed                                      |

---

## Compliance & FIPS posture

| Boundary                       | Module                                       | FIPS / control                       |
|---------------------------------|----------------------------------------------|--------------------------------------|
| Attestation cert signing — comm.| `AWSKMSTrustSigner`  (boto3 KMS Sign)        | FIPS 140-2 **Level 2** (KMS service) |
| Attestation cert signing — IL5  | `CloudHSMTrustSigner` (KMS CKS → CloudHSM)   | FIPS 140-2 **Level 3** (HSM cluster) |
| At-rest column encryption       | `field_crypto` (AES-256-GCM via Fernet)      | NIST SP 800-38D                      |
| In-transit (internal)           | `modules.security.mtls`                      | TLS 1.3 mTLS, X.509 client certs     |
| In-transit (external)           | DPoP RFC 9449 + JWT RS256/PS256/ES256        | FIPS-approved JWA only in IL4+       |
| Audit log                       | `certificate_transparency` Merkle chain      | AU-9 tamper-evident                  |

---

## Commercial tiers

| Tier        | Throughput / retention             | Notable features                                                  | Target                       |
|-------------|------------------------------------|-------------------------------------------------------------------|------------------------------|
| Community   | Self-host                          | UIS + drift + policy guard + transparency log                     | Evaluation / OSS adopters    |
| Starter     | 1k agents · 30-day retention        | Multi-tenant, SOC 2 evidence packages                              | SMB / fintech                |
| Pro         | 10k agents · 90-day                 | + MCP inspector + chain patterns + federation + cross-org trust    | Enterprise / commercial      |
| Enterprise  | Unlimited · multi-region · SLA     | + KMS/CloudHSM signers + IL5/IL6 deployment + dedicated on-call    | DoD / IC / FedRAMP High      |

---

## Procurement attachments (request via your AE)

- **NIST 800-53 Rev 5 control matrix** — full mapping with evidence pointers per control.
- **DISA STIG checklist** — pre-filled against current build (auto-generated by `compliance.generate_evidence_package`).
- **eMASS XML / OSCAL package** — automated export from the same control map.
- **SBOM** — committed to repo (`sbom.json`).
- **Vulnerability disclosure policy + private reporting** — enabled at `https://github.com/Bobcatsfan33/TokenDNA/security/advisories`.
- **Penetration test report** — last quarter's report available under NDA.
- **Insurance** — $5M E&O + $5M Cyber, certificate available.

---

## Contact

| | |
|---|---|
| **Federal sales** | federal@tokendna.io |
| **Channel partners** | Carahsoft · Epoch Concepts · FCN |
| **Vulnerabilities** | https://github.com/Bobcatsfan33/TokenDNA/security/advisories |
| **General** | hello@tokendna.io |
