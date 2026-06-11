# Security Policy — Aegis Security Platform

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (master) | ✅ |
| Older releases  | ❌ — upgrade to latest |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

All security reports go to: **ryanwallac33@gmail.com**

Subject line: `[AEGIS SECURITY] <brief description>`

Please include:
- Description of the vulnerability
- Steps to reproduce (proof-of-concept if available)
- Affected component(s) and version
- Potential impact assessment
- Your contact information for follow-up

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix development | Severity-dependent (see below) |
| Public disclosure | Coordinated with reporter |

### Severity-Based Fix Timeline

| CVSS | Severity | Target Fix |
|------|----------|------------|
| 9.0–10.0 | Critical | 24–72 hours |
| 7.0–8.9  | High     | 7 days |
| 4.0–6.9  | Medium   | 30 days |
| 0.1–3.9  | Low      | 90 days |

## Security Design Principles

Aegis Security is **designed toward FedRAMP High and DoD IL4+** authorization; IL5/IL6 remain roadmap targets reachable via the customer-managed federal build. Implemented posture is tracked in [`compliance/dod/control_matrix.json`](compliance/dod/control_matrix.json). Our security principles:

1. **Zero trust by default** — no implicit trust between components
2. **Least privilege** — RBAC enforced at every API endpoint
3. **Immutable audit trail** — all security events are hash-chained and tamper-evident
4. **Secrets never in code** — all secrets via environment variables or AWS Secrets Manager
5. **Defense in depth** — security controls at edge (Cloudflare Worker), API (FastAPI middleware), and data tier
6. **Open standards only** — no proprietary security vendor lock-in

## Known Security Limitations (Current)

These are documented gaps on our path to full FedRAMP High / IL4+ authorization (IL5/IL6 deployment profiles remain roadmap targets). The **Closed by** column links each gap to the workstream that remediates it.

| Limitation | Status | Closed by |
|------------|--------|-----------|
| **FIPS 140-3 validated cryptography** — runtime `FIPSEnforcer` ships, but the validated OpenSSL provider was not delivered as a build flavor | Closing | **T-3** — `Dockerfile.fips` (UBI9 CMVP-validated OpenSSL) + fail-closed `assert_fips_mode()` startup gate + `fips-smoke` CI job |
| **mTLS between internal services** — application-layer mTLS shipped for Redis/ClickHouse/Postgres; the internal API plane and SPIFFE-style peer authorization were not enforced | Closing | **T-2** — `:8443` mutual-TLS listener + `require_internal_peer` SAN allowlist + cert-manager `internal-pki.yaml` rotation |
| **Scope-based authorization** — RBAC roles enforced at every endpoint, but per-route OAuth scopes (least privilege) were not | Closing | **T-4** — `modules/auth/scopes.py` `require_scopes()`, log-only rollout then enforce |
| **CAC/PIV authentication** | Open | Planned v3.0 (government edition) |
| **Encryption at rest** | Operator-configured | Field-level crypto shipped (`modules/security/field_crypto.py`); data-tier volume encryption remains operator responsibility |
| **Full ABAC** | Open | Planned v3.0; scope-based authorization (T-4) is the intermediate step |

## Dependency Security

We use GitHub Dependabot for automated dependency vulnerability scanning. Security patches are prioritized over feature development.

Run a local dependency audit:
```bash
pip install pip-audit
pip-audit -r requirements.txt
```

## Responsible Disclosure

We follow coordinated vulnerability disclosure. We will credit researchers who report valid vulnerabilities (unless anonymity is requested).

We will not pursue legal action against researchers who:
- Act in good faith
- Do not access, modify, or exfiltrate production data
- Report findings before public disclosure
- Allow reasonable time for remediation
