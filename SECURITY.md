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

Aegis Security is built toward **FedRAMP High** and **DoD IL6** authorization. Our security principles:

1. **Zero trust by default** — no implicit trust between components
2. **Least privilege** — RBAC enforced at every API endpoint
3. **Immutable audit trail** — all security events are hash-chained and tamper-evident
4. **Secrets never in code** — all secrets via environment variables or AWS Secrets Manager
5. **Defense in depth** — security controls at edge (Cloudflare Worker), API (FastAPI middleware), and data tier
6. **Open standards only** — no proprietary security vendor lock-in

## Known Security Limitations (Current)

These are documented gaps on our path to full FedRAMP High / IL6 authorization:

- **FIPS 140-2 validated cryptography**: Not yet enforced platform-wide. Planned for v2.3.
- **CAC/PIV authentication**: Not yet supported. Planned for v3.0 (government edition).
- **Encryption at rest**: Data tier (Redis, ClickHouse) requires operator-configured encryption. Platform does not enforce this automatically.
- **mTLS between services**: Not yet enforced for internal service-to-service calls. Planned for v2.3.
- **RBAC**: Basic implementation in v2.2; full ABAC (attribute-based) access control planned for v3.0.

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
