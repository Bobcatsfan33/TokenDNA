# TokenDNA — External Engagements (Pen-Test & Compliance)

_Status: scope spec — vendor selection happens before the first paid pilot._

These engagements are required gates between a "GA-ready" build and the
first revenue-bearing tenant. They are external because nothing in this
repository can self-attest to either control:

* Pen-testing must be done by an independent firm with no commit access.
* Compliance attestations must be signed by counsel or an accredited
  auditor — not by an engineer.

---

## 1. External penetration test

### Scope

| Surface | In scope? | Notes |
|---------|----------|-------|
| FastAPI public routes (`api.py`) | Yes | All `/api/*` endpoints, including auth bypass attempts. |
| Dashboard (`dashboard/`) | Yes | XSS, CSRF, auth, IDOR. |
| HMAC signing & verification paths | Yes | Forging delegation receipts, workflow attestations, posture statements, honeytokens. |
| Cross-tenant isolation | Yes | Leakage between `tenant_id` in queries, threat sharing anonymization. |
| Demo seed data | No | Seed fixtures are demo-only. |
| Customer infrastructure | No | Outside our service boundary. |

### Required tests

1. **Auth & session**: OIDC issuer trust, JWT replay, DPoP binding bypass.
2. **Tenant isolation**: cross-tenant resource access via crafted IDs and
   subscription paths in threat-sharing.
3. **HMAC forgery**: published dev defaults must fail closed in prod.
4. **Replay & freshness**: rate-limited endpoints, idempotency keys, nonce
   reuse on workflow attestations.
5. **Injection**: SQL/JSON path injection across recursive CTE traversal.
6. **Cryptographic agility**: misuse of HS256 where RS256 is required;
   FIPS mode regressions.
7. **Honeypot & deception**: detection-evasion paths; verifying no
   exfiltration of synthetic credentials marks them safe.

### Deliverables

* Findings letter signed by lead tester, mapped to OWASP ASVS L2.
* CVSS-scored issue list with reproduction steps.
* Retest letter after we land remediations.
* Attestation suitable for SOC-2 Type II evidence.

### Vendor expectations

* Independence: no current or former TokenDNA employees on the engagement.
* Insurance: at least $5M E&O.
* CREST or equivalent certification.
* Willingness to operate against a staging tenant with seed data we
  control — not the public demo.

---

## 2. Compliance counsel review

### Why outside counsel

We make claims that imply legal duties — "GDPR-compatible", "SOC-2
controls", "tamper-evident audit log". Engineering can implement controls
but cannot self-certify their legal sufficiency.

### Engagement scope

1. **Data residency & GDPR**: Article 28 processor obligations, lawful
   basis for cross-border threat sharing, data subject access flow.
2. **SOC-2 mappings**: validate that `modules/identity/compliance_posture.py`
   framework labels (`SOC2`, `ISO27001`, `EU_AI_ACT`) match what we can
   actually evidence.
3. **EU AI Act (Article 14)**: human-in-the-loop drift review claims.
4. **License compliance**: BUSL-1.1 + dependency license inventory.
5. **Customer DPAs**: standard data processing addendum template.

### Deliverables

* Memo on each scope item, citing the relevant statute / framework
  control.
* DPA template + data-flow diagram approved for use with EU customers.
* Sign-off letter we can show prospective enterprise buyers.

---

## 3. Sequencing

```
PR-A (this) ──► assert_production_secrets() merged
                │
                ▼
        Preflight script gates deploy   ──► First paid pilot blocked here
                │
                ▼
   ┌────── External pen-test ──────┐
   │                                │
   ▼                                ▼
Compliance counsel              SOC-2 Type I observation period (90d)
review
   │                                │
   └─────────────► GA ◄─────────────┘
```

Neither engagement may be skipped or shortened by Engineering. Both are
contractual prerequisites for the GA tier in `commercial_tiers.py`.
