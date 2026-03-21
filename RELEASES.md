# Aegis Security Platform — Release Roadmap

---

## ✅ v2.0.0 — Core Engine (Current)
*The foundational detection layer.*

- TokenDNA behavioral fingerprinting (SHA-256 device + IP + geo DNA)
- Adaptive ML scoring model per user — Redis-backed, 7 weighted signals
- Session graph: impossible travel (Haversine) + session branching detection
- Threat intelligence: live Tor exit nodes, datacenter ASNs, VPN heuristics, AbuseIPDB
- Unified risk tier engine: ALLOW / STEP_UP / BLOCK / REVOKE
- Risk-adaptive FastAPI responses (200 / 202 / 403 / 401)
- Full RFC 9449 DPoP proof-of-possession at Cloudflare edge
- OIDC/JWKS JWT verification with key rotation support
- ClickHouse event store — 90-day TTL, 21-column schema
- HMAC-signed SIEM webhook + Slack alerting
- Docker + docker-compose full stack deployment

---

## ✅ v2.1.0 — Shippable Product (This Release)
*Everything needed to sell this to a first customer.*

**Multi-Tenant Control Plane**
- API key authentication (`X-API-Key` header) — SHA-256 hashed, never stored in plaintext
- Tenant isolation: all Redis keys namespaced by `t:{tenant_id}:`, ClickHouse partitioned by tenant
- SQLite-backed tenant store (swap to PostgreSQL via `DATA_DB_URL` env var)
- Admin REST API: create tenants, rotate API keys, revoke keys
- Per-tenant plan tiers: Free / Starter / Pro / Enterprise

**Admin Web Dashboard** (`GET /dashboard`)
- Dark-themed React SPA served directly by FastAPI (zero separate deploy)
- Real-time event feed with risk tier badges and score bars
- 24h event volume chart (stacked area: ALLOW / BLOCK / REVOKE)
- Threat signal breakdown (Tor, impossible travel, datacenter ASN, VPN, branching, AbuseIPDB)
- Session intelligence table with per-user risk profiles
- Cloud posture scan results (severity by category)
- AWS account onboarding wizard (5-minute guided flow)
- Tenant management (create, list, API key management)
- System health panel (Redis, ClickHouse, Tor list, Cloudflare edge)

**AWS Account Onboarding (< 10 minutes)**
- One-click CloudFormation template: deploys `AegisScanRole` (read-only) + optional `AegisRemediationRole`
- Cross-account STS AssumeRole with ExternalId (prevents confused-deputy attacks)
- Connection test endpoint: validates all permission categories before saving
- Quick posture scan: IAM root MFA, users without MFA, public S3 buckets, exposed security group ports
- One-click launch URL pre-populates ExternalId and account ID in CloudFormation console

**Cloudflare Workers Marketplace**
- `wrangler.toml` with staging + production environments
- KV namespace bindings for revocation list + DPoP nonce store
- Secret management (`wrangler secret put`) — no credentials in source control
- Ready for Cloudflare Workers Integrations marketplace submission

---

## 🔜 v2.2.0 — Growth Features
*Q3 2026 — the features that turn a trial into a contract.*

**RBAC (Role-Based Access Control)**
- Roles: `owner`, `admin`, `analyst`, `readonly`
- UI role assignment per tenant
- Endpoint-level permission checks

**Audit Log**
- Immutable log of every API call, config change, and remediation action
- Stored in ClickHouse with tenant isolation
- Exportable as CSV or NDJSON for compliance reviews
- `GET /admin/audit` paginated API

**Automated Reporting**
- Weekly PDF risk summary per tenant (auto-emailed)
- On-demand SOC 2 evidence package: control test results, user access log, anomaly summary
- Finding trend charts: MTTR (mean time to remediate), risk score trajectory

**Notification Channels**
- PagerDuty integration for REVOKE/BLOCK events (severity-mapped)
- Microsoft Teams webhook (alongside existing Slack)
- Email alerts via SMTP or SendGrid
- Configurable alert rules: "only alert if Tor + score < 20" etc.

**CI/CD Pipeline Integration**
- GitHub Actions workflow: run TokenDNA token validation in PR checks
- Pre-commit hook: scan IAM policy changes for privilege escalation before push
- Terraform plan interceptor: flag security regressions before `apply`

---

## 🔜 v3.0.0 — Platform
*Q1 2027 — unified control plane, AI-native workflows.*

**Unified Aegis + TokenDNA Control Plane**
- Single pane of glass: cloud posture + identity security on one dashboard
- Correlated events: "compromised host X → token theft from user Y" connected automatically
- Cross-signal remediation: Aegis isolates the host AND TokenDNA revokes the token in one action

**AI Remediation Co-pilot** *(building on Aegis agentic loop)*
- Natural language query: *"show me all Tor-exit REVOKE events from Russia last 72h"*
- AI-suggested remediation playbooks per finding type
- Human-in-the-loop approval UI: one click to approve or reject each AI-proposed action
- Playbook editor: define custom remediation sequences (e.g., "if impossible travel from country not in allowlist → BLOCK + notify manager")

**Kubernetes Operator**
- `kubectl apply -f aegis-operator.yaml` deploys the full stack to any K8s cluster
- CRD: `AegisScan`, `TokenDNAPolicy`
- Automatic secret injection via Kubernetes Secrets or Vault

**Compliance Module**
- SOC 2 Type II control mapping: auto-generates evidence for CC6, CC7, CC8, CC9
- ISO 27001 Annex A control mapping
- GDPR Article 32: technical security measure documentation
- One-click compliance report generation (PDF, DOCX)

**Threat Intelligence Feed**
- Proprietary blocked IP/ASN database (built from aggregated customer telemetry, anonymized)
- Industry-specific threat models: fintech vs. SaaS vs. healthcare risk profiles
- IP reputation score API: monetizable as a standalone data product

**Marketplace Integrations**
- Splunk App: native search commands (`| tokendna user=X`)
- Elastic SIEM integration: pre-built detection rules
- Wazuh integration: active response module
- Okta Workflows: TokenDNA risk score as step in Okta authentication pipeline
- Cloudflare Workers Marketplace (TokenDNA edge as managed integration)

**Mobile**
- iOS + Android app for CISO / security team: real-time push for REVOKE events
- Biometric-gated remediation approval (approve/reject from phone)

---

## 💡 Future Bets (Unscheduled)

**Behavioral Biometrics Layer**
- Beyond device/IP/geo: typing cadence, mouse movement, scroll velocity
- Browser-native collection via JS snippet (< 2KB)
- Detects account sharing and session hijacking that geo/IP signals miss

**Federated Threat Intelligence**
- Opt-in: share anonymized threat signals with the Aegis network
- Network effect: the more customers, the better the threat model for everyone
- Monetizable: sell the aggregated feed as a standalone API

**TokenDNA as a Standalone API Product**
- Simple REST API: POST a token + user context → get a risk score + tier
- Usage-based pricing: $X per 10k requests
- Cloudflare Workers marketplace listing
- Postman collection, SDK for Node.js / Python / Go / Java

**Zero-Knowledge Tenant Mode**
- Cryptographic guarantee that Aegis never sees plaintext user IDs or IPs
- For healthcare (HIPAA) and finance (GLBA) customers with strict data residency
