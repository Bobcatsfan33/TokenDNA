# Expansion Features Reference

The five primitives shipped in the expansion sprint, plus the salvage commit that anchors them. Each section: what it is, why it's a moat, the API surface, and where the code lives.

> **Status:** all five features are merged into `main` (or pending merge) as of the X-1..X-5 sprint commits stacked on PR #26 + follow-ups #27–#30. This doc tracks the *current* surface; commit history tracks the evolution.

---

## 0. Foundation: Commercial Tiers + Threat Sharing + Delegation Receipts

Salvage commit (`991c23d`) — three modules pulled across from a parallel branch.

### Commercial Tiers (`modules/product/commercial_tiers.py`)

Three tiers, six gates.

| Gate | Min tier | Used by |
|---|---|---|
| `ent.mcp_gateway` | enterprise | `/api/mcp/{verify,inspect,tools,violations,chain,gateway,fingerprint,anomaly}/*` |
| `ent.agent_discovery` | pro | `/api/discovery/*` |
| `ent.enforcement_plane` | enterprise | `/api/{enforcement,policy/guard,certs,policy/suggestions,delegation}/*` |
| `ent.behavioral_dna` | pro | `/api/{drift,behavioral,agent/drift}/*` |
| `ent.blast_radius` | enterprise | `/api/simulate/blast_radius*` |
| `ent.intent_correlation` | enterprise | `/api/intent/*`, `/api/threat-sharing/*` |

```python
from modules.product.commercial_tiers import require_feature

@app.post("/api/your_route")
async def handler(
    body: dict,
    tenant: TenantContext = Depends(require_feature("ent.X")),
):
    ...
```

A 403 from `require_feature` carries the structured upsell payload:

```json
{
  "error": "feature_not_entitled",
  "feature": "ent.blast_radius",
  "feature_name": "Blast Radius Simulator",
  "tenant_id": "...",
  "tenant_tier": "community",
  "required_tier": "enterprise",
  "message": "...",
  "upgrade_url": "/billing/upgrade"
}
```

The dashboard listens for this payload via `apiFetch`'s `tokendna:upsell` event and renders the `<UpsellModal />` automatically.

### Threat Sharing (`modules/product/threat_sharing.py`)

Cross-tenant, opt-in, strictly anonymized.

```
POST /api/threat-sharing/opt-in            tenant joins the network
POST /api/threat-sharing/publish/{id}      anonymize + share a custom playbook
POST /api/threat-sharing/sync              pull new network playbooks
GET  /api/threat-sharing/network           browse anonymized catalog
```

Source tenant id is **SHA-256 hashed** in the network catalog and never reversed. `anonymize_playbook` strips `tenant_id` / `agent_id` / `user_id` / IP fields and replaces them with stable per-playbook placeholders (`agent_A`, `user_B`); detection logic (`category`, `mitre_technique`, etc.) passes through verbatim.

### Delegation Receipts (`modules/identity/delegation_receipt.py`)

HMAC-SHA256-signed paper trail for agent delegation chains.

```
POST /api/delegation/receipt                          issue
GET  /api/delegation/receipt/{id}                     fetch
GET  /api/delegation/receipt/{id}/verify              re-derive signature + check expiry/revocation
GET  /api/delegation/chain/{id}                       walk root → leaf
GET  /api/delegation/receipts/{agent_id}              all active receipts for an agent
POST /api/delegation/receipt/{id}/revoke              cascade revoke (default cascade=true)
GET  /api/delegation/chain/{id}/report                signed liability report
```

`issue_receipt` enforces:
1. Root delegator must be `human:*`
2. Child `delegator_id == parent.delegatee_id` (you can only delegate authority you received)
3. Child scope ⊆ parent scope (with `*` and `ns:*` glob coverage)
4. Child cannot outlive parent

`revoke_receipt(cascade=True)` uses a recursive CTE to atomically revoke every descendant.

---

## 1. Network Effect Flywheel (`threat_sharing_flywheel.py`)

**The moat:** every confirmed match in any tenant raises the confidence score on the source playbook. New tenants make the catalog more accurate for everyone — competitors can copy the algorithm but not the dataset.

### Scoring formula

```
hit_component       = 1 - 1/(1 + confirmed_hits/3)
breadth_component   = min(distinct_tenants, BREADTH_SATURATION_TENANTS) / BREADTH_SATURATION_TENANTS
raw                 = 0.7 * hit_component + 0.3 * breadth_component
age_decay           = max(0, 1 - days_since_last_hit / (CONFIDENCE_HALF_LIFE_DAYS * 2))
confidence          = raw * age_decay
```

Defaults: `BREADTH_SATURATION_TENANTS=20`, `CONFIDENCE_HALF_LIFE_DAYS=180`.

### Industry digest

Tenants tag themselves with one of 11 industry verticals. The digest shows confirmed attacks against peers in the same vertical — excludes the requesting tenant via SHA-256 tenant hash so no raw IDs leak.

### Auto-subscribe

Opted-in tenants can flip `auto_subscribe=true` with a `min_confidence` threshold. `POST /api/threat-sharing/auto-sync` then pulls every network playbook above the threshold; below, it falls through to vanilla sync.

### API

```
POST /api/threat-sharing/network/{id}/hit            tenant logs a match
POST /api/threat-sharing/hits/{id}/confirm           operator confirms TP
GET  /api/threat-sharing/network/scored              scored catalog
GET  /api/threat-sharing/network/{id}/score          per-playbook score
POST /api/threat-sharing/industry                    set tenant industry
GET  /api/threat-sharing/industry/digest             vertical digest
POST /api/threat-sharing/subscription                set auto-subscribe
POST /api/threat-sharing/auto-sync                   threshold-aware sync
```

---

## 2. Workflow Attestation (`workflow_attestation.py`)

**The moat:** workflow-level identity is structurally harder than agent-level. Any competitor catching up has to rebuild trust graph + delegation receipts + per-agent attestation first.

### Concept

A workflow is a signed DAG of hops:

```python
hops = [
    {"actor": "agt-A", "action": "read",      "target": "doc",  "receipt_id": "rcpt:..."},
    {"actor": "agt-B", "action": "summarize", "target": "doc",  "receipt_id": "rcpt:..."},
]
```

`register_workflow` canonicalizes hops, computes a Merkle root, signs with HMAC-SHA256. The root is the workflow's stable identity — any deviation produces a different root.

### Replay

`replay_workflow` re-derives the signature, then re-verifies every linked delegation receipt via `delegation_receipt.verify_receipt`. A revoked or expired receipt at any hop flips `overall_valid` to false even when the workflow signature is intact.

### Drift

`record_observation(workflow_id, observed_hops)` compares observed runs against canonical. Drift surfaces extra hops, missing hops, and per-index field diffs. Adversarial agent insertion shows up as `observed_hops > canonical_hops` with the injected actor in `hop_diffs`.

### API

```
POST /api/workflow/register                           canonical chain
GET  /api/workflow                                    list
GET  /api/workflow/{id}                               fetch
POST /api/workflow/{id}/retire                        deactivate
GET  /api/workflow/{id}/replay                        per-hop verification
POST /api/workflow/{id}/observe                      record observation
GET  /api/workflow/{id}/observations?drift_only=...  drift list
```

---

## 3. Compliance Posture + Incident Reconstruction (`compliance_posture.py`)

**The moat:** long sales cycle to wire in, even longer to rip out. Once a Fortune 500 audit team accepts a TokenDNA posture statement as evidence, switching costs are enormous.

### Posture statements

```
POST /api/compliance/posture/{framework}/generate     pulls live metrics, signs, persists
GET  /api/compliance/posture/statements/{id}/verify   re-derive digest + signature
```

Frameworks supported: `soc2`, `iso42001`, `nist_ai_rmf`, `eu_ai_act`. Each control maps to a live metric collected from `permission_drift` / `policy_guard` / `intent_correlation` / `cert_dashboard` / `workflow_attestation` / `delegation_receipt` / `agent_lifecycle`. Collector failures degrade controls to fail-with-reason rather than crashing the statement.

> ⚠️ The control-to-metric mappings shipped here are **gestural**. Production deployment requires a compliance lawyer to confirm SOC 2 / NIST AI RMF / EU AI Act control coverage matches the regulatory text. Wire whatever they say.

Every statement carries:
- `evidence_digest` — SHA-256 of canonical evidence body
- `signature` — HMAC-SHA256 over `(statement_id, tenant_id, framework, digest, signed_at)`

`verify_posture_statement` re-derives both. Tampering with `controls_json` directly in SQLite produces a `digest_mismatch` on verify.

### Incident reconstruction

```
POST /api/compliance/incident/{agent_id}/reconstruct  build + sign dossier
```

Joins five best-effort sections — delegation receipts, intent matches, blast radius latest, drift events, policy-guard violations — into one structured report with its own `content_digest` + signature. Designed for direct PDF export to underwriters / litigators / auditors.

---

## 4. Honeypot Mesh (`honeypot_mesh.py`)

**The moat:** deception only works at multi-tenant scale. New entrants need a footprint before this surface means anything.

### Decoy classes

| Kind | Public ID format | What it traps |
|---|---|---|
| `synthetic_agent` | `agt-<hex>` | Reconnaissance — any traffic targeting an agent that no real workflow calls |
| `honeytoken_credential` | `htkn:<hex>` | Stolen API keys presented to any auth surface |
| `honeytoken_certificate` | `hcert:<hex>` | Replayed certs that look valid but are flagged revoked |

### Storage hardening

- `secret_value` visible **exactly once** on the creation response.
- Stored as `HMAC-SHA256(secret, server_secret)`. A leaked DB dump cannot be rainbow-tabled to recover plaintext; cross-tenant rainbow tables are infeasible because the salt is the server secret.
- `is_honeytoken(token)` hashes the input and looks up by hash only — no plaintext-comparison branch ever runs.

### Edge integration

`edge_enforcement.evaluate_runtime_enforcement` runs `_check_honeytokens` **before** cert verification, drift, or policy evaluation. A presented decoy never reaches those paths — timing and response shape don't reveal whether the value would have been real. Fail-open by design: if the honeypot module crashes, real auth still runs.

### API

```
POST /api/honeypot/decoy/synthetic-agent          mint a synthetic agent
POST /api/honeypot/decoy/honeytoken               seed a credential / certificate
GET  /api/honeypot/decoys                         inventory (secrets stripped)
POST /api/honeypot/decoys/{id}/deactivate         retire
POST /api/honeypot/hits/record                    typically called by edge
GET  /api/honeypot/hits                           open hits
POST /api/honeypot/hits/{id}/acknowledge          operator review
```

---

## 5. SDK Wedge (`tokendna_sdk/`)

**The moat:** developer mindshare. The other four are defensive (existing customer stickiness); the SDK is offensive (expand the customer universe). Once `from tokendna_sdk import identified` is in the developer's head, displacement is generational.

### One decorator

```python
from tokendna_sdk import identified, tool, configure

configure(api_base="...", api_key="...", tenant_id="...")

@identified("research-bot", scope=["docs:read"])
class ResearchAgent:
    @tool("fetch_doc", target="document")
    def fetch_doc(self, url: str) -> str: ...
```

Every method call now ships a UIS event under `research-bot`. The trace is recorded thread-local for later registration via `/api/workflow/register`.

### Offline-safe by design

Network failures buffer locally (memory by default; disk if `offline_buffer_path` is set). `Client.flush()` retries with re-buffering. **The decorator cannot fail your program**, even when TokenDNA is unreachable — that property is the wedge.

### CLI

```
tokendna config show                       # active config (key redacted)
tokendna policy plan ./bundle.json         # dry-run a policy bundle
tokendna policy apply <bundle_id>          # activate
tokendna replay <decision_id>              # replay a recorded decision
```

### Distribution

- Apache 2.0
- Zero runtime deps (`urllib` only)
- Python 3.9+
- `pip install tokendna-sdk` (after PyPI publish)
- `pip install tokendna-sdk[examples]` adds langchain
- `pip install tokendna-sdk[test]` adds pytest

---

## Ops surfaces shipped alongside

### Dashboard upsell modal

`dashboard/index.html` — the `apiFetch` wrapper dispatches a `tokendna:upsell` `CustomEvent` on any 403 with `detail.error === "feature_not_entitled"`. The `<UpsellModal />` listens and renders the upgrade CTA.

### Staged rollout / per-tenant allowlists

`modules/product/staged_rollout.py` + admin routes under `/api/admin/staged-rollout/`. Lets a tenant on `Plan.FREE` access an enterprise feature for design-partner / beta scenarios without changing their commercial plan. Audit-tracked, idempotent, fail-closed (allowlist outage cannot remove tier-based entitlement).

### Calibration harness for the flywheel

`scripts/flywheel_calibration.py` — synthetic-data simulator that lets operators tune `BREADTH_SATURATION_TENANTS` / `CONFIDENCE_HALF_LIFE_DAYS` against the false-positive rate they observe in production before flipping the auto-subscribe threshold. See the script header for usage.

---

## Outstanding work

Things explicitly deferred from this sprint, with the rationale:

| Item | Status | Reason |
|---|---|---|
| PG path implementations for the 9 new modules | Stubbed | One PR per module per the original review scope |
| Compliance control-to-regulation mappings | Gestural | Needs compliance lawyer review |
| Flywheel scoring parameter tuning | Default | Needs real false-positive data |
| Dashboard pages for new surfaces | Scaffolded | Manual click-through validation in next sprint |

Each is a tractable follow-up, not a structural unknown.
