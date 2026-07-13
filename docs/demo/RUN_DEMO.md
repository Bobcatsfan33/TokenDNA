# TokenDNA — How to Spin Up the Demo

End-to-end walkthrough for running the TokenDNA Runtime Risk Engine demo on a fresh machine. Two paths covered:

- **A. Seeded demo** — for sales meetings and evaluations. Fresh deployment with 30 days of synthetic-but-realistic operational history; live attack arc plays out against that backdrop.
- **B. Shadow Mode trial** — for prospects who want to see TokenDNA against THEIR data. Read-only ingestion of customer audit logs for 14 days; trial report at the end.

Both paths assume a Mac/Linux host with Python 3.11+ and `git`. No Postgres, Redis, or external services required for the demo path; everything runs against SQLite.

---

## Pre-flight (one time)

```bash
# Clone
git clone https://github.com/Bobcatsfan33/TokenDNA.git tokendna
cd tokendna

# Python deps — uses a venv to avoid polluting system python.
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Sanity check — should print test count + green.
python -m pytest -q
```

You should see `~1670 passed`. If not, stop and fix your environment before continuing.

---

## A. Seeded demo (recommended for sales)

### Step A1 — Seed 30 days of operational history

```bash
# Pick a writable DB path the demo will use.
export DATA_DB_PATH=/tmp/tokendna-demo.db
rm -f "$DATA_DB_PATH"   # start clean — the seeder is idempotent but a fresh DB is fastest

# Seed.
python scripts/demo_seed_v2.py
```

Output ends with a summary similar to:

```
  ✓ tenants:             acme, beta
  ✓ agents:              70  (50 acme + 20 beta)
  ✓ uis_events:          71,704
  ✓ drift_observations:  16
  ✓ policy_violations:   5
  ✓ policy_suggestions:  5
  ✓ honeytokens:         8
  ✓ federation_trusts:   1
  ✓ attack_chain_traces: 79
```

**What this gives you:**
- 50 Acme agents + 20 Beta agents organized into realistic archetypes (admin, finance, data-loader, support, engineering, ops, plus 2 deliberately drifty agents).
- 30 days of UIS events with diverse IP/ASN/geo distribution (drawn from `data/demo_fixtures/geo_samples.json`).
- Pre-existing policy_guard violations (open + approved + rejected) and policy_advisor suggestions — the dashboard is never empty on first land.
- Acme ↔ Beta federation trust already established.
- Honeytokens planted with realistic names (`finance-vault-token-Q4`, etc).
- Historical attack chain traces tagged with real MITRE ATT&CK technique IDs.

### Step A2 — Boot the API

```bash
# Same shell or a new one — make sure DATA_DB_PATH is exported.
export DATA_DB_PATH=/tmp/tokendna-demo.db
export DEV_MODE=true                 # bypasses auth for demo simplicity
export ATTESTATION_CA_SECRET=demo-secret-for-attestation-bundle-32b
# DEV_TENANT_ID defaults to "acme" (the seeded tenant).  Override only if you
# point the API at a different tenant's data.
# export DEV_TENANT_ID=acme
uvicorn api:app --host 127.0.0.1 --port 8000
```

Wait for `Application startup complete`. The dashboard is at:

```
http://127.0.0.1:8000/dashboard/
```

Open it. You should immediately see populated widgets — agent count, recent violations, drift alerts, federation status — not empty placeholders.

### Step A3 — Run the live demo arc

In a new terminal:

```bash
cd tokendna
source .venv/bin/activate
python scripts/demo_runtime_risk_engine.py
```

This walks through 10 scenes against the seeded backdrop:

**Act 1 — Intra-org Runtime Risk Engine (~6 min)**

| Scene | What happens | What to show |
|---|---|---|
| 1. Baseline | Innocuous activity recorded | Dashboard volume widget ticking up |
| 2. Drift | Permission scope grows >2x without attestation | `permission_drift` alert fires; growth_factor visible |
| 3. Self-mod | Agent modifies its own policy | `POLICY_SCOPE_MODIFICATION` (CRITICAL) in trust graph; policy_guard BLOCKs |
| 4. MCP chain | Agent reads sensitive file then sends_email within session | `MCP_CHAIN_PATTERN_MATCHED` with `read_then_exfil` confidence ~1.0 |
| 5. Deception | Agent trips a honeytoken decoy | Honeypot hit recorded |
| 6. Blast radius | Operator simulates blast for the agent | Live anomalies + MCP violations attached to result, not just topology |
| 7. Verdict | Policy advisor synthesizes a tightening suggestion | Suggestion appears in dashboard; operator approves it |

**Act 2 — Federated Agent Trust (~3 min)**

| Scene | What happens | What to show |
|---|---|---|
| 8. Federation | Beta initiates handshake to Acme; Acme accepts | New federation trust in the dashboard |
| 9. Cross-org without trust | Acme agent attempts action on Beta with no `federation_trust_id` | `CONST-06` BLOCKs in policy_guard; `CROSS_ORG_ACTION_WITHOUT_HANDSHAKE` (CRITICAL) in trust graph |
| 10. Cross-org WITH trust | Same action retried with the established trust_id | ALLOW disposition |

After the script completes, refresh the dashboard — every widget should show fresh activity from the arc layered on top of the seeded baseline.

### Step A4 — Replay (idempotent)

The arc script uses unique run-tag IDs so it can be re-run against the same instance without polluting prior demo state:

```bash
python scripts/demo_runtime_risk_engine.py
```

The seeder is also re-runnable (purges prior demo-tenant state first):

```bash
python scripts/demo_seed_v2.py
```

### Step A5 — Tier-gate verification matrix

The demo arc exercises the following gates. To verify they enforce correctly during a sales call, downgrade the demo tenant:

| Tier gate | Module | Scene that exercises it |
|---|---|---|
| `ent.blast_radius` | `blast_radius` | 6 |
| `ent.intent_correlation` | `intent_correlation` | 4, playbook seeds |
| `ent.enforcement_plane` | `policy_guard`, `policy_advisor` | 3, 7, 9, 10 |
| `ent.behavioral_dna` | `permission_drift` | 2 |
| `ent.mcp_gateway` | `mcp_inspector` | 4 |
| `ent.federation` | `federation` | 8, 9, 10 |

A `community`-tier tenant should see 403s with structured upgrade payloads on every gated endpoint. An `enterprise`-tier tenant should see no 403s.

---

## B. Shadow Mode trial (for prospect evaluations)

Goal: prove TokenDNA value against the prospect's REAL audit logs without taking any enforcement action.

### Step B1 — Activate shadow mode

```bash
export TOKENDNA_SHADOW_MODE=true
export DATA_DB_PATH=/tmp/tokendna-trial.db
rm -f "$DATA_DB_PATH"
```

### Step B2 — Build a connector mapping for the prospect's data

The shadow mode framework ships `FileTailJSONLConnector` — give it any newline-delimited JSON file (CloudTrail export, GitHub audit log, Okta system log dump) and a Python mapping function from their fields to TokenDNA's UIS event schema.

Minimal example for a prospect using AWS CloudTrail:

```python
from modules.product.shadow_mode import FileTailJSONLConnector

def cloudtrail_to_uis(row: dict) -> dict | None:
    if row.get("eventSource") != "iam.amazonaws.com":
        return None
    user = (row.get("userIdentity") or {})
    return {
        "uis_version": "1.0",
        "event_id": row["eventID"],
        "event_timestamp": row["eventTime"],
        "identity": {
            "entity_type": "machine",
            "subject": user.get("arn", "unknown"),
            "tenant_id": "prospect-acme",
            "tenant_name": "Prospect Acme Inc",
            "machine_classification": "agent",
            "agent_id": user.get("userName"),
        },
        "auth": {"method": "aws_sigv4", "mfa_asserted": False, "protocol": "aws"},
        "token": {"issuer": "iam.amazonaws.com", "audience": "aws", "expires_in": 3600},
        "binding": {},
        "network": {
            "ip": row.get("sourceIPAddress", "0.0.0.0"),
            "country": "US", "city": "unknown", "asn": 0, "asn_org": "AWS",
        },
        "outcome": "success" if not row.get("errorCode") else "failure",
        "metadata": {"aws_event_name": row.get("eventName")},
    }

connector = FileTailJSONLConnector(
    tenant_id="prospect-acme",
    source_path="/path/to/cloudtrail-2026-04.jsonl",
    mapping=cloudtrail_to_uis,
)
report = connector.run()
print(report.as_dict())
```

Run periodically (cron, systemd timer, etc) for the trial window. Every event flows into TokenDNA's detection pipeline; every detection fires; nothing is enforced because shadow mode is active.

### Step B3 — Generate the trial report after 14 days

```bash
python scripts/shadow_trial_report.py --tenant prospect-acme
```

Or as JSON for embedding in a customer-facing PDF:

```bash
python scripts/shadow_trial_report.py --tenant prospect-acme --json \
  --output /tmp/prospect-acme-trial.json
```

The text output looks like:

```
========================================================================
  TokenDNA Shadow Mode Trial Report
  Tenant:   prospect-acme
  Window:   last 14 days
=======================================================================

  ── Headline findings ─────────────────────────────────────────────────

    🔴 CRITICAL  Agent self-modification detected  (count: 3)
          One or more agents in this environment modified policies that
          govern their own permission boundary — the CrowdStrike F50
          self-elevation pattern. Existing tools missed this.

    🟠 HIGH      Critical permission drift  (count: 7)
          7 agents grew their permission scope by 3x or more without
          an accompanying attestation event.

    ...
```

That report is the closing artifact. It comes back to the prospect with: "Here are 23 unattested permission expansions in your real environment, here are the 7 agents whose blast radius exceeds policy, here is the self-modification attempt your existing tools missed."

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` on import | venv not active | `source .venv/bin/activate` |
| `OSError: Read-only file system: '/data'` | `DATA_DB_PATH` not set; default is `/data/tokendna.db` | `export DATA_DB_PATH=/tmp/tokendna-demo.db` |
| Empty dashboard after seed | API booted before seeder finished, or different DB path | Verify `DATA_DB_PATH` matches in seeder + uvicorn shells; restart uvicorn |
| Dashboard widgets all show 0 / empty arrays even after seed | API resolved request to a tenant other than the seeded `acme` (e.g. `DEV_TENANT_ID` was set to `dev-tenant` from a previous shell) | `unset DEV_TENANT_ID` (default is `acme`) and restart uvicorn |
| `ATTESTATION_CA_SECRET not set` | Missing required env var | `export ATTESTATION_CA_SECRET=demo-secret-32-bytes-aaaaaaaaa` |
| Demo arc hits HTTP 401 | `DEV_MODE` not set, auth required | `export DEV_MODE=true` and restart uvicorn |
| Federation scene errors with "module not found" | demo arc imports federation directly; venv missing repo path | confirm `pip install -r requirements.txt` ran inside the venv |
| Port 8000 in use | Another process bound | `lsof -i :8000` then either kill or use `--port 8001` |

---

## What each shipped module contributes to the demo narrative

For the SE / AE building the customer story:

| Module | Story beat |
|---|---|
| `uis_narrative` + `passport` | Identity layer — "every agent action is attributable" |
| `verifier_reputation` | Verifier integrity — "you can trust who attested this" |
| `trust_graph` | The relational substrate — "we model how trust actually flows" |
| `blast_radius` | The "what if" simulator — "if this agent is compromised, here's the radius" |
| `intent_correlation` | The kill-chain detector — "isolated events are noise; chained events are an attack" |
| `policy_guard` | The runtime gate — "we say no when it matters" |
| `policy_advisor` | The flywheel — "every block teaches the system how to tighten" |
| `permission_drift` | The longitudinal lens — "drift is invisible without history; we have history" |
| `mcp_inspector` | The MCP-aware story — "we inspect tool calls before they execute" |
| `deception_mesh` | The honeypot signal — "compromised agents trip our decoys" |
| `federation` | The cross-org wedge — "cross-org agent action without dual attestation is a CRITICAL anomaly" |
| `shadow_mode` | The pilot conversion path — "before you buy, prove value against your data" |

---

## Reference paths

- Demo seed: `scripts/demo_seed_v2.py`
- Live arc: `scripts/demo_runtime_risk_engine.py`
- Trial report CLI: `scripts/shadow_trial_report.py`
- Shadow mode framework: `modules/product/shadow_mode.py`
- Curated fixtures: `data/demo_fixtures/`
- Active sprint plan: `CLAUDE.md`
