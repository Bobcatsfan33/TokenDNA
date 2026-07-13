# Design partner activation kit

Everything needed to take a warm intro from one of your federal / channel relationships to a 14-day shadow trial that ends in a paid contract. Templates only — every personal touch goes in your voice, not mine.

> **What this kit cannot do**: identify the right contact at a target organization, reach out to a known person, deploy into a customer's network, or close a contract. Those are your relationships and your judgment. Use the templates as scaffolding.

## Stage 0 — target list (your homework)

Per the plan §5.1, three categories:

| Category   | Profile                                                    | Source for warm intros                       |
|------------|------------------------------------------------------------|----------------------------------------------|
| **Primary**   | DoD or IC org running MCP / LangChain agents with identity gaps | USSF / Army / Navy contacts from Zscaler-Elastic campaign |
| **Secondary** | Civilian agency with FedRAMP requirement evaluating agent security | Carahsoft, Epoch Concepts, FCN account teams |
| **Tertiary**  | Commercial enterprise (fintech / healthtech) where SOC 2 / DISA STIG automation is the wedge | Your direct network |

Track in a single spreadsheet (or Linear / Notion / Salesforce). Minimum columns: `org`, `contact`, `intro_via`, `stage`, `next_action`, `next_date`.

## Stage 1 — intro email (channel-partner-mediated)

Subject: **Quick intro — TokenDNA, the runtime layer below the agents you're already running**

> Hi {{contact_first_name}},
>
> {{intro_via_name}} suggested I reach out because {{their_org}} is starting to run AI agents in production and the identity / runtime story isn't fully solved yet.
>
> Quick framing — most of the existing identity vendors stop at "did this agent authenticate?". TokenDNA picks up where they leave off:
>
> 1. Detects when an agent silently expands its own permission scope (the CrowdStrike F50 incident pattern).
> 2. Catches MCP chain attacks (`read_file → send_email`) that look fine call-by-call.
> 3. Cross-org agent action with no federation handshake → blocked, not logged-and-forgotten.
>
> Three RSA 2026 gaps no major vendor closed.
>
> The ask: a 30-minute call to walk through a 2-minute demo and see if a 14-day shadow-mode trial against a non-prod agent fleet of yours makes sense. No commercial conversation until day 14.
>
> Calendar link: {{calendly}}
>
> {{your_signature}}

**Why this works**: it leads with a credit to the channel partner (relationship value), positions us against gaps the buyer already knows about (no vendor education tax), and closes with a soft trial ask, not a paid pilot.

## Stage 2 — the 30-minute call

Show the **2-minute landing video** first (per `docs/marketing/DEMO_VIDEO.md`), then the **10-minute deep version**, then leave 18 minutes for their team's questions. Send the **federal one-pager** (`docs/marketing/FEDERAL_ONEPAGER.md`) after the call as the leave-behind.

Anticipated questions + prepared answers — keep this open in a second tab during the call:

| Q                                                  | A                                                                                                  |
|----------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Where does the CA private key live?                | AWS KMS (FIPS 140-2 L2). CloudHSM (L3) for IL5/IL6. Source: `modules/identity/trust_authority.py`. |
| Latency overhead?                                  | p99 < 100 ms on `/secure`. Validated in `scripts/load_test_realistic.py`.                          |
| Does this require code changes?                    | One decorator per agent function. SDK install is `pip install tokendna-sdk`. ~5 min total.         |
| FedRAMP authorization status?                      | High alignment today; Provisional Authorization in progress. Customer-managed deployment unblocks IL4/5 today. |
| What if our agent framework isn't supported?       | Any callable can be wrapped. We've polished guides for LangChain / CrewAI / AutoGen / MCP.         |
| Can we self-host?                                  | Yes. Helm chart + plain k8s manifests + docker-compose ship today.                                  |
| What's the SOC 2 evidence story?                   | `compliance.generate_evidence_package` produces OSCAL + eMASS XML on demand. Live demo on the call. |
| Pricing?                                           | Don't price on the first call. "We'd rather see what we find in the trial first."                  |

## Stage 3 — 14-day shadow-mode trial

### Pre-deployment checklist (week before)

- [ ] Partner provides: staging/dev env with AI agents already running, network ingress for TokenDNA to observe agent traffic.
- [ ] You provide: TokenDNA deployed in shadow mode (observe-only), SDK integration for their primary agent framework, dashboard access for their security team, daily email summary, weekly 30-min sync.
- [ ] **Configuration baseline**:
  ```bash
  export SHADOW_MODE=true
  export ENFORCEMENT=observe
  export TOKENDNA_TENANT_ID=<partner-prefix>
  ```
- [ ] Tier flag: `ent.federation`, `ent.mcp_gateway`, `ent.behavioral_dna`, `ent.enforcement_plane` enabled for the trial.
- [ ] On-call rotation: you + one of theirs. Slack channel set up before deployment day.

### Day-1 deployment runbook

1. Walk their ops team through `docs/operations/MTLS.md` for the internal CA setup. (Alternative: skip mTLS for the trial; document as "deferred to enforcement-mode cutover".)
2. Run `./scripts/issue_internal_certs.sh --out /etc/tokendna/tls`.
3. `docker compose -f docker-compose.yml -f docker-compose.production.yml up -d`.
4. Confirm `curl https://<their-host>/api/health` returns 200.
5. Drop the SDK into their primary agent service (one decorator).
6. Open the dashboard, filter to their tenant, confirm UIS events flowing.

### Daily ops (each working day, 5 min)

- Check the dashboard's "Anomalies last 24h" widget.
- Send the partner contact a one-paragraph email summary (subject: `[TokenDNA Trial · day {{n}}] {{anomaly_count}} new findings`). Template:

  > Day {{n}} of 14. **{{events_today}}** events analysed, **{{anomalies_today}}** anomalies detected, **{{drift_today}}** drift episodes. Notable: {{top_finding_one_sentence}}. Full dashboard at {{url}}. Replying with questions is fine.

### Weekly sync (30 min, days 4 and 11)

Agenda:
1. **What we found this week** (you, 10 min) — top 3 findings with screenshots.
2. **Their questions** (open, 15 min).
3. **Next-week instrumentation tweaks** (5 min) — e.g., turn on a deferred check, tighten a baseline.

## Stage 4 — close-of-trial report (day 14)

Run `scripts/shadow_mode_report.py --tenant <partner-prefix> --pdf`. Produces:
- `/tmp/tokendna-trial-<tenant>-<utc>.html` — single-file HTML
- `/tmp/tokendna-trial-<tenant>-<utc>.pdf` — print-ready

Send the PDF + a personal note.

## Stage 5 — pricing conversation (day 14-21)

The data does the selling. The structure of the conversation:

1. *"You processed X events over 14 days."*
2. *"We detected Y anomalies your existing tooling didn't surface in the same window."* (Read straight from the **vs_existing_tooling** section of the report.)
3. *"Based on your agent fleet size (Z), the Pro tier at $2,499/mo covers your deployment, with the Enterprise tier ($N) once you cross 10k agents or need IL5."*
4. *"Here's the SOC 2 evidence package we generated during the trial — your ATO timeline just shortened by ~K months."*

Concession ladder if they push back on price:
- **Free month** — keep them on the trial with enforcement turned on. 30 more days of conversion data; if they cancel they walk with a usable security posture report.
- **Annual upfront, 10% discount** — preserves price integrity, accelerates revenue recognition.
- **Pilot-to-prod** — quote a 6-month pilot at the Starter price with a contractual upgrade trigger (volume or feature) to Pro.

Hard floor: **don't discount the Pro tier below 25%**. Below that we lose pricing power on the next deal in the segment.

## Templates ready to copy

The intro email, day-N summary, and post-trial close are above. Two more in `docs/partners/templates/`:

- `intro-email-direct.md` — for direct outreach (no channel partner).
- `daily-summary.md` — automated send-template variant.
