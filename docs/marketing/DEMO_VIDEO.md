# TokenDNA — demo video production guide

Two cuts:
- **2-minute** for the landing page (no headphones required, autoplay-friendly).
- **10-minute** for the prospect-handoff version (the full runtime risk engine arc, the one engineers will actually rewatch).

Both are **screen recordings** of `scripts/demo_runtime_risk_engine.py` running against a fully-seeded local stack, with overlay narration. No talking-head shots, no slides, no stock footage.

## What you need

- macOS / Linux laptop with a real microphone (AirPods are fine; built-in laptop mic is not).
- A clean fresh seed: `./scripts/demo_launch.sh` (boots `:8088` against the v2-seeded SQLite DB).
- Your favorite screen recorder. Known good:
  - macOS native: `Cmd-Shift-5` → record selected portion. Free, exports to .mov.
  - **Loom** for instant share-link if you want to send the raw take to me for a re-cut.
  - **OBS Studio** for the public-facing edit (split scenes, scene cuts, mic ducking).
- A 1920×1080 browser window. The dashboard renders crisp at this resolution; bigger looks zoomed-in on phone playback.
- 30 minutes of focus.

## Pre-flight checklist (run BEFORE you record)

1. Quit Slack, mail, calendar — nothing pops a notification mid-take.
2. Set the OS DND status (Focus mode on macOS).
3. Run `python3 scripts/demo_runtime_risk_engine.py --dry-run` once to confirm every scene completes (some require seeded data — the demo script aborts loudly if anything is missing).
4. Set the dashboard tenant filter to `acme` (top-right).
5. Drop a fresh DB the moment before you hit record:
   ```bash
   rm -f /tmp/tokendna-demo.db
   python3 scripts/demo_seed_v2.py     # ~2.7s
   ```
6. Open three browser tabs in one window: `dashboard`, `dashboard/trust-graph`, `dashboard/policy-decisions`. You'll switch between them with `Cmd-1/2/3`.

## Cut 1 — 2-minute landing page version

Hard cuts only (no transitions). Background music optional but soft. **Voice-over only** — the speaker never appears on screen.

| Time   | Visual                                                     | Narration |
|--------|------------------------------------------------------------|-----------|
| 0:00   | Dashboard home — "agents: 70" prominently visible          | "This is a TokenDNA tenant in production." |
| 0:08   | Click an agent row — `finance-bot-01` opens                | "Each agent has a behavioral DNA fingerprint, built from the first hour of UIS events." |
| 0:18   | Trigger drift via terminal:<br>`./scripts/demo_runtime_risk_engine.py --scene self-mod` | "Watch what happens when this agent tries to modify its own policy scope mid-session." |
| 0:35   | Dashboard refreshes, BLOCK appears in real time            | "Forty-seven milliseconds. BLOCK verdict, anomaly written to the trust graph." |
| 0:48   | Click anomaly — drilldown shows blast radius               | "Here's the blast radius — every downstream resource the agent could have touched if we'd let the call through." |
| 1:00   | Switch to `dashboard/policy-decisions`                     | "policy_advisor synthesised a tightening rule. The operator approves it in one click." |
| 1:14   | Click "Approve"                                             | "Now the agent is contained. The same attempt thirty seconds later — STILL blocked." |
| 1:28   | Cut to MCP scene: `--scene mcp-chain`                       | "MCP is where this gets interesting. read_file, then send_email — each call allowed in isolation." |
| 1:42   | `MCP_CHAIN_PATTERN_MATCHED` row appears                     | "Together, that's read_then_exfil. We catch the chain. No other vendor does." |
| 1:54   | Cut back to landing page hero                               | "Try it. Fourteen days, observe-only, against your own traffic." |
| 2:00   | End frame: tokendna.io                                      | (silent) |

## Cut 2 — 10-minute deep version

Same cold open as cut 1 (0:00–0:35). After the BLOCK, slow down and walk through every scene of the demo arc. The map below is one row per arc scene.

| Scene | Wall time | What to show | Narration anchor |
|-------|-----------|--------------|-----------------|
| 1 — Baseline | 0:35–1:30 | Volume widget ticking up, no anomalies | "Innocuous activity recorded. This is the baseline TokenDNA learns from." |
| 2 — Drift | 1:30–2:30 | `permission_drift` alert, growth_factor=3.2× | "Permission scope grew 3× without an attestation event. That's a drift alert." |
| 3 — Self-mod | 2:30–3:40 | `POLICY_SCOPE_MODIFICATION` (CRITICAL) | "The agent attempts to modify its own policy. policy_guard BLOCKs via CONST-01." |
| 4 — MCP chain | 3:40–4:50 | `MCP_CHAIN_PATTERN_MATCHED`, confidence ≈ 1.0 | "Read sensitive file, then send email. Read-then-exfil chain." |
| 5 — Deception | 4:50–5:50 | Honeypot hit | "Agent trips a honeytoken. We didn't deploy it for this agent — it's a tenant-wide trap." |
| 6 — Blast radius | 5:50–7:00 | Live blast radius enriched with anomalies + MCP violations | "Operator hits 'simulate blast radius' — the result includes live anomalies, not just topology." |
| 7 — Verdict | 7:00–8:10 | policy_advisor recommendation + approve | "policy_advisor synthesises the tightening rule. Operator approves." |
| 8 — Federation | 8:10–8:50 | Beta initiates handshake to Acme | "Cross-org trust. Beta initiates, Acme accepts, federation_trust persisted." |
| 9 — Cross-org BLOCK | 8:50–9:25 | `CROSS_ORG_ACTION_WITHOUT_HANDSHAKE` (CRITICAL) | "Acme agent tries to act on Beta with no trust_id. CONST-06 BLOCKs." |
| 10 — Cross-org ALLOW | 9:25–9:55 | Same call with the trust_id — ALLOW | "Same action, with the established trust. Allowed. Audit-logged." |
| End | 9:55–10:00 | Cut to landing | "tokendna.io. Fourteen-day shadow trial." |

## Editing notes

- **Mic levels**: leave at -12 dBFS peak. Compress lightly so the soft moments don't get lost on phone playback.
- **Subtitles**: bake them in. ~80% of LinkedIn / Twitter views are sound-off.
- **End frame**: leave the `tokendna.io` URL on screen for 2 seconds with a subtle fade. Don't cut to black instantly — viewers want to read the URL.
- **File**: export 1080p H.264, 6 Mbps target. Should land around 90 MB for the 10-min cut, ~15 MB for the 2-min cut. Both are within Twitter / LinkedIn / YouTube preview limits.

## What the AE / SE will be asked AFTER they show this

Pre-write the answers; have them at the top of the prospect kit:

1. *"Where does the CA private key live?"* — AWS KMS (FIPS 140-2 L2) by default, CloudHSM (L3) for IL5. Cite the new `AWSKMSTrustSigner` / `CloudHSMTrustSigner` modules.
2. *"How is this not just OAuth + an audit log?"* — three RSA gaps slide. Hand them `docs/integrations/mcp.md`.
3. *"Will this slow my agents down?"* — p99 < 100 ms. Show them the load harness report (`scripts/load_test_realistic.py`).
4. *"What's the deployment footprint?"* — Helm chart + docker-compose + plain k8s manifests in `deploy/`.
5. *"What if I don't want to send my data to your cloud?"* — self-host. The Community tier is the same engine.
