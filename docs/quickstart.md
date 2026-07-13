# TokenDNA — 5-minute quickstart

Goal: in five minutes, see TokenDNA catch a real attack pattern against a real Python agent. No mock data, no doctored demo — the agent below is a one-file LangChain helper that calls a tool, drifts, and triggers a policy guard verdict.

You'll do this on your laptop. Total wall-clock time is the install + a single `python` invocation.

## Prerequisites

- Python 3.9+
- A running TokenDNA backend. Pick one:
  - **Easiest**: `./scripts/demo_launch.sh` from a checkout of this repo (boots `uvicorn` on `:8088` against a fully seeded SQLite demo DB).
  - **Hosted**: a TokenDNA cloud tenant URL + API key.
- ~30 seconds of attention at each step.

## Step 1 — Install

```bash
pip install tokendna-sdk
```

That's it. The SDK has zero runtime dependencies (uses stdlib `urllib`); the install is sub-second.

## Step 2 — Initialise

```bash
tokendna init --tenant-id demo --api-key tokendna_demo_api_key \
  --base-url http://127.0.0.1:8088
```

Writes `~/.config/tokendna/config.toml`. You can override per-call via env: `TOKENDNA_TENANT_ID`, `TOKENDNA_API_KEY`, `TOKENDNA_BASE_URL`.

## Step 3 — Decorate your agent

Save this as `quickstart_agent.py`:

```python
import time
import tokendna_sdk as td

@td.identified(agent_id="quickstart-agent", role="finance-bot")
def fetch_invoice(customer_id: str) -> dict:
    """Pretend this is a LangChain tool call."""
    return {"customer_id": customer_id, "amount": 1234.56, "due_date": "2026-05-15"}


@td.identified(agent_id="quickstart-agent", role="finance-bot")
def fetch_invoice_v2(customer_id: str, *, also_export: bool = False) -> dict:
    """A 'newer' version of the same tool that, in this demo, expands its
    permission scope (also_export=True) — TokenDNA's drift detector
    will flag this as scope growth without an attestation event."""
    base = fetch_invoice(customer_id)
    if also_export:
        # Scope expansion: this is the drift signal
        base["exported_to"] = "third-party-billing.example.com"
    return base


if __name__ == "__main__":
    print("→ baseline call (this becomes the agent's profile)")
    print(fetch_invoice("acme-101"))

    print("\n→ second baseline (still within scope)")
    print(fetch_invoice("acme-102"))

    print("\n→ scope expansion (drift!)")
    print(fetch_invoice_v2("acme-103", also_export=True))

    print("\n→ same expansion again (drift confirmed across calls)")
    print(fetch_invoice_v2("acme-104", also_export=True))

    time.sleep(2)  # let backend ingest
```

## Step 4 — Run

```bash
python quickstart_agent.py
```

You should see four normal-looking call results.

## Step 5-8 — See what TokenDNA caught (open the dashboard)

Open the running dashboard in a browser:

```
http://127.0.0.1:8088/dashboard
```

You'll see, in order:

1. **UIS event feed** — four events for `quickstart-agent`. The first two carry a clean profile; the second two carry the new `also_export` field.
2. **Attestation certificates** — one cert per agent (issued automatically by the SDK on first call).
3. **Drift score** — for `quickstart-agent`, starts at **0.00**, climbs after the third call as the matcher detects the scope expansion.
4. **Drift alert** — `PERMISSION_WEIGHT_DRIFT` (severity HIGH) appears in the trust graph the moment the second `fetch_invoice_v2` call lands. The dashboard's "Recent anomalies" widget shows the growth_factor and which agent it concerns.
5. **Policy verdict** — under "Policy guard recent decisions", the second `also_export=True` call shows up with disposition `STEP_UP` (or `BLOCK` if you've enabled the strict ruleset).

## Step 9 — Trigger the harder case (self-modification)

```python
import tokendna_sdk as td

@td.identified(agent_id="quickstart-agent", role="finance-bot")
def alter_my_own_policy():
    """Ask the backend to expand my own permission scope.
    This is what no agent should be allowed to do — TokenDNA blocks it."""
    return td.client().request_policy_change(
        agent_id="quickstart-agent",
        new_scope=["fetch_invoice", "fetch_invoice_v2", "fetch_invoice_v2.also_export",
                   "send_email", "wire_transfer"],
    )

print(alter_my_own_policy())
```

Run it. You'll see the SDK return `{"disposition": "BLOCK", "rules_violated": ["CONST-01: agent cannot self-modify policy scope"]}`. In the dashboard:

6. **POLICY_SCOPE_MODIFICATION** anomaly fires (CRITICAL) in the trust graph.
7. **policy_advisor suggestion** appears — a proposed tightening rule the operator can approve in one click.

## Step 10 — Approve the suggestion

In the dashboard, click "Suggestions" → the proposed `STEP_UP` rule on `wire_transfer` → **Approve**. Re-run `alter_my_own_policy()` — it now reaches the backend but receives the operator-approved verdict you just authored.

You've watched the runtime risk engine close the loop end-to-end:

```
agent action → UIS event → trust graph anomaly → policy guard verdict → operator approves → tightened policy applied
```

Total time, including reading: ~5 minutes.

## What just happened (for the security engineer reviewing this)

- Every call to a `@td.identified` function emits a UIS (Universal Identity Schema) event over HTTPS to the configured backend. The event carries `agent_id`, the function name, the arg schema (not values), and a profile fingerprint.
- TokenDNA's drift detector compares the live profile fingerprint to the rolling baseline; a permission-weight delta above the configured threshold fires `PERMISSION_WEIGHT_DRIFT`.
- Policy guard's `CONST-01` rule blocks any agent action whose subject equals its actor (the self-modification case).
- Policy advisor synthesises a tightening suggestion from the violation pattern; an operator can approve it without writing YAML.
- The whole loop runs in under 100 ms p99 on a single-tenant deployment.

## Where to go next

| You want to… | Read |
|--------------|------|
| Wire this into LangChain / CrewAI / AutoGen / MCP | `docs/integrations/` |
| Run the full 10-minute demo arc (8 scenes) | `docs/demo/RUN_DEMO.md` |
| Run a 14-day shadow trial against your own logs | `docs/demo/RUN_DEMO.md` (path B) |
| Deploy to production (SaaS, on-prem, or hybrid) | `docs/operations/MTLS.md` + `docs/operations/RUNBOOK.md` |
| Browse the API surface | `/docs` (Swagger) on a running instance |
