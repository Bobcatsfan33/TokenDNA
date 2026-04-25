# tokendna-sdk

**Identity for AI agents in one decorator.**

Drop `@identified` on your LangChain / CrewAI / AutoGen / plain-Python agent and every action it takes becomes a signed, replayable, audit-trail-ready event — without any infrastructure on your side.

```python
from tokendna_sdk import identified, tool, configure

configure(
    api_base="https://api.tokendna.io",
    api_key=os.environ["TOKENDNA_API_KEY"],
    tenant_id="acme-prod",
)

@identified("research-bot", scope=["docs:read", "summarize"])
class ResearchAgent:
    @tool("fetch_doc", target="document")
    def fetch_doc(self, url: str) -> str:
        ...

    @tool("summarize")
    def summarize(self, text: str) -> str:
        ...
```

That's it. Every method call now ships a UIS (Universal Identity Signal) event under `research-bot`'s identity, with the call recorded as a hop in a workflow trace. No HTTP setup, no schemas to maintain, no middleware to write.

## Why?

Your agents are calling tools, escalating privileges, and pivoting through your infrastructure. **You can't audit what you can't identify.** Every other observability tool treats agents as anonymous workers. TokenDNA gives them names, scopes, and cryptographic provenance.

After 100 lines of Python, your agents have:

- **Provable identity** — every action signed under the agent's declared identity and scope
- **Workflow attestation** — multi-hop chains (Agent A → tool → Agent B) recorded as signed DAGs you can replay
- **Delegation receipts** — cryptographic proof that authority flowed from a human to the agent through every intermediate
- **Drift detection** — alerts when an agent's behavior diverges from its baseline
- **Compliance posture** — signed evidence packs for SOC 2 / ISO 42001 / NIST AI RMF / EU AI Act

## Install

```bash
pip install tokendna-sdk
```

Zero runtime dependencies (stdlib `urllib` only). Python 3.9+.

## Configure

Three ways, in priority order. Last one wins.

### Environment

```bash
export TOKENDNA_API_BASE="https://api.tokendna.io"
export TOKENDNA_API_KEY="..."
export TOKENDNA_TENANT_ID="..."
```

### Code

```python
from tokendna_sdk import configure

configure(
    api_base="https://api.tokendna.io",
    api_key="...",
    tenant_id="...",
    timeout_seconds=5.0,
    offline_buffer_path="/var/run/tokendna/buffer.jsonl",  # optional
)
```

### Disabled mode

```python
configure(enabled=False)  # decorators become no-ops; useful in tests / CI
```

## The decorators

### `@identified(agent_id, scope=..., description=..., delegation_receipt_id=...)`

Class decorator. Stamps `__tokendna_meta__` on the class with the declared identity. Non-invasive — does not modify methods, `__init__`, or attribute lookup.

```python
@identified("query-planner", scope=["sql:read"], delegation_receipt_id="rcpt:abc123")
class QueryPlanner:
    ...
```

`delegation_receipt_id` is optional but recommended in production: pass the ID of the receipt that delegates authority from a human to this agent, and every event will reference it. The receipt's chain becomes the agent's authorization audit trail.

### `@tool(name=None, target=None, capture_args=False)`

Method decorator. On every call:

1. Pushes a hop `{actor, action, target, receipt_id, metadata}` onto the per-thread workflow trace.
2. Best-effort emits a UIS-shaped event to `/api/uis/normalize`.
3. Calls the wrapped method and returns its value (or re-raises its exception).

**Cannot fail your program.** Network failures buffer locally; transport errors get retried by `client.flush()`. The SDK never swallows exceptions from the wrapped method, but it never raises its own either.

`capture_args=False` by default — opt in only for debugging non-sensitive code, since it serializes argument values into the event.

### `get_agent_metadata()`

Read the current thread's accumulated workflow trace. Use it to register a workflow at the end of a multi-step task:

```python
result = agent.run_research("topic X")
trace = get_agent_metadata()  # {"hops": [...]}

# Register the canonical chain — replay against it later
import requests
requests.post(
    "https://api.tokendna.io/api/workflow/register",
    json={"name": "research-flow", "hops": trace["hops"]},
    headers={"X-API-Key": os.environ["TOKENDNA_API_KEY"]},
)
```

## Offline-safe by design

The SDK never blocks your code on TokenDNA availability. If the API is unreachable, events buffer (memory by default; disk if `offline_buffer_path` is set). Call `client.flush()` to drain when connectivity returns.

```python
from tokendna_sdk import Client, configure

configure(api_base="https://api.tokendna.io", api_key="...",
          offline_buffer_path="/var/run/tokendna/buffer.jsonl")

client = Client()
print(client.flush())   # {"sent": 47, "buffered": 0}
```

This is the wedge: **you can adopt the SDK before you trust the platform**, because adoption costs you nothing on the bad days.

## CLI

```bash
$ tokendna --help
$ tokendna config show                         # active config (key redacted)
$ tokendna policy plan ./policy_bundle.json    # dry-run a policy bundle
$ tokendna policy apply <bundle_id>            # activate a bundle
$ tokendna replay <decision_id>                # replay a recorded decision
```

## Examples

See `examples/` in the repo:

- `examples/langchain_research_agent/` — full LangChain integration with attested tool calls

## What's the catch?

There is none for the SDK itself — it's Apache 2.0, zero deps, works against any TokenDNA tenant or in offline-only mode. The catch is that the *value* of the events you ship lives on the platform: trust graph, blast radius, intent correlation, the network flywheel. The SDK is the on-ramp; the platform is where your agents become provably trustworthy.

## Status

Alpha. The decorator surface is stable; the optional features (delegation receipt embedding, workflow auto-registration) may evolve. Pin the version while we're pre-1.0.

## License

Apache 2.0.

---

🌱 [TokenDNA](https://github.com/Bobcatsfan33/TokenDNA) — runtime risk engine for AI agents.
