# tokendna-sdk

**Identity for AI agents in one decorator.**

[![PyPI](https://img.shields.io/pypi/v/tokendna-sdk.svg)](https://pypi.org/project/tokendna-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/tokendna-sdk.svg)](https://pypi.org/project/tokendna-sdk/)
[![License](https://img.shields.io/pypi/l/tokendna-sdk.svg)](https://github.com/Bobcatsfan33/TokenDNA/blob/main/LICENSE)
[![Build](https://github.com/Bobcatsfan33/TokenDNA/actions/workflows/publish.yml/badge.svg)](https://github.com/Bobcatsfan33/TokenDNA/actions)

Drop `@identified` on your LangChain / CrewAI / AutoGen / plain-Python agent — or attach `TokenDNAMiddleware` natively — and every action becomes a signed, replayable, audit-trail-ready event with zero infrastructure on your side.

```python
from tokendna_sdk import identified, tool

@identified("research-bot", scope=["docs:read", "summarize"])
class ResearchAgent:
    @tool("fetch_doc", target="document")
    def fetch_doc(self, url: str) -> str: ...

    @tool("summarize")
    def summarize(self, text: str) -> str: ...
```

That's it. No HTTP setup, no schemas, no middleware to write. Every method call ships a signed UIS event under `research-bot`'s identity and lands as a hop in a workflow trace.

## Why?

Your agents are calling tools, escalating privileges, and pivoting through your infrastructure. **You can't audit what you can't identify.** Most observability tools treat agents as anonymous workers. TokenDNA gives them names, scopes, and cryptographic provenance.

After a couple of decorators, your agents have:

- **Provable identity** — every action signed under the agent's declared identity and scope
- **Workflow attestation** — multi-hop chains (Agent A → tool → Agent B) recorded as signed DAGs you can replay
- **Delegation receipts** — cryptographic proof that authority flowed from a human to the agent through every intermediate
- **Behavioral baselines** — alerts when an agent's behavior diverges from its norm
- **Compliance posture** — signed evidence packs for SOC 2 / ISO 42001 / NIST AI RMF / EU AI Act

## Install

```bash
# Core (zero runtime deps)
pip install tokendna-sdk

# With native framework middleware
pip install "tokendna-sdk[langchain]"
pip install "tokendna-sdk[crewai]"
pip install "tokendna-sdk[autogen]"
pip install "tokendna-sdk[mcp]"
pip install "tokendna-sdk[all]"
```

Python 3.9+. The core uses only the stdlib (`urllib`); framework adapters are opt-in extras.

## Two ways to use it

### 1. Classic — decorators (works with anything)

```python
from tokendna_sdk import identified, tool

@identified("research-bot", scope=["docs:read"])
class ResearchAgent:
    @tool("fetch_doc")
    def fetch_doc(self, url): ...
```

### 2. Native framework middleware (LangChain shown — same idea for CrewAI / AutoGen)

```python
# pip install "tokendna-sdk[langchain]"
from tokendna_sdk.integrations.langchain import TokenDNAMiddleware

agent = create_react_agent(
    model="gpt-4o",
    tools=[search_web, send_email],
    middleware=[TokenDNAMiddleware(agent_id="research-bot",
                                    scope=["web:read", "email:send"])],
)
```

The middleware adapter implements the LangChain v0.3 `wrap_model_call` / `wrap_tool_call` / `after_agent` hooks so you get attestation, behavioral scoring, and workflow traces without changing your agent code.

> **Sprint 2** ships native `TokenDNAMiddleware`, `TokenDNACrewCallback`, and `TokenDNAAutoGenMiddleware`. **Sprint 3** ships the `TokenDNAMCPProxy` MCP interceptor. The decorator wedge above works today.

## Local mode (no server required)

If you don't set `TOKENDNA_URL`, the SDK runs in **local mode**: signed JSONL events are appended to `~/.tokendna/events.jsonl` with a host-local HMAC key. Useful for trying it out, for tests, and for air-gapped environments.

```python
from tokendna_sdk import make_client

client = make_client()       # auto-picks remote if TOKENDNA_URL set, else local
print(client.health())       # {'status': 'ok', 'mode': 'local', ...}
client.normalize({"event_id": "demo-1", "agent_id": "research-bot"})
```

Inspect the trail:

```bash
tail -1 ~/.tokendna/events.jsonl | python -m json.tool
```

## Configure (remote mode)

Two ways. Code takes precedence over env.

### Environment

```bash
export TOKENDNA_URL="https://api.tokendna.io"
export TOKENDNA_API_KEY="..."
export TOKENDNA_TENANT_ID="..."
```

(The legacy `TOKENDNA_API_BASE` still works.)

### Code

```python
from tokendna_sdk import configure

configure(
    url="https://api.tokendna.io",
    api_key="...",
    tenant_id="...",
    timeout_seconds=5.0,
    offline_buffer_path="/var/run/tokendna/buffer.jsonl",  # optional
)
```

### Disabled

```python
configure(enabled=False)   # decorators / middleware become no-ops — useful in CI
```

## The high-level client

```python
from tokendna_sdk import make_client

client = make_client()

# Health check
client.health()
# Best-effort event stream (buffered, batched)
client.normalize({"event_id": "...", "agent_id": "...", ...})
# Synchronous policy check — raises TokenDNAVerificationError on deny
verdict = client.verify("research-bot", "send_email", target="bob@example.com")
# Issue an attestation receipt for a completed workflow
att = client.attest("research-bot", hops=[{"actor": "...", "action": "..."}])
```

## The decorators (classic surface — still supported)

### `@identified(agent_id, scope=..., description=..., delegation_receipt_id=...)`

Class decorator. Stamps `__tokendna_meta__` on the class with the declared identity. Non-invasive — does not modify methods, `__init__`, or attribute lookup.

### `@tool(name=None, target=None, capture_args=False)`

Method decorator. Per call: push a hop onto the per-thread workflow trace, ship a UIS event, then call the wrapped method.

**Cannot fail your program.** Network failures buffer locally; transport errors retry on `client.flush()`. `capture_args=False` by default — opt in only for non-sensitive code; argument values land in the event when on.

### `get_agent_metadata()`

Read the current thread's accumulated workflow trace.

## Offline-safe by design

The SDK never blocks your code on TokenDNA availability. If the API is unreachable, events buffer (memory; disk if `offline_buffer_path` is set). Call `client.flush()` to drain when connectivity returns.

This is the wedge: **you can adopt the SDK before you trust the platform**, because adoption costs nothing on the bad days.

## CLI

```bash
tokendna --help
tokendna config show                # active config (key redacted)
tokendna policy plan ./bundle.json
tokendna policy apply <bundle_id>
tokendna replay <decision_id>
```

Sprint 3 adds: `tokendna verify`, `tokendna demo`, `tokendna status`, `tokendna baseline show <agent_id>`.

## Examples

The [examples/](https://github.com/Bobcatsfan33/TokenDNA/tree/main/examples) directory in the repo:

- `examples/langchain_research_agent/` — LangChain agent with attested tool calls
- `examples/quickstart/` — Sprint 3 quickstart demos (LangChain / CrewAI / MCP / local mode)

## What's the catch?

None for the SDK itself — Apache 2.0, zero runtime deps, works against any TokenDNA tenant or in offline-only mode. The *value* of the events you ship lives on the platform: trust graph, blast radius scoring, intent correlation, the network flywheel. The SDK is the on-ramp; the platform is where your agents become provably trustworthy.

## Status

**Beta** (v0.2.x). The core surface — `@identified` / `@tool`, `TokenDNAClient`, `TokenDNALocalClient`, `make_client` — is stable. Framework middleware adapters land in v0.2.x as they're released. Pin the version while we're pre-1.0.

## License

Apache 2.0. See [LICENSE](https://github.com/Bobcatsfan33/TokenDNA/blob/main/LICENSE).

## Links

- [Documentation](https://github.com/Bobcatsfan33/TokenDNA/tree/main/tokendna_sdk)
- [Changelog](https://github.com/Bobcatsfan33/TokenDNA/blob/main/CHANGELOG.md)
- [Issues](https://github.com/Bobcatsfan33/TokenDNA/issues)
- [Security Policy](https://github.com/Bobcatsfan33/TokenDNA/security/policy)

---

[TokenDNA](https://github.com/Bobcatsfan33/TokenDNA) — runtime identity & risk engine for AI agents.
