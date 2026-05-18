# tokendna-sdk quickstart examples

Four runnable demos that cover the SDK's main surfaces. Each script
is independently runnable and prints what it did to stdout. None of
them require a TokenDNA server account — local mode is the default.

## Install

```bash
pip install tokendna-sdk           # core
pip install "tokendna-sdk[all]"    # core + langchain + crewai + autogen + mcp
```

For each example below, install only the extra you need.

## 1. `local_mode.py` — zero-config on-ramp

```bash
python examples/quickstart/local_mode.py
```

Drops a couple of decorator-instrumented tool calls and verifies the
signed JSONL trail at `~/.tokendna/events.jsonl`. No extras needed.

## 2. `langchain_agent.py` — native LangChain middleware

```bash
pip install "tokendna-sdk[langchain]"
export OPENAI_API_KEY=...
python examples/quickstart/langchain_agent.py
```

Runs a tiny ReAct agent through `TokenDNAMiddleware`. Every model and
tool hop lands in the JSONL trail; the agent's final answer is
unaffected by instrumentation.

## 3. `crewai_workflow.py` — CrewAI callback

```bash
pip install "tokendna-sdk[crewai]"
python examples/quickstart/crewai_workflow.py
```

Attaches `TokenDNACrewCallback` to a two-agent crew and prints the
resulting attestation receipt.

## 4. `mcp_proxy.py` — MCP tool-call interceptor

```bash
pip install "tokendna-sdk[mcp]"
python examples/quickstart/mcp_proxy.py
```

Shows the `secure_mcp_server` decorator wrapping a toy MCP handler.
Drives a `read_file → send_email` exfil pattern through the proxy
and demonstrates the deny chain firing in enforcement mode.

## CLI demos

The CLI ships the same scenarios as `tokendna demo`:

```bash
tokendna demo                      # synthetic agent run
tokendna status                    # what's in ~/.tokendna right now?
tokendna baseline show demo-agent  # rolling baseline
tokendna verify demo-agent search --scope demo:read   # one-shot verify
```

Use these to sanity-check a fresh install before you wire the SDK
into a real agent.
