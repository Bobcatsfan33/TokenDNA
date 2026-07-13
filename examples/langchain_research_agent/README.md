# LangChain Research Agent + TokenDNA

A minimal LangChain agent with TokenDNA identity. ~30 lines of integration code.

## What this shows

- `@identified` declares the agent's TokenDNA identity once at the class level.
- `@tool` on every callable method emits a signed UIS event under that identity.
- `get_agent_metadata()` retrieves the workflow trace at the end of the run, ready to be registered as a canonical workflow.
- The whole thing is offline-safe: with no `TOKENDNA_API_BASE` set, the SDK buffers events locally and the LangChain agent runs unaffected.

## Run it

```bash
pip install tokendna-sdk[examples]   # pulls in langchain
export OPENAI_API_KEY=sk-...
# Optional — without these the SDK runs offline and buffers events
export TOKENDNA_API_BASE=https://api.tokendna.io
export TOKENDNA_API_KEY=tdna_...
export TOKENDNA_TENANT_ID=acme

python main.py "What's the latest on agentic security?"
```

Output:

```
[research-bot] fetching: https://news.example/agentic-security-2026
[research-bot] summarizing 3,421 chars
[research-bot] result: AI agent identity is the next frontier ...
[tokendna] registered workflow wf:abc123 with 3 hops
```

## What you should expect to see

1. The agent runs to completion.
2. UIS events for `fetch_url`, `summarize`, and `final_answer` ship to your TokenDNA tenant.
3. A `wf:*` workflow gets registered with the canonical chain `fetch_url → summarize → final_answer`.
4. Your TokenDNA dashboard shows the agent in the inventory under `research-bot`.

If TokenDNA is unreachable, events buffer to `/tmp/tokendna_research_agent_buffer.jsonl` and the LangChain agent still works. Run again later with `tokendna` reachable, then `python -c "from tokendna_sdk import Client; print(Client().flush())"` to drain.
