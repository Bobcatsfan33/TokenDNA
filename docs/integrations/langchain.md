# TokenDNA + LangChain / LangGraph

Drop-in identity, drift, and policy enforcement for any LangChain agent or LangGraph node. Two integration points, both copy-paste-run.

## Install

```bash
pip install tokendna-sdk langchain langchain-openai
tokendna init --tenant-id <your-tenant> --api-key <your-key> \
  --base-url <your-tokendna-url>
```

## Pattern 1 — wrap individual tools

The fastest way: decorate the underlying Python function before you hand it to LangChain.

```python
import tokendna_sdk as td
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate

@td.identified(agent_id="research-agent", role="research")
def search_web(query: str) -> str:
    """Search the public web — every call emits a UIS event +
    is checked against the agent's drift baseline."""
    return f"results for {query}"

@td.identified(agent_id="research-agent", role="research")
def fetch_url(url: str) -> str:
    """Fetch a URL — same enforcement applies."""
    return f"contents of {url}"

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a research assistant."),
    ("user", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
agent = create_openai_tools_agent(llm, [tool(search_web), tool(fetch_url)], prompt)
executor = AgentExecutor(agent=agent, tools=[tool(search_web), tool(fetch_url)])

executor.invoke({"input": "Summarise the Cloudflare 2026 RSA keynote."})
```

What you get for free:
- Every tool call is recorded as a UIS event tagged `research-agent`.
- TokenDNA detects when `search_web` starts being called for things it never used to do (drift).
- A self-modification attempt by the LLM (e.g. asking the agent to add `wire_transfer` to its toolset mid-session) is blocked at the SDK boundary by `policy_guard`'s `CONST-01` rule.

## Pattern 2 — LangGraph node guard

For LangGraph state machines, wrap the node function. TokenDNA receives the same agent_id across multiple node invocations in a graph run, so the trust graph correctly attributes the call chain.

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict
import tokendna_sdk as td

class State(TypedDict):
    query: str
    results: list
    summary: str

@td.identified(agent_id="researcher-graph", role="research-node")
def search_node(state: State) -> State:
    return {**state, "results": [f"hit-{i}" for i in range(3)]}

@td.identified(agent_id="researcher-graph", role="summary-node")
def summarise_node(state: State) -> State:
    return {**state, "summary": " | ".join(state["results"])}

g = StateGraph(State)
g.add_node("search", search_node)
g.add_node("summarise", summarise_node)
g.add_edge("search", "summarise")
g.add_edge("summarise", END)
g.set_entry_point("search")

graph = g.compile()
print(graph.invoke({"query": "RSA 2026"}))
```

The trust graph will show:
```
researcher-graph (search-node) → searches:hit-0,hit-1,hit-2
researcher-graph (summary-node) → produces:summary
```
…and any cross-node anomaly (e.g. summary-node suddenly calling something only search-node used to call) raises `PERMISSION_WEIGHT_DRIFT`.

## Pattern 3 — gate before invocation

If you want a hard pre-check before LangChain even spins up the LLM call:

```python
verdict = td.client().pre_check(
    agent_id="research-agent",
    proposed_tool_calls=[t.name for t in agent_executor.tools],
)
if verdict["disposition"] == "BLOCK":
    raise PermissionError(verdict["reason"])
executor.invoke({"input": user_query})
```

This is the right pattern for high-value agents (anything that touches money, customer data, or production infra) where you want the policy decision to happen before LLM compute is consumed.

## Reading the dashboard for a LangChain run

After invoking your chain a few times, on the dashboard:
- **UIS events**: one row per `@td.identified` call. Filter by `agent_id`.
- **Trust graph**: nodes for each tool, edges weighted by call frequency. Anomalies surface here first.
- **Drift score**: a single number per agent. The chart shows it climbing as the LLM tries new tools.
- **Policy guard**: every BLOCK decision listed with the rule that fired.

## Common gotchas

- **Streaming**: `executor.stream(...)` works fine — each chunk is a separate UIS event. If you'd rather batch, set `TOKENDNA_BATCH_FLUSH_MS=500` and the SDK will coalesce.
- **Async**: use `td.identified_async` for `@tool(coroutine=...)` and async-callable nodes.
- **Multi-tenant**: pass `tenant_id=` to the decorator if your agent serves multiple end-customers from one process.
