"""
LangChain research agent with TokenDNA identity.

Run:
    python main.py "What's the latest on agentic security?"

Requires:
    pip install tokendna-sdk[examples]   # tokendna-sdk + langchain
    OPENAI_API_KEY env var
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

from tokendna_sdk import (
    Client,
    configure,
    get_agent_metadata,
    identified,
    tool,
)


# ── Configure once at startup ─────────────────────────────────────────────────
# Falls back to env vars if these are blank.
configure(
    api_base=os.getenv("TOKENDNA_API_BASE", ""),
    api_key=os.getenv("TOKENDNA_API_KEY", ""),
    tenant_id=os.getenv("TOKENDNA_TENANT_ID", ""),
    offline_buffer_path="/tmp/tokendna_research_agent_buffer.jsonl",
)


# ── The agent ─────────────────────────────────────────────────────────────────

@identified(
    "research-bot",
    scope=["docs:read", "summarize", "answer"],
    description="LangChain research agent with TokenDNA identity",
)
class ResearchAgent:
    """Plain-Python research agent. LangChain (or any other framework) wraps
    these methods — the decorators don't care."""

    @tool("fetch_url", target="document")
    def fetch_url(self, url: str) -> str:
        print(f"[research-bot] fetching: {url}")
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.read().decode("utf-8", errors="replace")[:50_000]
        except Exception as exc:  # pragma: no cover — example only
            return f"[fetch failed: {exc}]"

    @tool("summarize")
    def summarize(self, text: str) -> str:
        print(f"[research-bot] summarizing {len(text)} chars")
        # In a real LangChain agent, this calls an LLM via ChatOpenAI etc.
        # For this example we keep it dependency-free.
        sentences = text.split(".")[:3]
        return ". ".join(s.strip() for s in sentences if s.strip())

    @tool("final_answer")
    def final_answer(self, summary: str) -> str:
        print(f"[research-bot] result: {summary[:120]}{'...' if len(summary) > 120 else ''}")
        return summary


# ── Optionally wrap as a LangChain AgentExecutor ──────────────────────────────
# Demonstrates that @identified / @tool layer ON TOP of any framework — they
# don't replace it. If LangChain isn't installed, fall back to direct calls.

def _maybe_run_with_langchain(agent: ResearchAgent, question: str) -> str:
    try:
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain.tools import Tool
        from langchain_openai import ChatOpenAI
        from langchain.prompts import PromptTemplate
    except ImportError:
        return _run_direct(agent, question)

    tools = [
        Tool(name="fetch_url",
             func=agent.fetch_url,
             description="Fetch the contents of a URL."),
        Tool(name="summarize",
             func=agent.summarize,
             description="Summarize a body of text."),
    ]
    prompt = PromptTemplate.from_template(
        "You are a research assistant. Question: {input}\n"
        "Tools: {tools}\nTool names: {tool_names}\n"
        "{agent_scratchpad}"
    )
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    react = create_react_agent(llm, tools, prompt)
    executor = AgentExecutor(agent=react, tools=tools, verbose=False, max_iterations=4)
    out = executor.invoke({"input": question})
    return agent.final_answer(out.get("output", ""))


def _run_direct(agent: ResearchAgent, question: str) -> str:
    """Fallback path when LangChain isn't installed — still demonstrates
    the SDK wiring and produces a workflow trace."""
    text = agent.fetch_url("https://example.com")
    summary = agent.summarize(text)
    return agent.final_answer(summary)


# ── Drive ─────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    question = " ".join(args) or "What's the latest on agentic security?"

    agent = ResearchAgent()
    answer = _maybe_run_with_langchain(agent, question)

    # Read the workflow trace and (when configured) register it as a canonical
    # workflow on TokenDNA.
    trace = get_agent_metadata()
    print(f"[tokendna] hops recorded: {len(trace['hops'])}")
    api_base = os.getenv("TOKENDNA_API_BASE")
    api_key = os.getenv("TOKENDNA_API_KEY")
    if api_base and api_key and trace["hops"]:
        try:
            req = urllib.request.Request(
                f"{api_base.rstrip('/')}/api/workflow/register",
                data=json.dumps({
                    "name": "research-flow",
                    "description": "research-bot canonical chain",
                    "hops": trace["hops"],
                }).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": api_key,
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                wf = json.loads(resp.read())
                print(f"[tokendna] registered workflow {wf.get('workflow_id')} "
                      f"with {len(wf.get('hops', []))} hops")
        except Exception as exc:
            print(f"[tokendna] workflow registration failed (buffered): {exc}")

    # Best-effort: drain anything the SDK buffered offline this run.
    flush = Client().flush()
    if flush["sent"]:
        print(f"[tokendna] flushed {flush['sent']} buffered events "
              f"({flush['buffered']} still pending)")

    return 0 if answer else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
