"""
Quickstart 2 — native LangChain middleware.

Runs a tiny LangChain ReAct agent with ``TokenDNAMiddleware``
attached. Every model + tool hop lands in the JSONL trail (or your
configured TokenDNA tenant if ``TOKENDNA_URL`` is set).

Install::

    pip install "tokendna-sdk[langchain]"
    export OPENAI_API_KEY=...

Run::

    python examples/quickstart/langchain_agent.py

Notes
-----
The script defensively handles import errors so you can read it as
documentation even without the LangChain extra installed. Real usage:
remove the try/except wrapping below and run with the extras pinned.
"""

from __future__ import annotations

import os
import sys

from tokendna_sdk import make_client
from tokendna_sdk.integrations.langchain import TokenDNAMiddleware


def main() -> int:
    try:
        from langchain_openai import ChatOpenAI
        from langgraph.prebuilt import create_react_agent
    except ImportError as exc:
        print("LangChain not installed. Run:")
        print('  pip install "tokendna-sdk[langchain]" langchain-openai langgraph')
        print(f"\nUnderlying error: {exc}")
        return 1

    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY missing — set it to run this demo.")
        return 1

    def search_web(query: str) -> str:
        """Tiny mock 'tool' so the agent has something to call."""
        return f"results for {query}: A, B, C"

    middleware = TokenDNAMiddleware(
        agent_id="research-bot",
        scope=["web:read"],
        # enforce=True would raise on policy denies; left False to keep
        # the wedge contract for the demo.
        enforce=False,
    )

    agent = create_react_agent(
        model=ChatOpenAI(model="gpt-4o-mini", temperature=0),
        tools=[search_web],
        middleware=[middleware],
    )

    result = agent.invoke({"messages": [
        {"role": "user", "content": "Find three facts about TokenDNA."},
    ]})

    print("Agent output:")
    print(result["messages"][-1].content)
    print()

    client = make_client()
    health = client.health()
    print(f"Client mode: {health['mode']}")
    if health["mode"] == "local":
        print(f"Signed events recorded to {health.get('events_path')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
