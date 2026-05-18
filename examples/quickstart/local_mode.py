"""
Quickstart 1 — zero-config local mode.

Runs entirely against ``~/.tokendna/events.jsonl``. No server, no env
vars, no extras. Useful for the first 60 seconds after
``pip install tokendna-sdk``.

Run::

    python examples/quickstart/local_mode.py
"""

from __future__ import annotations

import json
from pathlib import Path

from tokendna_sdk import (
    get_agent_metadata,
    identified,
    make_client,
    tool,
)


@identified("research-bot", scope=["web:read", "summarize"])
class ResearchAgent:
    @tool("search_web", target="example.com")
    def search_web(self, query: str) -> list[str]:
        # Pretend we hit a search engine.
        return [f"result-{i} for {query}" for i in range(3)]

    @tool("summarize")
    def summarize(self, hits: list[str]) -> str:
        return f"Summary of {len(hits)} hits: " + "; ".join(hits[:2])


def main() -> None:
    agent = ResearchAgent()
    hits = agent.search_web("token dna sdk")
    summary = agent.summarize(hits)
    print(f"Agent produced: {summary}")

    # Workflow trace assembled by the @tool decorator.
    trace = get_agent_metadata()
    print(f"\nWorkflow trace ({len(trace['hops'])} hops):")
    for hop in trace["hops"]:
        print(f"  {hop['actor']} -> {hop['action']} (target={hop['target']!r})")

    # The signed JSONL trail is the receipt for everything above.
    client = make_client()
    health = client.health()
    print(f"\nClient mode: {health['mode']}")
    if health["mode"] == "local":
        path = Path(health["events_path"])
        n_lines = sum(1 for _ in path.open()) if path.exists() else 0
        print(f"Signed JSONL trail: {path} ({n_lines} events recorded)")
        if n_lines:
            print("\nLast event (pretty-printed):")
            last = path.read_text().splitlines()[-1]
            print(json.dumps(json.loads(last), indent=2))


if __name__ == "__main__":
    main()
