"""
Quickstart 3 — CrewAI callback.

Drives a two-step CrewAI flow through ``TokenDNACrewCallback`` and
prints the attestation receipt. CrewAI is imported lazily — the script
reads cleanly as documentation even without the extra installed.

Install::

    pip install "tokendna-sdk[crewai]"

Run::

    python examples/quickstart/crewai_workflow.py
"""

from __future__ import annotations

import sys

from tokendna_sdk.integrations.crewai import TokenDNACrewCallback


def main() -> int:
    try:
        from crewai import Agent, Crew, Task  # noqa: F401
    except ImportError as exc:
        print("CrewAI not installed — falling back to the callback-only demo.")
        print(f"(Install with: pip install \"tokendna-sdk[crewai]\")\n"
              f"Underlying error: {exc}\n")
        return _run_standalone()

    callback = TokenDNACrewCallback(
        agent_id="research-crew",
        scope=["docs:read", "docs:write"],
    )

    # Real CrewAI usage looks roughly like:
    #
    #     researcher = Agent(role="Researcher", ...)
    #     writer = Agent(role="Writer", ...)
    #     crew = Crew(
    #         agents=[researcher, writer],
    #         tasks=[Task(...), Task(...)],
    #         step_callback=callback,
    #     )
    #     result = crew.kickoff()
    #
    # We don't actually call the LLMs in this demo to keep the script
    # cost-free; we drive the callback directly with synthetic steps
    # so you can see what TokenDNA records.

    callback({"tool": "search_docs", "tool_input": {"query": "TokenDNA"}})
    callback({"tool": "summarize", "tool_input": {"chunks": 3}})
    callback.on_finish(result="Final report")

    print("CrewAI callback ran 2 steps + finalized — see "
          "~/.tokendna/events.jsonl for the trail.")
    return 0


def _run_standalone() -> int:
    """Fallback when CrewAI isn't installed: show what the callback
    sees and records anyway."""
    callback = TokenDNACrewCallback(agent_id="research-crew")
    callback({"tool": "demo_tool", "tool_input": {"x": 1}})
    callback.on_finish(result="ok")
    print("Standalone callback ran — see ~/.tokendna/events.jsonl for the trail.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
