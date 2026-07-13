# TokenDNA + CrewAI

CrewAI organises agents as a "crew" with explicit roles. TokenDNA records each agent's `role` (e.g. `researcher`, `analyst`, `reviewer`) so cross-role permission expansion is detectable and the trust graph reflects the org chart you already designed in your `Crew()` definition.

## Install

```bash
pip install tokendna-sdk crewai
tokendna init --tenant-id <your-tenant> --api-key <your-key>
```

## Pattern — decorate the tool functions, pass into CrewAI tools

```python
from crewai import Agent, Task, Crew
from crewai.tools import tool
import tokendna_sdk as td

@td.identified(agent_id="crew-researcher", role="researcher")
def search(query: str) -> str:
    return f"results for {query}"

@td.identified(agent_id="crew-analyst", role="analyst")
def analyse(content: str) -> str:
    return f"analysis: {content[:80]}"

@td.identified(agent_id="crew-reviewer", role="reviewer")
def approve(memo: str) -> bool:
    return memo.startswith("APPROVED:")

researcher = Agent(
    role="Senior Research Analyst",
    goal="Surface RSA 2026 vendor positioning",
    backstory="You read every vendor blog so the team doesn't have to.",
    tools=[tool(search)],
    verbose=False,
)
analyst = Agent(
    role="Strategy Analyst",
    goal="Distil the research into a strategic memo",
    backstory="You write the brief that gets read by the CEO.",
    tools=[tool(analyse)],
    verbose=False,
)
reviewer = Agent(
    role="Approver",
    goal="Sign off on the memo or send it back",
    backstory="You're the brand voice; you approve or reject.",
    tools=[tool(approve)],
    verbose=False,
)

crew = Crew(
    agents=[researcher, analyst, reviewer],
    tasks=[
        Task(description="Research RSA 2026 themes", agent=researcher,
             expected_output="3-paragraph summary"),
        Task(description="Analyse the research", agent=analyst,
             expected_output="strategic memo"),
        Task(description="Approve the memo", agent=reviewer,
             expected_output="APPROVED: ... or REJECT: ..."),
    ],
)

result = crew.kickoff()
print(result)
```

What TokenDNA records:

- Three distinct `agent_id`s, each with their declared `role` from the decorator.
- The trust graph builds **role→tool** edges as the crew runs.
- A reviewer that suddenly calls `search` instead of `approve` triggers a `ROLE_BOUNDARY_VIOLATION` anomaly — TokenDNA enforces the role separation you encoded in the crew definition.

## Pattern — block the entire crew if any agent fails policy guard

```python
import tokendna_sdk as td

pre_verdict = td.client().pre_check_crew(
    agents=[
        {"agent_id": a.role.lower(), "tool_calls": [t.name for t in a.tools]}
        for a in crew.agents
    ],
)
if any(a["disposition"] == "BLOCK" for a in pre_verdict["per_agent"]):
    raise PermissionError("crew rejected by policy guard")
crew.kickoff()
```

Useful when a crew runs on a schedule and you want to fail fast rather than waste LLM credits on a kickoff that policy guard would have blocked downstream.

## Dashboard view

After a `crew.kickoff()` run:
- **Trust graph**: a clean bipartite graph with three role-nodes on one side and the tool names on the other. Edge thickness = call count.
- **Policy guard**: BLOCK decisions per agent, with the offending rule.
- **Compliance posture**: SOC 2 evidence package picks up the role-separation activity for AC-6 (Least Privilege).

## Multi-crew / parallel runs

If you fan out multiple crews from the same process, set `tenant_id` per crew so the trust graph stays segmented:

```python
@td.identified(agent_id="researcher", role="researcher", tenant_id="customer-acme")
def search(query): ...
```

The dashboard then filters per `tenant_id`.
