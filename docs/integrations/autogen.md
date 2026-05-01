# TokenDNA + AutoGen

Microsoft's AutoGen orchestrates multi-agent conversations where one agent's output is another's input. TokenDNA's job is to:

1. Record each agent's identity + tool calls (UIS events).
2. Detect when agent A starts calling tools that historically only agent B called (cross-role drift).
3. Block self-modification attempts inside the conversation loop.

## Install

```bash
pip install tokendna-sdk pyautogen openai
tokendna init --tenant-id <your-tenant> --api-key <your-key>
```

## Pattern — wrap the function map handed to UserProxyAgent

```python
import autogen
import tokendna_sdk as td

@td.identified(agent_id="ag-coder", role="coder")
def write_code(spec: str) -> str:
    return f"def solve(): ...  # impl for {spec}"

@td.identified(agent_id="ag-reviewer", role="reviewer")
def lint(code: str) -> dict:
    return {"errors": [], "warnings": ["consider type hints"]}

@td.identified(agent_id="ag-runner", role="runner")
def execute(code: str) -> dict:
    return {"stdout": "...", "exit_code": 0}

llm_config = {"config_list": autogen.config_list_from_json("OAI_CONFIG_LIST")}

coder = autogen.AssistantAgent(name="Coder", llm_config=llm_config)
reviewer = autogen.AssistantAgent(name="Reviewer", llm_config=llm_config)
user = autogen.UserProxyAgent(
    name="User",
    code_execution_config={"work_dir": "/tmp", "use_docker": False},
    function_map={
        "write_code": write_code,
        "lint":       lint,
        "execute":    execute,
    },
)

groupchat = autogen.GroupChat(
    agents=[user, coder, reviewer],
    messages=[],
    max_round=8,
)
manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=llm_config)
user.initiate_chat(manager, message="Write a function that returns the nth Fibonacci.")
```

The decorator catches every function-map dispatch — TokenDNA sees `ag-coder.write_code(...)`, `ag-reviewer.lint(...)`, etc., and the trust graph builds the conversation topology in real time.

## Pattern — enforce role separation

AutoGen's group-chat manager can pick any registered agent for the next turn. If your `coder` agent suddenly invokes `lint`, you have a role-boundary violation. Wire it up:

```python
import tokendna_sdk as td

original_select = manager.groupchat.select_speaker
def guarded_select(last_speaker, selector):
    next_speaker = original_select(last_speaker, selector)
    verdict = td.client().role_check(
        agent_id=next_speaker.name.lower(),
        proposed_tools=list(user.function_map.keys()),
    )
    if verdict.get("violations"):
        raise autogen.OpenAIException(
            f"role boundary violation: {next_speaker.name} -> {verdict['violations']}"
        )
    return next_speaker
manager.groupchat.select_speaker = guarded_select
```

This converts what would otherwise be a silent permission drift over many turns into an immediate exception you can surface to the user.

## Dashboard view

After running the example above:
- **UIS events**: one per function dispatch — interleaved coder/reviewer/runner activity.
- **Trust graph**: three agent nodes, three tool nodes, edges weighted by dispatch count. Conversation topology is implicit in the edge weights.
- **Drift score**: per agent, climbs if the LLM-driven group chat starts pushing tools to agents that don't usually call them.
- **Policy guard**: any `CONST-01` self-modification (e.g. coder asking the runner to grant it execute privileges on a new path) shows up here.

## Async / streaming

AutoGen's async path (`a_initiate_chat`) is supported via `td.identified_async`. The decorator detects the coroutine and uses the SDK's async UIS emit path so you don't double-block the event loop.

```python
@td.identified_async(agent_id="ag-streamer", role="streamer")
async def stream_response(prompt: str): ...
```
