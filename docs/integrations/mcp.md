# TokenDNA + MCP (Model Context Protocol)

> This is the integration that matters most. MCP is your RSA 2026 differentiator: every other vendor checks "did this agent authenticate?", TokenDNA checks "is this MCP tool call **what the agent claims it is** and is the **chain of calls** consistent with this agent's intent?".

## Install

```bash
pip install tokendna-sdk mcp
tokendna init --tenant-id <your-tenant> --api-key <your-key>
```

## What you get that nobody else ships

| Existing vendors | TokenDNA |
|------------------|----------|
| Verify the MCP server's TLS cert | Verify it AND the agent's attestation cert |
| Allow/deny per tool name | Inspect parameters → flag forbidden patterns even on allowed tools |
| Log calls | Match call sequences against MCP chain patterns (e.g. `read_file → send_email`) — **CHAIN_PATTERN_MATCHED** is unique to TokenDNA |
| Per-call audit | Per-call audit + per-session anomaly correlation against the trust graph |

## Pattern 1 — instrument the MCP client

The cleanest place to plug in. Wrap your MCP `ClientSession.call_tool` so every tool call goes through TokenDNA's `mcp_inspector` first.

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import tokendna_sdk as td

async def run():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "your_mcp_server"],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Wrap call_tool with TokenDNA's MCP inspector
            original_call = session.call_tool

            async def inspected_call(tool_name: str, arguments: dict, **kw):
                verdict = await td.client_async().mcp_inspect(
                    agent_id="my-mcp-agent",
                    session_id=session.session_id,
                    tool_name=tool_name,
                    params=arguments,
                )
                if not verdict["allowed"]:
                    raise PermissionError(
                        f"MCP call blocked: {verdict['recommendation']}; "
                        f"violations={verdict['violations']}; "
                        f"chain_patterns={verdict['chain_patterns']}"
                    )
                return await original_call(tool_name, arguments, **kw)

            session.call_tool = inspected_call

            # Now every tool call goes through TokenDNA
            result = await session.call_tool("read_file", {"path": "/etc/safe.json"})
            print(result)

asyncio.run(run())
```

## Pattern 2 — the chain-pattern detector in action

This is the differentiator. Run two MCP calls in the same session — `read_file("/etc/secrets")` followed by `send_email(to="external@example.com")`. The first looks innocuous, the second looks innocuous; together they're a `read_then_exfil` chain pattern.

```python
# These are two perfectly valid MCP tool calls.  Each in isolation is fine.
await session.call_tool("read_file", {"path": "/etc/secrets"})
await session.call_tool("send_email", {
    "to": "external@example.com",
    "subject": "x",
    "body": "x",
})
```

In the dashboard you'll see, attached to that session:

```
MCP_CHAIN_PATTERN_MATCHED   pattern=read_then_exfil   confidence=1.00
  step 1: read_file(path=/etc/secrets)        @ 12:14:01.041
  step 2: send_email(to=external@example.com) @ 12:14:01.388

POLICY_GUARD: BLOCK           rule=CHAIN-EXFIL-01
```

The match is bounded-gap (default `CHAIN_PATTERN_MAX_GAP=3`, `CHAIN_PATTERN_WINDOW_SECONDS=3600`), so an attacker can't slip in a few decoy calls between the read and the exfil to evade detection.

## Pattern 3 — federated MCP across orgs

If your agent talks to an MCP server in another organisation (e.g. a partner's internal service), TokenDNA's Federated Agent Trust (FAT) model verifies that there's a valid `federation_trust` between your org and the target's, and BLOCKs the cross-org call if not.

```python
verdict = await td.client_async().mcp_inspect(
    agent_id="my-agent",
    session_id=session.session_id,
    tool_name="execute_query",
    params={"query": "SELECT ...", "target_org": "partner-corp"},
    federation_trust_id="trust-abc123",  # from /api/federation/trusts
)
```

If `federation_trust_id` is missing or revoked, the call is blocked with `CROSS_ORG_ACTION_WITHOUT_HANDSHAKE` (CRITICAL) in the trust graph and `CONST-06` in the policy guard.

## Pattern 4 — server-side: instrument your own MCP server

If you publish an MCP server (not just consume one), wrap your tool handlers so the server-side also reports to TokenDNA. The server then has the same drift / chain pattern protection as the client.

```python
from mcp.server.fastmcp import FastMCP
import tokendna_sdk as td

server = FastMCP("my-mcp-server")

@server.tool()
@td.identified(agent_id="mcp-server", role="tool-server")
async def query_db(sql: str) -> dict:
    # ... your impl
    return {"rows": []}
```

## Dashboard view

The MCP-specific widgets:

- **MCP inspections** — every `inspect_call` row with `clean / violation / chain_pattern / privilege_escalation` classification.
- **Chain patterns matched** — sessions with confirmed multi-step attack patterns.
- **Trust graph (MCP edges)** — agent → tool edges built from MCP calls. Cross-org edges are flagged red until a valid `federation_trust` is attached.
- **Cross-org calls** — federation handshake + ALLOW/BLOCK history.

## What this protects against (concrete)

- **Read-then-exfil**: agent reads a sensitive file then sends an email — blocked even if both calls are individually allowed.
- **Privilege ladder**: agent calls `execute_command(sudo …)` — flagged as privilege escalation regardless of session history.
- **Forbidden-param exfiltration**: agent calls `read_file({"write": "evil"})` — blocked because `write` is a forbidden param on `read_file` regardless of the agent's permissions.
- **Cross-org without handshake**: agent in org A calls a tool whose target field references org B with no active `federation_trust` — `CONST-06` BLOCK.
- **MCP tool spoofing**: agent claims to call `read_file` but the parameter shape doesn't match the registered tool profile — flagged by `mcp_inspector` even before the call dispatches.
