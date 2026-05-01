# Direct-outreach intro email template

Use when there is no channel-partner intro. Subject and tone are intentionally short — the goal is to clear a 30-second skim.

---

**Subject**: TokenDNA — runtime layer for the agents you're already running

Hi {{first_name}},

You're running AI agents in production. The identity / runtime story for those agents isn't fully solved by the IAM tools you have today.

Three things existing vendors miss:

1. An agent silently expands its own permission scope mid-session. (The CrowdStrike F50 pattern.)
2. MCP chain attacks: `read_file → send_email`. Each call is allowed; the chain is exfiltration.
3. Cross-org agent action without a federation handshake. Today, this gets logged. We block it.

Most of what we build sits *underneath* your existing IAM stack — we don't replace it, we make it actually work for agents.

If a 14-day shadow-mode trial against a non-prod agent fleet of yours sounds useful, here's my calendar: {{calendly}}.

{{signature}}
