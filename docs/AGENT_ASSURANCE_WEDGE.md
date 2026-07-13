# Agent Assurance Wedge

TokenDNA should read as one product before it reads as a collection of engines:

> Agent identity assurance for the AI workforce.

The acquisition-friendly wedge is simple:

1. **Identify**: prove this is a real agent identity, not just a bearer token.
2. **Authorize**: decide whether the agent is allowed to do this action on this resource.
3. **Investigate**: detect compromise signals and show the blast-radius implications.
4. **Contain**: recommend credential, session, policy, and asset-owner response steps.

The repo still contains deeper engines such as passports, policy guard,
permission drift, behavioral DNA, trust graph, and blast-radius simulation. The
buyer-facing surface should package those engines behind a single verdict:

```json
{
  "outcome": "allow | review | block",
  "identity_status": "verified | unverified | revoked",
  "policy_status": "allowed | denied",
  "compromise_status": "clear | suspected | compromised",
  "blast_radius": {
    "impact_score": 72,
    "risk_tier": "high",
    "total_nodes_reached": 9,
    "affected_assets": ["payments-db", "invoice-tool"]
  },
  "remediation": [
    "suspend the agent and revoke active sessions while the signal is investigated",
    "notify owners of affected assets and run the blast-radius containment plan"
  ]
}
```

## What To Simplify Next

| Current surface | Buyer-facing product surface |
| --- | --- |
| Passport, attestation, verifier reputation | Agent identity proof |
| Policy guard, policy bundles, ABAC | Agent authorization decision |
| Permission drift, behavioral DNA, MCP inspector, honeytokens | Compromise detection |
| Trust graph, blast-radius simulator, response actions | Impact analysis and containment |

The implementation starter is `modules.identity.agent_assurance`, a pure facade
that returns the single verdict an IDP, CNAPP, XDR, SIEM, or agent-security
platform would want to call before or during agent execution.
