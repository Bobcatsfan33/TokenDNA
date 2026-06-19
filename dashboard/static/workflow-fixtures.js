/*
 * Demo workflow fixtures for the Workflows page. Each is a STAGED agentic
 * pipeline (start → triage agent → sub-agents → tools/MCP → guardrail → end) —
 * a genuinely connected multi-rank DAG, so the layered left→right renderer
 * spreads it across the canvas like the reference "Example" image.
 *
 * This is local demo data (no network). Node types reuse the engine palette:
 * start, agent, tool, mcp_server, guardrail, end.
 */
(function (global) {
  "use strict";

  function n(id, label, type) { return { node_id: id, label: label, node_type: type }; }
  function e(s, d, type, sl, dl, st, dt) {
    return { src_node: s, dst_node: d, edge_type: type || "invokes",
      src_label: sl, dst_label: dl, src_type: st, dst_type: dt, weight: 1 };
  }

  // ── 1. Airline customer-service agent (à la the reference screenshot) ─────────
  function airline() {
    const nodes = [
      n("start", "request", "start"),
      n("triage", "Triage Agent", "agent"),
      n("web", "Web Search Agent", "agent"),
      n("flight", "Flight Agent", "agent"),
      n("faq", "FAQ Agent", "agent"),
      n("seat", "Seat Booking Agent", "agent"),
      n("t_search", "search_flights", "tool"),
      n("t_charge", "charge_card", "tool"),
      n("t_email", "send_email", "tool"),
      n("mcp_crm", "crm-mcp", "mcp_server"),
      n("guard", "Guardrail Check", "guardrail"),
      n("end", "response", "end"),
    ];
    const edges = [
      e("start", "triage", "routes", "request", "Triage Agent"),
      e("triage", "web", "delegates", "Triage Agent", "Web Search Agent", "agent", "agent"),
      e("triage", "flight", "delegates", "Triage Agent", "Flight Agent", "agent", "agent"),
      e("triage", "faq", "delegates", "Triage Agent", "FAQ Agent", "agent", "agent"),
      e("triage", "seat", "delegates", "Triage Agent", "Seat Booking Agent", "agent", "agent"),
      e("web", "t_search", "invokes", "Web Search Agent", "search_flights", "agent", "tool"),
      e("flight", "t_search", "invokes", "Flight Agent", "search_flights", "agent", "tool"),
      e("flight", "mcp_crm", "invokes", "Flight Agent", "crm-mcp", "agent", "mcp_server"),
      e("seat", "t_charge", "invokes", "Seat Booking Agent", "charge_card", "agent", "tool"),
      e("seat", "mcp_crm", "invokes", "Seat Booking Agent", "crm-mcp", "agent", "mcp_server"),
      e("faq", "t_email", "invokes", "FAQ Agent", "send_email", "agent", "tool"),
      e("t_search", "guard", "checks", "search_flights", "Guardrail Check", "tool", "guardrail"),
      e("t_charge", "guard", "checks", "charge_card", "Guardrail Check", "tool", "guardrail"),
      e("t_email", "guard", "checks", "send_email", "Guardrail Check", "tool", "guardrail"),
      e("mcp_crm", "guard", "checks", "crm-mcp", "Guardrail Check", "mcp_server", "guardrail"),
      e("guard", "end", "returns", "Guardrail Check", "response", "guardrail", "end"),
    ];
    return {
      id: "airline-agent-demo", name: "Airline Customer Service", framework: "OpenAI Agents SDK",
      source: "airline-agent-demo", scanned_at: "2026-06-19T09:12:00Z",
      counts: { agents: 5, tools: 3, mcp_servers: 1, vulnerabilities: 1 },
      graphData: { nodes: nodes, edges: edges },
      anomalies: [
        { id: "wf-a1", anomaly_type: "unauthenticated_mcp_server", severity: "high", subject_node: "crm-mcp",
          detected_at: "2026-06-19T09:13:00Z", detail: "crm-mcp accepts tool calls without verifying the agent attestation.", context: { port: 8931 } },
      ],
    };
  }

  // ── 2. Customer support copilot ──────────────────────────────────────────────
  function support() {
    const nodes = [
      n("start", "ticket", "start"),
      n("orch", "Orchestrator", "agent"),
      n("classify", "Classifier Agent", "agent"),
      n("retrieve", "Retriever Agent", "agent"),
      n("respond", "Responder Agent", "agent"),
      n("kb", "kb-mcp", "mcp_server"),
      n("ticket_tool", "ticket_update", "tool"),
      n("email_tool", "send_reply", "tool"),
      n("guard", "Policy Guardrail", "guardrail"),
      n("end", "resolution", "end"),
    ];
    const edges = [
      e("start", "orch", "routes", "ticket", "Orchestrator"),
      e("orch", "classify", "delegates", "Orchestrator", "Classifier Agent", "agent", "agent"),
      e("orch", "retrieve", "delegates", "Orchestrator", "Retriever Agent", "agent", "agent"),
      e("orch", "respond", "delegates", "Orchestrator", "Responder Agent", "agent", "agent"),
      e("retrieve", "kb", "invokes", "Retriever Agent", "kb-mcp", "agent", "mcp_server"),
      e("respond", "email_tool", "invokes", "Responder Agent", "send_reply", "agent", "tool"),
      e("classify", "ticket_tool", "invokes", "Classifier Agent", "ticket_update", "agent", "tool"),
      e("kb", "guard", "checks", "kb-mcp", "Policy Guardrail", "mcp_server", "guardrail"),
      e("ticket_tool", "guard", "checks", "ticket_update", "Policy Guardrail", "tool", "guardrail"),
      e("email_tool", "guard", "checks", "send_reply", "Policy Guardrail", "tool", "guardrail"),
      e("guard", "end", "returns", "Policy Guardrail", "resolution", "guardrail", "end"),
    ];
    return {
      id: "support-copilot-demo", name: "Support Copilot", framework: "LangGraph",
      source: "support-copilot-demo", scanned_at: "2026-06-19T08:40:00Z",
      counts: { agents: 4, tools: 2, mcp_servers: 1, vulnerabilities: 0 },
      graphData: { nodes: nodes, edges: edges }, anomalies: [],
    };
  }

  // ── 3. DevOps copilot ────────────────────────────────────────────────────────
  function devops() {
    const nodes = [
      n("start", "prompt", "start"),
      n("planner", "Planner Agent", "agent"),
      n("code", "Code Agent", "agent"),
      n("test", "Test Agent", "agent"),
      n("deploy", "Deploy Agent", "agent"),
      n("gh", "github-mcp", "mcp_server"),
      n("k8s", "kubectl", "tool"),
      n("ci", "ci_runner", "tool"),
      n("guard", "Deploy Guardrail", "guardrail"),
      n("end", "release", "end"),
    ];
    const edges = [
      e("start", "planner", "routes", "prompt", "Planner Agent"),
      e("planner", "code", "delegates", "Planner Agent", "Code Agent", "agent", "agent"),
      e("planner", "test", "delegates", "Planner Agent", "Test Agent", "agent", "agent"),
      e("planner", "deploy", "delegates", "Planner Agent", "Deploy Agent", "agent", "agent"),
      e("code", "gh", "invokes", "Code Agent", "github-mcp", "agent", "mcp_server"),
      e("test", "ci", "invokes", "Test Agent", "ci_runner", "agent", "tool"),
      e("deploy", "k8s", "invokes", "Deploy Agent", "kubectl", "agent", "tool"),
      e("gh", "guard", "checks", "github-mcp", "Deploy Guardrail", "mcp_server", "guardrail"),
      e("ci", "guard", "checks", "ci_runner", "Deploy Guardrail", "tool", "guardrail"),
      e("k8s", "guard", "checks", "kubectl", "Deploy Guardrail", "tool", "guardrail"),
      e("guard", "end", "returns", "Deploy Guardrail", "release", "guardrail", "end"),
    ];
    return {
      id: "devops-copilot-demo", name: "DevOps Copilot", framework: "CrewAI",
      source: "devops-copilot-demo", scanned_at: "2026-06-19T07:55:00Z",
      counts: { agents: 4, tools: 2, mcp_servers: 1, vulnerabilities: 1 },
      graphData: { nodes: nodes, edges: edges },
      anomalies: [
        { id: "wf-d1", anomaly_type: "excessive_scope", severity: "medium", subject_node: "Deploy Agent",
          detected_at: "2026-06-19T07:58:00Z", detail: "Deploy Agent holds cluster-admin on kubectl — broader than its task requires.", context: {} },
      ],
    };
  }

  global.WORKFLOW_FIXTURES = [airline(), support(), devops()];
})(typeof window !== "undefined" ? window : this);
