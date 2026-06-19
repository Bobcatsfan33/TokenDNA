/*
 * Offline demo fixture for the Trust Graph. Loaded locally (no network). The
 * host pages prefer live API data; this is the fallback so the graph is never
 * blank when the API is empty or unreachable. Shape mirrors the real endpoints:
 *   /api/graph/stats · /api/graph/data · /api/graph/anomalies · /api/intent/matches
 */
(function (global) {
  "use strict";

  function n(id, label, type) { return { node_id: id, label: label, node_type: type }; }
  function e(s, d, type, w, sl, dl, st, dt) {
    return { src_node: s, dst_node: d, edge_type: type, weight: w || 1,
      src_label: sl, dst_label: dl, src_type: st, dst_type: dt };
  }

  var nodes = [
    n("tenant-acme", "acme", "tenant"),
    n("iss-root", "acme-root-ca", "issuer"),
    n("iss-int", "acme-intermediate", "issuer"),
    n("agent-triage", "triage-agent", "agent"),
    n("agent-billing", "billing-agent", "agent"),
    n("agent-research", "research-agent", "agent"),
    n("agent-rogue", "rogue-scraper", "agent"),
    n("tool-db", "postgres-readonly", "tool"),
    n("tool-s3", "s3-exporter", "tool"),
    n("tool-email", "email-sender", "tool"),
    n("mcp-files", "filesystem-mcp", "mcp_server"),
    n("mcp-web", "web-fetch-mcp", "mcp_server"),
    n("life-active", "active", "lifecycle_state"),
    n("life-quar", "quarantined", "lifecycle_state"),
  ];

  // verifier mass attached to triage-agent — demonstrates clustering (×N badge)
  for (var i = 1; i <= 9; i++) nodes.push(n("ver-t" + i, "attest:verifier-t" + i, "verifier"));
  for (var j = 1; j <= 6; j++) nodes.push(n("ver-b" + j, "attest:verifier-b" + j, "verifier"));
  for (var k = 1; k <= 5; k++) nodes.push(n("ver-r" + k, "attest:verifier-r" + k, "verifier"));

  var edges = [
    e("tenant-acme", "iss-root", "owns", 1, "acme", "acme-root-ca", "tenant", "issuer"),
    e("iss-root", "iss-int", "issues", 1, "acme-root-ca", "acme-intermediate", "issuer", "issuer"),
    e("iss-int", "agent-triage", "issued_to", 3, "acme-intermediate", "triage-agent", "issuer", "agent"),
    e("iss-int", "agent-billing", "issued_to", 2, "acme-intermediate", "billing-agent", "issuer", "agent"),
    e("iss-int", "agent-research", "issued_to", 2, "acme-intermediate", "research-agent", "issuer", "agent"),
    e("iss-int", "agent-rogue", "issued_to", 1, "acme-intermediate", "rogue-scraper", "issuer", "agent"),
    e("agent-triage", "tool-db", "invokes", 5, "triage-agent", "postgres-readonly", "agent", "tool"),
    e("agent-triage", "mcp-files", "invokes", 4, "triage-agent", "filesystem-mcp", "agent", "mcp_server"),
    e("agent-billing", "tool-email", "invokes", 3, "billing-agent", "email-sender", "agent", "tool"),
    e("agent-billing", "tool-db", "invokes", 2, "billing-agent", "postgres-readonly", "agent", "tool"),
    e("agent-research", "mcp-web", "invokes", 4, "research-agent", "web-fetch-mcp", "agent", "mcp_server"),
    e("agent-research", "tool-s3", "invokes", 2, "research-agent", "s3-exporter", "agent", "tool"),
    e("agent-rogue", "tool-s3", "invokes", 6, "rogue-scraper", "s3-exporter", "agent", "tool"),
    e("agent-rogue", "mcp-web", "invokes", 5, "rogue-scraper", "web-fetch-mcp", "agent", "mcp_server"),
    e("agent-triage", "life-active", "in_state", 1, "triage-agent", "active", "agent", "lifecycle_state"),
    e("agent-rogue", "life-quar", "in_state", 1, "rogue-scraper", "quarantined", "agent", "lifecycle_state"),
  ];
  for (var a = 1; a <= 9; a++) edges.push(e("agent-triage", "ver-t" + a, "attested_by", 1, "triage-agent", "attest:verifier-t" + a, "agent", "verifier"));
  for (var b = 1; b <= 6; b++) edges.push(e("agent-billing", "ver-b" + b, "attested_by", 1, "billing-agent", "attest:verifier-b" + b, "agent", "verifier"));
  for (var c = 1; c <= 5; c++) edges.push(e("agent-research", "ver-r" + c, "attested_by", 1, "research-agent", "attest:verifier-r" + c, "agent", "verifier"));

  var nodeTypes = {};
  nodes.forEach(function (x) { nodeTypes[x.node_type] = (nodeTypes[x.node_type] || 0) + 1; });

  var anomalies = [
    { id: "an-1", anomaly_type: "policy_scope_modification", severity: "critical", subject_node: "rogue-scraper",
      detected_at: "2026-06-18T14:02:00Z", detail: "Agent self-modified its policy scope to add s3:* and bulk read permissions.",
      context: { added_scope: "s3:GetObject,s3:ListBucket", prior_scope: "none" } },
    { id: "an-2", anomaly_type: "cross_org_action_without_handshake", severity: "high", subject_node: "rogue-scraper",
      detected_at: "2026-06-18T14:05:30Z", detail: "Cross-org data pull attempted without a federated trust handshake.", context: { target_org: "beta-corp" } },
    { id: "an-3", anomaly_type: "permission_weight_drift", severity: "medium", subject_node: "research-agent",
      detected_at: "2026-06-18T13:40:00Z", detail: "Tool-invocation distribution drifted 38% from the 30-day behavioral baseline.", context: {} },
    { id: "an-4", anomaly_type: "agent_decommissioned", severity: "low", subject_node: "rogue-scraper",
      detected_at: "2026-06-18T14:10:00Z", detail: "Agent moved to quarantined lifecycle state pending review.", context: {} },
  ];

  var intent = [
    { id: "im-1", playbook_name: "MCP read → exfil chain", subject: "rogue-scraper", severity: "critical", confidence: 0.92,
      detected_at: "2026-06-18T14:06:00Z", first_event_at: "2026-06-18T14:01:00Z", last_event_at: "2026-06-18T14:06:00Z",
      detail: "web-fetch-mcp read followed by s3-exporter bulk write — classic stage→exfil sequence.",
      matched_events: ["evt-9001", "evt-9002", "evt-9003"], mitre: ["T1119", "T1567"] },
    { id: "im-2", playbook_name: "Privilege ladder", subject: "rogue-scraper", severity: "high", confidence: 0.81,
      detected_at: "2026-06-18T14:03:00Z", first_event_at: "2026-06-18T14:00:00Z", last_event_at: "2026-06-18T14:03:00Z",
      detail: "Sequential scope escalations culminating in an export permission grant.",
      matched_events: ["evt-8801", "evt-8802"], mitre: ["T1098"] },
    { id: "im-3", playbook_name: "Behavioral drift precursor", subject: "research-agent", severity: "medium", confidence: 0.64,
      detected_at: "2026-06-18T13:45:00Z", first_event_at: "2026-06-18T13:30:00Z", last_event_at: "2026-06-18T13:45:00Z",
      detail: "Tool mix diverging from baseline — early-warning signal, not yet an attack.",
      matched_events: ["evt-7700"], mitre: [] },
  ];

  global.TRUSTGRAPH_FIXTURE = {
    stats: { node_count: nodes.length, edge_count: edges.length, anomaly_count: anomalies.length, node_types: nodeTypes },
    graphData: { nodes: nodes, edges: edges },
    anomalies: anomalies,
    intent: intent,
  };
})(typeof window !== "undefined" ? window : this);
