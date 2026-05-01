# Daily trial summary email template

Sent each working day during the 14-day shadow trial. Short, factual, no pitch — the trial is the pitch.

---

**Subject**: `[TokenDNA Trial · day {{n}}/14] {{anomaly_count}} new findings`

Hi {{contact_first_name}},

Day {{n}} of 14:

- **{{events_today}}** UIS events analysed (running total: {{events_total}})
- **{{anomalies_today}}** new anomalies (drift / scope / chain pattern / federation)
- **{{drift_today}}** new drift episodes
- **{{would_have_blocked_today}}** policy violations that would have been blocked under default rules

Top finding from today:

> **{{top_finding_severity}} · {{top_finding_title}}**
> {{top_finding_detail}}
> First seen: {{top_finding_first_seen}} · Agent: {{top_finding_agent_id}}

Full dashboard: {{dashboard_url}}

Replying with questions is fine — we read every one.

— {{your_first_name}}
