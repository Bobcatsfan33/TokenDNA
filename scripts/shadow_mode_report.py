#!/usr/bin/env python3
"""
TokenDNA — Shadow Mode 14-Day Trial Report → HTML/PDF generator.

This is the close-of-trial deliverable: a single-file HTML report that
the prospect's CISO can read on their phone, forward to procurement,
and have rendered as a PDF for inclusion in a Series-B-style risk-
assessment binder. It compiles the same trial data ``generate_trial_report``
already returns into a presentation-ready document with executive
summary, findings table, blast-radius map, compliance-posture score,
and a "what your existing tooling missed" delta.

Output:
  /tmp/tokendna-trial-<tenant>-<utc>.html       single-file HTML
  /tmp/tokendna-trial-<tenant>-<utc>.pdf        optional, if --pdf is set
                                                 (requires `weasyprint`
                                                 in the running env)

Usage:

  # HTML only (no extra deps)
  python scripts/shadow_mode_report.py --tenant prospect-acme

  # HTML + PDF (needs weasyprint)
  pip install weasyprint
  python scripts/shadow_mode_report.py --tenant prospect-acme --pdf

  # Custom window (default 14 days)
  python scripts/shadow_mode_report.py --tenant prospect-acme --window-days 30

The script is read-only over the existing TokenDNA tables.  Safe to run
against a live customer instance.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.product.shadow_mode import generate_trial_report  # noqa: E402


# ── HTML rendering ───────────────────────────────────────────────────────────

_CSS = """
@page { size: letter; margin: 0.6in; }
* { box-sizing: border-box; }
body { font: 11pt/1.45 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       color: #1a2027; margin: 0; }
h1 { font-size: 22pt; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 14pt; margin: 28px 0 8px; padding-bottom: 4px;
     border-bottom: 1px solid #e3e7eb; letter-spacing: -0.005em; }
h3 { font-size: 11pt; margin: 14px 0 4px; color: #475568; text-transform: uppercase; letter-spacing: 0.04em; }
.subtitle { color: #5f6b78; margin: 0 0 24px; }
.cover { border-bottom: 1px solid #e3e7eb; padding-bottom: 18px; margin-bottom: 24px; }
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0 28px; }
.kpi { background: #f6f8fa; border: 1px solid #e3e7eb; border-radius: 6px; padding: 12px; }
.kpi .v { font-size: 20pt; font-weight: 700; line-height: 1; }
.kpi .l { font-size: 9pt; color: #5f6b78; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 10pt; }
th, td { padding: 8px 10px; border-bottom: 1px solid #eef1f4; text-align: left; vertical-align: top; }
th { font-weight: 600; color: #475568; background: #f6f8fa; font-size: 9pt;
     text-transform: uppercase; letter-spacing: 0.04em; }
.sev { display: inline-block; padding: 2px 8px; border-radius: 999px;
       font-size: 9pt; font-weight: 600; }
.sev-critical { background: #fee2e2; color: #991b1b; }
.sev-high     { background: #ffedd5; color: #9a3412; }
.sev-medium   { background: #fef3c7; color: #854d0e; }
.sev-low      { background: #dcfce7; color: #166534; }
.muted { color: #5f6b78; }
.pill  { display: inline-block; padding: 2px 8px; border-radius: 4px;
         background: #eef2ff; color: #3730a3; font-size: 9pt; font-weight: 600; }
.delta-bar { background: #f6f8fa; border-left: 3px solid #3b82f6;
             padding: 10px 14px; margin: 8px 0 18px; font-size: 10pt; }
.fp { font-family: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
      font-size: 9pt; color: #475568; word-break: break-all; }
footer { margin-top: 48px; padding-top: 14px; border-top: 1px solid #e3e7eb;
         color: #8a939c; font-size: 9pt; display: flex; justify-content: space-between; }
"""


def _sev_badge(sev: str) -> str:
    cls = f"sev-{sev.lower()}"
    return f'<span class="sev {cls}">{sev.upper()}</span>'


def _row(cells: list[str]) -> str:
    return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def _kpi(value: Any, label: str) -> str:
    return f'<div class="kpi"><div class="v">{value}</div><div class="l">{label}</div></div>'


def _esc(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<p class="muted">No findings in this trial window.</p>'
    rows = []
    for f in findings[:25]:
        rows.append(_row([
            _sev_badge(f.get("severity", "medium")),
            f"<strong>{_esc(f.get('title', '(untitled)'))}</strong><br>"
            f"<span class=\"muted\">{_esc(f.get('detail', ''))}</span>",
            _esc(f.get("agent_id", "—")),
            _esc(f.get("first_seen", "—")),
            _esc(f.get("count", "")),
        ]))
    return (
        "<table><thead><tr>"
        "<th>Severity</th><th>Finding</th><th>Agent</th><th>First seen</th><th>Count</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _delta_table(delta: dict[str, Any]) -> str:
    if not delta:
        return ""
    rows = []
    for k, v in delta.items():
        rows.append(_row([_esc(k.replace("_", " ").title()), _esc(v)]))
    return (
        '<table><thead><tr><th>Category</th><th>Caught by TokenDNA</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def render_html(report: dict[str, Any], tenant: str, window_days: int) -> str:
    s = report.get("summary", {})
    posture = report.get("compliance_posture", {})
    findings = report.get("findings", [])
    delta = report.get("vs_existing_tooling", {})
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>TokenDNA Shadow Trial — {_esc(tenant)}</title>
<style>{_CSS}</style></head><body>

<section class="cover">
  <h1>TokenDNA Shadow Mode Trial Report</h1>
  <p class="subtitle">Tenant: <strong>{_esc(tenant)}</strong> ·
     Window: <strong>{window_days} days</strong> ·
     Generated: {generated_at}</p>
  <div class="kpis">
    {_kpi(s.get('uis_events_processed', 0), 'UIS events analysed')}
    {_kpi(s.get('agents_baselined', 0), 'Agents baselined')}
    {_kpi(s.get('drift_episodes', 0), 'Drift episodes')}
    {_kpi(s.get('would_have_blocked', 0), 'Would-have-blocked')}
  </div>
</section>

<h2>Executive summary</h2>
<p>Over the {window_days}-day shadow-mode window, TokenDNA observed
<strong>{s.get('uis_events_processed', 0):,}</strong> agent actions across
<strong>{s.get('agents_baselined', 0)}</strong> distinct agent identities
in <strong>{_esc(tenant)}</strong>'s environment.  Operating in
observe-only mode (no enforcement), the engine surfaced
<strong>{s.get('drift_episodes', 0)}</strong> permission-drift episodes
and <strong>{s.get('would_have_blocked', 0)}</strong> policy violations
that would have been blocked under default policy guard rules.</p>

<p>The blast-radius engine identified
<strong>{s.get('high_blast_radius_agents', 0)}</strong> agents whose
permission scope, if compromised, would have reached production data
stores.  These are the candidates for the first wave of policy guard
hardening when this trial converts to enforcement mode.</p>

<h2>Compliance posture</h2>
<div class="kpis">
  {_kpi(posture.get('coverage_score', '—'), 'Coverage score')}
  {_kpi(posture.get('maturity_tier', '—'), 'Maturity tier')}
  {_kpi(posture.get('frameworks_covered', '—'), 'Frameworks covered')}
  {_kpi(posture.get('controls_passing', '—'), 'Controls passing')}
</div>
{_delta_table(posture.get('control_breakdown', {}))}

<h2>Top findings</h2>
{_findings_table(findings)}

<h2>What your existing tooling missed</h2>
<div class="delta-bar">
  Findings TokenDNA detected that your current SIEM / IAM / endpoint
  agent did not surface during the same window.  Categorised by control
  domain so the conversation goes straight to the right team owner.
</div>
{_delta_table(delta)}

<h2>Recommended next steps</h2>
<ol>
  <li><strong>Promote the trial to enforcement mode.</strong> Flip
  <code>SHADOW_MODE=false</code> on the tenant; the same engine begins
  blocking the same patterns it surfaced here.  Roll out per-agent via
  staged_rollout if you want a phased cutover.</li>
  <li><strong>Approve the top {min(5, len(findings))} policy_advisor
  suggestions</strong> — each one tightens a rule against a specific
  pattern observed in your traffic.  One-click approval in the
  dashboard.</li>
  <li><strong>Wire the high-blast-radius agents into HVIP.</strong>
  Add MFA assertion + DPoP binding for the
  {s.get('high_blast_radius_agents', 0)} agents above; covers NIST
  IA-2(1), IA-3, AC-6(5).</li>
  <li><strong>Activate Federated Agent Trust</strong> if any of the
  cross-org actions detected here are intentional but currently
  unattested.</li>
  <li><strong>Schedule the conversion conversation</strong> with your
  TokenDNA AE referencing this report.</li>
</ol>

<footer>
  <span>TokenDNA Shadow Mode Trial · {_esc(tenant)} · v1</span>
  <span class="fp">report_digest: {report.get('digest', '')[:32]}…</span>
</footer>

</body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--window-days", type=int, default=14)
    parser.add_argument("--out-dir", default="/tmp")
    parser.add_argument("--pdf", action="store_true",
                        help="Also write a PDF (requires weasyprint)")
    parser.add_argument("--json-out", default=None,
                        help="Optional: also write the raw JSON report alongside the HTML")
    args = parser.parse_args()

    report = generate_trial_report(
        tenant_id=args.tenant,
        window_days=args.window_days,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = pathlib.Path(args.out_dir) / f"tokendna-trial-{args.tenant}-{stamp}"
    html_path = base.with_suffix(".html")
    html = render_html(report, args.tenant, args.window_days)
    html_path.write_text(html)
    print(f"wrote {html_path}  ({html_path.stat().st_size:,} bytes)")

    if args.json_out:
        json_path = pathlib.Path(args.json_out)
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"wrote {json_path}")

    if args.pdf:
        try:
            from weasyprint import HTML  # noqa: PLC0415
        except ImportError:
            print("::warning:: --pdf requested but weasyprint is not installed; "
                  "run `pip install weasyprint` and re-run.", file=sys.stderr)
            return 0
        pdf_path = base.with_suffix(".pdf")
        HTML(string=html).write_pdf(str(pdf_path))
        print(f"wrote {pdf_path}  ({pdf_path.stat().st_size:,} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
