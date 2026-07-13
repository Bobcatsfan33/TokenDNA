#!/usr/bin/env python3
"""
TokenDNA — Shadow Trial Report CLI

Render the "what we found" report for a 14-day shadow-mode trial.  Walks
the existing TokenDNA tables (read-only) and produces a human-readable
finding bundle suitable for embedding in a customer-facing PDF or
emailing as the close-of-trial artifact.

Usage
─────

  # Print the trial report for tenant ``prospect-acme`` (last 14 days).
  python scripts/shadow_trial_report.py --tenant prospect-acme

  # Custom window.
  python scripts/shadow_trial_report.py --tenant prospect-acme --window-days 30

  # JSON output instead of human-readable.
  python scripts/shadow_trial_report.py --tenant prospect-acme --json

  # Save to a file (handy for piping into PDF generation).
  python scripts/shadow_trial_report.py --tenant prospect-acme --json \\
      --output /tmp/prospect-acme-trial.json

The report is read-only.  Safe to invoke against a live customer instance.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.product.shadow_mode import generate_trial_report  # noqa: E402


# ── Rendering ────────────────────────────────────────────────────────────────

_SEVERITY_BADGE = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH    ",
    "medium":   "🟡 MEDIUM  ",
    "low":      "🟢 LOW     ",
    "info":     "🔵 INFO    ",
}


def _render_text(report) -> str:
    d = report.as_dict()
    out: list[str] = []
    push = out.append
    push("=" * 72)
    push(f"  TokenDNA Shadow Mode Trial Report")
    push(f"  Tenant:   {d['tenant_id']}")
    push(f"  Window:   last {d['window_days']} days")
    push(f"  Generated: {d['generated_at']}")
    push("=" * 72)

    push("")
    push("  ── Headline findings ─────────────────────────────────────────────────")
    for f in d["top_findings"]:
        badge = _SEVERITY_BADGE.get(f["severity"], "         ")
        push(f"    {badge}  {f['title']}  (count: {f['count']})")
        # Wrap summary at ~70 cols inside the indent.
        for chunk in _wrap(f["summary"], width=66):
            push(f"          {chunk}")
        push("")

    push("  ── Volume ────────────────────────────────────────────────────────────")
    push(f"    Events observed:        {d['events_observed']:>8,}")
    push(f"    Unique agents observed: {d['unique_agents_observed']:>8,}")

    push("")
    push("  ── Trust graph anomalies ─────────────────────────────────────────────")
    if d["anomalies_by_type"]:
        for atype, n in sorted(d["anomalies_by_type"].items(),
                               key=lambda kv: -kv[1]):
            push(f"    {atype:<40}  {n:>5}")
    else:
        push("    (none in window)")

    push("")
    push("  ── Policy enforcement ────────────────────────────────────────────────")
    push(f"    BLOCKED violations:    {d['policy_violations_blocked']:>5}")
    push(f"    OPEN  violations:      {d['policy_violations_open']:>5}")

    push("")
    push("  ── Permission drift ──────────────────────────────────────────────────")
    push(f"    Total drift alerts:    {d['drift_alerts_total']:>5}")
    push(f"    Critical (≥3x growth): {d['drift_alerts_critical']:>5}")

    push("")
    push("  ── MCP runtime inspection ────────────────────────────────────────────")
    push(f"    Chain-pattern matches: {d['mcp_chain_pattern_matches']:>5}")

    push("")
    push("  ── Federated agent trust ─────────────────────────────────────────────")
    push(f"    Active federation trusts: {d['federation_trusts_active']:>5}")
    push(f"    Cross-org actions blocked: {d['cross_org_blocks']:>5}")

    push("")
    push("  ── Top blast-radius agents ───────────────────────────────────────────")
    if d["high_blast_radius_agents"]:
        for row in d["high_blast_radius_agents"]:
            push(f"    {row['agent']:<40}  reach={row['reach']}")
    else:
        push("    (no agents with non-zero blast in window)")

    push("")
    push("=" * 72)
    push("  Next step: convert this trial into a paid pilot.")
    push("  Schedule a follow-up at https://tokendna.example.com/contact")
    push("=" * 72)
    push("")
    return "\n".join(out)


def _wrap(text: str, *, width: int) -> list[str]:
    """Trivial whitespace-aware wrap; avoids the textwrap dep on punctuation."""
    out: list[str] = []
    line = ""
    for word in text.split():
        if len(line) + len(word) + 1 > width and line:
            out.append(line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        out.append(line)
    return out


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tenant", required=True,
                        help="Tenant ID to report on")
    parser.add_argument("--window-days", type=int, default=14,
                        help="Trial window length (default 14)")
    parser.add_argument("--db-path", default=None,
                        help="Override DATA_DB_PATH for this run")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of human-readable text")
    parser.add_argument("--output", default=None,
                        help="Write to a file instead of stdout")
    args = parser.parse_args()

    if args.db_path:
        os.environ["DATA_DB_PATH"] = args.db_path

    report = generate_trial_report(
        tenant_id=args.tenant,
        window_days=args.window_days,
        db_path=args.db_path,
    )

    if args.json:
        payload = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    else:
        payload = _render_text(report)

    if args.output:
        pathlib.Path(args.output).write_text(payload)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
