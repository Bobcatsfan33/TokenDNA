#!/usr/bin/env python3
"""
TokenDNA policy regression gate.

Replays recent decision-audit records against a candidate policy bundle config
and fails when action delta exceeds a configurable threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.identity import decision_audit
from modules.identity import policy_bundles


def _load_candidate_config(path: str | None, inline_json: str | None) -> dict[str, Any]:
    if inline_json:
        parsed = json.loads(inline_json)
        if not isinstance(parsed, dict):
            raise ValueError("candidate-json must decode to an object")
        return parsed
    if path:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("candidate file must contain a JSON object")
        return payload
    return {}


def run(
    *,
    tenant_id: str,
    candidate_config: dict[str, Any],
    sample_size: int = 100,
    max_action_delta_pct: float = 5.0,
    min_samples: int = 10,
) -> dict[str, Any]:
    decision_audit.init_db()
    policy_bundles.init_db()

    page = decision_audit.list_decisions_paginated(
        tenant_id=tenant_id,
        page_size=min(max(sample_size, 1), 500),
        cursor=None,
        source_endpoint=None,
    )
    audits = page.get("items") or []
    sample_count = len(audits)
    if sample_count < max(1, int(min_samples)):
        return {
            "ok": False,
            "failed_count": 1,
            "reason": "insufficient_sample_size",
            "sample_count": sample_count,
            "minimum_required": int(min_samples),
            "checks": [
                {
                    "name": "sample_size_gate",
                    "ok": False,
                    "detail": f"sample_count={sample_count} minimum_required={min_samples}",
                }
            ],
        }

    changed = 0
    changed_examples: list[dict[str, Any]] = []
    expected_action = str(candidate_config.get("expected_action", "")).strip().lower()
    for record in audits:
        replay = decision_audit.replay_decision(record=record, policy_bundle_config=candidate_config)
        diff = replay.get("diff") or {}
        replay_action = str((replay.get("replay_decision") or {}).get("action", "")).strip().lower()
        reasons_added = [str(v) for v in (diff.get("reasons_added") or [])]
        material_change = bool(diff.get("action_changed")) or (
            expected_action and replay_action and replay_action != expected_action
        ) or ("policy_bundle_expected_action_mismatch" in reasons_added)
        if material_change:
            changed += 1
            if len(changed_examples) < 20:
                changed_examples.append(
                    {
                        "audit_id": replay.get("audit_id"),
                        "previous_action": diff.get("previous_action"),
                        "replay_action": replay_action or diff.get("replay_action"),
                        "reasons_added": reasons_added,
                        "reasons_removed": diff.get("reasons_removed"),
                        "expected_action": expected_action or None,
                    }
                )

    delta_pct = (changed / sample_count) * 100.0 if sample_count else 0.0
    threshold = max(0.0, float(max_action_delta_pct))
    ok = delta_pct <= threshold
    checks = [
        {
            "name": "action_delta_threshold",
            "ok": ok,
            "detail": f"delta_pct={round(delta_pct, 3)} threshold_pct={threshold}",
        },
        {
            "name": "sample_size_gate",
            "ok": True,
            "detail": f"sample_count={sample_count}",
        },
    ]
    return {
        "ok": ok,
        "failed_count": len([c for c in checks if not c["ok"]]),
        "tenant_id": tenant_id,
        "sample_count": sample_count,
        "changed_count": changed,
        "action_delta_pct": round(delta_pct, 4),
        "threshold_pct": threshold,
        "checks": checks,
        "changed_examples": changed_examples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TokenDNA policy regression gate")
    parser.add_argument("--tenant-id", default=os.getenv("POLICY_REGRESSION_TENANT_ID", "dev-tenant"))
    parser.add_argument("--candidate-file", default=os.getenv("POLICY_REGRESSION_CANDIDATE_FILE"))
    parser.add_argument("--candidate-json", default=os.getenv("POLICY_REGRESSION_CANDIDATE_JSON"))
    parser.add_argument("--sample-size", type=int, default=int(os.getenv("POLICY_REGRESSION_SAMPLE_SIZE", "100")))
    parser.add_argument(
        "--max-action-delta-pct",
        type=float,
        default=float(os.getenv("POLICY_REGRESSION_MAX_ACTION_DELTA_PCT", "5.0")),
    )
    parser.add_argument("--min-samples", type=int, default=int(os.getenv("POLICY_REGRESSION_MIN_SAMPLES", "10")))
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when checks fail")
    args = parser.parse_args()

    try:
        candidate = _load_candidate_config(args.candidate_file, args.candidate_json)
        report = run(
            tenant_id=args.tenant_id,
            candidate_config=candidate,
            sample_size=args.sample_size,
            max_action_delta_pct=args.max_action_delta_pct,
            min_samples=args.min_samples,
        )
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "failed_count": 1, "error": f"exception:{exc}"}
        print(json.dumps(payload, indent=2, sort_keys=True))
        raise SystemExit(1 if args.strict else 0) from exc

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.strict and not report.get("ok", False):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
