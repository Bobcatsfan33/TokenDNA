"""
``tokendna`` CLI — pragmatic devops surface.

Today's commands
----------------
``tokendna policy plan <bundle.json>``      Dry-run a policy bundle against
                                             the configured tenant by POSTing
                                             to /api/policy/bundles/simulate.
                                             Emits a JSON diff to stdout.
``tokendna policy apply <bundle_id>``       Activate a previously-uploaded
                                             policy bundle.
``tokendna replay <decision_id>``           Replay a recorded decision via
                                             /api/decision-audit/{id}/replay.
``tokendna config show``                    Print the active SDK config (with
                                             API key redacted).

The CLI deliberately never imports anything heavy at module-load time so
``tokendna --help`` stays fast even in CI containers without network.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from .config import current_config


logger = logging.getLogger(__name__)


def _client():
    from .client import Client  # noqa: PLC0415
    return Client()


def _print_json(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True))
    sys.stdout.write("\n")


def cmd_config_show(args: argparse.Namespace) -> int:  # noqa: ARG001
    cfg = current_config().to_dict()
    cfg["api_key_present"] = bool(current_config().api_key)
    _print_json(cfg)
    return 0


def cmd_policy_plan(args: argparse.Namespace) -> int:
    try:
        with open(args.bundle, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"failed to load bundle: {exc}\n")
        return 2
    cli = _client()
    out = cli.post("/api/policy/bundles/simulate", {"bundle": bundle})
    _print_json(out)
    return 0


def cmd_policy_apply(args: argparse.Namespace) -> int:
    cli = _client()
    out = cli.post(
        f"/api/policy/bundles/{args.bundle_id}/activate",
        {"reason": args.reason or "applied via tokendna CLI"},
    )
    _print_json(out)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    cli = _client()
    out = cli.post(f"/api/decision-audit/{args.decision_id}/replay", {})
    _print_json(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tokendna")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cfg = sub.add_parser("config", help="Inspect SDK configuration.")
    cfg_sub = cfg.add_subparsers(dest="config_cmd", required=True)
    cfg_show = cfg_sub.add_parser("show", help="Print active configuration.")
    cfg_show.set_defaults(func=cmd_config_show)

    pol = sub.add_parser("policy", help="Plan / apply policy bundles.")
    pol_sub = pol.add_subparsers(dest="policy_cmd", required=True)

    plan = pol_sub.add_parser("plan", help="Dry-run a policy bundle.")
    plan.add_argument("bundle", help="Path to bundle JSON.")
    plan.set_defaults(func=cmd_policy_plan)

    apply_p = pol_sub.add_parser("apply", help="Activate a policy bundle by id.")
    apply_p.add_argument("bundle_id")
    apply_p.add_argument("--reason", help="Audit reason for activation.")
    apply_p.set_defaults(func=cmd_policy_apply)

    rep = sub.add_parser("replay", help="Replay a recorded decision.")
    rep.add_argument("decision_id")
    rep.set_defaults(func=cmd_replay)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
