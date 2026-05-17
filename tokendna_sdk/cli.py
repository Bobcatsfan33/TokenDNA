"""
``tokendna`` CLI — pragmatic devops surface.

Commands
--------
``tokendna config show``
    Print the active SDK config (with API key redacted).

``tokendna status``
    Show the active client mode, recent event count, baseline summary
    for every known agent. Local-friendly: works without any server.

``tokendna verify <agent_id> <action> [--target T] [--scope S ...]``
    Run a single policy verify and print the verdict.

``tokendna demo [--agent-id ID]``
    Drive a synthetic agent run end-to-end (tool calls + attestation).
    Useful for shaking out a fresh install — works against local mode
    or a configured remote endpoint.

``tokendna baseline show <agent_id>``
    Print the rolling behavioral baseline for an agent.

``tokendna policy plan <bundle.json>``     (server-mode only)
    Dry-run a policy bundle.

``tokendna policy apply <bundle_id>``      (server-mode only)
    Activate a previously-uploaded policy bundle.

``tokendna replay <decision_id>``          (server-mode only)
    Replay a recorded decision.

The CLI deliberately never imports anything heavy at module-load time
so ``tokendna --help`` stays fast even in CI containers without network.
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
    """Low-level transport used by ``policy`` / ``replay``."""
    from .client import Client  # noqa: PLC0415
    return Client()


def _smart_client():
    """High-level client (remote or local) used by ``status`` /
    ``verify`` / ``demo`` / ``baseline``."""
    from . import make_client  # noqa: PLC0415
    return make_client()


def _print_json(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True, default=str))
    sys.stdout.write("\n")


# ── existing commands ────────────────────────────────────────────────────────

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


# ── v0.2 commands ────────────────────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> int:  # noqa: ARG001
    """Print mode, recent event count, baseline summary for every agent."""
    client = _smart_client()
    out: dict[str, Any] = {"health": client.health()}
    if hasattr(client, "read_events"):
        events = client.read_events(limit=10)
        out["recent_events"] = len(events)
        out["recent_event_types"] = sorted({
            e["_body"].get("type", "post") for e in events
        })
    try:
        from pathlib import Path  # noqa: PLC0415
        from ._core.behavioral import BaselineStore  # noqa: PLC0415
        root = current_config().local_root or str(Path.home() / ".tokendna")
        store = BaselineStore(f"{root}/baselines.json")
        store._load()
        out["baselines"] = sorted(store._cache.keys())
    except Exception:  # noqa: BLE001
        out["baselines"] = []
    _print_json(out)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    client = _smart_client()
    try:
        verdict = client.verify(
            args.agent_id, args.action,
            target=args.target or "",
            scope=list(args.scope or []),
            score=float(args.score),
        )
    except Exception as exc:  # noqa: BLE001
        _print_json({
            "decision": "error",
            "reason": type(exc).__name__,
            "message": str(exc),
        })
        return 1
    _print_json(verdict.to_dict())
    return 0 if verdict.allowed else 1


def cmd_demo(args: argparse.Namespace) -> int:
    from pathlib import Path  # noqa: PLC0415

    from ._core.behavioral import BaselineStore  # noqa: PLC0415
    from ._core.verifier import Verifier  # noqa: PLC0415

    client = _smart_client()
    agent_id = args.agent_id or "tokendna-demo-agent"

    v = Verifier(client, agent_id=agent_id, scope=["demo:read", "demo:write"],
                  framework="demo")

    sequence = [
        ("search", "demo://example.com"),
        ("fetch", "demo://example.com/doc"),
        ("summarize", ""),
        ("write_note", "demo://notes/local"),
    ]
    for name, target in sequence:
        v.record_tool_call(name, target=target)

    att = v.finish(metadata={"demo": True, "run": "cli"})

    # Roll the per-agent baseline so subsequent `tokendna baseline show`
    # commands surface state from this run.
    root = current_config().local_root or str(Path.home() / ".tokendna")
    BaselineStore(f"{root}/baselines.json").record_session(
        agent_id, [name for name, _ in sequence],
    )

    _print_json({
        "agent_id": agent_id,
        "mode": client.health().get("mode"),
        "tool_calls": [n for n, _ in sequence],
        "attestation": att.to_dict() if att is not None else None,
        "note": "Local mode wrote a signed JSONL trail to ~/.tokendna/events.jsonl.",
    })
    return 0


def cmd_baseline_show(args: argparse.Namespace) -> int:
    from pathlib import Path  # noqa: PLC0415
    from ._core.behavioral import BaselineStore  # noqa: PLC0415
    root = current_config().local_root or str(Path.home() / ".tokendna")
    store = BaselineStore(f"{root}/baselines.json")
    baseline = store.get(args.agent_id)
    _print_json({**baseline.to_dict(), "is_warm": baseline.is_warm()})
    return 0


# ── parser ────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tokendna")
    sub = parser.add_subparsers(dest="cmd", required=True)

    cfg = sub.add_parser("config", help="Inspect SDK configuration.")
    cfg_sub = cfg.add_subparsers(dest="config_cmd", required=True)
    cfg_show = cfg_sub.add_parser("show", help="Print active configuration.")
    cfg_show.set_defaults(func=cmd_config_show)

    status = sub.add_parser("status",
                              help="Show client mode, recent events, and known baselines.")
    status.set_defaults(func=cmd_status)

    ver = sub.add_parser("verify",
                          help="Run a single policy verify and print the verdict.")
    ver.add_argument("agent_id")
    ver.add_argument("action")
    ver.add_argument("--target", default="", help="Optional target identifier.")
    ver.add_argument("--scope", action="append", default=[],
                      help="Declared scope (repeatable).")
    ver.add_argument("--score", default=0.0,
                      help="Behavioral anomaly score in [0, 1].")
    ver.set_defaults(func=cmd_verify)

    demo = sub.add_parser("demo",
                            help="Run a synthetic agent + attestation end-to-end.")
    demo.add_argument("--agent-id", dest="agent_id", default=None)
    demo.set_defaults(func=cmd_demo)

    base = sub.add_parser("baseline", help="Inspect behavioral baselines.")
    base_sub = base.add_subparsers(dest="baseline_cmd", required=True)
    bshow = base_sub.add_parser("show", help="Show the baseline for an agent.")
    bshow.add_argument("agent_id")
    bshow.set_defaults(func=cmd_baseline_show)

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
