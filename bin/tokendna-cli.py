#!/usr/bin/env python3
"""
TokenDNA OSS helper CLI.

Provides frictionless onboarding for open-source developers:
  - inspect UIS spec
  - normalize protocol payloads through adapter logic
"""

from __future__ import annotations

import argparse
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules.identity.uis_protocol import get_uis_spec, normalize_with_adapter  # noqa: E402


def cmd_spec(_args: argparse.Namespace) -> int:
    print(json.dumps(get_uis_spec(), indent=2, sort_keys=True))
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    payload = json.loads(args.payload_json)
    request_context = json.loads(args.request_context_json) if args.request_context_json else {}
    risk_context = json.loads(args.risk_context_json) if args.risk_context_json else {}
    event = normalize_with_adapter(
        protocol=args.protocol,
        tenant_id=args.tenant_id,
        tenant_name=args.tenant_name,
        payload=payload,
        request_context=request_context,
        risk_context=risk_context,
    )
    print(json.dumps(event, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TokenDNA OSS developer CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_spec = sub.add_parser("uis-spec", help="Print UIS spec")
    p_spec.set_defaults(func=cmd_spec)

    p_norm = sub.add_parser("normalize", help="Normalize a protocol payload into UIS")
    p_norm.add_argument("--protocol", required=True, help="Protocol name (oidc/saml/oauth2_opaque/spiffe/mcp/custom)")
    p_norm.add_argument("--tenant-id", required=True, help="Tenant identifier")
    p_norm.add_argument("--tenant-name", required=True, help="Tenant name")
    p_norm.add_argument("--payload-json", required=True, help="Protocol payload JSON string")
    p_norm.add_argument("--request-context-json", default="", help="Optional request context JSON string")
    p_norm.add_argument("--risk-context-json", default="", help="Optional risk context JSON string")
    p_norm.set_defaults(func=cmd_normalize)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
