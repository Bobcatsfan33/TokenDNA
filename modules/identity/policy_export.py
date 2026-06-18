"""Policy Generator -> guardrail export (Gap roadmap Epic 3.2 / Challenge C4).

Turns TokenDNA policy_advisor suggestions (or a hand-authored PolicySpec) into
exportable guardrail configs for multiple targets — primarily **AWS Bedrock
Guardrails** (JSON + ``aws bedrock create-guardrail`` CLI snippet), matching the
Zscaler-style Policy Generator UX, plus OpenAI-style and a generic target.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SUPPORTED_TARGETS = ("bedrock", "openai", "generic")

_DEFAULT_BLOCK_INPUT = "This request was blocked by TokenDNA policy."
_DEFAULT_BLOCK_OUTPUT = "This response was blocked by TokenDNA policy."


@dataclass
class DeniedTopic:
    name: str
    definition: str
    examples: list[str] = field(default_factory=list)


@dataclass
class PolicySpec:
    name: str
    description: str = ""
    denied_topics: list[DeniedTopic] = field(default_factory=list)
    blocked_words: list[str] = field(default_factory=list)
    pii_entities: list[str] = field(default_factory=list)  # e.g. EMAIL, US_SOCIAL_SECURITY_NUMBER
    blocked_input_message: str = _DEFAULT_BLOCK_INPUT
    blocked_output_message: str = _DEFAULT_BLOCK_OUTPUT


def _sanitize_name(name: str) -> str:
    # Bedrock guardrail/topic names allow [0-9a-zA-Z-_], <=50 chars.
    cleaned = "".join(c if (c.isalnum() or c in "-_") else "-" for c in name).strip("-")
    return (cleaned or "tokendna-guardrail")[:50]


# ── Build a spec from advisor suggestions ─────────────────────────────────────

def spec_from_suggestions(name: str, suggestions: list[Any], description: str = "") -> PolicySpec:
    """Build a PolicySpec from policy_advisor PolicySuggestion objects/dicts.

    Each suggestion becomes a denied topic; scope/word payloads in the amendment
    become blocked words.
    """
    spec = PolicySpec(name=name, description=description or
                      "Generated from TokenDNA policy_advisor suggestions")
    for s in suggestions:
        amendment_type = _attr(s, "amendment_type")
        amendment_type = getattr(amendment_type, "value", str(amendment_type))
        gap = _attr(s, "gap_description") or amendment_type
        amendment = _attr(s, "amendment") or {}
        examples = []
        words = amendment.get("remove_scopes") or amendment.get("scopes") or amendment.get("patterns") or []
        if isinstance(words, str):
            words = [words]
        examples = [str(w) for w in words][:5]
        spec.denied_topics.append(DeniedTopic(
            name=_sanitize_name(amendment_type), definition=str(gap), examples=examples))
        for w in words:
            if isinstance(w, str) and w and w not in spec.blocked_words:
                spec.blocked_words.append(w)
    return spec


def _attr(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# ── Target renderers ──────────────────────────────────────────────────────────

def to_bedrock(spec: PolicySpec) -> dict[str, Any]:
    """AWS Bedrock CreateGuardrail request shape."""
    config: dict[str, Any] = {
        "name": _sanitize_name(spec.name),
        "description": spec.description[:200],
        "blockedInputMessaging": spec.blocked_input_message,
        "blockedOutputsMessaging": spec.blocked_output_message,
    }
    if spec.denied_topics:
        config["topicPolicyConfig"] = {
            "topicsConfig": [
                {"name": t.name, "definition": t.definition,
                 "examples": t.examples, "type": "DENY"}
                for t in spec.denied_topics
            ]
        }
    if spec.blocked_words:
        config["wordPolicyConfig"] = {
            "wordsConfig": [{"text": w} for w in spec.blocked_words]
        }
    if spec.pii_entities:
        config["sensitiveInformationPolicyConfig"] = {
            "piiEntitiesConfig": [{"type": e, "action": "BLOCK"} for e in spec.pii_entities]
        }
    return config


def to_bedrock_cli(bedrock_config: dict[str, Any]) -> str:
    """`aws bedrock create-guardrail` CLI snippet for copy/paste."""
    payload = json.dumps(bedrock_config, separators=(",", ":"))
    # Single-quote the JSON for the shell; escape embedded single quotes.
    escaped = payload.replace("'", "'\\''")
    return f"aws bedrock create-guardrail --cli-input-json '{escaped}'"


def to_openai(spec: PolicySpec) -> dict[str, Any]:
    """OpenAI-style moderation/guardrail config (generic blocklist shape)."""
    return {
        "name": spec.name,
        "type": "guardrail",
        "blocked_topics": [{"name": t.name, "description": t.definition} for t in spec.denied_topics],
        "blocked_words": list(spec.blocked_words),
        "pii_entities": list(spec.pii_entities),
        "on_violation": {"input_message": spec.blocked_input_message,
                         "output_message": spec.blocked_output_message},
    }


def to_generic(spec: PolicySpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "denied_topics": [{"name": t.name, "definition": t.definition, "examples": t.examples}
                          for t in spec.denied_topics],
        "blocked_words": list(spec.blocked_words),
        "pii_entities": list(spec.pii_entities),
        "blocked_input_message": spec.blocked_input_message,
        "blocked_output_message": spec.blocked_output_message,
    }


def export_policy(spec: PolicySpec, target: str) -> dict[str, Any]:
    """Render a spec for a target. Returns {target, format, config[, cli]}."""
    target = target.lower()
    if target == "bedrock":
        cfg = to_bedrock(spec)
        return {"target": "bedrock", "format": "json", "config": cfg, "cli": to_bedrock_cli(cfg)}
    if target == "openai":
        return {"target": "openai", "format": "json", "config": to_openai(spec)}
    if target == "generic":
        return {"target": "generic", "format": "json", "config": to_generic(spec)}
    raise ValueError(f"unsupported target '{target}'; supported: {', '.join(SUPPORTED_TARGETS)}")


def spec_from_dict(d: dict[str, Any]) -> PolicySpec:
    """Build a PolicySpec from a raw dict (hand-authored policy)."""
    topics = [DeniedTopic(name=_sanitize_name(t.get("name", "topic")),
                          definition=str(t.get("definition", "")),
                          examples=list(t.get("examples", []) or []))
              for t in d.get("denied_topics", []) if isinstance(t, dict)]
    return PolicySpec(
        name=str(d.get("name", "tokendna-guardrail")),
        description=str(d.get("description", "")),
        denied_topics=topics,
        blocked_words=[str(w) for w in d.get("blocked_words", []) or []],
        pii_entities=[str(e) for e in d.get("pii_entities", []) or []],
        blocked_input_message=str(d.get("blocked_input_message", _DEFAULT_BLOCK_INPUT)),
        blocked_output_message=str(d.get("blocked_output_message", _DEFAULT_BLOCK_OUTPUT)),
    )
