"""Tests for TokenDNALocalClient — the no-server on-ramp."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from tokendna_sdk.exceptions import TokenDNAAttestationError
from tokendna_sdk.local import KEY_FILENAME, TokenDNALocalClient


def test_root_is_created_with_locked_down_perms(tmp_path):
    root = tmp_path / "tdna"
    TokenDNALocalClient(root=root)
    assert root.exists() and root.is_dir()
    # POSIX permission check — skipped on Windows / non-POSIX filesystems.
    mode = stat.S_IMODE(root.stat().st_mode)
    # Some filesystems (FAT, network mounts) ignore chmod; accept any
    # mode but require *no world-write* on POSIX.
    if hasattr(root, "chmod"):
        assert (mode & stat.S_IWOTH) == 0


def test_key_is_generated_once_and_reused(tmp_path):
    root = tmp_path / "tdna"
    c1 = TokenDNALocalClient(root=root)
    key_path = root / KEY_FILENAME
    assert key_path.exists()
    key_a = key_path.read_bytes()

    c2 = TokenDNALocalClient(root=root)
    assert key_path.read_bytes() == key_a
    # Different instances pointed at the same root share the same key.
    assert c1._key == c2._key


def test_health_reports_local_mode(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    h = c.health()
    assert h["status"] == "ok"
    assert h["mode"] == "local"
    assert h["root"].endswith("tdna")


def test_post_records_event_to_jsonl(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    result = c.post("/api/uis/normalize", {"hello": "world"})
    assert result["sent"] is True and result["mode"] == "local"
    lines = (tmp_path / "tdna" / "events.jsonl").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["_body"]["body"]["hello"] == "world"
    assert rec["_sig"]
    # Signature verifies.
    assert c.verify_signature(rec)


def test_post_signature_is_tamper_evident(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    c.post("/x", {"k": "v"})
    line = (tmp_path / "tdna" / "events.jsonl").read_text().splitlines()[0]
    rec = json.loads(line)
    rec["_body"]["body"]["k"] = "TAMPERED"
    assert not c.verify_signature(rec)


def test_attest_returns_signed_receipt(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    att = c.attest("agent-1", [{"actor": "agent-1", "action": "read"}])
    assert att.receipt_id.startswith("loc-")
    assert att.agent_id == "agent-1"
    assert att.signature
    assert len(att.hops) == 1


def test_attest_requires_agent_id(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    with pytest.raises(TokenDNAAttestationError):
        c.attest("", [])


def test_verify_always_allows_in_local_mode(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    v = c.verify("agent-1", "search_web", target="example.com",
                  scope=["web:read"], score=0.42)
    assert v.allowed
    assert v.score == 0.42
    assert v.reason == "local_mode"


def test_read_events_returns_newest_first(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    for i in range(3):
        c.post("/x", {"i": i})
    events = c.read_events()
    assert len(events) == 3
    # newest first: i=2, 1, 0
    assert events[0]["_body"]["body"]["i"] == 2
    assert events[-1]["_body"]["body"]["i"] == 0


def test_read_events_respects_limit(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    for i in range(10):
        c.post("/x", {"i": i})
    assert len(c.read_events(limit=4)) == 4


def test_emit_batch_writes_one_line_per_event(tmp_path):
    c = TokenDNALocalClient(root=tmp_path / "tdna")
    c.emit_batch([{"a": 1}, {"b": 2}, {"c": 3}])
    lines = (tmp_path / "tdna" / "events.jsonl").read_text().splitlines()
    assert len(lines) == 3
