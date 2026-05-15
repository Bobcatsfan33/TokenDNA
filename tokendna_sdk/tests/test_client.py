"""Tests for the low-level Client and high-level TokenDNAClient.

We avoid hitting real HTTP — every test overrides ``_do_post`` /
``_do_get`` so the suite is fully hermetic.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from tokendna_sdk.client import Client, OfflineBufferClient, TokenDNAClient
from tokendna_sdk.config import configure
from tokendna_sdk.exceptions import (
    TokenDNAAttestationError,
    TokenDNAUnavailableError,
    TokenDNAVerificationError,
)


class _StubTransport(Client):
    """Hermetic Client — records every call instead of hitting HTTP."""

    def __init__(self, *, config=None, posts: list | None = None,
                 status: int = 200, response: bytes = b"{}",
                 raise_on_post: BaseException | None = None) -> None:
        super().__init__(config=config)
        self.posts = posts if posts is not None else []
        self._status = status
        self._response = response
        self._raise = raise_on_post

    def _do_post(self, url, body, headers):
        self.posts.append({"url": url, "body": json.loads(body),
                           "headers": headers})
        if self._raise is not None:
            raise self._raise
        return (self._status, self._response)

    def _do_get(self, url, headers):
        if self._raise is not None:
            raise self._raise
        return (self._status, self._response)


def test_client_post_when_disabled():
    cfg = configure(api_base="https://x", enabled=False)
    c = Client(config=cfg)
    r = c.post("/api/uis/normalize", {"k": "v"})
    assert r["sent"] is False and r["reason"] == "sdk_disabled"


def test_client_post_when_offline_buffers_event():
    cfg = configure(api_base="")
    c = Client(config=cfg)
    r = c.post("/api/uis/normalize", {"k": "v"})
    assert r["buffered"] is True and r["reason"] == "offline"
    assert len(c.buffer) == 1


def test_client_post_network_failure_buffers():
    cfg = configure(api_base="https://x", api_key="k")
    c = _StubTransport(config=cfg, raise_on_post=urllib.error.URLError("boom"))
    r = c.post("/api/uis/normalize", {"k": "v"})
    assert r["buffered"] is True
    assert len(c.buffer) == 1


def test_client_post_success_returns_status():
    cfg = configure(api_base="https://x", api_key="k")
    posts = []
    c = _StubTransport(config=cfg, posts=posts, status=201)
    r = c.post("/api/uis/normalize", {"k": "v"})
    assert r == {"sent": True, "buffered": False, "status": 201}
    assert posts[0]["url"] == "https://x/api/uis/normalize"
    assert posts[0]["headers"]["X-API-Key"] == "k"


def test_client_flush_drains_then_reinjects_on_failure():
    cfg = configure(api_base="https://x", api_key="k")
    c = _StubTransport(config=cfg)
    # Seed buffer with an event then make flush fail.
    c.buffer.append.__self__  # noqa: B018 — just a sanity touch
    c.post = lambda *_a, **_k: None  # type: ignore[method-assign]
    # Direct buffer seed (post returns offline since stub still has api_base)
    # — call append explicitly:
    from tokendna_sdk.client import BufferedEvent
    c.buffer.append(BufferedEvent(path="/p", body={"x": 1}))

    # First flush attempt fails: switch _do_post to raise.
    c._raise = urllib.error.URLError("nope")
    res = c.flush()
    assert res == {"sent": 0, "buffered": 1}

    # Recover and flush again — should succeed.
    c._raise = None
    res = c.flush()
    assert res == {"sent": 1, "buffered": 0}


def test_offline_buffer_persists_to_disk(tmp_path):
    path = str(tmp_path / "buf.jsonl")
    cfg = configure(api_base="https://x", api_key="k",
                     offline_buffer_path=path)
    c = _StubTransport(config=cfg, raise_on_post=urllib.error.URLError("boom"))
    c.post("/p", {"a": 1})
    assert (tmp_path / "buf.jsonl").exists()
    # New instance restores it.
    c2 = OfflineBufferClient(path=path)
    assert len(c2) == 1


# ── TokenDNAClient ────────────────────────────────────────────────────────────

def test_tokendna_client_health_remote_ok():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(config=cfg, response=b'{"status":"ok","build":"abc"}')
    client = TokenDNAClient(config=cfg, transport=transport)
    h = client.health()
    assert h == {"status": "ok", "mode": "remote",
                 "api_base": "https://x", "build": "abc"}


def test_tokendna_client_health_unreachable():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(
        config=cfg, raise_on_post=urllib.error.URLError("nope"),
    )
    transport._do_get = lambda *a, **k: (_ for _ in ()).throw(  # type: ignore[assignment]
        urllib.error.URLError("nope")
    )
    client = TokenDNAClient(config=cfg, transport=transport)
    h = client.health()
    assert h["status"] == "unreachable"


def test_tokendna_client_attest_remote_returns_attestation():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(
        config=cfg, response=b'{"receipt_id":"r-42","signature":"sig"}',
    )
    client = TokenDNAClient(config=cfg, transport=transport)
    att = client.attest("agent-1", [{"actor": "agent-1", "action": "x"}])
    assert att.receipt_id == "r-42"
    assert att.signature == "sig"


def test_tokendna_client_attest_missing_receipt_raises():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(config=cfg, response=b'{}')
    client = TokenDNAClient(config=cfg, transport=transport)
    with pytest.raises(TokenDNAAttestationError):
        client.attest("a", [])


def test_tokendna_client_verify_allow():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(
        config=cfg,
        response=b'{"decision":"allow","reason":"","score":0.1}',
    )
    client = TokenDNAClient(config=cfg, transport=transport)
    v = client.verify("agent-1", "search_web", target="example.com")
    assert v.allowed and v.score == 0.1


def test_tokendna_client_verify_deny_raises():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(
        config=cfg,
        response=b'{"decision":"deny","reason":"scope:missing","score":0.9}',
    )
    client = TokenDNAClient(config=cfg, transport=transport)
    with pytest.raises(TokenDNAVerificationError) as exc_info:
        client.verify("a", "search_web")
    assert exc_info.value.verdict.decision == "deny"
    assert exc_info.value.verdict.reason == "scope:missing"


def test_tokendna_client_verify_transport_failure():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(
        config=cfg, raise_on_post=urllib.error.URLError("net down"),
    )
    client = TokenDNAClient(config=cfg, transport=transport)
    with pytest.raises(TokenDNAVerificationError):
        client.verify("a", "x")


def test_tokendna_client_normalize_queues_via_emitter():
    cfg = configure(api_base="https://x", api_key="k")
    transport = _StubTransport(config=cfg)
    client = TokenDNAClient(config=cfg, transport=transport)
    r = client.normalize({"event_id": "e-1"})
    assert r["queued"] is True
    # Flushing should ship the event through the transport.
    client.flush()
    assert any(p["body"].get("event_id") == "e-1" for p in transport.posts)
    client.emitter.stop()
