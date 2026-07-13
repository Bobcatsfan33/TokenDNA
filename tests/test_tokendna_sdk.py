"""
Tests for tokendna_sdk — the developer wedge.

Coverage:
  - configure() merges with env defaults and is read-only outside of
    setter (no field-level mutation).
  - OfflineBufferClient persists + restores from disk.
  - Client.post buffers when offline and tries-then-buffers on transport
    failure. Successful post returns sent=True.
  - Client.flush re-buffers transport failures.
  - @identified stamps __tokendna_meta__ on the class without mutating
    methods.
  - @tool emits one event per call via the injected client; the wrapped
    method's return value passes through; exceptions in the wrapped
    method are not swallowed.
  - @tool on a non-@identified class is a no-op (passes through).
  - get_agent_metadata returns the workflow trace and clears it after
    read.
  - CLI: build_parser exposes policy/replay/config; cmd_config_show
    redacts api_key.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _reset_sdk_config(monkeypatch):
    # Ensure a clean SDK config per test.
    monkeypatch.delenv("TOKENDNA_API_BASE", raising=False)
    monkeypatch.delenv("TOKENDNA_API_KEY", raising=False)
    monkeypatch.delenv("TOKENDNA_TENANT_ID", raising=False)
    monkeypatch.delenv("TOKENDNA_OFFLINE_BUFFER", raising=False)
    monkeypatch.setenv("TOKENDNA_ENABLED", "true")
    from tokendna_sdk import reset_config, get_agent_metadata
    reset_config()
    get_agent_metadata()  # drain any thread-local trace from prior tests
    yield
    reset_config()
    get_agent_metadata()


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_defaults_from_env(self, monkeypatch):
        monkeypatch.setenv("TOKENDNA_API_BASE", "https://example/")
        monkeypatch.setenv("TOKENDNA_API_KEY", "k1")
        monkeypatch.setenv("TOKENDNA_TENANT_ID", "t1")
        from tokendna_sdk import reset_config, current_config
        reset_config()
        cfg = current_config()
        assert cfg.api_base == "https://example"  # trailing / stripped
        assert cfg.api_key == "k1"
        assert cfg.tenant_id == "t1"
        assert cfg.is_online() is True

    def test_configure_partial_update(self):
        from tokendna_sdk import configure, current_config
        configure(api_base="https://a/", api_key="key", tenant_id="t1")
        before = current_config()
        # Update only the key — other fields preserved.
        configure(api_key="newkey")
        after = current_config()
        assert after.api_base == before.api_base
        assert after.tenant_id == before.tenant_id
        assert after.api_key == "newkey"

    def test_disabled_is_offline_signal(self):
        from tokendna_sdk import configure
        cfg = configure(api_base="https://a/", api_key="k", enabled=False)
        assert cfg.is_online() is False


# ─────────────────────────────────────────────────────────────────────────────
# OfflineBufferClient
# ─────────────────────────────────────────────────────────────────────────────

class TestOfflineBuffer:
    def test_in_memory_round_trip(self):
        from tokendna_sdk.client import OfflineBufferClient, BufferedEvent
        buf = OfflineBufferClient()
        buf.append(BufferedEvent("/p", {"a": 1}))
        assert len(buf) == 1
        items = list(buf.drain())
        assert items[0].body == {"a": 1}
        assert len(buf) == 0

    def test_disk_persistence(self, tmp_path):
        from tokendna_sdk.client import OfflineBufferClient, BufferedEvent
        path = str(tmp_path / "buf.jsonl")
        buf = OfflineBufferClient(path=path)
        buf.append(BufferedEvent("/p1", {"a": 1}))
        buf.append(BufferedEvent("/p2", {"b": 2}))
        # Re-instantiate against the same file — events are restored.
        restored = OfflineBufferClient(path=path)
        items = list(restored.drain())
        assert {i.path for i in items} == {"/p1", "/p2"}


# ─────────────────────────────────────────────────────────────────────────────
# Client transport
# ─────────────────────────────────────────────────────────────────────────────

class _FakeClient:
    """A Client subclass that captures _do_post calls instead of hitting HTTP."""

    def __init__(self, *args, fail: bool = False, **kwargs):
        from tokendna_sdk.client import Client
        # Re-use Client's init via composition rather than super() to keep
        # the test surface small.
        self._inner = Client(*args, **kwargs)
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []
        self.fail = fail
        self.config = self._inner.config
        self.buffer = self._inner.buffer

    def _do_post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        self.calls.append((url, body, headers))
        if self.fail:
            import urllib.error
            raise urllib.error.URLError("fake unreachable")
        return 200

    def post(self, *a, **kw):
        # Patch the bound method so the inner client uses our _do_post.
        self._inner._do_post = self._do_post  # type: ignore[assignment]
        return self._inner.post(*a, **kw)

    def flush(self):
        self._inner._do_post = self._do_post  # type: ignore[assignment]
        return self._inner.flush()


class TestClientTransport:
    def test_offline_buffers(self):
        from tokendna_sdk import configure
        configure(api_base="", api_key="")  # no api_base → offline
        c = _FakeClient()
        out = c.post("/api/uis/normalize", {"e": 1})
        assert out["sent"] is False
        assert out["buffered"] is True
        assert len(c.buffer) == 1

    def test_online_success(self):
        from tokendna_sdk import configure
        configure(api_base="https://api/", api_key="k")
        c = _FakeClient(fail=False)
        out = c.post("/api/uis/normalize", {"e": 1})
        assert out["sent"] is True
        assert c.calls and c.calls[0][0].startswith("https://api/")

    def test_online_failure_buffers(self):
        from tokendna_sdk import configure
        configure(api_base="https://api/", api_key="k")
        c = _FakeClient(fail=True)
        out = c.post("/api/uis/normalize", {"e": 1})
        assert out["sent"] is False
        assert out["buffered"] is True

    def test_flush_retries(self):
        from tokendna_sdk import configure
        from tokendna_sdk.client import BufferedEvent
        configure(api_base="https://api/", api_key="k")
        c = _FakeClient(fail=False)
        # Pre-buffer a couple of events as if from earlier offline runs.
        c.buffer.append(BufferedEvent("/api/uis/normalize", {"x": 1}))
        c.buffer.append(BufferedEvent("/api/uis/normalize", {"x": 2}))
        out = c.flush()
        assert out["sent"] == 2
        assert out["buffered"] == 0

    def test_disabled_short_circuits(self):
        from tokendna_sdk import configure
        configure(api_base="https://api/", api_key="k", enabled=False)
        c = _FakeClient()
        out = c.post("/api/uis/normalize", {"x": 1})
        assert out["sent"] is False
        assert out["buffered"] is False
        assert "sdk_disabled" in out["reason"]


# ─────────────────────────────────────────────────────────────────────────────
# Decorators
# ─────────────────────────────────────────────────────────────────────────────

class _CapturingClient:
    """Stand-in client used inside @identified to capture posted events."""

    def __init__(self):
        from tokendna_sdk.config import current_config
        self.config = current_config()
        self.posted: list[tuple[str, dict]] = []
        # Decorators expect a buffer attribute exists — provide a no-op.
        self.buffer = type("_B", (), {"__len__": lambda self: 0})()  # noqa: SLF001

    def post(self, path: str, body: dict) -> dict:
        self.posted.append((path, body))
        return {"sent": True, "buffered": False, "status": 200}


class TestIdentifiedAndTool:
    def test_identified_stamps_meta(self):
        from tokendna_sdk import identified

        @identified("agt-x", scope=["docs:read"], description="desc")
        class Agent:
            pass

        meta = Agent.__tokendna_meta__
        assert meta.agent_id == "agt-x"
        assert meta.scope == ["docs:read"]
        assert meta.description == "desc"

    def test_identified_rejects_blank(self):
        from tokendna_sdk import identified
        with pytest.raises(ValueError):
            @identified("")
            class _A: pass  # noqa: E701

    def test_tool_emits_event_and_records_hop(self):
        from tokendna_sdk import identified, tool, get_agent_metadata
        cap = _CapturingClient()

        @identified("agt-x", scope=["docs:read"], client=cap)
        class A:
            @tool("fetch_doc", target="doc")
            def fetch_doc(self, url: str) -> str:
                return f"got:{url}"

        result = A().fetch_doc("https://x")
        assert result == "got:https://x"
        # Event posted.
        assert len(cap.posted) == 1
        path, body = cap.posted[0]
        assert path == "/api/uis/normalize"
        assert body["identity"]["agent_id"] == "agt-x"
        # Hop pushed.
        meta = get_agent_metadata()
        assert len(meta["hops"]) == 1
        hop = meta["hops"][0]
        assert hop["actor"] == "agt-x"
        assert hop["action"] == "fetch_doc"
        assert hop["target"] == "doc"

    def test_get_agent_metadata_clears_trace(self):
        from tokendna_sdk import identified, tool, get_agent_metadata
        cap = _CapturingClient()

        @identified("a", client=cap)
        class A:
            @tool("op")
            def op(self): return "ok"

        A().op()
        first = get_agent_metadata()
        assert len(first["hops"]) == 1
        second = get_agent_metadata()
        assert second["hops"] == []

    def test_tool_passes_through_exceptions(self):
        from tokendna_sdk import identified, tool
        cap = _CapturingClient()

        @identified("a", client=cap)
        class A:
            @tool("boom")
            def boom(self): raise RuntimeError("oops")

        with pytest.raises(RuntimeError, match="oops"):
            A().boom()

    def test_tool_without_identified_passes_through(self):
        from tokendna_sdk import tool

        class Plain:
            @tool("op")
            def op(self): return "noop"

        # Class wasn't decorated → no event posted, original return preserved.
        assert Plain().op() == "noop"

    def test_capture_args_opt_in(self):
        from tokendna_sdk import identified, tool, get_agent_metadata
        cap = _CapturingClient()

        @identified("a", client=cap)
        class A:
            @tool("greet", capture_args=True)
            def greet(self, name): return f"hi {name}"

        A().greet("alice")
        meta = get_agent_metadata()
        # capture_args=True should have stored an "arguments" dict.
        assert "arguments" in meta["hops"][0]["metadata"]


# ─────────────────────────────────────────────────────────────────────────────
# Thread-safety
# ─────────────────────────────────────────────────────────────────────────────

class TestThreadIsolation:
    def test_traces_are_per_thread(self):
        from tokendna_sdk import identified, tool, get_agent_metadata
        cap = _CapturingClient()

        @identified("a", client=cap)
        class A:
            @tool("op")
            def op(self): return None

        results: dict[str, int] = {}

        def _worker(label: str):
            for _ in range(3):
                A().op()
            results[label] = len(get_agent_metadata()["hops"])

        threads = [threading.Thread(target=_worker, args=(f"t{i}",))
                   for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Each thread saw exactly its own 3 hops.
        assert all(v == 3 for v in results.values())


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

class TestCLI:
    def test_parser_routes(self):
        from tokendna_sdk.cli import build_parser
        p = build_parser()
        ns = p.parse_args(["policy", "plan", "/tmp/bundle.json"])
        assert ns.cmd == "policy"
        assert ns.policy_cmd == "plan"

    def test_config_show_redacts_key(self, monkeypatch, capsys):
        monkeypatch.setenv("TOKENDNA_API_KEY", "super-secret")
        from tokendna_sdk import reset_config
        from tokendna_sdk.cli import build_parser
        reset_config()
        p = build_parser()
        ns = p.parse_args(["config", "show"])
        ns.func(ns)
        out = capsys.readouterr().out
        assert "super-secret" not in out
        assert "api_key_present" in out

    def test_replay_routes_to_post(self, monkeypatch):
        from tokendna_sdk import configure
        configure(api_base="https://api/", api_key="k")

        from tokendna_sdk import client as client_mod
        # Patch Client._do_post globally for this test.
        recorded: dict = {}

        def _fake(_self, url, body, headers):  # noqa: ARG001
            recorded["url"] = url
            return 200

        monkeypatch.setattr(client_mod.Client, "_do_post", _fake)
        from tokendna_sdk.cli import build_parser
        p = build_parser()
        ns = p.parse_args(["replay", "decision-123"])
        rc = ns.func(ns)
        assert rc == 0
        assert recorded["url"].endswith("/api/decision-audit/decision-123/replay")
