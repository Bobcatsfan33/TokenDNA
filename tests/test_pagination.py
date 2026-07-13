"""Tests for the opaque cursor pagination helper."""
from __future__ import annotations

import pytest

from modules.storage.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Page,
    clamp_limit,
    decode_cursor,
    encode_cursor,
    paginate_keyset,
    paginate_offset,
)


# ── Cursor encoding ──────────────────────────────────────────────────────────


def test_encode_decode_round_trip():
    cur = encode_cursor({"offset": 50})
    assert isinstance(cur, str)
    # No padding chars in opaque cursor
    assert "=" not in cur
    assert decode_cursor(cur) == {"offset": 50}


def test_decode_handles_empty_and_garbage():
    assert decode_cursor(None) == {}
    assert decode_cursor("") == {}
    assert decode_cursor("not-base64!!!") == {}


def test_encode_is_stable():
    """Same state → same cursor string."""
    a = encode_cursor({"a": 1, "b": 2})
    b = encode_cursor({"b": 2, "a": 1})
    assert a == b


# ── Limit clamping ───────────────────────────────────────────────────────────


def test_clamp_limit_default_when_none():
    assert clamp_limit(None) == DEFAULT_LIMIT


def test_clamp_limit_floor_at_one():
    assert clamp_limit(0) == 1
    assert clamp_limit(-5) == 1


def test_clamp_limit_ceiling_at_max():
    assert clamp_limit(MAX_LIMIT + 1) == MAX_LIMIT
    assert clamp_limit(99999) == MAX_LIMIT


def test_clamp_limit_passes_valid():
    assert clamp_limit(75) == 75


# ── Offset pagination ────────────────────────────────────────────────────────


def _make_window(rows):
    """Build a fetch_window stub backed by a list."""
    def fetch(offset, lim):
        return rows[offset:offset + lim]
    return fetch


def test_paginate_offset_first_page_with_more():
    rows = list(range(150))
    page = paginate_offset(_make_window(rows), cursor=None, limit=50)
    assert len(page.items) == 50
    assert page.items == list(range(50))
    assert page.next_cursor is not None


def test_paginate_offset_walk_to_end():
    rows = list(range(120))
    seen = []
    cursor = None
    while True:
        page = paginate_offset(_make_window(rows), cursor=cursor, limit=50)
        seen.extend(page.items)
        if not page.next_cursor:
            break
        cursor = page.next_cursor
    assert seen == rows


def test_paginate_offset_last_page_emits_no_next_cursor():
    rows = list(range(50))
    page = paginate_offset(_make_window(rows), cursor=None, limit=50)
    assert page.next_cursor is None
    assert len(page.items) == 50


def test_paginate_offset_empty_table():
    page = paginate_offset(_make_window([]), cursor=None, limit=50)
    assert page.items == []
    assert page.next_cursor is None


def test_paginate_offset_limit_bounds_applied():
    rows = list(range(500))
    page = paginate_offset(_make_window(rows), cursor=None, limit=999)
    assert len(page.items) == MAX_LIMIT


def test_paginate_offset_garbage_cursor_starts_from_top():
    rows = list(range(150))
    page = paginate_offset(_make_window(rows), cursor="garbage!!!", limit=50)
    assert page.items == list(range(50))


# ── Keyset pagination ────────────────────────────────────────────────────────


def test_paginate_keyset_walks_using_last_key():
    rows = [{"id": i, "v": f"row-{i}"} for i in range(120)]

    def fetch_after(after, lim):
        start = 0 if after is None else after + 1
        return rows[start:start + lim]

    seen = []
    cursor = None
    while True:
        page = paginate_keyset(
            fetch_after, cursor=cursor, limit=50,
            key_of=lambda r: r["id"],
        )
        seen.extend(page.items)
        if not page.next_cursor:
            break
        cursor = page.next_cursor
    assert [r["id"] for r in seen] == list(range(120))


# ── as_response shape ───────────────────────────────────────────────────────


def test_page_as_response_default_key():
    p = Page(items=[1, 2, 3], next_cursor="c1")
    body = p.as_response()
    assert body == {"items": [1, 2, 3], "count": 3, "next_cursor": "c1"}


def test_page_as_response_custom_key_and_extras():
    p = Page(items=["a"], next_cursor=None)
    body = p.as_response("signals", extra={"tenant_id": "t1"})
    assert body == {"signals": ["a"], "count": 1, "next_cursor": None, "tenant_id": "t1"}
