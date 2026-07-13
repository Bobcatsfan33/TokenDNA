"""
TokenDNA — opaque cursor pagination helper.

Used by every public list endpoint that returns more than a handful of rows.
Provides a single encode/decode contract so the API surface looks the same
regardless of whether the underlying storage is keyset-based, offset-based,
or hand-rolled (some of our list functions are too small to justify a
proper keyset scan, others must be).

Wire shape:

    GET /api/foo?limit=50&cursor=<opaque>
    →  { "items": [...], "count": 50, "next_cursor": "<opaque|null>" }

The cursor is opaque (base64) so callers can't inspect or mutate the
internal pagination state. ``next_cursor`` is null when there are no more
pages.

Limits:

    DEFAULT_LIMIT = 50
    MAX_LIMIT     = 200      # documented in every endpoint's docstring
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence, TypeVar

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


T = TypeVar("T")


def clamp_limit(limit: Optional[int]) -> int:
    """Apply DEFAULT/MAX bounds to a caller-supplied limit."""
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1:
        return 1
    if limit > MAX_LIMIT:
        return MAX_LIMIT
    return int(limit)


def encode_cursor(state: dict[str, Any]) -> str:
    """Base64url-encode a JSON state object."""
    raw = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: Optional[str]) -> dict[str, Any]:
    """Decode an opaque cursor back into its state dict.  Empty/None → {}."""
    if not cursor:
        return {}
    try:
        padded = cursor + "=" * ((4 - len(cursor) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw.decode("utf-8"))
        return decoded if isinstance(decoded, dict) else {}
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        # Treat malformed cursors as "start from the beginning" — never
        # raise into the caller because that would let a typo'd cursor
        # take down a UI list view.
        return {}


@dataclass(frozen=True)
class Page:
    items: list[Any]
    next_cursor: Optional[str]

    def as_response(self, items_key: str = "items", extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            items_key: self.items,
            "count": len(self.items),
            "next_cursor": self.next_cursor,
        }
        if extra:
            body.update(extra)
        return body


def paginate_offset(
    fetch_window: Callable[[int, int], Sequence[T]],
    *,
    cursor: Optional[str],
    limit: Optional[int],
) -> Page:
    """
    Offset-based pagination wrapped behind an opaque cursor.

    ``fetch_window(offset, fetch_limit)`` is called with one extra row
    (``limit + 1``) so we can detect "is there another page" without an
    extra ``COUNT(*)``.  If we get back ``limit + 1`` rows we strip the
    last and emit a ``next_cursor`` pointing at the next offset.

    Use this for tables where keyset pagination is not justified (small
    tables, complex multi-column ORDER BY, or hand-rolled in-memory
    aggregations).  Use ``paginate_keyset`` for hot-path large tables.
    """
    page_limit = clamp_limit(limit)
    state = decode_cursor(cursor)
    offset = max(int(state.get("offset", 0)), 0)
    rows = list(fetch_window(offset, page_limit + 1))
    has_more = len(rows) > page_limit
    items = rows[:page_limit]
    next_cur = encode_cursor({"offset": offset + page_limit}) if has_more else None
    return Page(items=items, next_cursor=next_cur)


def paginate_keyset(
    fetch_after: Callable[[Optional[Any], int], Sequence[T]],
    *,
    cursor: Optional[str],
    limit: Optional[int],
    key_of: Callable[[T], Any],
    cursor_field: str = "k",
) -> Page:
    """
    Keyset (last-row) pagination.

    ``fetch_after(after_key, fetch_limit)`` returns up to ``fetch_limit + 1``
    rows ordered by the same key the cursor encodes.  ``key_of(item)``
    extracts the cursor value from a returned row (typically a primary
    key, sequence number, or ISO timestamp string).

    Preferred for hot tables.
    """
    page_limit = clamp_limit(limit)
    state = decode_cursor(cursor)
    after = state.get(cursor_field)
    rows = list(fetch_after(after, page_limit + 1))
    has_more = len(rows) > page_limit
    items = rows[:page_limit]
    next_cur = (
        encode_cursor({cursor_field: key_of(items[-1])})
        if (has_more and items)
        else None
    )
    return Page(items=items, next_cursor=next_cur)
