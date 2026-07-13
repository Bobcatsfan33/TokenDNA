from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auth.scim_filter import FilterError, UnsupportedFilter, apply, parse


_RESOURCES = [
    {"userName": "alice@example.com", "active": True,  "name": {"givenName": "Alice"}},
    {"userName": "bob@example.com",   "active": True,  "name": {"givenName": "Bob"}},
    {"userName": "carol@other.com",   "active": False, "name": {"givenName": "Carol"}},
    {"userName": "dave@example.com",  "active": True,  "name": {"givenName": "Dave", "familyName": "Vader"}},
]


def test_eq_string():
    out = apply('userName eq "alice@example.com"', _RESOURCES)
    assert [r["userName"] for r in out] == ["alice@example.com"]


def test_eq_is_case_insensitive():
    out = apply('userName eq "ALICE@EXAMPLE.COM"', _RESOURCES)
    assert [r["userName"] for r in out] == ["alice@example.com"]


def test_sw_ew_co():
    assert len(apply('userName sw "alice"', _RESOURCES)) == 1
    assert len(apply('userName ew "@example.com"', _RESOURCES)) == 3
    assert len(apply('userName co "ob"', _RESOURCES)) == 1


def test_eq_bool():
    inactive = apply("active eq false", _RESOURCES)
    assert [r["userName"] for r in inactive] == ["carol@other.com"]


def test_pr_present():
    out = apply("name.familyName pr", _RESOURCES)
    assert [r["userName"] for r in out] == ["dave@example.com"]


def test_dotted_path_resolves():
    out = apply('name.givenName eq "Bob"', _RESOURCES)
    assert [r["userName"] for r in out] == ["bob@example.com"]


def test_and_or_not():
    out = apply('userName ew "@example.com" and active eq true', _RESOURCES)
    assert {r["userName"] for r in out} == {"alice@example.com", "bob@example.com", "dave@example.com"}

    out = apply('userName eq "alice@example.com" or userName eq "carol@other.com"', _RESOURCES)
    assert {r["userName"] for r in out} == {"alice@example.com", "carol@other.com"}

    out = apply("not (active eq true)", _RESOURCES)
    assert {r["userName"] for r in out} == {"carol@other.com"}


def test_grouping_changes_precedence():
    out = apply(
        '(userName eq "alice@example.com" or userName eq "bob@example.com") and active eq true',
        _RESOURCES,
    )
    assert {r["userName"] for r in out} == {"alice@example.com", "bob@example.com"}


def test_iso_timestamp_compare_via_lex():
    docs = [
        {"meta": {"lastModified": "2026-01-01T00:00:00Z"}},
        {"meta": {"lastModified": "2026-04-15T12:00:00Z"}},
        {"meta": {"lastModified": "2026-06-30T23:59:59Z"}},
    ]
    out = apply('meta.lastModified gt "2026-04-01T00:00:00Z"', docs)
    assert len(out) == 2


def test_unsupported_bracketed_filter_raises():
    with pytest.raises(UnsupportedFilter):
        parse('emails[type eq "work"]')


def test_malformed_filter_raises_filter_error():
    with pytest.raises(FilterError):
        parse('userName eq')  # no value
    with pytest.raises(FilterError):
        parse('eq "x"')        # no attr
    with pytest.raises(FilterError):
        parse('')              # empty


# ── ReDoS / DoS guards ────────────────────────────────────────────────────────


def test_long_whitespace_input_does_not_hang():
    """
    Adversarial whitespace-only payload: must reject quickly, not catastrophically
    backtrack.  CodeQL py/polynomial-redos flagged the pre-fix _TOKEN_RE pattern
    on inputs starting with '\\n    ' repetitions; the rewrite handles whitespace
    in a separate cheap match instead of as a top-level alternation arm.
    """
    import time

    payload = ("\n    " * 600) + 'userName eq "alice"'
    start = time.perf_counter()
    f = parse(payload)
    elapsed = time.perf_counter() - start
    # Generous bound — pre-fix this could go quadratic; sub-second proves linear.
    assert elapsed < 1.0, f"tokenize took {elapsed:.3f}s on whitespace-padded input"
    assert f({"userName": "alice"}) is True


def test_filter_length_cap_rejects_oversize():
    huge = 'userName eq "' + ("a" * 10_000) + '"'
    with pytest.raises(FilterError, match="maximum length"):
        parse(huge)


def test_token_count_cap_rejects_compound_explosion():
    # Many short ``pr`` clauses — exceeds _MAX_TOKENS without tripping the
    # length cap.  ``a pr`` = 2 tokens; joined by ``or`` (1 token); ~3 tokens
    # per ~8 chars => 350 reps yields ~1050 tokens in ~2800 chars.
    expr = " or ".join(["a pr"] * 350)
    assert len(expr) < 4096
    with pytest.raises(FilterError, match="token count"):
        parse(expr)
