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
