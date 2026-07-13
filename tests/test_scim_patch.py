from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.auth.scim_patch import (
    SCHEMA_PATCH_OP,
    PatchError,
    UnsupportedPatch,
    apply_patch,
)


def _user(**overrides):
    base = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "abc",
        "userName": "alice@example.com",
        "active": True,
        "name": {"givenName": "Alice"},
        "emails": [{"value": "alice@example.com", "type": "work"}],
    }
    base.update(overrides)
    return base


def _patch(*ops):
    return {"schemas": [SCHEMA_PATCH_OP], "Operations": list(ops)}


def test_replace_scalar():
    out = apply_patch(_user(), _patch({"op": "replace", "path": "active", "value": False}))
    assert out["active"] is False


def test_replace_nested():
    out = apply_patch(_user(), _patch({"op": "replace", "path": "name.givenName", "value": "Alicia"}))
    assert out["name"]["givenName"] == "Alicia"


def test_add_creates_intermediate_dict():
    out = apply_patch(_user(), _patch({"op": "add", "path": "name.middleName", "value": "M"}))
    assert out["name"]["middleName"] == "M"


def test_add_to_array_appends():
    out = apply_patch(
        _user(),
        _patch({"op": "add", "path": "emails", "value": [{"value": "alice@new.com", "type": "home"}]}),
    )
    assert len(out["emails"]) == 2
    assert out["emails"][1]["value"] == "alice@new.com"


def test_remove_field():
    out = apply_patch(_user(), _patch({"op": "remove", "path": "active"}))
    assert "active" not in out


def test_remove_nested_field():
    out = apply_patch(_user(), _patch({"op": "remove", "path": "name.givenName"}))
    assert "givenName" not in out["name"]


def test_replace_without_path_is_a_merge():
    out = apply_patch(
        _user(),
        _patch({"op": "replace", "value": {"active": False, "userName": "alice2@x.com"}}),
    )
    assert out["active"] is False
    assert out["userName"] == "alice2@x.com"
    # untouched fields preserved
    assert out["name"]["givenName"] == "Alice"


def test_does_not_mutate_input():
    original = _user()
    snapshot = copy.deepcopy(original)
    apply_patch(original, _patch({"op": "replace", "path": "active", "value": False}))
    assert original == snapshot


def test_bad_op_raises():
    with pytest.raises(PatchError):
        apply_patch(_user(), _patch({"op": "bogus", "path": "active", "value": False}))


def test_missing_schema_raises():
    with pytest.raises(PatchError):
        apply_patch(_user(), {"Operations": [{"op": "replace", "path": "active", "value": False}]})


def test_remove_requires_path():
    with pytest.raises(PatchError):
        apply_patch(_user(), _patch({"op": "remove"}))


def test_filtered_path_is_unsupported():
    with pytest.raises(UnsupportedPatch):
        apply_patch(_user(), _patch({"op": "replace", "path": 'emails[type eq "work"].value', "value": "x"}))


def test_multiple_ops_apply_in_order():
    out = apply_patch(
        _user(),
        _patch(
            {"op": "replace", "path": "active", "value": False},
            {"op": "add",     "path": "name.familyName", "value": "Liddell"},
            {"op": "remove",  "path": "emails"},
        ),
    )
    assert out["active"] is False
    assert out["name"]["familyName"] == "Liddell"
    assert "emails" not in out
