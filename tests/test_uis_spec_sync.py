from __future__ import annotations

from scripts.ci.verify_uis_spec_sync import verify


def test_vendored_uis_schema_matches_pinned_open_spec() -> None:
    result = verify()

    assert result == {
        "revision": "6f1cbba76a378f9013864be080b4a76b57063ed2",
        "schema_sha256": "cddcdf73bb9a5d9caf6093740168c196c8af525a0edf4fd739bc359f94967d50",
        "schema_version": "1.0",
    }
