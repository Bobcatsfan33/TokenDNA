from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import build_release_bundle


def test_release_manifest_enumerates_only_shipped_components(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"

    manifest = build_release_bundle.build_manifest("example/tokendna:3.0.0", output)

    assert manifest["product_version"] == "3.0.0"
    assert manifest["sdk_version"] == "0.2.0"
    assert manifest["components"]["python_packages"] == [
        {"name": "tokendna-sdk", "path": "tokendna_sdk"}
    ]
    assert json.loads(output.read_text(encoding="utf-8")) == manifest


def test_release_manifest_fails_closed_when_a_component_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build_release_bundle, "ROOT", tmp_path)

    with pytest.raises(RuntimeError, match="missing release docs"):
        build_release_bundle.build_manifest("example/tokendna:3.0.0", tmp_path / "manifest.json")


def test_runtime_and_release_product_versions_match() -> None:
    from api_routers._shared import APP_VERSION

    assert APP_VERSION == build_release_bundle._read_product_version()
