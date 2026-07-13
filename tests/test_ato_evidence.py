from __future__ import annotations

import json

from scripts.ato_common import load_control_matrix
from scripts.collect_ato_evidence import build_evidence_manifest
from scripts.generate_oscal import build_oscal_component
from scripts.stig_evidence import build_stig_evidence


def test_control_matrix_has_required_shape():
    matrix = load_control_matrix()

    assert matrix["schema_version"]
    assert "dod_il5" in matrix["profiles"]
    assert len(matrix["controls"]) >= 10
    for control in matrix["controls"]:
        assert control["id"]
        assert control["implementation_summary"]
        assert control["evidence_files"]


def test_ato_evidence_manifest_has_no_missing_files():
    manifest = build_evidence_manifest(load_control_matrix())

    assert manifest["control_count"] >= 10
    assert manifest["missing_evidence_count"] == 0


def test_generate_oscal_component_definition(tmp_path):
    payload = build_oscal_component(load_control_matrix())
    output = tmp_path / "component.json"
    output.write_text(json.dumps(payload), encoding="utf-8")

    component = payload["component-definition"]["components"][0]
    implemented = component["control-implementations"][0]["implemented-requirements"]
    control_ids = {item["control-id"] for item in implemented}

    assert "ac-3" in control_ids
    assert "sc-13" in control_ids


def test_stig_evidence_mapping_references_existing_files():
    payload = build_stig_evidence()

    assert payload["mappings"]
    for mapping in payload["mappings"]:
        assert mapping["stig"]
        assert mapping["evidence_entries"]
        assert all(entry["exists"] for entry in mapping["evidence_entries"])
