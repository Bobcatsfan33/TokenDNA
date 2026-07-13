from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

try:
    from scripts.ato_common import DEFAULT_ATO_OUT, load_control_matrix, write_json
except ModuleNotFoundError:
    from ato_common import DEFAULT_ATO_OUT, load_control_matrix, write_json


def build_oscal_component(matrix: dict) -> dict:
    controls = matrix["controls"]
    return {
        "component-definition": {
            "uuid": str(uuid5(NAMESPACE_URL, "tokendna:dod-ato-component")),
            "metadata": {
                "title": "TokenDNA DoD ATO Readiness Component Definition",
                "last-modified": datetime.now(timezone.utc).isoformat(),
                "version": matrix["schema_version"],
                "oscal-version": "1.1.2",
                "remarks": matrix["baseline"],
            },
            "components": [
                {
                    "uuid": str(uuid5(NAMESPACE_URL, "tokendna:control-plane")),
                    "type": "software",
                    "title": matrix["system"],
                    "description": matrix["boundary"],
                    "control-implementations": [
                        {
                            "uuid": str(uuid5(NAMESPACE_URL, "tokendna:nist-800-53-rev5")),
                            "source": "https://doi.org/10.6028/NIST.SP.800-53r5",
                            "description": "TokenDNA product and shared-responsibility implementation statements for DoD ATO readiness.",
                            "implemented-requirements": [
                                {
                                    "uuid": str(uuid5(NAMESPACE_URL, "tokendna:" + control["id"])),
                                    "control-id": control["id"].lower(),
                                    "description": control["implementation_summary"],
                                    "props": [
                                        {"name": "family", "value": control["family"]},
                                        {"name": "owner", "value": control["owner"]},
                                        {"name": "implementation-status", "value": control["implementation_status"]},
                                    ],
                                    "links": [
                                        {"href": evidence, "rel": "evidence"}
                                        for evidence in control.get("evidence_files", [])
                                    ],
                                }
                                for control in controls
                            ],
                        }
                    ],
                }
            ],
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TokenDNA OSCAL component definition")
    parser.add_argument("--output", type=Path, default=DEFAULT_ATO_OUT / "oscal-component-definition.json")
    args = parser.parse_args()

    payload = build_oscal_component(load_control_matrix())
    write_json(args.output, payload)
    print(args.output)


if __name__ == "__main__":
    main()
