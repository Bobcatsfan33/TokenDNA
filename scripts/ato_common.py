from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTROL_MATRIX = ROOT / "compliance" / "dod" / "control_matrix.json"
DEFAULT_ATO_OUT = ROOT / "dist" / "ato"


def load_control_matrix(path: Path = CONTROL_MATRIX) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_entry(path_text: str) -> dict[str, Any]:
    path = ROOT / path_text
    exists = path.exists()
    entry: dict[str, Any] = {
        "path": path_text,
        "exists": exists,
    }
    if exists and path.is_file():
        entry["sha256"] = sha256_file(path)
        entry["size_bytes"] = path.stat().st_size
    return entry


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
