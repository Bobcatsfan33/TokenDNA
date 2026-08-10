from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROTECT_SCRIPT = ROOT / "scripts" / "org" / "protect.sh"


def _required_contexts() -> set[str]:
    text = PROTECT_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'"contexts":\s*(\[.*?\])', text, re.DOTALL)
    assert match is not None
    return set(json.loads(match.group(1)))


def test_protection_contexts_match_current_workflow_job_names() -> None:
    job_names: set[str] = set()
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow.get("jobs", {}).values():
            if "name" in job:
                job_names.add(job["name"])

    assert _required_contexts() <= job_names


def test_protection_script_fails_before_github_without_second_codeowner() -> None:
    result = subprocess.run(
        ["bash", str(PROTECT_SCRIPT), "TokenDNA", "independent-reviewer"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "CODEOWNERS must include @independent-reviewer" in result.stderr
