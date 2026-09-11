from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROTECT_SCRIPT = ROOT / "scripts" / "org" / "protect.sh"
GITHUB_ADVANCED_SECURITY_CONTEXTS = {"CodeQL", "Trivy"}
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_ADVANCED_SECURITY_APP_ID = 57789


def _required_checks() -> dict[str, int]:
    text = PROTECT_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'"checks":\s*(\[.*?\])', text, re.DOTALL)
    assert match is not None
    return {check["context"]: check["app_id"] for check in json.loads(match.group(1))}


def test_protection_contexts_match_current_workflow_job_names() -> None:
    job_names: set[str] = set()
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in workflow.get("jobs", {}).values():
            if "name" in job:
                job_names.add(job["name"])

    required_checks = _required_checks()
    assert set(required_checks) <= job_names | GITHUB_ADVANCED_SECURITY_CONTEXTS
    assert {
        context: required_checks[context] for context in GITHUB_ADVANCED_SECURITY_CONTEXTS
    } == dict.fromkeys(GITHUB_ADVANCED_SECURITY_CONTEXTS, GITHUB_ADVANCED_SECURITY_APP_ID)
    assert all(
        app_id == GITHUB_ACTIONS_APP_ID
        for context, app_id in required_checks.items()
        if context not in GITHUB_ADVANCED_SECURITY_CONTEXTS
    )


def test_protection_script_fails_before_github_without_second_codeowner() -> None:
    result = subprocess.run(
        ["bash", str(PROTECT_SCRIPT), "TokenDNA", "independent-reviewer"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "CODEOWNERS must include @independent-reviewer" in result.stderr
