from pathlib import Path

from scripts.ci.workflow_action_pin_guard import find_unpinned


def test_repository_workflows_pin_every_remote_action():
    assert find_unpinned() == []


def test_guard_rejects_mutable_refs_and_accepts_full_commits(tmp_path: Path):
    (tmp_path / "unsafe.yml").write_text(
        "steps:\n  - uses: actions/checkout@v6\n",
        encoding="utf-8",
    )
    assert find_unpinned(tmp_path) == ["unsafe.yml:2: actions/checkout@v6"]

    (tmp_path / "unsafe.yml").write_text(
        "steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n",
        encoding="utf-8",
    )
    assert find_unpinned(tmp_path) == []
