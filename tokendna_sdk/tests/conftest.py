"""Shared pytest fixtures for the SDK test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tokendna_sdk.config import reset_config


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Strip TOKENDNA_* env vars before every test so behaviour is
    deterministic regardless of the developer's shell."""
    for key in list(os.environ):
        if key.startswith("TOKENDNA_"):
            monkeypatch.delenv(key, raising=False)
    reset_config()
    yield
    reset_config()


@pytest.fixture
def tmp_tokendna_root(tmp_path: Path, monkeypatch) -> Path:
    """Isolated ~/.tokendna for tests that touch the local client."""
    root = tmp_path / "tokendna"
    monkeypatch.setenv("TOKENDNA_LOCAL_ROOT", str(root))
    reset_config()
    return root
