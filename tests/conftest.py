"""
TokenDNA pytest configuration.
Adds project root to sys.path so module imports work without install.
"""
from __future__ import annotations

import os
import sys
import tempfile

# Project root (parent of tests/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Several modules read DATA_DB_PATH at import time and freeze it into a
# module-level constant. The default ("/data/tokendna.db") is unwritable on
# CI hosts and developer macs, so we point the default at a per-session
# tmpdir before any test imports happen. Individual tests that want their
# own isolated DB still override DATA_DB_PATH locally.
os.environ.setdefault(
    "DATA_DB_PATH",
    os.path.join(tempfile.mkdtemp(prefix="tokendna_test_session_"), "tokendna.db"),
)
