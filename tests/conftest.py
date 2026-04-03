"""
TokenDNA pytest configuration.
Adds project root to sys.path so module imports work without install.
"""
from __future__ import annotations

import os
import sys

# Project root (parent of tests/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
