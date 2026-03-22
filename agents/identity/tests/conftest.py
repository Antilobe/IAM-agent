"""Shared test fixtures for the Identity Security Agent."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
