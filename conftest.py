"""Ensure the project root is on sys.path for all test modules."""
from __future__ import annotations

import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent))
