#!/usr/bin/env python3
"""Run the safeharbor-check test suite (stdlib unittest only).

Usage:  python3 run_tests.py
Exits 0 if all tests pass, 1 otherwise.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    suite = unittest.TestLoader().discover("tests", top_level_dir=str(ROOT))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
