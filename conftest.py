"""Root conftest: ensure top-level scripts (cli.py, build.py, run.py) are importable in tests."""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
