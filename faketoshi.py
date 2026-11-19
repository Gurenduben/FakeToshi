#!/usr/bin/env python3
"""Launcher: `python faketoshi.py ...` from the repository root.

The implementation lives in the ``faketoshi`` package next to this file, so
either of these works without installing anything:

    python faketoshi.py --help
    python -m faketoshi --help
    ./faketoshi.py --help          # after chmod +x

Installing the project (``pip install -e .``) additionally provides a
``faketoshi`` command on your PATH.
"""

import os
import sys

# Allow running straight from a source checkout, even when the current working
# directory is somewhere else (e.g. `python /path/to/faketoshi.py`).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from faketoshi.__main__ import main
except ImportError as exc:  # pragma: no cover - only on a broken checkout
    sys.exit(
        'could not import the faketoshi package (%s).\n'
        'Make sure you are running this launcher from the repository root, '
        'where the faketoshi/ package sits.' % exc
    )

if __name__ == '__main__':
    sys.exit(main())
