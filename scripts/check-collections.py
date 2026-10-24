#!/usr/bin/env python3
"""Verify local pinned collections without Galaxy or managed-host access."""

from pathlib import Path
import sys

from portfolio_cli.collection_integrity import check_collections

try:
    check_collections(Path.cwd())
except (ValueError, OSError, KeyError, TypeError):
    print('Pinned collection integrity failed; STOP and inspect the local dependency tree.', file=sys.stderr)
    sys.exit(1)
print('Pinned collection contents verified.')
