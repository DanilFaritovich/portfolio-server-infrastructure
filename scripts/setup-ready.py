#!/usr/bin/env python3
"""Read-only dependency readiness; never inspect real inventory or private keys."""

import importlib.metadata
from pathlib import Path
import sys

try:
    root = Path.cwd()
    if sys.version_info[:2] != (3, 12) or not Path(sys.base_prefix).resolve().is_relative_to(root / '.tools/python'):
        sys.exit(1)
    for line in (root / 'requirements-dev.txt').read_text().splitlines():
        if line and not line.startswith('#'):
            name, version = line.split('==')
            if importlib.metadata.version(name) != version:
                sys.exit(1)
    from portfolio_cli.collection_integrity import check_collections
    check_collections(root)
except (OSError, ValueError, KeyError, TypeError, importlib.metadata.PackageNotFoundError, ImportError):
    sys.exit(1)
