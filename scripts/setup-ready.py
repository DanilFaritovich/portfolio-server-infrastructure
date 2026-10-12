#!/usr/bin/env python3
"""Read-only dependency readiness; never inspect real inventory or private keys."""

import importlib.metadata
import json
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
    import yaml
    for collection in yaml.safe_load((root / 'collections.yml').read_text())['collections']:
        path = root / '.ansible/collections/ansible_collections' / collection['name'].replace('.', '/') / 'MANIFEST.json'
        if json.loads(path.read_text())['collection_info']['version'] != collection['version']:
            sys.exit(1)
except (OSError, ValueError, KeyError, importlib.metadata.PackageNotFoundError, ImportError):
    sys.exit(1)
