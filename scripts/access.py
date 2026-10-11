#!/usr/bin/env python3
"""Controller-only setup and explicit live access entry points; never store passwords."""

import sys as _sys
from pathlib import Path as _Path

# File-based importers need not put scripts/ on sys.path. Keep that adjustment
# temporary so importing this compatibility entry point does not alter lookup.
_scripts = str(_Path(__file__).resolve().parent)
_sys.path.insert(0, _scripts)
try:
    from portfolio_cli import cli as _cli
    from portfolio_cli.compat import install as _install
finally:
    _sys.path.pop(0)

if __name__ == '__main__':
    _sys.exit(_cli.main())
else:
    _install(globals())
