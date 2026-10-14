#!/usr/bin/env python3
"""Controller-only setup and explicit live access entry points; never store passwords."""

import sys as _sys
from pathlib import Path as _Path

# File-based importers need not put scripts/ on sys.path. Keep that adjustment
# temporary so importing this compatibility entry point does not alter lookup.
_scripts = str(_Path(__file__).resolve().parent)
_sys.path.insert(0, _scripts)
try:
    if __name__ == '__main__':
        import os as _os
        if _os.environ.get('PORTFOLIO_E2E_ROOT'):
            from portfolio_cli.e2e import configure_child as _configure_e2e, E2EError as _E2EError
            try:
                _configure_e2e()
            except _E2EError as _error:
                print('E2E guard failed: ' + str(_error) + ' No provisioning dispatched.', file=_sys.stderr)
                _sys.exit(1)
            except Exception:
                print('E2E guard failed; no provisioning dispatched. Inspect the local fixture.', file=_sys.stderr)
                _sys.exit(1)
    from portfolio_cli import cli as _cli
    from portfolio_cli.compat import install as _install
finally:
    _sys.path.pop(0)

if __name__ == '__main__':
    _sys.exit(_cli.main())
else:
    _install(globals())
