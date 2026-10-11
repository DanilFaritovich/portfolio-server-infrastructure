#!/usr/bin/env python3
"""Local E2E fixture entry point; never contacts a production inventory."""
from portfolio_cli.e2e import main

if __name__ == '__main__':
    raise SystemExit(main())
