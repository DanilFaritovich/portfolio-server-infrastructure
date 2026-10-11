"""Controller-only setup and explicit live access entry points; never store passwords."""

from pathlib import Path
import argparse
import os
import subprocess
import sys

from .common import ROOT
from .host_trust import TRUST_GUIDANCE, server_trust
from .human_access import human_access
from .inventory import setup_inventory
from .local_keys import local_key
from .operations import operations
from .provisioning import live
from .ssh import cli_connection
from .user_management import USER_MANAGEMENT_MODES, user_management


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=[*USER_MANAGEMENT_MODES, 'show-server-trust', 'copy-server-trust', 'trust-server', 'generate-user-key', 'load-user-key', 'show-public-key', 'copy-public-key', 'show-controller', 'connect-controller', 'connect-user', 'preview-apt-policy', 'apply-apt-policy', 'inspect-operations', 'setup-operations', 'verify-operations', 'setup', 'bootstrap-user', 'verify-access', 'docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host', 'add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'])
    parser.add_argument('--inventory', default=str(ROOT / 'inventories/production.yml'))
    parser.add_argument('--key', default=None, help='Legacy key override; explicit inventories own the key path.')
    args = parser.parse_args()
    os.umask(0o077)
    inventory = Path(args.inventory).expanduser().absolute()
    try:
        if args.mode == 'setup':
            setup_inventory(inventory)
        elif args.mode in ('show-server-trust', 'copy-server-trust', 'trust-server'):
            server_trust(args.mode, inventory)
        elif args.mode in ('generate-user-key', 'load-user-key', 'show-public-key', 'copy-public-key'):
            local_key(args.mode)
        elif args.mode in ('show-controller', 'connect-controller', 'connect-user'):
            cli_connection(args.mode, inventory, args.key or None)
        elif args.mode in ('preview-apt-policy', 'apply-apt-policy', 'inspect-operations', 'setup-operations', 'verify-operations'):
            operations(args.mode, inventory, args.key or None)
        elif args.mode in USER_MANAGEMENT_MODES:
            user_management(args.mode, inventory, args.key or None)
        elif args.mode in ('add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'):
            human_access(args.mode, inventory, args.key or None)
        else:
            live(args.mode, inventory, args.key or None)
    except ValueError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if args.mode in ('show-server-trust', 'copy-server-trust', 'trust-server'):
            print('Local host-trust operation failed; no success was confirmed. '
                  'Check local OpenSSH tools and known_hosts permissions; inspect trust before retrying. '
                  + TRUST_GUIDANCE, file=sys.stderr)
            return 1
        print('A local prerequisite, SSH or Ansible stage failed; stopping. '
              'For an encrypted key, run make load-user-key in the same shell with the selected key. '
              'Keep recovery access.', file=sys.stderr)
        return 1
    return 0
