"""Controller-only setup and explicit live access entry points; never store passwords."""

from pathlib import Path
import argparse
import os
import subprocess
import sys
from contextlib import nullcontext

from .plans import e2e_child_plan
from .ansible import pipeline_lock
from .common import ROOT, require
from .deployment_artifact import prepared_gh
from .deployment_prerequisites import DEPLOYMENT_MODES, deployment_prerequisites
from .host_trust import TRUST_GUIDANCE, server_trust
from .human_access import human_access
from .inventory import setup_inventory
from .initialization import init_server
from .local_keys import local_key
from .operations import operations
from .provisioning import live
from .ssh import cli_connection
from .user_management import USER_MANAGEMENT_MODES, user_management


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare-deployment-prerequisites', *DEPLOYMENT_MODES, 'setup-swap', 'verify-swap', 'init-server', *USER_MANAGEMENT_MODES, 'show-server-trust', 'copy-server-trust', 'trust-server', 'generate-user-key', 'load-user-key', 'show-public-key', 'copy-public-key', 'show-controller', 'connect-controller', 'connect-user', 'preview-apt-policy', 'apply-apt-policy', 'inspect-operations', 'setup-operations', 'verify-operations', 'setup', 'bootstrap-user', 'verify-access', 'docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host', 'add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'])
    parser.add_argument('--inventory', default=str(ROOT / 'inventories/production.yml'))
    parser.add_argument('--key', default=None, help='Legacy key override; explicit inventories own the key path.')
    args = parser.parse_args()
    os.umask(0o077)
    inventory = Path(args.inventory).expanduser().absolute()
    local_modes = ('prepare-deployment-prerequisites', 'setup', 'show-server-trust', 'copy-server-trust', 'trust-server',
                   'generate-user-key', 'load-user-key', 'show-public-key', 'copy-public-key',
                   'show-controller', 'connect-controller', 'connect-user')
    try:
        with nullcontext() if args.mode in local_modes else pipeline_lock():
            with e2e_child_plan(inventory, args.mode):
                return dispatch(args, inventory)
    except KeyboardInterrupt:
        if args.mode in local_modes:
            print('Command interrupted; no success was confirmed. Inspect its state before retrying.', file=sys.stderr)
            return 1
        print('Interrupted; STOP. Remote work may already have started or may still be running. '
              'Use recovery access and read-only diagnosis; do not repeat a mutation blindly.', file=sys.stderr)
        return 1
    except ValueError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if args.mode in ('show-server-trust', 'copy-server-trust', 'trust-server'):
            print('Local host-trust operation failed; no success was confirmed. '
                  'Check local OpenSSH tools and known_hosts permissions; inspect trust before retrying. '
                  + TRUST_GUIDANCE, file=sys.stderr)
            return 1
        print('A local prerequisite, SSH or Ansible stage failed; STOP. '
              'Remote state is unconfirmed and work may still be running. Use recovery access and '
              'read-only diagnosis; do not repeat mutations blindly. For an encrypted key, '
              'run make load-user-key in the same shell with the selected key.', file=sys.stderr)
        return 1


def dispatch(args, inventory):
    """Dispatch inside the stage lock; exceptions retain their public CLI boundary."""
    if args.mode == 'prepare-deployment-prerequisites':
        with prepared_gh():
            print('LOCAL: official gh 2.102.0 archive, binary SHA256, ELF AMD64 and version verified; temporary artifacts removed on completion.')
    elif args.mode in DEPLOYMENT_MODES:
        require(not os.environ.get('CI'), 'Deployment prerequisites LIVE commands are disabled in offline CI.')
        deployment_prerequisites(args.mode, inventory, args.key or None)
    elif args.mode == 'setup':
        setup_inventory(inventory)
    elif args.mode == 'init-server':
        init_server(inventory, args.key or None)
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
    return 0
