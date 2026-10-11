"""Server operations and separately confirmed guarded APT policy orchestration."""

import subprocess
import sys

from .ansible import prerequisites, run_playbook
from .common import SSH_BASE, require
from .host_trust import known_host
from .inspection import operations_probe
from .inventory import hardening_inputs, load_host, managed_access
from .keys import check_key


def operations(mode, inventory, key=None):
    managed_user, key = managed_access(inventory, key)
    prerequisites(mode)
    check_key(key)
    alias, host, port, _, interpreter = load_host(inventory)
    inputs = hardening_inputs(inventory, alias, port)
    known_host(host, port)
    # Stage 3 verification is also streamed: no Ansible ping/temp payloads.
    operations_probe(host, port, interpreter, key, 'portfolio_hardening_info.py', {
        'current_port': port, 'ssh_ports': inputs['ssh_listen_ports'],
        'tcp_ports': inputs['firewall_allowed_tcp_ports'], 'verify': True,
        'refresh_rules': False, 'socket_candidate': False, 'report_only': True,
    }, managed_user)
    operations_probe(host, port, interpreter, key, 'portfolio_operations_info.py',
                     {'verify': mode == 'verify-operations'}, managed_user)
    if mode in ('preview-apt-policy', 'apply-apt-policy'):
        preview = mode == 'preview-apt-policy'
        if not preview:
            require(sys.stdin.isatty(), 'APT-only application requires an interactive terminal.')
            try:
                answer = input('Apply only the single missing APT policy line? [y/N] ')
            except (EOFError, KeyboardInterrupt):
                answer = ''
            require(answer.strip().lower() in ('y', 'yes'), 'APT-only application declined; no change requested.')
        variables = {
            'ansible_user': managed_user, 'ansible_connection': 'ssh',
            'ansible_private_key_file': str(key), 'ansible_host_key_checking': True,
            'ansible_become_flags': '-n', 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
            'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                                ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                                ' -o KbdInteractiveAuthentication=no',
            'portfolio_apt_confirmed': not preview,
        }
        try:
            run_playbook(inventory, alias, variables, 'apt-policy.yml', check=preview, diff=True)
            if not preview:
                operations_probe(host, port, interpreter, key, 'portfolio_operations_info.py', {'verify': True}, managed_user)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            raise ValueError('APT-only stage failed; STOP. If application was requested, the file may already '
                             'have changed; inspect read-only and do not retry blindly.') from None
        return
    if mode != 'setup-operations':
        return
    require(sys.stdin.isatty(), 'Operations setup requires an interactive terminal; no changes requested.')
    print('LIVE / MUTATING: security update policy, bounded journald retention and timers. '
          'Keep provider recovery access. No automatic reboot.', flush=True)
    try:
        answer = input('Apply server operations configuration? [y/N] ')
    except (EOFError, KeyboardInterrupt):
        answer = ''
    require(answer.strip().lower() in ('y', 'yes'), 'Operations setup declined; no changes requested.')
    run_playbook(inventory, alias, {
        'ansible_user': managed_user, 'ansible_connection': 'ssh',
        'ansible_private_key_file': str(key), 'ansible_host_key_checking': True,
        'ansible_become_flags': '-n', 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no',
        'server_operations_confirmed': True,
    }, 'setup-operations.yml')
    operations_probe(host, port, interpreter, key, 'portfolio_operations_info.py', {'verify': True}, managed_user)
