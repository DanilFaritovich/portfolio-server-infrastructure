"""Server operations and separately confirmed guarded APT policy orchestration."""

import subprocess
import sys

import yaml

from .ansible import prerequisites, run_playbook
from .common import ROOT, SSH_BASE, require
from .host_trust import known_host
from .inspection import operations_probe
from .inventory import hardening_inputs, load_host, managed_access
from .keys import check_key
from .plans import PLAN_NOOP_MESSAGES, stage_consent


def operations_expected():
    defaults = yaml.safe_load((ROOT / 'roles/server_operations/defaults/main.yml').read_text())
    journal = (ROOT / 'roles/server_operations/templates/journald.j2').read_text()
    for name, value in defaults.items():
        journal = journal.replace('{{ ' + name + ' }}', str(value))
    require('{{' not in journal, 'Unsupported operations template inputs; STOP.')
    return {
        '/etc/apt/apt.conf.d/99zz-portfolio-security': (ROOT / 'roles/server_operations/templates/apt-security.j2').read_text(),
        '/etc/systemd/journald.conf.d/99-portfolio.conf': journal,
    }


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
    expected = operations_expected()
    planning = mode in ('setup-operations', 'apply-apt-policy')
    params = {'verify': mode == 'verify-operations'} | ({'plan_expected': expected} if planning else {})
    before = operations_probe(host, port, interpreter, key, 'portfolio_operations_info.py', params, managed_user)
    if planning:
        require(isinstance(before, dict) and isinstance(before.get('plan'), dict), 'Operations plan unavailable; STOP.')
        changes = before['plan']['changes']
        require(isinstance(changes, dict) and all(type(value) is bool for value in changes.values()), 'Invalid operations plan; STOP.')
        needed = changes['/etc/apt/apt.conf.d/99zz-portfolio-security'] if mode == 'apply-apt-policy' else any(changes.values())
        if not needed:
            print(PLAN_NOOP_MESSAGES.get(mode, 'Managed configuration already matches; no changes required.'))
            return
        print('Planned changes: ' + ', '.join(name for name, changed in changes.items() if changed and
              (mode == 'setup-operations' or name == '/etc/apt/apt.conf.d/99zz-portfolio-security')))
    def revalidate():
        current = operations_probe(host, port, interpreter, key, 'portfolio_operations_info.py', params, managed_user)
        require(current['plan'] == before['plan'], 'Operations plan changed; STOP before mutation.')
    if mode in ('preview-apt-policy', 'apply-apt-policy'):
        preview = mode == 'preview-apt-policy'
        if not preview:
            require(sys.stdin.isatty(), 'APT-only application requires an interactive terminal.')
            stage_consent(mode, inventory, key)
            revalidate()
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
    stage_consent(mode, inventory, key)
    revalidate()
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
    return 'verify-operations'
