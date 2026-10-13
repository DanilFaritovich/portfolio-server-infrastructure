"""Managed user lifecycle orchestration with independent recovery proof."""

from pathlib import Path
import json
import os
import re
import sys

from .ansible import prerequisites
from .plans import plan_confirm, planned_action
from .common import SSH_BASE, require
from .host_trust import known_host
from .inspection import operations_probe, user_probe
from .inventory import hardening_inputs, load_host, managed_access
from .keys import check_key, human_key_path, public_fingerprint, public_key_file, public_key_snapshot, read_public_key, require_independent_key
from .verification import verify_human


USER_MANAGEMENT_MODES = ('list-users', 'show-user', 'list-user-keys', 'add-user-key', 'revoke-user-key', 'remove-user')


def user_management(mode, inventory, override=None):
    controller, key = managed_access(inventory, override)
    name = os.environ.get('HUMAN_USER', '')
    if mode != 'list-users':
        require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', controller),
                'Set HUMAN_USER to a managed human account separate from root/current controller.')
    params = {'action': mode, 'name': name}
    if mode == 'add-user-key':
        public = public_key_file(os.environ.get('HUMAN_PUBLIC_KEY', ''))
        # Freeze the validated input before identity checks and any host contact.
        with public_key_snapshot(read_public_key(public)) as snapshot:
            require_independent_key(snapshot, key, 'Human and controller must use different SSH key identities.')
            params['key'] = read_public_key(snapshot).strip()
    if mode == 'revoke-user-key':
        digest = os.environ.get('KEY_FINGERPRINT', '')
        require(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', digest), 'Set KEY_FINGERPRINT to an exact SHA256 fingerprint.')
        params['fingerprint'] = digest
    if mode in ('revoke-user-key', 'remove-user'):
        recovery = os.environ.get('RECOVERY_USER', '')
        require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', recovery or '') and recovery not in ('root', controller, name),
                'Set RECOVERY_USER to another managed human admin whose access will be retained.')
        recovery_key = human_key_path(os.environ.get('RECOVERY_KEY'), recovery)
        require(recovery_key != key, 'Use a separate recovery administrator key.')
        check_key(recovery_key)
        require_independent_key(str(recovery_key) + '.pub', key,
                                'Recovery and controller must use different SSH key identities.')
    prerequisites(mode)
    check_key(key)
    alias, host, port, _, interpreter = load_host(inventory)
    inputs = hardening_inputs(inventory, alias, port)
    known_host(host, port)
    probe = lambda values: user_probe(host, port, interpreter, key, controller, values)
    if mode in ('list-users', 'show-user', 'list-user-keys'):
        print(json.dumps(probe(params), indent=2))
        return
    # Validate Stage 3 and fresh managed key-only sudo before every mutation.
    operations_probe(host, port, interpreter, key, 'portfolio_hardening_info.py', {
        'current_port': port, 'ssh_ports': inputs['ssh_listen_ports'],
        'tcp_ports': inputs['firewall_allowed_tcp_ports'], 'verify': True,
        'refresh_rules': False, 'socket_candidate': False, 'report_only': True,
    }, controller)
    before = probe({'action': 'show-user', 'name': name})
    if mode == 'remove-user' and before.get('removed'):
        print(json.dumps(before, indent=2))
        return
    if mode == 'add-user-key' and any(entry.get('managed') is True and entry.get('key') == params['key'] for entry in before['keys']):
        print('Exact managed public key already registered; no changes required.')
        return
    params['token'] = before['token']
    if mode in ('revoke-user-key', 'remove-user'):
        retained = probe({'action': 'show-user', 'name': recovery})
        require(retained.get('sudo') == 'admin', 'Recovery account must be a managed administrator.')
        managed = {'ansible_user': controller, 'ansible_connection': 'ssh',
                   'ansible_private_key_file': str(key), 'ansible_host_key_checking': True,
                   'ansible_become_flags': '-n', 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
                   'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                   ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                   ' -o KbdInteractiveAuthentication=no'}
        human = {'human_access_user_name': recovery, 'human_access_user_sudo': 'admin',
                 'human_access_user_groups': retained['groups'], 'human_access_user_sudo_commands': ['ALL']}
        selected = public_fingerprint(Path(str(recovery_key) + '.pub'))
        verify_human(inventory, alias, host, port, managed, inputs, human, recovery_key)
        require(public_fingerprint(Path(str(recovery_key) + '.pub')) == selected,
                'Recovery public identity changed during access proof.')
        target_keys = {entry['fingerprint'] for entry in before['keys']}
        recovery_keys = {entry['fingerprint'] for entry in retained['keys']}
        require(not target_keys & recovery_keys, 'Target and recovery SSH keys overlap.')
        require(selected in recovery_keys, 'Selected recovery identity is absent from the retained account.')
        params.update(recovery_user=recovery, recovery_token=retained['token'], recovery_fingerprint=selected)
    require(sys.stdin.isatty(), 'User/key mutation requires interactive recovery confirmation.')
    print(json.dumps(before, indent=2))
    if mode == 'add-user-key':
        print('Public key to add: ' + json.dumps(params['key']))
    elif mode == 'revoke-user-key':
        print('Fingerprint to revoke: ' + params['fingerprint'])
    print('LIVE / MUTATING: ' + mode + ' for ' + name + '. Keep provider console recovery available.', flush=True)
    validate = lambda: require(probe({'action': 'show-user', 'name': name})['token'] == before['token'],
                               'Account plan changed; STOP before mutation.')
    if planned_action(mode):
        validate()
    else:
        plan_confirm(['Remote sudo: ' + mode + ' for ' + name + '. ' +
                      ('Revoke keys/sudo and run non-forced userdel; preserve files; require independent recovery access.'
                       if mode == 'remove-user' else 'Change only the selected authorized key and its protected ownership ledger.')],
                     validate=validate)
    result = probe(params | {'confirmed': True})
    # The remote engine verifies exact key/account results. Fresh controller proof
    # after mutation detects a lost automation route; failures never trigger retries.
    operations_probe(host, port, interpreter, key, 'portfolio_hardening_info.py', {
        'current_port': port, 'ssh_ports': inputs['ssh_listen_ports'],
        'tcp_ports': inputs['firewall_allowed_tcp_ports'], 'verify': True,
        'refresh_rules': False, 'socket_candidate': False, 'report_only': True,
    }, controller)
    print(json.dumps(result, indent=2))
    if mode == 'add-user-key':
        print('Key installed; its owner must independently verify key-only SSH access from their PC.')
