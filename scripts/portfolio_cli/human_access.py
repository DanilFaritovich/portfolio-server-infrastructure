"""Human account policy, public-key registration and final SSH security stages."""

from pathlib import Path
import contextlib
import os
import re
import subprocess
import sys

from .ansible import prerequisites, run_playbook
from .common import SSH_BASE, require
from .host_trust import known_host
from .inspection import user_probe, hardening_plan
from .inventory import hardening_inputs, load_host, managed_access
from .keys import check_key, human_key_path, public_fingerprint, public_key_file, public_key_identity, public_key_snapshot, read_public_key, require_independent_key
from .plans import PLAN_NOOP_MESSAGES, plan_scope, plan_snapshot, planned_action, stage_consent
from .ssh import verify_auth_methods
from .verification import verify_hardening, verify_human


def human_inputs(environment=None, managed_user='ansible'):
    env = os.environ if environment is None else environment
    name = env.get('HUMAN_USER', '')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', managed_user),
            'Set HUMAN_USER to a separate non-root Ubuntu username.')
    policy = env.get('HUMAN_SUDO') or 'none'
    require(policy in ('none', 'admin', 'restricted'), 'HUMAN_SUDO must be none, admin or restricted.')
    groups = [value.strip() for value in env.get('HUMAN_GROUPS', '').split(',') if value.strip()]
    require(len(groups) == len(set(groups)) and all(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', g) for g in groups),
            'HUMAN_GROUPS must be unique comma-separated Ubuntu group names.')
    require(not set(groups) & {'root', managed_user, 'docker', 'lxd', 'disk', 'shadow', 'libvirt',
                              'libvirt-qemu', 'incus', 'incus-admin', 'adm', 'systemd-journal',
                              'kvm', 'sudoers', 'wheel', 'storage', 'input', 'video', 'render'},
            'Root-equivalent/system groups are not supported for human accounts.')
    require(policy == 'admin' or not set(groups) & {'sudo', 'admin'},
            'sudo/admin group membership requires HUMAN_SUDO=admin.')
    approved = [value.strip() for value in env.get('HUMAN_GROUPS_APPROVED', '').split(',') if value.strip()]
    require(len(approved) == len(set(approved)) and
            set(approved) == set(groups) - {'sudo', 'admin'},
            'Set HUMAN_GROUPS_APPROVED to the exact non-sudo groups only after reviewing their server-side rights. '
            'Membership may grant sensitive file/log/device access or administrative operations, regardless of HUMAN_SUDO.')
    commands = [value.strip() for value in env.get('HUMAN_SUDO_COMMANDS', '').split(',') if value.strip()]
    require(policy == 'restricted' or not commands, 'HUMAN_SUDO_COMMANDS is only for restricted sudo.')
    require(policy != 'restricted' or (commands and len(commands) == len(set(commands)) and
            all(re.fullmatch(r'/[a-zA-Z0-9_./-]+', c) and '..' not in Path(c).parts for c in commands)),
            'Restricted sudo requires comma-separated absolute executable paths without arguments or wildcards.')
    return {'human_access_user_name': name, 'human_access_user_groups': groups,
            'human_access_user_approved_groups': approved,
            'human_access_user_sudo': policy,
            'human_access_user_sudo_commands': ['ALL'] if policy == 'admin' else commands}


@contextlib.contextmanager
def add_user_public_key():
    imported = os.environ.get('HUMAN_PUBLIC_KEY', '')
    if imported:
        content = read_public_key(public_key_file(imported))
    else:
        require(sys.stdin.isatty(), 'Set HUMAN_PUBLIC_KEY to a .pub file in noninteractive mode.')
        print('Public SSH key was not provided.\n\nPaste the public SSH key (ssh-ed25519 ...):')
        try:
            content = input('> ')
        except (EOFError, KeyboardInterrupt):
            raise ValueError('Public key input cancelled; no VPS changes requested.') from None
    # Snapshot either input in a private, automatically removed file for Ansible.
    with public_key_snapshot(content) as public:
        yield public


def human_access(mode, inventory, automation_key=None):
    if mode != 'add-user':
        return human_access_stage(mode, inventory, automation_key)
    managed_user, managed_key = managed_access(inventory, automation_key)
    human = human_inputs(managed_user=managed_user)
    key = human_key_path(os.environ.get('HUMAN_KEY'), human['human_access_user_name'])
    require(key.resolve() != managed_key.resolve(), 'Use separate human and automation SSH keys.')
    with add_user_public_key() as public:
        require_independent_key(public, managed_key, 'Use separate human and automation SSH key identities.')
        print(f"User: {human['human_access_user_name']}\nHUMAN_SUDO: {human['human_access_user_sudo']}\n"
              f'SHA256 fingerprint: {public_fingerprint(public)}')
        if human['human_access_user_approved_groups']:
            print('Explicitly approved groups: ' + ', '.join(human['human_access_user_approved_groups']) +
                  '\nMembership grants their configured file/log/device and administrative rights independently of sudo.')
        if sys.stdin.isatty():
            # Terminal public-key registration requires consent before host contact.
            with plan_scope([mode], lambda: (plan_snapshot(inventory, automation_key), public.read_bytes())):
                planned_action(mode)
                return human_access_stage(mode, inventory, automation_key, public)
        return human_access_stage(mode, inventory, automation_key, public)


def human_access_stage(mode, inventory, automation_key=None, supplied_public=None):
    managed_user, automation_key = managed_access(inventory, automation_key)
    human = human_inputs(managed_user=managed_user)
    name = human['human_access_user_name']
    key = human_key_path(os.environ.get('HUMAN_KEY'), name)
    require(key.resolve() != automation_key.resolve(), 'Use separate human and automation SSH keys.')
    imported = supplied_public or os.environ.get('HUMAN_PUBLIC_KEY', '')
    public = public_key_file(imported) if imported else Path(str(key) + '.pub')
    require_independent_key(public, automation_key, 'Use separate human and automation SSH key identities.')
    if imported and mode != 'add-user':
        check_key(key)
        require(public_key_identity(public) == public_key_identity(str(key) + '.pub'),
                'HUMAN_KEY must correspond to HUMAN_PUBLIC_KEY for independent verification.')
    prerequisites(mode)
    check_key(automation_key)
    alias, host, port, _, interpreter = load_host(inventory)
    inputs = hardening_inputs(inventory, alias, port)
    known_host(host, port)
    managed = {
        'ansible_connection': 'ssh', 'ansible_user': managed_user, 'ansible_host_key_checking': True,
        'ansible_private_key_file': str(automation_key), 'ansible_become_flags': '-n',
        'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no',
    }
    # No cached receipt: re-prove automation access and completed Stage 3 on every selected route.
    verify_hardening(inventory, alias, host, port, managed, inputs)
    if mode == 'add-user':
        _, _, _, _, interpreter = load_host(inventory)
        before = user_probe(host, port, interpreter, automation_key, managed_user, {
            'action': 'preflight-add-user', 'name': name, 'sudo': human['human_access_user_sudo'],
            'groups': human['human_access_user_groups'], 'commands': human['human_access_user_sudo_commands'],
        })
        if before.get('existing'):
            existing = user_probe(host, port, interpreter, automation_key, managed_user, {'action': 'show-user', 'name': name})
            if any(entry.get('managed') is True and entry.get('key') == public.read_text().strip()
                   for entry in existing['keys']):
                print('Account policy and exact managed public key already match; no changes required.')
                return
        stage_consent(mode, inventory, automation_key, public)
        # Revalidate the account/controller token after operator interaction.
        current = user_probe(host, port, interpreter, automation_key, managed_user, {
            'action': 'preflight-add-user', 'name': name, 'sudo': human['human_access_user_sudo'],
            'groups': human['human_access_user_groups'], 'commands': human['human_access_user_sudo_commands'],
        })
        require(current == before, 'Account plan changed; STOP before mutation.')
        if not before.get('existing'):
            run_playbook(inventory, alias, managed | human | {'human_access_user_public_key_path': str(public)}, 'add-user.yml')
            before = user_probe(host, port, interpreter, automation_key, managed_user, {'action': 'show-user', 'name': name})
        user_probe(host, port, interpreter, automation_key, managed_user, {
            'action': 'add-user-key', 'name': name, 'key': public.read_text().strip(),
            'token': before['token'], 'confirmed': True,
        })
        if imported:
            print('Public key installed. Access is UNVERIFIED: its owner must run make verify-user with the matching key.')
            return
    if mode == 'secure-ssh':
        require(human['human_access_user_sudo'] == 'admin', 'Final hardening requires HUMAN_SUDO=admin.')
        require(sys.stdin.isatty(), 'Final SSH hardening requires interactive recovery confirmation.')
    verify_human(inventory, alias, host, port, managed, inputs, human, key)
    if mode == 'secure-ssh':
        print('LIVE / MUTATING: disable root, password and keyboard-interactive SSH login. '
              'Keep an administrator session open and provider console available.', flush=True)
        before = hardening_plan(host, port, interpreter, automation_key, inputs, managed_user, security=True)
        if not before['changes_required']:
            print(PLAN_NOOP_MESSAGES[mode])
            return
        stage_consent(mode, inventory, automation_key)
        require(hardening_plan(host, port, interpreter, automation_key, inputs, managed_user, security=True) == before,
                'Final SSH plan changed; STOP before mutation.')
        verify_human(inventory, alias, host, port, managed, inputs, human, key)
        try:
            confirmation = {'ssh_security_confirmed': True, 'human_access_user_private_key_path': str(key),
                            'human_access_user_ssh_args': managed['ansible_ssh_args']}
            run_playbook(inventory, alias, managed | inputs | human | confirmation, 'secure-ssh.yml')
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError('SSH policy application failed; it may already be installed. Stop and use the retained '
                             'administrator session/provider console; do not retry blindly.') from None
    if mode in ('secure-ssh', 'verify-ssh-security'):
        require(human['human_access_user_sudo'] == 'admin', 'SSH security verification requires HUMAN_SUDO=admin.')
        verify_hardening(inventory, alias, host, port, managed, inputs)
        verify_human(inventory, alias, host, port, managed, inputs, human, key)
        run_playbook(inventory, alias, managed | inputs, 'verify-ssh-security.yml')
        identity = host if port == 22 else f'[{host}]:{port}'
        for target in inputs['ssh_verify_ports']:
            for login in (managed_user, name):
                verify_auth_methods(host, target, login, identity)
    print('Requested human access stage completed. STOP.')
    if mode == 'secure-ssh':
        return 'verify-ssh-security'
