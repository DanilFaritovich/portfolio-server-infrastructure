#!/usr/bin/env python3
"""Controller-only setup and explicit live access entry points; never store passwords."""

import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import socket
import subprocess
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = Path.home() / '.ssh/portfolio-server-infrastructure/ansible_ed25519'
PASSWORD_CONNECTION = 'portfolio_password'
HARDENING_FIELDS = {'ssh_listen_ports', 'ssh_verify_ports', 'firewall_allowed_tcp_ports'}
HOST_FIELDS = {'ansible_host', 'ansible_port', 'ansible_user', 'bootstrap_login_user', 'ansible_private_key_file', 'ansible_python_interpreter'} | HARDENING_FIELDS
SSH_BASE = ('-F /dev/null -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none'
            ' -o ConnectTimeout=15 -o ForwardAgent=no -o ClearAllForwardings=yes'
            ' -o PermitLocalCommand=no -o UpdateHostKeys=no')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def setup_inventory(path):
    """Exclusive creation: never read or overwrite an existing production inventory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as target:
            target.write((ROOT / 'inventories/production.example.yml').read_text())
    except FileExistsError:
        print('Inventory already exists; preserved without reading it.')
    else:
        print('Inventory created. Edit ansible_host and ansible_port before bootstrap.')


def load_host(path, validate_hardening=True):
    require(path.is_file() and path.resolve() != ROOT / 'inventories/production.example.yml',
            'Real local inventory required. Run make setup, then edit host and port.')
    try:
        data = yaml.safe_load(path.read_text())
        require(set(data) == {'all'}, 'Use the static example inventory structure.')
        require(set(data['all']) == {'children'}, 'Use the static example inventory structure.')
        children = data['all']['children']
        require(set(children) == {'bootstrap'}, 'Exactly one bootstrap group is supported.')
        group = children['bootstrap']
        require(set(group) == {'hosts'}, 'Keep credentials and runtime variables out of inventory.')
        hosts = group['hosts']
        require(len(hosts) == 1, 'Exactly one bootstrap host is supported.')
        alias, values = next(iter(hosts.items()))
        require(isinstance(alias, str) and re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]*', alias),
                'Use a simple host alias such as portfolio.')
        require(alias != 'localhost', 'Reserve localhost for the controller; use a separate VPS alias.')
        require(isinstance(values, dict) and set(values) <= HOST_FIELDS,
                'Only host, port, access users/key path, Python interpreter and hardening port lists belong in inventory.')
        for name in HARDENING_FIELDS & values.keys() if validate_hardening else ():
            validate_ports(values[name], allow_empty=name == 'firewall_allowed_tcp_ports')
        host = values.get('ansible_host')
        port = values.get('ansible_port')
        user = values.get('bootstrap_login_user', values.get('ansible_user', 'root'))
        validate_access_values(values)
        interpreter = values.get('ansible_python_interpreter', '/usr/bin/python3')
        require(isinstance(host, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]*', host)
                and not host.endswith('.invalid') and '{{' not in host,
                'Set ansible_host to your verified VPS hostname or address.')
        require(type(port) is int and 1 <= port <= 65535, 'Set ansible_port to an integer from 1 to 65535.')
        require(isinstance(user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user), 'Initial login must be root or another existing administrator.')
        require(isinstance(interpreter, str) and re.fullmatch(r'/[a-zA-Z0-9_./-]+', interpreter),
                'Use an absolute Python interpreter path.')
    except (yaml.YAMLError, TypeError, KeyError, AttributeError):
        # Parser exceptions can include inventory contents: do not expose them.
        raise ValueError('Invalid inventory. Use the static example structure without credentials.') from None
    return alias, host, port, user, interpreter


def validate_access_values(values):
    """Explicit access contract; legacy initial-login inventories remain supported."""
    explicit = 'bootstrap_login_user' in values or 'ansible_private_key_file' in values
    if explicit:
        require({'bootstrap_login_user', 'ansible_user', 'ansible_private_key_file'} <= values.keys(),
                'Set bootstrap_login_user, ansible_user and ansible_private_key_file together.')
        name = values['ansible_user']
        require(isinstance(name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name)
                and name != 'root', 'ansible_user must be a non-root managed Ubuntu username.')
        value = values['ansible_private_key_file']
        require(isinstance(value, str) and value and (value.startswith('/') or value.startswith('~/'))
                and '{{' not in value and '\n' not in value,
                'ansible_private_key_file must be an absolute or ~/ local key path.')
        key_path(value)
    else:
        require(values.get('ansible_user', 'root') != 'ansible',
                'Legacy inventory describes the initial login; use the explicit access fields for managed login.')


def managed_access(inventory, override=None):
    # Validate the entire static inventory before selecting any connection identity.
    alias, _, _, _, _ = load_host(inventory, validate_hardening=False)
    values = yaml.safe_load(inventory.read_text())['all']['children']['bootstrap']['hosts'][alias]
    if 'ansible_private_key_file' in values:
        key = key_path(values['ansible_private_key_file'])
        require(not override or key_path(override) == key,
                'Key override conflicts with ansible_private_key_file; update a candidate inventory explicitly.')
        return values['ansible_user'], key
    # Compatibility only: old inventory holds the initial login, with the established key.
    return 'ansible', key_path(override or DEFAULT_KEY)


def validate_ports(values, allow_empty=False):
    require(isinstance(values, list) and (allow_empty or values) and
            all(type(port) is int and 1 <= port <= 65535 for port in values) and
            len(values) == len(set(values)), 'Hardening ports must be unique integers from 1 to 65535.')


def hardening_inputs(path, alias, port, validate=True):
    # load_host has already validated the complete static inventory structure.
    host = yaml.safe_load(path.read_text())['all']['children']['bootstrap']['hosts'][alias]
    result = {'ssh_listen_ports': host.get('ssh_listen_ports', [port]),
              'firewall_allowed_tcp_ports': host.get('firewall_allowed_tcp_ports', [80, 443])}
    result['ssh_verify_ports'] = host.get('ssh_verify_ports', result['ssh_listen_ports'])
    if not validate:
        return result
    for name, values in result.items():
        validate_ports(values, allow_empty=name == 'firewall_allowed_tcp_ports')
    require(set(result['ssh_verify_ports']) <= set(result['ssh_listen_ports']),
            'ssh_verify_ports must be a non-empty subset of ssh_listen_ports.')
    require(port in result['ssh_listen_ports'],
            'Keep current ansible_port in ssh_listen_ports. Add new ports alongside the current route first.')
    require(port in result['ssh_verify_ports'], 'Keep current ansible_port in ssh_verify_ports.')
    return result


def key_path(value):
    path = Path(value).expanduser().absolute()
    validate_cli_path(path)
    require(not path.resolve().is_relative_to(ROOT), 'Keep automation keys outside the repository.')
    require(not any(part.is_symlink() for part in [path, *path.parents]), 'Key paths must not use symlinks.')
    return path


def check_key(path):
    info = path.parent.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            'Key directory must be owned by you with permissions 0700 or stricter.')
    for item in (path, Path(str(path) + '.pub')):
        require(item.exists() and not item.is_symlink(), 'A complete regular private/public key pair is required.')
        info = item.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and os.access(item, os.R_OK),
                'Key files must be readable regular files owned by the current controller user.')
    require(path.stat().st_mode & 0o077 == 0, 'Private key permissions must be 0600 or stricter.')


def prepare_key(path, label='automation', interactive_passphrase=False):
    """Only inspect private-key metadata; ssh-keygen creates new material locally."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            'Key directory must be owned by you with permissions 0700 or stricter.')
    # Serialize concurrent wrapper runs before checking/creating the pair.
    descriptor = os.open(path.parent / '.bootstrap-key.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        public = Path(str(path) + '.pub')
        require(not path.is_symlink() and not public.is_symlink(), 'Key files must not be symlinks.')
        created = not path.exists() and not public.exists()
        if created:
            if interactive_passphrase:
                require(sys.stdin.isatty(), 'New user key generation requires a terminal for the passphrase prompt.')
            command = ['ssh-keygen', '-q', '-t', 'ed25519', '-C',
                       'portfolio-server-infrastructure ' + label, '-f', str(path)]
            if not interactive_passphrase:
                command.extend(['-N', ''])
            subprocess.run(command, check=True)
            print(f'Dedicated {label} key created locally' +
                  ('.' if interactive_passphrase else ' (without passphrase).'))
        else:
            print(f'Existing {label} key preserved.')
        check_key(path)
        return created


def prerequisites(mode):
    for tool in ('ssh', 'ssh-keygen', 'sftp', 'scp', *(['ssh-keyscan'] if mode == 'bootstrap-user' else [])):
        require(shutil.which(tool), f'Missing {tool}. Install the documented controller prerequisite.')
    if mode == 'bootstrap-user':
        require(importlib.util.find_spec('paramiko') is not None, 'Missing local Paramiko. Run make setup or make deps.')
    require((ROOT / '.venv/bin/ansible-playbook').is_file(), 'Run make setup or make deps first.')
    require((ROOT / '.ansible/collections/ansible_collections/ansible/posix').is_dir(),
            'Missing ansible.posix collection. Run make deps.')


def known_host(host, port, allow_trust=False):
    """First-use trust is explicit and precedes passwords, key generation and provisioning."""
    name = host if port == 22 else f'[{host}]:{port}'
    path = Path.home() / '.ssh/known_hosts'

    def trusted():
        if not path.exists():
            return False
        result = subprocess.run(['ssh-keygen', '-F', name, '-f', str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(result.returncode in (0, 1), 'Cannot inspect known_hosts; stopping without changing trust.')
        return result.returncode == 0

    if trusted():
        return
    require(allow_trust, 'Host is not trusted. Run make bootstrap-user for interactive first-use trust.')
    require(sys.stdin.isatty(), 'First-use trust requires an interactive terminal.')
    scan = subprocess.run(['ssh-keyscan', '-T', '15', '-p', str(port), '-t', 'ed25519,ecdsa,rsa', host],
                          capture_output=True, text=True, timeout=60)
    require(scan.returncode == 0, 'SSH host-key retrieval failed; no trust was saved.')
    keys = {}
    for line in scan.stdout.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        require(len(fields) == 3 and fields[1] in (
            'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa')
            and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', fields[2]),
            'Invalid SSH host-key response; no trust was saved.')
        kind, blob = fields[1:]
        require(kind not in keys or keys[kind] == blob, 'Conflicting SSH host keys; no trust was saved.')
        keys[kind] = blob
    require(keys, 'No SSH host key was retrieved; no trust was saved.')
    # Trust just one displayed key; prefer Ed25519 over ECDSA and RSA.
    kind = next(kind for kind in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                                 'ecdsa-sha2-nistp521', 'ssh-rsa') if kind in keys)
    entry = f'{name} {kind} {keys[kind]}\n'
    fingerprint = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'],
                                 input=entry, capture_output=True, text=True)
    require(fingerprint.returncode == 0, 'SSH fingerprint calculation failed; no trust was saved.')
    fields = fingerprint.stdout.split()
    require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fields[1]),
            'Invalid SSH fingerprint; no trust was saved.')
    print(f'FIRST TRUST: host={host} port={port} key={kind} fingerprint={fields[1]}', flush=True)
    print('This host is not yet trusted. Compare this fingerprint with the VPS provider panel/console.\n'
          'The network response alone does not prove the server identity.', flush=True)
    try:
        answer = input('Trust this host? [y/N] ')
    except EOFError:
        answer = ''
    require(answer.strip().lower() in ('y', 'yes'), 'Host trust declined; bootstrap stopped.')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a+b') as target:
        fcntl.flock(target, fcntl.LOCK_EX)
        # A concurrent run may have accepted a key while this prompt was open.
        # Preserve that trust and let strict checking detect any mismatch.
        if not trusted():
            target.seek(0, os.SEEK_END)
            size = target.tell()
            if size:
                target.seek(size - 1)
                if target.read(1) != b'\n':
                    target.write(b'\n')
            target.write(entry.encode('ascii'))
            target.flush()
    print('Host key saved to ~/.ssh/known_hosts. Strict host-key checking remains enabled.', flush=True)


def run_playbook(path, alias, variables, playbook, ask_pass=False, ask_become=False, check=False, diff=False):
    # Connection extra-vars would override even delegated localhost. Scope runtime
    # settings to the managed host in an additional inventory source instead.
    connection = {name: value for name, value in variables.items() if name.startswith('ansible_')}
    inputs = {name: value for name, value in variables.items() if not name.startswith('ansible_')}
    overlay = {'all': {'hosts': {alias: connection, 'localhost': {
        'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable, 'ansible_become': False,
    }}}}
    command = [str(ROOT / '.venv/bin/ansible-playbook'), '-i', str(path),
               str(ROOT / 'playbooks' / playbook), '--limit', alias, '-e', json.dumps(inputs)]
    if ask_pass:
        command.append('--ask-pass')
    if ask_become:
        command.append('--ask-become-pass')
    if check:
        command.append('--check')
    if diff:
        command.append('--diff')
    environment = os.environ.copy()
    for name in ('ANSIBLE_PARAMIKO_LOOK_FOR_KEYS', 'ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD',
                 'ANSIBLE_PARAMIKO_RECORD_HOST_KEYS'):
        environment.pop(name, None)
    # Contains only connection settings and paths, never passwords/key contents.
    # NamedTemporaryFile uses 0600 and removes this overlay after the child exits.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', prefix='bootstrap-inventory-') as inventory:
        json.dump(overlay, inventory)
        inventory.flush()
        command.extend(['-i', inventory.name])
        subprocess.run(command, cwd=ROOT, check=True, env=environment)


def inspect_host(host, port, interpreter, key, inputs, user):
    """Read-only SSH transport avoids Ansible's remote payload/tempfile writes."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), user + '@' + host,
    ]
    login = subprocess.run(ssh + ['id -un'], capture_output=True, text=True, check=False)
    if login.returncode or login.stdout.strip() != user:
        print('Hardening preflight\nFAIL  managed SSH access\n'
              'FAIL  host inspection unavailable without managed key-only access\n\nResult: NOT READY')
        raise ValueError('Managed SSH access failed; remaining host checks cannot run safely.')
    params = {'current_port': port, 'ssh_ports': inputs['ssh_listen_ports'],
              'tcp_ports': inputs['firewall_allowed_tcp_ports'], 'verify': False,
              'refresh_rules': False, 'socket_candidate': False, 'report_only': True}
    # Python receives code through stdin. -I isolates imports; -B prevents bytecode-cache writes;
    # imports are standard-library only. No copy, temp files, modules or handlers.
    payload = '__name__ = "portfolio_inspection"\n' + (ROOT / 'library/portfolio_hardening_info.py').read_text()
    payload += '\ninspect_stream(json.loads(' + repr(json.dumps(params)) + '))\n'
    process = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                             input=payload, capture_output=True, text=True, check=False)
    try:
        require(process.returncode == 0, 'Managed sudo or host inspection failed.')
        result = json.loads(process.stdout)
        require(type(result['ready']) is bool and isinstance(result['report'], str), 'Invalid inspection result.')
    except (ValueError, KeyError, TypeError):
        # Never dump SSH stderr, sudo errors, parser input or captured stdout.
        print('Hardening preflight\nPASS  managed SSH login\n'
              'FAIL  managed sudo or read-only inspection unavailable\n\nResult: NOT READY')
        raise ValueError('Cannot safely complete host inspection; check managed sudo and Python.') from None
    print(result['report'].replace('Hardening preflight', 'Hardening preflight\nPASS  managed SSH access', 1))
    require(result['ready'], 'Resolve all FAIL findings before make harden. WARN findings can converge safely.')


def verify_hardening(inventory, alias, host, port, stage, inputs):
    # Each selected verification port gets a new independent connection. Reuse the
    # already trusted host identity via HostKeyAlias; never scan/accept keys.
    identity = host if port == 22 else f'[{host}]:{port}'
    print('LIVE / POST-CONVERGENCE VERIFY: all ssh_listen_ports are required on the server; '
          'fresh SSH access is required on every ssh_verify_ports entry.', flush=True)
    for target_port in inputs['ssh_verify_ports']:
        connection = stage | {'ansible_port': target_port,
                              'ansible_ssh_args': stage['ansible_ssh_args'] + f' -o HostKeyAlias={identity}'}
        try:
            run_playbook(inventory, alias, connection, 'verify.yml')
        except subprocess.CalledProcessError:
            print(f'Post-convergence access verification failed on configured SSH port {target_port}. '
                  'Stop and check make verify-access on the current inventory route and recovery access. '
                  'A future port may be unavailable until make harden succeeds.', flush=True)
            raise
        run_playbook(inventory, alias, connection | inputs, 'verify-hardening.yml')


def live(mode, inventory, key=None):
    managed_user, key = managed_access(inventory, key)
    prerequisites(mode)
    if mode in ('docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host'):
        try:
            check_key(key)
        except (ValueError, OSError):
            raise ValueError('Managed access is not ready. Run make bootstrap-user first; check the dedicated key pair.') from None
    alias, host, port, user, interpreter = load_host(inventory, validate_hardening=mode != 'inspect-hardening')
    inputs = hardening_inputs(inventory, alias, port, validate=mode != 'inspect-hardening') if mode in ('harden', 'verify-hardening', 'inspect-hardening', 'reboot-host') else {}
    if mode == 'reboot-host':
        require(sys.stdin.isatty(), 'Reboot requires an interactive terminal; no reboot was requested.')
    if mode == 'bootstrap-user':
        require(user != managed_user, 'Bootstrap login and managed user must be separate accounts.')
    known_host(host, port, allow_trust=mode == 'bootstrap-user')
    if mode == 'inspect-hardening':
        inspect_host(host, port, interpreter, key, inputs, managed_user)
        return
    if mode == 'bootstrap-user':
        require(sys.stdin.isatty(), 'Bootstrap requires an interactive terminal for the Ansible password prompt.')
        print(f'LIVE / MUTATING: configures {managed_user} and approves unrestricted NOPASSWD sudo.', flush=True)
        prepare_key(key)
    else:
        check_key(key)
    variables = {
        'ansible_connection': 'ssh', 'ansible_host_key_checking': True,
        'ansible_ssh_args': SSH_BASE, 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
    }
    if mode == 'bootstrap-user':
        run_playbook(inventory, alias, variables | {
            'ansible_user': user,
            'ansible_connection': PASSWORD_CONNECTION,
            'ansible_paramiko_host_key_checking': True,
            'ansible_paramiko_private_key_file': '', 'ansible_paramiko_proxy_command': '',
            'ansible_paramiko_timeout': 15,
            'bootstrap_user_name': managed_user, 'bootstrap_user_public_key_path': str(key) + '.pub',
            'bootstrap_user_allow_passwordless_sudo': True,
        }, 'bootstrap.yml', ask_pass=True, ask_become=user != 'root')
    print(f'LIVE / VERIFY: checking key-only {managed_user} access, ping and sudo -n.', flush=True)
    managed = variables | {
        'ansible_user': managed_user, 'ansible_private_key_file': str(key), 'ansible_become': False,
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no',
    }
    try:
        run_playbook(inventory, alias, managed, 'verify.yml')
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if mode == 'reboot-host':
            raise ValueError('Pre-reboot key-only SSH/sudo verification failed; no reboot was requested. '
                             'Stop and check make verify-access and recovery access.') from None
        raise
    if mode == 'reboot-host':
        print(f'LIVE / MUTATING: reboot {host}:{port}. Keep provider console/recovery access. '
              'Docker verification afterward may change the image cache.', flush=True)
        try:
            answer = input('Reboot this host now? [y/N] ')
        except (EOFError, KeyboardInterrupt):
            answer = ''
        require(answer.strip().lower() in ('y', 'yes'), 'Reboot declined; no reboot was requested.')
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        stage['ansible_become_flags'] = '-n'
        phase = 'reboot and bounded SSH recovery'
        try:
            run_playbook(inventory, alias, stage | {'reboot_host_confirmed': True}, 'reboot-host.yml')
            phase = 'verify-access after reboot'
            run_playbook(inventory, alias, managed, 'verify.yml')
            phase = 'verify-docker after reboot'
            run_playbook(inventory, alias, stage, 'verify-docker.yml')
            phase = 'verify-hardening after reboot'
            verify_hardening(inventory, alias, host, port, stage, inputs)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError(f'{phase} failed; the host may already have rebooted. Stop and use provider '
                             'console/recovery access; do not repeat reboot blindly. No later checks ran.') from None
        print('Reboot and access/Docker/hardening verification completed. STOP.')
        return
    if mode in ('docker-host', 'verify-docker'):
        print('LIVE / MUTATING: Docker host provisioning.' if mode == 'docker-host' else
              'LIVE / VERIFY: Docker checks and disposable runtime smoke test (image cache may change).', flush=True)
        # Host-level ansible_become=False would override task-level become=True.
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        run_playbook(inventory, alias, stage | {'ansible_become_flags': '-n'}, mode + '.yml')
    if mode in ('harden', 'verify-hardening'):
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        stage['ansible_become_flags'] = '-n'
        if mode == 'harden':
            print('LIVE / MUTATING: UFW and SSH listening ports. Keep provider recovery console access.', flush=True)
            run_playbook(inventory, alias, stage | inputs, 'harden.yml')
        verify_hardening(inventory, alias, host, port, stage, inputs)
    print('Requested stage completed. STOP.')



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
    require(not set(groups) & {'root', managed_user, 'docker', 'lxd', 'disk', 'shadow'},
            'Root-equivalent/system groups are not supported for human accounts.')
    require(policy == 'admin' or not set(groups) & {'sudo', 'admin'},
            'sudo/admin group membership requires HUMAN_SUDO=admin.')
    commands = [value.strip() for value in env.get('HUMAN_SUDO_COMMANDS', '').split(',') if value.strip()]
    require(policy == 'restricted' or not commands, 'HUMAN_SUDO_COMMANDS is only for restricted sudo.')
    require(policy != 'restricted' or (commands and len(commands) == len(set(commands)) and
            all(re.fullmatch(r'/[a-zA-Z0-9_./-]+', c) and '..' not in Path(c).parts for c in commands)),
            'Restricted sudo requires comma-separated absolute executable paths without arguments or wildcards.')
    return {'human_access_user_name': name, 'human_access_user_groups': groups,
            'human_access_user_sudo': policy,
            'human_access_user_sudo_commands': ['ALL'] if policy == 'admin' else commands}


def human_key_path(value, name, key_name=None):
    if key_name:
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', key_name) and not key_name.endswith('.pub'),
                'KEY_NAME must be a simple private-key filename, without directories or a .pub suffix.')
    path = Path(value or Path.home() / '.ssh/portfolio-infra' / (key_name or name + '_ed25519')).expanduser().absolute()
    validate_cli_path(path)
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'Human key paths must not use symlinks.')
    require(not path.resolve().is_relative_to(ROOT) or
            path.resolve().is_relative_to(ROOT / 'secrets/portfolio-infra'),
            'Repository human keys are allowed only under secrets/portfolio-infra/.')
    return path


def public_key_file(value):
    path = Path(value).expanduser().absolute()
    require(path.suffix == '.pub' and not any(p.is_symlink() for p in [path, *path.parents]),
            'Import a regular .pub file without symlinks.')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= 16384,
            'Public key must be a small regular file owned by you.')
    require(info.st_mode & 0o022 == 0, 'Public key must not be writable by group or others.')
    content = path.read_text().strip()
    require(len(content.splitlines()) == 1 and re.fullmatch(
        r'(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}( [^\r\n]*)?', content),
        'Import exactly one plain OpenSSH public key without authorized_keys options.')
    result = subprocess.run(['ssh-keygen', '-l', '-f', str(path)], capture_output=True, check=False)
    require(result.returncode == 0, 'Public key is invalid.')
    return path


def prepare_human_key(key, name, interactive_passphrase=False):
    if key.is_relative_to(ROOT):
        for directory in (ROOT / 'secrets', ROOT / 'secrets/portfolio-infra'):
            directory.mkdir(mode=0o700, exist_ok=True)
            require(directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o077 == 0,
                    'Local secrets directories must be owned by you with permissions 0700.')
    if interactive_passphrase:
        return prepare_key(key, label='human ' + name, interactive_passphrase=True)
    else:
        return prepare_key(key, label='human ' + name)


def validate_cli_path(path):
    # OpenSSH expands tokens in identity/trust paths even when argv bypasses a shell.
    value = str(path)
    require(all(ord(char) >= 32 and ord(char) != 127 for char in value) and
            '%' not in value and '${' not in value,
            'SSH paths must not contain control characters or OpenSSH expansion tokens.')


def cli_human_key():
    """Local key selection does not imply account creation or a sudo policy."""
    name = os.environ.get('HUMAN_USER', '')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name) and name != 'root',
            'Set HUMAN_USER to a non-root Ubuntu username.')
    key = human_key_path(os.environ.get('HUMAN_KEY'), name, os.environ.get('KEY_NAME'))
    validate_cli_path(key)
    return name, key


def load_agent_key(key, public):
    """OpenSSH owns passphrase input; never launch an agent in a child shell."""
    require(shutil.which('ssh-add'), 'Missing ssh-add. Install OpenSSH client tools.')
    fingerprint = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(public)],
                                 capture_output=True, text=True, check=True)
    fields = fingerprint.stdout.split()
    require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', fields[1]),
            'Cannot determine the public-key SHA256 fingerprint.')
    selected = fields[1]

    def identities():
        try:
            result = subprocess.run(['ssh-add', '-l', '-E', 'sha256'],
                                    capture_output=True, text=True, check=False, timeout=10)
        except subprocess.TimeoutExpired:
            raise ValueError('SSH agent did not respond within 10 seconds; check SSH_AUTH_SOCK and retry make load-user-key.') from None
        require(result.returncode in (0, 1),
                'SSH agent unavailable. Start it in your shell with eval "$(ssh-agent -s)", '
                'then run make load-user-key with the same HUMAN_USER/HUMAN_KEY/KEY_NAME.')
        return {line.split()[1] for line in result.stdout.splitlines()
                if len(line.split()) >= 2} if result.returncode == 0 else set()

    if selected in identities():
        print('SSH key already loaded in ssh-agent.\nFingerprint: ' + selected)
        return
    require(sys.stdin.isatty(),
            'Key is not loaded. Run make load-user-key in a terminal for the OpenSSH passphrase prompt. '
            'Use AGENT_LOAD=no to skip loading during generation.')
    environment = os.environ.copy()
    environment['SSH_ASKPASS_REQUIRE'] = 'never'
    try:
        result = subprocess.run(['ssh-add', '-q', str(key)], check=False, env=environment)
    except KeyboardInterrupt:
        raise ValueError('ssh-add cancelled; key preserved. Retry make load-user-key.') from None
    require(result.returncode == 0, 'ssh-add failed or was cancelled; key preserved. Retry make load-user-key.')
    require(selected in identities(), 'ssh-add did not load the selected public identity; key preserved.')
    print('SSH key added to ssh-agent successfully.\nFingerprint: ' + selected)


def local_key(mode):
    require(shutil.which('ssh-keygen'), 'Missing ssh-keygen. Install OpenSSH client tools.')
    name, key = cli_human_key()
    policy = os.environ.get('AGENT_LOAD', 'ask')
    require(policy in ('ask', 'yes', 'no'), 'AGENT_LOAD must be ask, yes or no.')
    created = False
    if mode == 'generate-user-key':
        created = prepare_human_key(key, name, interactive_passphrase=True)
    # Inspect only private metadata; validate and read public material separately.
    check_key(key)
    public = public_key_file(str(key) + '.pub')
    if mode == 'load-user-key':
        load_agent_key(key, public)
    elif mode == 'generate-user-key':
        if created:
            print('SSH key generated successfully.')
        if policy == 'yes' or (created and policy == 'ask' and sys.stdin.isatty()):
            accepted = policy == 'yes'
            if not accepted:
                try:
                    answer = input('Add private key to ssh-agent? [Y/n]: ').strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = 'n'
                require(answer in ('', 'y', 'yes', 'n', 'no'), 'Answer Y or N; key preserved. Use make load-user-key later.')
                accepted = answer in ('', 'y', 'yes')
            if accepted:
                try:
                    load_agent_key(key, public)
                except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                    print('Key preserved; agent loading failed. ' + str(error), file=sys.stderr)
            else:
                print('Agent loading skipped; key preserved.')
        else:
            print('Agent loading skipped. Use make load-user-key when ready.')
    elif mode == 'show-public-key':
        fingerprint = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(public)],
                                     capture_output=True, text=True, check=True)
        fields = fingerprint.stdout.split()
        require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', fields[1]),
                'Cannot determine the public-key SHA256 fingerprint.')
        # Comments are not needed for transfer and may contain terminal control codes.
        print(' '.join(public.read_text().split()[:2]))
        print('SHA256 fingerprint: ' + fields[1])


def interactive_ssh_command(host, port, user, key):
    """The selected identity may use an unlocked agent; only existing trust is eligible."""
    require(shutil.which('ssh') and shutil.which('ssh-keygen'), 'Missing OpenSSH client tools.')
    validate_cli_path(key)
    check_key(key)
    public_key_file(str(key) + '.pub')
    trusted = Path.home() / '.ssh/known_hosts'
    validate_cli_path(trusted)
    require(not any(path.is_symlink() for path in [trusted, *trusted.parents]),
            'Known-host trust paths must not use symlinks.')
    require(trusted.is_file(), 'Existing known_hosts trust is required; verify the server identity before connecting.')
    for path in (trusted.parent, trusted):
        info = path.stat()
        require(info.st_uid == os.getuid() and info.st_mode & 0o022 == 0 and
                (stat.S_ISDIR(info.st_mode) if path == trusted.parent else stat.S_ISREG(info.st_mode)),
                'Known-host trust must be owned by you and not writable by group or others.')
    known_host(host, port)
    # Ignore SSH config commands, proxies and alternate identities. Pin the same
    # local trust file inspected above, including when HOME differs from passwd.
    trust_option = 'UserKnownHostsFile="' + str(trusted).replace('\\', '\\\\').replace('"', '\\"') + '"'
    return ['ssh', '-F', '/dev/null', '-t'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'ForwardAgent=no',
        '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
        '-o', 'UpdateHostKeys=no', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', trust_option,
        '-i', str(key), '-p', str(port), user + '@' + host,
    ]


def cli_connection(mode, inventory, override=None):
    managed_user, managed_key = managed_access(inventory, override)
    _, host, port, _, _ = load_host(inventory)
    user, key = cli_human_key() if mode == 'connect-user' else (managed_user, managed_key)
    if mode != 'show-controller':
        require(sys.stdin.isatty(), 'SSH connection requires an interactive terminal.')
    command = interactive_ssh_command(host, port, user, key)
    if mode == 'show-controller':
        print(f'ansible_user: {user}\nserver: {host}\nport: {port}\nkey: {key}')
        print('SSH command: ' + shlex.join(command))
    else:
        subprocess.run(command, check=True)


def verify_human(inventory, alias, host, port, managed, inputs, human, key):
    check_key(key)
    public_key_file(str(key) + '.pub')
    identity = host if port == 22 else f'[{host}]:{port}'
    for target in inputs['ssh_verify_ports']:
        connection = managed | {'ansible_user': human['human_access_user_name'],
                                'ansible_private_key_file': str(key), 'ansible_port': target,
                                # Human encrypted keys may use their existing agent; only this identity is eligible.
                                'ansible_ssh_args': managed['ansible_ssh_args']
                                + f' -o HostKeyAlias={identity}'}
        run_playbook(inventory, alias, connection | human | {'portfolio_automation_user': managed['ansible_user']}, 'verify-user.yml')



def verify_auth_methods(host, port, user, trust_name):
    """Probe offered authentication without sending a password or private key."""
    import paramiko

    trusted = paramiko.HostKeys()
    trusted.load(str(Path.home() / '.ssh/known_hosts'))
    transport = None
    try:
        with socket.create_connection((host, port), timeout=15) as connection:
            transport = paramiko.Transport(connection)
            entries = trusted.lookup(trust_name)
            require(entries, 'SSH runtime probe requires existing verified host trust.')
            options = transport.get_security_options()
            options.key_types = tuple(kind for kind in options.key_types if kind in entries or
                                      (kind.startswith('rsa-sha2-') and 'ssh-rsa' in entries))
            require(options.key_types, 'No supported trusted SSH host-key algorithm for runtime probe.')
            transport.start_client(timeout=15)
            transport.auth_timeout = 15
            remote_key = transport.get_remote_server_key()
            require(entries and remote_key.get_name() in entries and entries[remote_key.get_name()] == remote_key,
                    'SSH security probe host key does not match existing trust.')
            try:
                transport.auth_none(user)
            except paramiko.BadAuthenticationType as error:
                methods = set(error.allowed_types)
            else:
                raise ValueError('Unexpected authentication response; cannot prove final SSH runtime policy.')
            require('publickey' in methods and not methods & {'password', 'keyboard-interactive'},
                    'Running SSH daemon still offers password or keyboard-interactive authentication.')
    except (paramiko.SSHException, socket.timeout):
        raise ValueError('SSH runtime authentication probe failed; stop and retain recovery access.') from None
    finally:
        if transport is not None:
            transport.close()


def human_access(mode, inventory, automation_key=None):
    managed_user, automation_key = managed_access(inventory, automation_key)
    human = human_inputs(managed_user=managed_user)
    name = human['human_access_user_name']
    key = human_key_path(os.environ.get('HUMAN_KEY'), name)
    require(key.resolve() != automation_key.resolve(), 'Use separate human and automation SSH keys.')
    imported = os.environ.get('HUMAN_PUBLIC_KEY', '')
    public = public_key_file(imported) if imported else Path(str(key) + '.pub')
    prerequisites(mode)
    check_key(automation_key)
    alias, host, port, _, _ = load_host(inventory)
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
    if imported and mode != 'add-user':
        check_key(key)
        pair_public = public_key_file(str(key) + '.pub')
        require(public.read_text().split()[:2] == pair_public.read_text().split()[:2],
                'HUMAN_KEY must correspond to HUMAN_PUBLIC_KEY for independent verification.')
    # No cached receipt: re-prove automation access and completed Stage 3 on every selected route.
    verify_hardening(inventory, alias, host, port, managed, inputs)
    if mode == 'add-user':
        if not imported:
            prepare_human_key(key, name)
            public = public_key_file(str(key) + '.pub')
        _, _, _, _, interpreter = load_host(inventory)
        before = user_probe(host, port, interpreter, automation_key, managed_user, {
            'action': 'preflight-add-user', 'name': name, 'sudo': human['human_access_user_sudo'],
            'groups': human['human_access_user_groups'], 'commands': human['human_access_user_sudo_commands'],
        })
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
        try:
            answer = input('Provider console recovery tested and available; secure SSH now? [y/N] ')
        except (EOFError, KeyboardInterrupt):
            answer = ''
        require(answer.strip().lower() in ('y', 'yes'), 'Final hardening declined; no SSH policy was changed.')
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


USER_MANAGEMENT_MODES = ('list-users', 'show-user', 'list-user-keys', 'add-user-key', 'revoke-user-key', 'remove-user')


def user_probe(host, port, interpreter, key, controller, params):
    """Stream a bounded engine with no remote payload files or private-key reads."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), controller + '@' + host,
    ]
    source = (ROOT / 'library/portfolio_human_info.py').read_text()
    source = source.split('def main():')[0].replace('from ansible.module_utils.basic import AnsibleModule', '')
    payload = source + '\n' + (ROOT / 'scripts/user_management.py').read_text()
    payload += '\nmanage_stream(json.loads(' + repr(json.dumps(params | {'controller': controller})) + '))\n'
    result = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                            input=payload, capture_output=True, text=True, check=False, timeout=180)
    try:
        response = json.loads(result.stdout)
        require(result.returncode == 0 and response.get('ready') is True and isinstance(response['result'], dict),
                response.get('error', 'User management SSH/sudo failed; stop and inspect through recovery.'))
        return response['result']
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError('Invalid user management response; stop and inspect through recovery.') from None


def user_management(mode, inventory, override=None):
    controller, key = managed_access(inventory, override)
    name = os.environ.get('HUMAN_USER', '')
    if mode != 'list-users':
        require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', controller),
                'Set HUMAN_USER to a managed human account separate from root/current controller.')
    params = {'action': mode, 'name': name}
    if mode == 'add-user-key':
        public = public_key_file(os.environ.get('HUMAN_PUBLIC_KEY', ''))
        params['key'] = public.read_text().strip()
    if mode == 'revoke-user-key':
        digest = os.environ.get('KEY_FINGERPRINT', '')
        require(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', digest), 'Set KEY_FINGERPRINT to an exact SHA256 fingerprint.')
        params['fingerprint'] = digest
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
    params['token'] = before['token']
    if mode in ('revoke-user-key', 'remove-user'):
        recovery = os.environ.get('RECOVERY_USER', '')
        require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', recovery or '') and recovery not in ('root', controller, name),
                'Set RECOVERY_USER to another managed human admin whose access will be retained.')
        recovery_key = human_key_path(os.environ.get('RECOVERY_KEY'), recovery)
        require(recovery_key != key, 'Use a separate recovery administrator key.')
        check_key(recovery_key)
        recovery_public = public_key_file(str(recovery_key) + '.pub').read_text().split()[:2]
        controller_public = public_key_file(str(key) + '.pub').read_text().split()[:2]
        require(recovery_public != controller_public, 'Recovery and controller must use different SSH key identities.')
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
        verify_human(inventory, alias, host, port, managed, inputs, human, recovery_key)
        params.update(recovery_user=recovery, recovery_token=retained['token'])
    require(sys.stdin.isatty(), 'User/key mutation requires interactive recovery confirmation.')
    print(json.dumps(before, indent=2))
    if mode == 'add-user-key':
        print('Public key to add: ' + json.dumps(params['key']))
    elif mode == 'revoke-user-key':
        print('Fingerprint to revoke: ' + params['fingerprint'])
    print('LIVE / MUTATING: ' + mode + ' for ' + name + '. Keep provider console recovery available.', flush=True)
    try:
        answer = input('Apply this user/key change? [y/N] ')
    except (EOFError, KeyboardInterrupt):
        answer = ''
    require(answer.strip().lower() in ('y', 'yes'), 'User/key change declined; no mutation requested.')
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


def operations_probe(host, port, interpreter, key, module, params, user):
    """Strict key-only stream transport; no Ansible remote files or cache writes."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), user + '@' + host,
    ]
    login = subprocess.run(ssh + ['id -un'], capture_output=True, text=True, check=False, timeout=30)
    require(login.returncode == 0 and login.stdout.strip() == user, 'Managed key-only SSH access failed.')
    payload = '__name__ = "portfolio_inspection"\n' + (ROOT / 'library' / module).read_text()
    payload += '\ninspect_stream(json.loads(' + repr(json.dumps(params)) + '))\n'
    process = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                             input=payload, capture_output=True, text=True, check=False, timeout=300)
    try:
        result = json.loads(process.stdout)
        require(process.returncode == 0 and type(result['ready']) is bool and
                isinstance(result['report'], str), 'Invalid read-only inspection result.')
    except (ValueError, KeyError, TypeError):
        raise ValueError('Managed sudo or read-only inspection failed; review manually.') from None
    print(result['report'])
    require(result['ready'], 'Resolve FAIL findings manually before proceeding.')


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=[*USER_MANAGEMENT_MODES, 'generate-user-key', 'load-user-key', 'show-public-key', 'show-controller', 'connect-controller', 'connect-user', 'preview-apt-policy', 'apply-apt-policy', 'inspect-operations', 'setup-operations', 'verify-operations', 'setup', 'bootstrap-user', 'verify-access', 'docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host', 'add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'])
    parser.add_argument('--inventory', default=str(ROOT / 'inventories/production.yml'))
    parser.add_argument('--key', default=None, help='Legacy key override; explicit inventories own the key path.')
    args = parser.parse_args()
    os.umask(0o077)
    inventory = Path(args.inventory).expanduser().absolute()
    try:
        if args.mode == 'setup':
            setup_inventory(inventory)
        elif args.mode in ('generate-user-key', 'load-user-key', 'show-public-key'):
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
        print('A local prerequisite, SSH or Ansible stage failed; stopping. '
              'For an encrypted key, run make load-user-key in the same shell with the selected key. '
              'Keep recovery access.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
