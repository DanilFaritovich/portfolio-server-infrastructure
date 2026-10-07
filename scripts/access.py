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
import subprocess
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = Path.home() / '.ssh/portfolio-server-infrastructure/ansible_ed25519'
PASSWORD_CONNECTION = 'portfolio_password'
HARDENING_FIELDS = {'ssh_listen_ports', 'firewall_allowed_tcp_ports'}
HOST_FIELDS = {'ansible_host', 'ansible_port', 'ansible_user', 'ansible_python_interpreter'} | HARDENING_FIELDS
SSH_BASE = '-o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -o ConnectTimeout=15'


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
                'Only host, port, initial user, Python interpreter and hardening port lists belong in inventory.')
        for name in HARDENING_FIELDS & values.keys() if validate_hardening else ():
            validate_ports(values[name], allow_empty=name == 'firewall_allowed_tcp_ports')
        host = values.get('ansible_host')
        port = values.get('ansible_port')
        user = values.get('ansible_user', 'root')
        interpreter = values.get('ansible_python_interpreter', '/usr/bin/python3')
        require(isinstance(host, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]*', host)
                and not host.endswith('.invalid') and '{{' not in host,
                'Set ansible_host to your verified VPS hostname or address.')
        require(type(port) is int and 1 <= port <= 65535, 'Set ansible_port to an integer from 1 to 65535.')
        require(isinstance(user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user)
                and user != 'ansible', 'Initial login must be root or another existing administrator.')
        require(isinstance(interpreter, str) and re.fullmatch(r'/[a-zA-Z0-9_./-]+', interpreter),
                'Use an absolute Python interpreter path.')
    except (yaml.YAMLError, TypeError, KeyError, AttributeError):
        # Parser exceptions can include inventory contents: do not expose them.
        raise ValueError('Invalid inventory. Use the static example structure without credentials.') from None
    return alias, host, port, user, interpreter


def validate_ports(values, allow_empty=False):
    require(isinstance(values, list) and (allow_empty or values) and
            all(type(port) is int and 1 <= port <= 65535 for port in values) and
            len(values) == len(set(values)), 'Hardening ports must be unique integers from 1 to 65535.')


def hardening_inputs(path, alias, port, validate=True):
    # load_host has already validated the complete static inventory structure.
    host = yaml.safe_load(path.read_text())['all']['children']['bootstrap']['hosts'][alias]
    result = {'ssh_listen_ports': host.get('ssh_listen_ports', [port]),
              'firewall_allowed_tcp_ports': host.get('firewall_allowed_tcp_ports', [80, 443])}
    if not validate:
        return result
    for name, values in result.items():
        validate_ports(values, allow_empty=name == 'firewall_allowed_tcp_ports')
    require(port in result['ssh_listen_ports'],
            'Keep current ansible_port in ssh_listen_ports. Add new ports alongside the current route first.')
    return result


def key_path(value):
    path = Path(value).expanduser().absolute()
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


def prepare_key(path):
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
        if not path.exists() and not public.exists():
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C',
                            'portfolio-server-infrastructure automation', '-f', str(path)], check=True)
            print('Dedicated automation key created locally (without passphrase).')
        else:
            print('Existing automation key preserved.')
        check_key(path)


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


def run_playbook(path, alias, variables, playbook, ask_pass=False, ask_become=False):
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


def inspect_host(host, port, interpreter, key, inputs):
    """Read-only SSH transport avoids Ansible's remote payload/tempfile writes."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no', '-o', 'IdentityAgent=none',
        '-i', str(key), '-p', str(port), 'ansible@' + host,
    ]
    login = subprocess.run(ssh + ['id -un'], capture_output=True, text=True, check=False)
    if login.returncode or login.stdout.strip() != 'ansible':
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


def live(mode, inventory, key):
    prerequisites(mode)
    if mode in ('docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening'):
        try:
            check_key(key)
        except (ValueError, OSError):
            raise ValueError('Managed access is not ready. Run make bootstrap-user first; check the dedicated key pair.') from None
    alias, host, port, user, interpreter = load_host(inventory, validate_hardening=mode != 'inspect-hardening')
    inputs = hardening_inputs(inventory, alias, port, validate=mode != 'inspect-hardening') if mode in ('harden', 'verify-hardening', 'inspect-hardening') else {}
    known_host(host, port, allow_trust=mode == 'bootstrap-user')
    if mode == 'inspect-hardening':
        inspect_host(host, port, interpreter, key, inputs)
        return
    if mode == 'bootstrap-user':
        require(sys.stdin.isatty(), 'Bootstrap requires an interactive terminal for the Ansible password prompt.')
        print('LIVE / MUTATING: creates ansible and approves unrestricted NOPASSWD sudo.', flush=True)
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
            'bootstrap_user_name': 'ansible', 'bootstrap_user_public_key_path': str(key) + '.pub',
            'bootstrap_user_allow_passwordless_sudo': True,
        }, 'bootstrap.yml', ask_pass=True, ask_become=user != 'root')
    print('LIVE / VERIFY: checking key-only ansible access, ping and sudo -n. Run make bootstrap-user first if access fails.', flush=True)
    managed = variables | {
        'ansible_user': 'ansible', 'ansible_private_key_file': str(key), 'ansible_become': False,
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no -o IdentityAgent=none',
    }
    run_playbook(inventory, alias, managed, 'verify.yml')
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
        # Each configured port gets a new independent connection. Reuse the
        # already trusted host identity via HostKeyAlias; never scan/accept keys.
        identity = host if port == 22 else f'[{host}]:{port}'
        print('LIVE / POST-CONVERGENCE VERIFY: all configured SSH ports are required. '
              'Before the first successful make harden, future ports may be unavailable; '
              'this alone does not mean the current inventory route is locked out.', flush=True)
        for target_port in inputs['ssh_listen_ports']:
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
    print('Requested stage completed. STOP.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['setup', 'bootstrap-user', 'verify-access', 'docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening'])
    parser.add_argument('--inventory', default=str(ROOT / 'inventories/production.yml'))
    parser.add_argument('--key', default=str(DEFAULT_KEY))
    args = parser.parse_args()
    os.umask(0o077)
    inventory = Path(args.inventory).expanduser().absolute()
    try:
        if args.mode == 'setup':
            setup_inventory(inventory)
        else:
            live(args.mode, inventory, key_path(args.key))
    except ValueError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print('A local prerequisite, SSH or Ansible stage failed; stopping. Keep recovery access.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
