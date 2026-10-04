#!/usr/bin/env python3
"""Controller-only setup and explicit live access entry points; never store passwords."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = Path.home() / '.ssh/portfolio-server-infrastructure/ansible_ed25519'
HOST_FIELDS = {'ansible_host', 'ansible_port', 'ansible_user', 'ansible_python_interpreter'}
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


def load_host(path):
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
        require(isinstance(values, dict) and set(values) <= HOST_FIELDS,
                'Only host, port, initial user and Python interpreter belong in this inventory.')
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
    for tool in ('ssh', 'ssh-keygen', 'sftp', 'scp', *(['sshpass'] if mode == 'bootstrap' else [])):
        require(shutil.which(tool), f'Missing {tool}. Install the documented controller prerequisite.')
    require((ROOT / '.venv/bin/ansible-playbook').is_file(), 'Run make setup or make deps first.')
    require((ROOT / '.ansible/collections/ansible_collections/ansible/posix').is_dir(),
            'Missing ansible.posix collection. Run make deps.')


def known_host(host, port):
    name = host if port == 22 else f'[{host}]:{port}'
    result = subprocess.run(['ssh-keygen', '-F', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0,
            'Host not found in ~/.ssh/known_hosts. First use OpenSSH to verify its fingerprint '
            'against the provider console and accept it. Never disable host-key checking.')


def run_playbook(path, alias, variables, playbook, ask_pass=False, ask_become=False):
    command = [str(ROOT / '.venv/bin/ansible-playbook'), '-i', str(path),
               str(ROOT / 'playbooks' / playbook), '--limit', alias, '-e', json.dumps(variables)]
    if ask_pass:
        command.append('--ask-pass')
    if ask_become:
        command.append('--ask-become-pass')
    subprocess.run(command, cwd=ROOT, check=True)


def live(mode, inventory, key):
    prerequisites(mode)
    alias, host, port, user, interpreter = load_host(inventory)
    known_host(host, port)
    if mode == 'bootstrap':
        require(sys.stdin.isatty(), 'Bootstrap requires an interactive terminal for the Ansible password prompt.')
        print('LIVE / MUTATING: creates ansible and approves unrestricted NOPASSWD sudo.', flush=True)
        prepare_key(key)
    else:
        check_key(key)
    variables = {
        'ansible_host': host, 'ansible_port': port, 'ansible_python_interpreter': interpreter,
        'ansible_connection': 'ssh', 'ansible_host_key_checking': True,
        'ansible_ssh_args': SSH_BASE, 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
    }
    if mode == 'bootstrap':
        run_playbook(inventory, alias, variables | {
            'ansible_user': user,
            'ansible_ssh_args': SSH_BASE + ' -o PreferredAuthentications=password -o PubkeyAuthentication=no'
                                ' -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no',
            'bootstrap_user_name': 'ansible', 'bootstrap_user_public_key_path': str(key) + '.pub',
            'bootstrap_user_allow_passwordless_sudo': True,
        }, 'bootstrap.yml', ask_pass=True, ask_become=user != 'root')
    print('LIVE / VERIFY: checking new key-only ansible access, ping and sudo -n.', flush=True)
    run_playbook(inventory, alias, variables | {
        'ansible_user': 'ansible', 'ansible_private_key_file': str(key), 'ansible_become': False,
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no -o IdentityAgent=none',
    }, 'verify.yml')
    print('Verified ansible login and UID 0 via sudo -n. STOP.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['setup', 'bootstrap', 'verify'])
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
    except (OSError, subprocess.CalledProcessError):
        print('A local prerequisite, SSH or Ansible stage failed; stopping. Keep recovery access.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
