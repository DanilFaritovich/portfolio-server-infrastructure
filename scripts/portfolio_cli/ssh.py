"""Interactive key-only connections and host-bound authentication-method probes."""

from pathlib import Path
import os
import shlex
import shutil
import socket
import stat
import subprocess
import sys

from .common import SSH_BASE, require, validate_cli_path
from .host_trust import known_host, transfer_port_trust
from .inventory import load_host, managed_access
from .keys import check_key, public_key_file
from .local_keys import cli_human_key


def interactive_ssh_command(host, port, user, key, transfer_trust=False):
    """The selected identity may use an unlocked agent; only existing trust is eligible."""
    require(shutil.which('ssh') and shutil.which('ssh-keygen'), 'Missing OpenSSH client tools.')
    validate_cli_path(key)
    check_key(key)
    public_key_file(str(key) + '.pub')
    trusted = Path.home() / '.ssh/known_hosts'
    validate_cli_path(trusted)
    require(not any(path.is_symlink() for path in [trusted, *trusted.parents]),
            'Known-host trust paths must not use symlinks.')
    require(trusted.is_file(), 'Existing known_hosts trust is required. '
            'Run make show-server-trust on a trusted computer, then make trust-server here with the same inventory.')
    for path in (trusted.parent, trusted):
        info = path.stat()
        require(info.st_uid == os.getuid() and info.st_mode & 0o022 == 0 and
                (stat.S_ISDIR(info.st_mode) if path == trusted.parent else stat.S_ISREG(info.st_mode)),
                'Known-host trust must be owned by you and not writable by group or others.')
    if transfer_trust:
        transfer_port_trust(host, port)
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
    command = interactive_ssh_command(host, port, user, key, transfer_trust=mode == 'connect-controller')
    if mode == 'show-controller':
        print(f'ansible_user: {user}\nserver: {host}\nport: {port}\nkey: {key}')
        print('SSH command: ' + shlex.join(command))
    else:
        subprocess.run(command, check=True)


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
