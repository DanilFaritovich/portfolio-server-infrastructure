"""Endpoint-bound host trust, atomic imports and signed cross-port proof."""

from pathlib import Path
import base64
import fcntl
import hmac
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

from .clipboard import copy_clipboard
from .common import require, validate_cli_path
from .inventory import load_host
from .keys import validate_public_key_text


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
    require(allow_trust, 'Host is not trusted. Use make show-server-trust on a trusted computer, '
            'then make trust-server here with the same inventory.')
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


TRUST_GUIDANCE = ('Use make show-server-trust on an already trusted computer for the same hostname/IP. '
                  'Without that source, ask your administrator or use the authenticated VPS provider console '
                  'to obtain the public SSH host key and its verified SHA256 fingerprint. '
                  'A network scan alone cannot establish trust.')


def trust_file_signature(info):
    # Reads may update atime; inode, metadata and content changes invalidate review.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trust_snapshot(path):
    """Read only the public trust file; reject unsafe paths before inspection."""
    validate_cli_path(path)
    require(not path.is_symlink(), 'Known-host trust paths must not use symlinks.')
    for parent in path.parents:
        require(not parent.is_symlink(), 'Known-host trust paths must not use symlinks.')
    if path.parent.exists():
        info = path.parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
                'Known-host directory must be owned by you and not writable by group or others.')
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                info.st_mode & 0o022 == 0 and info.st_nlink == 1 and info.st_size <= 4 * 1024 * 1024,
                'Known-host file must be a small regular file owned by you, without hardlinks or unsafe permissions.')
        content = source.read(4 * 1024 * 1024 + 1)
        require(trust_file_signature(os.fstat(source.fileno())) == trust_file_signature(info) and len(content) == info.st_size,
                'Known-host file changed during inspection; no trust was saved.')
    return trust_file_signature(info), content


def host_key_fingerprint(public):
    validate_public_key_text(public)
    require(len(public.split()) == 2 and public == ' '.join(public.split()),
            'Host key must contain only the public algorithm and key separated by one space.')
    result = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'],
                            input=public + '\n', capture_output=True, text=True, check=False, timeout=10)
    fields = result.stdout.split()
    require(result.returncode == 0 and len(fields) >= 2 and
            re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fields[1]), 'Invalid public SSH host key or SHA256 fingerprint.')
    return fields[1]


def trusted_host_keys(snapshot, host, port):
    if snapshot is None:
        return {}
    name = host if port == 22 else f'[{host}]:{port}'
    # Inspect a stable public snapshot with OpenSSH's own hashed/wildcard lookup.
    with tempfile.TemporaryDirectory(prefix='portfolio-host-trust-') as directory:
        source = Path(directory) / 'known_hosts'
        source.write_bytes(snapshot[1])
        source.chmod(0o600)
        result = subprocess.run(['ssh-keygen', '-F', name, '-f', str(source)],
                                capture_output=True, text=True, check=False, timeout=10)
    require(result.returncode in (0, 1), 'Cannot inspect existing OpenSSH host trust.')
    keys = {}
    for line in result.stdout.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split()
        require(len(fields) >= 3 and not fields[0].startswith('@'),
                'Marked/revoked/certificate host trust is unsupported; resolve it with your administrator.')
        public = ' '.join(fields[1:3])
        fingerprint = host_key_fingerprint(public)
        kind = fields[1]
        require(kind not in keys or keys[kind]['public_key'] == public,
                'Conflicting existing SSH host keys; no trust was saved.')
        keys[kind] = {'public_key': public, 'fingerprint': fingerprint}
    require(result.returncode != 0 or keys, 'No usable SSH host keys in the OpenSSH trust lookup.')
    return keys


def parse_server_trust(text, host):
    require(len(text) <= 65536, 'Host trust data is too large.')
    try:
        data = json.loads(text)
        require(isinstance(data, dict) and set(data) == {'version', 'host', 'port', 'keys'} and
                type(data['version']) is int and data['version'] == 1 and
                data['host'] == host and type(data['port']) is int and 1 <= data['port'] <= 65535,
                'Host trust hostname/IP does not match inventory, or the transfer format/port is invalid.')
        require(isinstance(data['keys'], list) and 1 <= len(data['keys']) <= 16, 'Expected a non-empty host key list.')
        keys = {}
        for key in data['keys']:
            require(isinstance(key, dict) and set(key) == {'public_key', 'fingerprint'} and
                    isinstance(key['public_key'], str) and isinstance(key['fingerprint'], str),
                    'Invalid host key transfer entry.')
            fingerprint = host_key_fingerprint(key['public_key'])
            require(fingerprint == key['fingerprint'], 'SSH host key SHA256 fingerprint mismatch; no trust was saved.')
            kind = key['public_key'].split()[0]
            require(kind not in keys, 'Duplicate host key algorithm in transfer data.')
            keys[kind] = key
        return data['port'], keys
    except (json.JSONDecodeError, TypeError, KeyError):
        raise ValueError('Invalid host trust transfer data; paste the single JSON line from make show-server-trust.') from None


def check_trust_conflicts(existing, imported):
    require(all(kind in imported and entry == imported[kind] for kind, entry in existing.items()),
            'Existing SSH host trust conflicts with the imported keys; no entries were replaced. '
            'Resolve host identity/rotation with your administrator.')


def save_server_trust(path, snapshot, host, port, existing, imported):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(trust_snapshot(path) == snapshot, 'Known-host trust changed since review; no trust was saved.')
    lock_path = path.parent / '.portfolio-known-hosts.lock'
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                info.st_mode & 0o077 == 0 and info.st_nlink == 1, 'Unsafe known-host trust lock.')
        fcntl.flock(lock, fcntl.LOCK_EX)
        require(trust_snapshot(path) == snapshot, 'Known-host trust changed since review; no trust was saved.')
        name = host if port == 22 else f'[{host}]:{port}'
        additions = [f'{name} {entry["public_key"]}\n' for kind, entry in imported.items() if kind not in existing]
        if not additions:
            return False
        content = snapshot[1] if snapshot else b''
        if content and not content.endswith(b'\n'):
            content += b'\n'
        content += ''.join(additions).encode('ascii')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.known_hosts-', delete=False) as target:
                temporary = Path(target.name)
                os.fchmod(target.fileno(), 0o600)
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            require(trust_snapshot(path) == snapshot, 'Known-host trust changed during write; no trust was saved.')
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return True


def server_trust(mode, inventory):
    require(shutil.which('ssh-keygen'), 'Missing OpenSSH ssh-keygen. Install the OpenSSH client tools.')
    _, host, port, _, _ = load_host(inventory, validate_hardening=False)
    source_port = port
    path = Path.home() / '.ssh/known_hosts'
    if mode == 'trust-server':
        require(sys.stdin.isatty(), 'Host trust import requires an interactive terminal. ' + TRUST_GUIDANCE)
    snapshot = trust_snapshot(path)
    existing = trusted_host_keys(snapshot, host, port)
    if mode in ('show-server-trust', 'copy-server-trust'):
        require(existing, 'No existing trusted SSH host key for this inventory. ' + TRUST_GUIDANCE)
        keys = existing
    else:
        print('Paste trusted host data from make show-server-trust (one JSON line).\n' + TRUST_GUIDANCE)
        try:
            text = input('Host trust data: ')
        except (EOFError, KeyboardInterrupt):
            raise ValueError('Host trust import cancelled; no trust was saved.') from None
        source_port, keys = parse_server_trust(text, host)
        existing = trusted_host_keys(snapshot, host, source_port)
        check_trust_conflicts(existing, keys)
    if mode == 'copy-server-trust':
        copy_clipboard(server_trust_json(host, port, keys), fallback='show-server-trust')
    print(f'Server: {host}\nSSH port: {source_port}')
    if source_port != port:
        print(f'Trusted server: {host}:{source_port}\nConfigured endpoint: {host}:{port}\n\n'
              'The transferred trust belongs to the same server but uses a different SSH port.')
    for entry in keys.values():
        print('Public host key: ' + entry['public_key'] + '\nSHA256 fingerprint: ' + entry['fingerprint'])
    if mode == 'show-server-trust':
        print('Transfer data (paste this single JSON line on the new computer):')
        print(server_trust_json(host, port, keys))
    elif mode == 'copy-server-trust':
        print('Server trust JSON copied to clipboard.')
    else:
        try:
            answer = input('Confirm these keys came from an independently verified source. '
                           f'Import verified trust for port {source_port}? [y/N]: ')
        except (EOFError, KeyboardInterrupt):
            raise ValueError('Host trust import cancelled; no trust was saved.') from None
        require(answer.strip().lower() in ('y', 'yes'), 'Host trust declined; no trust was saved.')
        changed = save_server_trust(path, snapshot, host, source_port, existing, keys)
        print('Host trust saved to ~/.ssh/known_hosts.' if changed else 'Host trust already present; known_hosts unchanged.')
        print('Strict host-key checking remains enabled.')
        if source_port != port:
            configure_imported_port(host, port, source_port, keys)


def configure_imported_port(host, port, source_port, keys):
    """Keep the confirmed source import even if optional destination setup fails."""
    guidance = (f'Trust for {host}:{source_port} remains saved. '
                f'Check the configured endpoint {host}:{port} with your administrator/provider console; '
                'then retry make trust-server or make connect-controller. '
                'No inventory or VPS settings were changed.')
    try:
        path = Path.home() / '.ssh/known_hosts'
        existing = trusted_host_keys(trust_snapshot(path), host, port)
        check_trust_conflicts(existing, keys)
        if not existing:
            answer = input(f'Verify and trust configured port {port} now? [y/N]: ')
            if answer.strip().lower() not in ('y', 'yes'):
                print(f'Configured port {port} remains untrusted. ' + guidance)
                return
            transfer_port_trust(host, port)
        print(f'SUCCESS: configured endpoint {host}:{port} is trusted.')
    except (EOFError, KeyboardInterrupt):
        raise ValueError('Configured port setup cancelled. ' + guidance) from None
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise ValueError(f'Configured port setup failed: {error} ' + guidance) from None


def server_trust_json(host, port, keys):
    return json.dumps({'version': 1, 'host': host, 'port': port, 'keys': list(keys.values())}, separators=(',', ':'))


def previous_trust_ports(snapshot, host, port):
    """Discover exact endpoints locally, including salted OpenSSH hashes; no scans."""
    if snapshot is None:
        return []
    ports, hashes = set(), set()
    for line in snapshot[1].decode('utf-8').splitlines():
        fields = line.split()
        if not fields or fields[0].startswith('#'):
            continue
        names = fields[1] if fields[0].startswith('@') and len(fields) > 1 else fields[0]
        for name in names.split(','):
            if name == host:
                ports.add(22)
            match = re.fullmatch(r'\[' + re.escape(host) + r'\]:([0-9]{1,5})', name)
            if match and 1 <= int(match[1]) <= 65535:
                ports.add(int(match[1]))
            if name.startswith('|'):
                hashes.add(name)
    # Bound work on foreign/oversized trust stores rather than blocking indefinitely.
    require(len(hashes) <= 32, 'Too many hashed trust entries for automatic port discovery; use explicit trust transfer.')
    for name in hashes:
        try:
            _, version, salt, digest = name.split('|')
            salt, digest = base64.b64decode(salt, validate=True), base64.b64decode(digest, validate=True)
            require(version == '1' and len(salt) == len(digest) == 20, 'Unsupported hashed host trust.')
        except (ValueError, TypeError):
            raise ValueError('Unsupported hashed host trust; use explicit trust transfer.') from None
        for candidate in range(1, 65536):
            endpoint = host if candidate == 22 else f'[{host}]:{candidate}'
            if hmac.compare_digest(hmac.digest(salt, endpoint.encode('ascii'), 'sha1'), digest):
                ports.add(candidate)
                break
    return sorted(ports - {port})


def verify_port_identity(host, port, keys):
    """Complete signed SSH key exchange without login, commands or agent access."""
    import paramiko

    transport = None
    try:
        with socket.create_connection((host, port), timeout=15) as connection:
            transport = paramiko.Transport(connection)
            options = transport.get_security_options()
            options.key_types = tuple(kind for kind in options.key_types if kind in keys or
                                      (kind.startswith('rsa-sha2-') and 'ssh-rsa' in keys))
            require(options.key_types, 'No supported previously trusted SSH host-key algorithm.')
            transport.banner_timeout = 15
            transport.handshake_timeout = 15
            # Paramiko verifies the exchange signature before initial KEX completes;
            # get_remote_server_key refuses incomplete/failed exchanges, including timeout.
            transport.start_client(timeout=15)
            remote = transport.get_remote_server_key()
            kind = remote.get_name()
            public = kind + ' ' + remote.get_base64()
            require(kind in keys and keys[kind]['public_key'] == public,
                    'SSH host key differs from existing trust; no trust was saved.')
            return {kind: keys[kind]}
    except (paramiko.SSHException, OSError, EOFError):
        raise ValueError('SSH host identity verification failed (unreachable port or invalid handshake/signature); '
                         'no trust was saved.') from None
    finally:
        if transport is not None:
            transport.close()


def transfer_port_trust(host, port):
    require(sys.stdin.isatty(), 'Port trust transfer requires an interactive terminal; use make connect-controller.')
    path = Path.home() / '.ssh/known_hosts'
    snapshot = trust_snapshot(path)
    existing = trusted_host_keys(snapshot, host, port)
    if existing:
        return
    ports = previous_trust_ports(snapshot, host, port)
    keys = {}
    for previous in ports:
        entries = trusted_host_keys(snapshot, host, previous)
        for kind, entry in entries.items():
            require(kind not in keys or keys[kind] == entry,
                    'Conflicting host identities across trusted ports; no trust was saved.')
            keys[kind] = entry
    require(keys, 'No previously trusted SSH host key for this server. ' + TRUST_GUIDANCE)
    print(f'SSH trust not found for {host}:{port}.\n\nPreviously trusted:')
    for previous in ports:
        print(f'{host}:{previous}')
    print('\nChecking SSH host identity...')
    verified = verify_port_identity(host, port, keys)
    print('Host key verified against existing trust.')
    for entry in verified.values():
        print('Fingerprint: ' + entry['fingerprint'])
    try:
        answer = input(f'Trust this server on port {port}? [y/N]: ')
    except (EOFError, KeyboardInterrupt):
        raise ValueError('Port trust transfer cancelled; no trust was saved.') from None
    require(answer.strip().lower() in ('y', 'yes'), 'Port trust declined; no trust was saved.')
    save_server_trust(path, snapshot, host, port, existing, verified)
    print('Host trust saved to ~/.ssh/known_hosts.')
