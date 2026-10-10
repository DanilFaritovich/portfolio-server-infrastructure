"""Remote user/key engine, streamed with the existing human-account inspector.

Only protected server records establish account ownership. Key ownership is recorded
separately; legacy keys must be explicitly added before they can be revoked.
"""

import base64
import fcntl
import hashlib
import os
import json
from pathlib import Path
import re
import stat
import shlex
import subprocess
import tempfile


LOGIN_DEFS = Path('/etc/login.defs')
SSH_MAIN = Path('/etc/ssh/sshd_config')
SSH_INCLUDES = Path('/etc/ssh/sshd_config.d')
SSH_PENDING = Path('/etc/ssh/portfolio-security.pending')
USERDEL_HOOKS = (Path('/etc/shadow-maint/userdel-pre.d'), Path('/etc/shadow-maint/userdel-post.d'))


class Runner:
    def __init__(self, params):
        self.params = params

    def run_command(self, argv, environ_update=None):
        result = subprocess.run(argv, capture_output=True, text=True, check=False,
                                timeout=30, env=dict(os.environ, LC_ALL='C'))
        return result.returncode, result.stdout, result.stderr


def fingerprint(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    for value in lexer:
        if re.fullmatch(r'ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)', value):
            blob = base64.b64decode(next(lexer), validate=True)
            require(len(blob) >= 4, 'Invalid SSH key blob.')
            length = int.from_bytes(blob[:4], 'big')
            require(blob[4:4 + length].decode('ascii') == value, 'SSH key type mismatch.')
            return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    raise PreflightError('Unsupported authorized_keys entry; review manually.')


def ssh_sources():
    require(not SSH_PENDING.exists() and not SSH_PENDING.is_symlink(), 'Pending SSH activation; use recovery access.')
    safe(SSH_MAIN)
    safe(SSH_INCLUDES, directory=True)
    files = [SSH_MAIN, *sorted(SSH_INCLUDES.glob('*.conf'))]
    digests = []
    for path in files:
        safe(path)
        content = path.read_text()
        for line in content.splitlines():
            tokens = re.split(r'[\s=]+', line.split('#', 1)[0].strip())
            require(not tokens or tokens[0].lower() != 'match', 'Conditional SSH Match policy is unsupported.')
            if tokens and tokens[0].lower() == 'include':
                require(path == SSH_MAIN and re.fullmatch(
                    r'\s*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf[ \t]*(?:#.*)?', line, re.I),
                    'Unsupported SSH includes; review manually.')
        digests.append([str(path), hashlib.sha256(content.encode()).hexdigest()])
    return digests


def read_keys(name, uid):
    home_fd = os.open(HOME_ROOT / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        ssh_fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            for descriptor in (home_fd, ssh_fd):
                info = os.fstat(descriptor)
                require(info.st_uid == uid and info.st_mode & 0o022 == 0, 'Unsafe SSH directory.')
            descriptor = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ssh_fd)
            with os.fdopen(descriptor, newline='') as keys:
                info = os.fstat(keys.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_mode & 0o022 == 0
                        and info.st_size <= 1024 * 1024, 'Unsafe or oversized authorized_keys.')
                return keys.read()
        finally:
            os.close(ssh_fd)
    finally:
        os.close(home_fd)


def read_account(name, controller):
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', controller),
            'Root and current controller are protected.')
    path = STATE_ROOT / (name + '.json')
    safe(path)
    record = json.loads(path.read_text())
    inspect(Runner(record))
    require(record.get('name') == name, 'Account record identity mismatch.')
    rc, groups, _ = Runner({}).run_command(['id', '-Gn', name])
    require(rc == 0 and set(groups.split()) == set(record['groups']) | {name},
            'Unmanaged supplementary group state; review manually.')
    try:
        rc, listing, _ = Runner({}).run_command(['sudo', '-n', '-l', '-U', name])
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightError('Cannot inspect effective sudo grants; sudo listing failed.') from None
    require(rc == 0 or (record['sudo'] == 'none' and rc == 1),
            'Cannot inspect effective sudo grants; sudo listing failed.')
    grants = [line.strip() for line in listing.splitlines() if line.strip().startswith('(')]
    expected = '(ALL : ALL) NOPASSWD: ' + ', '.join(record['commands'])
    if record['sudo'] == 'none':
        require(not grants, 'Unmanaged sudo grants; review manually.')
    else:
        permitted = {expected}
        if record['sudo'] == 'admin' and set(record['groups']) & {'sudo', 'admin'}:
            permitted.add('(ALL : ALL) ALL')
        require(rc == 0 and expected in grants and set(grants) <= permitted,
                'Unmanaged effective sudo grants; review manually.')
    # Refuse alternate authorization sources rather than silently leaving access behind.
    rc, effective, _ = Runner({}).run_command(['/usr/sbin/sshd', '-T', '-C',
                                              'user=' + name + ',host=localhost,addr=127.0.0.1'])
    require(rc == 0, 'Cannot inspect effective SSH policy.')
    settings = dict(line.split(' ', 1) for line in effective.splitlines() if ' ' in line)
    require(settings.get('authorizedkeysfile') in ('.ssh/authorized_keys', '.ssh/authorized_keys .ssh/authorized_keys2')
            and settings.get('authorizedkeyscommand') == 'none'
            and settings.get('trustedusercakeys') == 'none'
            and settings.get('authorizedprincipalsfile') == 'none', 'Unsupported SSH authorization sources.')
    home = HOME_ROOT / name
    require(not (home / '.ssh/authorized_keys2').exists() and not (home / '.ssh/authorized_keys2').is_symlink(),
            'Alternate authorized_keys2 exists; review manually.')
    keys_path = home / '.ssh/authorized_keys'
    require(keys_path.is_file(), 'Missing authorized_keys; review manually.')
    content = read_keys(name, record['uid'])
    entries = []
    for line in content.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            entries.append({'key': line, 'fingerprint': fingerprint(line)})
    ledger_path = STATE_ROOT / (name + '.keys.json')
    owned = []
    if ledger_path.exists() or ledger_path.is_symlink():
        safe(ledger_path)
        owned = json.loads(ledger_path.read_text())
        require(isinstance(owned, list) and all(isinstance(key, str) for key in owned), 'Invalid key ledger.')
    for entry in entries:
        entry['managed'] = entry['key'] in owned
    snapshot = json.dumps([record, content, owned, ssh_sources()], sort_keys=True).encode()
    return {'name': name, 'sudo': record['sudo'], 'groups': record['groups'], 'commands': record['commands'],
            'uid': record['uid'], 'gid': record['gid'], 'keys': entries,
            'token': hashlib.sha256(snapshot).hexdigest()}, content, owned


def atomic_keys(name, content, uid, gid, expected=None):
    # Pin every user-controlled directory with O_NOFOLLOW. Rename relative to the
    # pinned SSH directory so a concurrent home/symlink replacement cannot redirect root.
    home_fd = os.open(HOME_ROOT / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        ssh_fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            for fd in (home_fd, ssh_fd):
                info = os.fstat(fd)
                require(info.st_uid == uid and info.st_mode & 0o022 == 0, 'SSH directory changed during mutation.')
            key_fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=ssh_fd)
            with os.fdopen(key_fd, newline='') as current:
                metadata = os.fstat(current.fileno())
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_mode & 0o022 == 0,
                        'authorized_keys changed during mutation.')
                if expected is not None:
                    require(current.read() == expected, 'Keys changed during mutation; stop and inspect.')
            temporary = '.portfolio-keys-' + os.urandom(16).hex()
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=ssh_fd)
            try:
                os.fchown(fd, uid, gid)
                with os.fdopen(fd, 'w') as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.rename(temporary, 'authorized_keys', src_dir_fd=ssh_fd, dst_dir_fd=ssh_fd)
                os.fsync(ssh_fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=ssh_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(ssh_fd)
    finally:
        os.close(home_fd)


def write_ledger(name, owned):
    fd, temporary = tempfile.mkstemp(dir=STATE_ROOT, prefix='.keys-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(owned, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, STATE_ROOT / (name + '.keys.json'))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def removed_account(name, controller):
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', controller),
            'Root and current controller are protected.')
    receipt = STATE_ROOT / (name + '.removed')
    if not receipt.exists() and not receipt.is_symlink():
        return None
    safe(receipt)
    record = json.loads(receipt.read_text())
    rc, _, _ = Runner({}).run_command(['getent', 'passwd', name])
    require(record.get('name') == name and rc == 2 and not (STATE_ROOT / (name + '.json')).exists()
            and not (SUDO_ROOT / ('portfolio-human-' + name)).exists(), 'Removed account state changed; inspect manually.')
    home = HOME_ROOT / name
    require(home.is_dir() and not any(path.is_symlink() for path in [home, *home.parents])
            and home.stat().st_uid == record['uid'] and home.stat().st_mode & 0o022 == 0,
            'Preserved home changed; inspect manually.')
    ssh = home / '.ssh'
    require(ssh.is_dir() and not ssh.is_symlink() and ssh.stat().st_uid == record['uid']
            and ssh.stat().st_mode & 0o022 == 0, 'Preserved SSH directory changed.')
    keys = home / '.ssh/authorized_keys'
    require(not keys.is_symlink() and keys.is_file() and keys.read_text() == '', 'Removed account credentials changed.')
    return {'name': name, 'removed': True, 'files_preserved': True, 'changed': False}


def execute(params):
    action = params['action']
    controller = params['controller']
    require(action in ('list-users', 'show-user', 'list-user-keys', 'add-user-key', 'revoke-user-key', 'remove-user', 'preflight-add-user'),
            'Unsupported user operation.')
    if action == 'list-users':
        # This account was authenticated by the stream transport and its root
        # execution is proven by manage_stream; it is never a mutation target.
        protected = {'name': controller, 'protected': True, 'sudo': 'root execution via sudo verified',
                     'source': 'inventory controller'}
        if not STATE_ROOT.exists():
            return {'users': [protected], 'changed': False}
        safe(STATE_ROOT, directory=True)
        names = [path.stem for path in sorted(STATE_ROOT.glob('*.json')) if not path.name.endswith('.keys.json')]
        return {'users': [protected] + [read_account(name, controller)[0] for name in names if name != controller], 'changed': False}
    name = params['name']
    removed = removed_account(name, controller)
    if removed:
        require(action in ('show-user', 'remove-user'), 'Account was removed; home retained, automatic recreation is unsupported.')
        return removed
    if action == 'preflight-add-user' and not (STATE_ROOT / (name + '.json')).exists():
        require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name or '') and name not in ('root', controller),
                'Root and current controller are protected.')
        require(not (STATE_ROOT / (name + '.json')).is_symlink(), 'Unsafe account record.')
        return {'existing': False, 'changed': False}
    before, content, owned = read_account(name, controller)
    if action == 'preflight-add-user':
        require(before['sudo'] == params['sudo'] and before['commands'] == params['commands']
                and set(before['groups']) == set(params['groups']),
                'Existing privilege/group changes require a separately reviewed migration; use add-user-key.')
        return before | {'existing': True, 'changed': False}
    if action in ('show-user', 'list-user-keys'):
        return before | {'changed': False}
    require(params.get('confirmed') is True, 'Explicit confirmation required.')
    safe(STATE_ROOT, directory=True)
    lock_path = STATE_ROOT / '.management.lock'
    if lock_path.exists() or lock_path.is_symlink():
        safe(lock_path)
    with open(lock_path, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before, content, owned = read_account(name, controller)
        require(params.get('token') == before['token'], 'Account/key state changed after preflight; stop and inspect.')
        if action in ('revoke-user-key', 'remove-user'):
            recovery, _, _ = read_account(params.get('recovery_user', ''), controller)
            require(recovery['name'] != name and recovery['sudo'] == 'admin' and recovery['keys']
                    and params.get('recovery_token') == recovery['token'], 'A separately proven retained human admin is required.')
        original = content
        if action == 'add-user-key':
            key = params['key'].strip()
            require(len(key.splitlines()) == 1 and re.fullmatch(
                r'(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}( [^\r\n]*)?', key),
                'Only one plain public key is supported.')
            digest = fingerprint(key)
            matches = [entry for entry in before['keys'] if entry['fingerprint'] == digest]
            require(not matches or len(matches) == 1 and matches[0]['key'] == key,
                    'Existing key has different options/comment or duplicate identity; review manually.')
            if key in owned and matches:
                return before | {'changed': False}
            if not matches:
                content = content + ('' if not content or content.endswith('\n') else '\n') + key + '\n'
            owned = list(dict.fromkeys(owned + [key]))
        elif action == 'revoke-user-key':
            matches = [entry for entry in before['keys'] if entry['fingerprint'] == params['fingerprint']]
            if not matches:
                require(any(fingerprint(key) == params['fingerprint'] for key in owned), 'Unknown or unmanaged key fingerprint.')
                return before | {'changed': False}
            require(len(matches) == 1 and matches[0]['managed'], 'Refusing unmanaged or ambiguous key revocation.')
            key = matches[0]['key']
            content = ''.join(line for line in content.splitlines(keepends=True) if line.rstrip('\r\n') != key)
        else:
            require(all(entry['managed'] for entry in before['keys']), 'Unmanaged keys block account removal.')
            # Separate probes implement OR: pgrep combines -U and -u with AND.
            # procps pgrep(1): only status 1 means no matches; errors fail closed.
            for selector in ('-U', '-u'):
                rc, _, _ = Runner({}).run_command(['pgrep', selector, str(before['uid'])])
                require(rc == 1, 'Account has active processes or process lookup failed; stop them manually.')
            login_defs = LOGIN_DEFS
            safe(login_defs)
            require(not any(line.split('#', 1)[0].strip().startswith('USERDEL_CMD')
                            for line in login_defs.read_text().splitlines()), 'Custom userdel hooks are unsupported.')
            for hooks in USERDEL_HOOKS:
                if hooks.exists() or hooks.is_symlink():
                    safe(hooks, directory=True)
                    require(not any(hooks.iterdir()), 'Custom userdel hooks are unsupported.')
            content = ''
        if content != read_keys(name, before['uid']):
            atomic_keys(name, content, before['uid'], before['gid'], expected=original)
        if action == 'add-user-key':
            write_ledger(name, owned)
        if action == 'remove-user':
            require(read_account(name, controller)[1] == '', 'Credential revocation verification failed; stop and inspect.')
            fragment = SUDO_ROOT / ('portfolio-human-' + name)
            if before['sudo'] != 'none':
                fragment.unlink()
            # No -r/--remove and no --force: all home/mail/user files are retained.
            rc, _, _ = Runner({}).run_command(['/usr/sbin/userdel', name])
            require(rc == 0, 'Account removal failed after credentials were revoked; use recovery and inspect, do not retry blindly.')
            rc, _, _ = Runner({}).run_command(['getent', 'passwd', name])
            require(rc == 2 and (HOME_ROOT / name).is_dir() and not fragment.exists(), 'Removal verification failed.')
            os.replace(STATE_ROOT / (name + '.json'), STATE_ROOT / (name + '.removed'))
            return {'name': name, 'removed': True, 'files_preserved': True, 'changed': True}
        after, actual, _ = read_account(name, controller)
        require(actual == content, 'Key mutation verification failed; stop and inspect.')
        return after | {'changed': True}


def manage_stream(params):
    try:
        require(os.geteuid() == 0, 'User inspection/mutation requires non-interactive root sudo.')
        result = execute(params)
        print(json.dumps({'ready': True, 'result': result}))
    except PreflightError as error:
        print(json.dumps({'ready': False, 'error': str(error)}))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError, StopIteration):
        print(json.dumps({'ready': False, 'error': 'User operation refused or incomplete. Inspect account/key/policy state through recovery access before retrying.'}))
