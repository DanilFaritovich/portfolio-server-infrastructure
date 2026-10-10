"""Remote user/key engine, streamed with the existing human-account inspector.

Only protected server records establish account ownership. Key ownership is recorded
separately; legacy keys must be explicitly added before they can be revoked.
"""

import fcntl
import hashlib
import os
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile


LOGIN_DEFS = Path('/etc/login.defs')
USERDEL_HOOKS = (Path('/etc/shadow-maint/userdel-pre.d'), Path('/etc/shadow-maint/userdel-post.d'))


class Runner:
    def __init__(self, params):
        self.params = params

    def run_command(self, argv, environ_update=None):
        result = subprocess.run(argv, capture_output=True, text=True, check=False,
                                timeout=30, env=dict(os.environ, LC_ALL='C'))
        return result.returncode, result.stdout, result.stderr


def read_keys(name, uid):
    return read_authorized_keys(HOME_ROOT / name, uid)


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
    entries = key_entries(content)
    ledger_path = STATE_ROOT / (name + '.keys.json')
    owned = []
    if ledger_path.exists() or ledger_path.is_symlink():
        safe(ledger_path)
        owned = json.loads(ledger_path.read_text())
        require(isinstance(owned, list) and all(isinstance(key, str) for key in owned), 'Invalid key ledger.')
    for entry in entries:
        entry['managed'] = entry['key'] in owned
    snapshot = json.dumps([record, content, owned, ssh_sources(), controller_state(Runner({}), controller)], sort_keys=True).encode()
    return {'name': name, 'sudo': record['sudo'], 'groups': record['groups'], 'commands': record['commands'],
            'uid': record['uid'], 'gid': record['gid'], 'keys': entries,
            'token': hashlib.sha256(snapshot).hexdigest()}, content, owned


def key_directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def atomic_keys(name, content, uid, gid, expected=None, validate=None):
    # Pin every user-controlled directory with O_NOFOLLOW. Rename relative to the
    # pinned SSH directory so a concurrent home/symlink replacement cannot redirect root.
    home_fd = os.open(HOME_ROOT / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        ssh_fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            for fd in (home_fd, ssh_fd):
                info = os.fstat(fd)
                require(info.st_uid == uid and info.st_mode & 0o022 == 0, 'SSH directory changed during mutation.')
            key_fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=ssh_fd)
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
                if validate is not None:
                    validate()
                # Recheck content after staging and bind the pinned directory to the live path.
                require(key_directory_identity(os.stat(HOME_ROOT / name, follow_symlinks=False)) == key_directory_identity(os.fstat(home_fd))
                        and key_directory_identity(os.stat(HOME_ROOT / name / '.ssh', follow_symlinks=False)) == key_directory_identity(os.fstat(ssh_fd)),
                        'SSH directory replaced during mutation.')
                require(expected is None or read_keys(name, uid) == expected, 'Keys changed during staged write.')
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
        def validate_recovery(target_keys):
            retained = read_account(params.get('recovery_user', ''), controller)[0]
            require(retained['name'] != name and retained['sudo'] == 'admin' and retained['keys']
                    and retained['token'] == params.get('recovery_token'),
                    'Recovery state changed or a separately proven retained human admin is unavailable.')
            recovery_keys = {entry['fingerprint'] for entry in retained['keys']}
            controller_keys = set(controller_state(Runner({}), controller)['fingerprints'])
            require(not target_keys & recovery_keys, 'Target and recovery SSH keys overlap.')
            require(params.get('recovery_fingerprint') in recovery_keys
                    and params['recovery_fingerprint'] not in controller_keys,
                    'Proven recovery identity must be retained and independent of controller.')

        def validate():
            current = read_account(name, controller)[0]
            require(current['token'] == params.get('token'), 'Account/key state changed during mutation.')
            if action in ('revoke-user-key', 'remove-user'):
                validate_recovery({entry['fingerprint'] for entry in current['keys']})

        validate()
        original = content
        if action == 'add-user-key':
            key = params['key'].strip()
            require(len(key.splitlines()) == 1 and re.fullmatch(
                r'(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}( [^\r\n]*)?', key),
                'Only one plain public key is supported.')
            digest = fingerprint(key)
            require(digest not in controller_state(Runner({}), controller)['fingerprints'],
                    'Human and controller SSH identities must be independent.')
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
        validate()
        if content != original:
            atomic_keys(name, content, before['uid'], before['gid'], expected=original, validate=validate)
        if action == 'add-user-key':
            write_ledger(name, owned)
        if action in ('revoke-user-key', 'remove-user'):
            validate_recovery({entry['fingerprint'] for entry in before['keys']})
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
