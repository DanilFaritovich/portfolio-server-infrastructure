#!/usr/bin/python
"""Fail closed on unmanaged accounts, unsafe homes and privilege-policy adoption."""

DOCUMENTATION = r'''
---
module: portfolio_human_info
short_description: Inspect managed human account ownership before mutation
description:
  - Refuse unmanaged existing users and conflicting sudo fragments.
options:
  name:
    description: Human username.
    type: str
    required: true
  groups:
    description: Supplementary group names.
    type: list
    elements: str
    required: true
  sudo:
    description: Selected privilege policy.
    type: str
    choices: [none, admin, restricted]
    required: true
  identity_only:
    description: Check public identity independence without account creation preflight.
    type: bool
    default: false
  controller:
    description: Current managed SSH controller for creation identity checks.
    type: str
    default: ''
  public_key:
    description: Public human key to check against server controller identities.
    type: str
    default: ''
  commands:
    description: Approved sudo executable paths or ALL for an administrator.
    type: list
    elements: str
    required: true
'''
EXAMPLES = r'''
- name: Inspect human account
  portfolio_human_info:
    name: operator
    groups: []
    sudo: admin
    commands: [ALL]
'''
RETURN = r'''
changed:
  description: This inspector never changes state.
  returned: always
  type: bool
'''

import base64
import hashlib
import json
import os
import shlex
from pathlib import Path
import re
import stat

from ansible.module_utils.basic import AnsibleModule


HOME_ROOT = Path('/home')
STATE_ROOT = Path('/var/lib/portfolio-human-access')
SUDO_ROOT = Path('/etc/sudoers.d')
SSH_MAIN = Path('/etc/ssh/sshd_config')
SSH_INCLUDES = Path('/etc/ssh/sshd_config.d')
SSH_PENDING = Path('/etc/ssh/portfolio-security.pending')


class PreflightError(ValueError):
    """A reviewed, sanitized refusal to manage the requested account."""


def require(condition, message):
    if not condition:
        raise PreflightError(message)


def safe(path, directory=False, label='account-management path'):
    try:
        require(not any(p.is_symlink() for p in [path, *path.parents]),
                label + ': symlinks are unsupported; inspect through recovery access.')
        for parent in path.parents:
            metadata = parent.stat()
            require(metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
                    label + ': unsafe parent ownership or permissions; inspect through recovery access.')
        info = path.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0 and
                (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
                label + ': unsafe file ownership, permissions or type; inspect through recovery access.')
    except OSError:
        raise PreflightError(label + ': metadata unavailable; inspect existence/permissions through recovery access.') from None


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


def fingerprint(line):
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    # authorized_keys has at most one options field before the algorithm.
    # Never interpret a supported key embedded in an unsupported entry's comment.
    kind = r'ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)'
    algorithm = next(lexer, '')
    if not re.fullmatch(kind, algorithm):
        require(not re.search(r'(^|,)cert-authority(,|$)', algorithm, re.I),
                'Certificate-authority authorized_keys entries are unsupported.')
        algorithm = next(lexer, '')
    require(re.fullmatch(kind, algorithm), 'Unsupported authorized_keys entry; review manually.')
    blob = base64.b64decode(next(lexer, ''), validate=True)
    require(len(blob) >= 4, 'Invalid SSH key blob.')
    length = int.from_bytes(blob[:4], 'big')
    require(blob[4:4 + length].decode('ascii') == algorithm, 'SSH key type mismatch.')
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def key_metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_authorized_keys(home, uid):
    home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        ssh_fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            for descriptor in (home_fd, ssh_fd):
                info = os.fstat(descriptor)
                require(info.st_uid == uid and info.st_mode & 0o022 == 0, 'Unsafe SSH directory.')
            descriptor = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=ssh_fd)
            with os.fdopen(descriptor, newline='') as keys:
                info = os.fstat(keys.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_mode & 0o022 == 0
                        and info.st_nlink == 1 and info.st_size <= 1024 * 1024, 'Unsafe or oversized authorized_keys.')
                content = keys.read(1024 * 1024 + 1)
                require(len(content.encode()) <= 1024 * 1024 and key_metadata(os.fstat(keys.fileno())) == key_metadata(info),
                        'authorized_keys changed during inspection.')
                return content
        finally:
            os.close(ssh_fd)
    finally:
        os.close(home_fd)


def key_entries(content):
    return [{'key': line, 'fingerprint': fingerprint(line)} for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith('#')]


def controller_state(module, controller):
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', controller or '') and controller != 'root',
            'A non-root controller identity is required.')
    rc, output, _ = module.run_command(['getent', 'passwd', controller])
    fields = output.strip().split(':')
    require(rc == 0 and len(fields) == 7 and fields[0] == controller and fields[2].isdigit()
            and fields[5] == str(HOME_ROOT / controller), 'Unsupported controller account identity.')
    rc, effective, _ = module.run_command(['/usr/sbin/sshd', '-T', '-C',
                                          'user=' + controller + ',host=localhost,addr=127.0.0.1'])
    settings = dict(line.split(' ', 1) for line in effective.splitlines() if ' ' in line)
    require(rc == 0 and settings.get('authorizedkeysfile') in
            ('.ssh/authorized_keys', '.ssh/authorized_keys .ssh/authorized_keys2')
            and settings.get('authorizedkeyscommand') == 'none' and settings.get('trustedusercakeys') == 'none'
            and settings.get('authorizedprincipalsfile') == 'none', 'Unsupported controller SSH authorization sources.')
    home = HOME_ROOT / controller
    safe(HOME_ROOT, directory=True)
    alternate = home / '.ssh/authorized_keys2'
    require(not alternate.exists() and not alternate.is_symlink(), 'Alternate controller keys are unsupported.')
    content = read_authorized_keys(home, int(fields[2]))
    entries = key_entries(content)
    require(entries, 'No inspectable controller SSH keys.')
    return {'passwd': output, 'policy': effective, 'content': content,
            'fingerprints': sorted({entry['fingerprint'] for entry in entries})}


def inspect(module):
    args = module.params
    require(not args.get('identity_only') or args.get('controller'), 'Controller is required for identity validation.')
    name = args['name']
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name) and name != 'root',
            'Unsupported human account name.')
    home = HOME_ROOT / name
    record = STATE_ROOT / (name + '.json')
    receipt = STATE_ROOT / (name + '.removed')
    require(not receipt.exists() and not receipt.is_symlink(), 'Removed account cannot be recreated automatically.')
    if args.get('controller'):
        ssh_sources()
        require(name != args['controller'], 'Current controller is protected.')
        require(fingerprint(args['public_key']) not in controller_state(module, args['controller'])['fingerprints'],
                'Human and controller SSH identities must be independent.')
        if args.get('identity_only'):
            return False
        require(not record.exists() and not record.is_symlink(),
                'Existing accounts must use the locked add-user-key engine; direct account mutation is unsupported.')
    fragment = SUDO_ROOT / ('portfolio-human-' + name)
    safe(HOME_ROOT, directory=True, label='home root')
    safe(SUDO_ROOT, directory=True, label='sudo include directory')
    safe(Path('/usr/sbin/visudo'), label='sudo validator /usr/sbin/visudo')
    rc, _, _ = module.run_command(['/usr/sbin/visudo', '-c'], environ_update={'LC_ALL': 'C'})
    require(rc == 0, 'sudo validator failed; inspect sudo policy through recovery access before account creation.')
    for command in args['commands']:
        if command != 'ALL':
            executable = Path(command)
            safe(executable, label='restricted sudo executable')
            require(executable.is_absolute() and executable.stat().st_mode & 0o111,
                    'Restricted sudo requires protected root-owned executable files and parent directories.')
    if record.parent.exists() or record.parent.is_symlink():
        safe(record.parent, directory=True, label='managed account records directory')
    managed = record.exists() or record.is_symlink()
    if managed:
        safe(record, label='managed account record file')
        try:
            previous = json.loads(record.read_text())
        except (ValueError, OSError):
            raise PreflightError('Invalid human account record; inspect through recovery access.') from None
        require(isinstance(previous, dict) and isinstance(previous.get('groups'), list),
                'Invalid managed-account record schema.')
        require(previous.get('name') == name and previous.get('sudo') == args['sudo'] and
                previous.get('commands') == args['commands'],
                'Changing an existing privilege policy requires a separately reviewed migration.')
        require(set(previous.get('groups', [])) == set(args['groups']),
                'Group removal/addition requires a separately reviewed migration.')
    rc, output, _ = module.run_command(['getent', 'passwd', name])
    require(rc in (0, 2), 'Account lookup failed.')
    if rc == 0:
        fields = output.strip().split(':')
        require(managed and len(fields) == 7 and fields[0] == name and fields[2].isdigit() and
                int(fields[2]) >= 1000 and fields[3].isdigit() and int(fields[3]) >= 1000 and
                previous.get('uid') == int(fields[2]) and previous.get('gid') == int(fields[3]) and
                fields[5] == str(home) and fields[6] == '/bin/bash',
                'Existing unmanaged/system account or changed managed identity; choose an unused HUMAN_USER without overwriting it, '
                'or inspect through recovery access.')
        uid = int(fields[2])
        require(home.is_dir() and not any(p.is_symlink() for p in [home, *home.parents]) and
                home.stat().st_uid == uid and home.stat().st_mode & 0o022 == 0,
                'Managed home ownership, permissions or type changed.')
        for path, directory in ((home / '.ssh', True), (home / '.ssh/authorized_keys', False)):
            if path.exists() or path.is_symlink():
                info = path.lstat()
                require(not path.is_symlink() and info.st_uid == uid and info.st_mode & 0o022 == 0 and
                        (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
                        'Unsafe human SSH directory or authorized_keys file.')
    else:
        require(not managed and not home.exists() and not home.is_symlink(),
                'Orphan managed record/home; inspect through recovery access before retrying.')
    if fragment.exists() or fragment.is_symlink():
        safe(fragment, label='human sudo fragment')
        expected = name + ' ALL=(ALL:ALL) NOPASSWD: ' + ', '.join(args['commands']) + '\n'
        require(managed and args['sudo'] != 'none' and fragment.read_text() == expected,
                'Conflicting or unmanaged human sudo fragment.')
    elif managed:
        require(args['sudo'] == 'none', 'Managed sudo fragment disappeared; investigate before repair.')
    # Do not silently inherit custom privileged primary groups.
    rc, output, _ = module.run_command(['getent', 'group', name])
    require(rc in (0, 2), 'Primary-group lookup failed.')
    if rc == 0:
        fields = output.strip().split(':')
        require(len(fields) == 4 and fields[0] == name and fields[2].isdigit(),
                'Primary-group lookup returned invalid data; inspect through recovery access.')
        gid = int(fields[2])
        if not managed:
            group_kind = 'system group' if gid < 1000 else 'unmanaged group'
            require(False, f'Existing {group_kind} {name} (GID {gid}); choose an unused HUMAN_USER; do not adopt or delete the group.')
        require(gid >= 1000 and previous.get('gid') == gid,
                'Managed primary group identity changed; inspect through recovery access.')
    return False


def main():
    module = AnsibleModule(argument_spec={
        'name': {'type': 'str', 'required': True},
        'groups': {'type': 'list', 'elements': 'str', 'required': True},
        'sudo': {'type': 'str', 'choices': ['none', 'admin', 'restricted'], 'required': True},
        'commands': {'type': 'list', 'elements': 'str', 'required': True},
        'identity_only': {'type': 'bool', 'default': False},
        'controller': {'type': 'str', 'default': ''},
        'public_key': {'type': 'str', 'default': '', 'no_log': True},
    }, supports_check_mode=True)
    try:
        inspect(module)
        module.exit_json(changed=False)
    except PreflightError as error:
        module.fail_json(changed=False, msg='Human account preflight failed: ' + str(error))
    except (ValueError, OSError, TypeError, AttributeError, UnicodeError):
        module.fail_json(changed=False, msg='Human account preflight failed: unable to safely inspect state; '
                        'inspect account, home, record and sudo policy through recovery access. Raw exception details are withheld.')


if __name__ == '__main__':
    main()
