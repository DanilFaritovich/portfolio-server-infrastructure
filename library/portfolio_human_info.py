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

import json
from pathlib import Path
import re
import stat

from ansible.module_utils.basic import AnsibleModule


HOME_ROOT = Path('/home')
STATE_ROOT = Path('/var/lib/portfolio-human-access')
SUDO_ROOT = Path('/etc/sudoers.d')


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


def inspect(module):
    args = module.params
    name = args['name']
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name) and name != 'root',
            'Unsupported human account name.')
    home = HOME_ROOT / name
    record = STATE_ROOT / (name + '.json')
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
        require(set(previous.get('groups', [])) <= set(args['groups']),
                'Group removal is outside additive account management.')
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
