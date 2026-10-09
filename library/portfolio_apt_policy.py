#!/usr/bin/python
"""Apply only the previously diagnosed one-line managed APT policy drift."""

DOCUMENTATION = r'''
---
module: portfolio_apt_policy
short_description: Preview or repair one exact managed APT policy line
description:
  - Rejects every drift except the missing explicit new-unused-dependencies flag.
  - Check mode reads only; application replaces only the existing managed file.
options:
  candidate:
    description: Rendered existing server_operations APT template.
    required: true
    type: str
  confirmed:
    description: Explicit operator confirmation for application.
    type: bool
    default: false
author: Portfolio infrastructure maintainers
'''
EXAMPLES = r'''
- name: Repair the exact managed APT drift
  portfolio_apt_policy:
    candidate: "{{ lookup('ansible.builtin.template', '../roles/server_operations/templates/apt-security.j2') }}"
    confirmed: true
  become: true
'''
RETURN = r'''
changed:
  description: Whether the single missing line was added or would be added.
  returned: always
  type: bool
'''

import fcntl
import os
from pathlib import Path
import stat
import tempfile

from ansible.module_utils.basic import AnsibleModule

DESTINATION = '/etc/apt/apt.conf.d/99zz-portfolio-security'
DIRECTIVE = 'Unattended-Upgrade::Remove-New-Unused-Dependencies "false";\n'
MARKER = '# Managed by portfolio server_operations\n'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def trusted_path(path):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not info.st_mode & 0o022, 'Unsafe APT parent path; STOP.')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o644 and info.st_nlink == 1
            and info.st_size <= 65536, 'Managed APT file metadata differs; STOP.')
    return info


def identity(info):
    # Reading the policy can update atime; it is not a configuration change.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_mode, info.st_nlink, info.st_size)


def repair(module):
    path = Path(DESTINATION)
    candidate = module.params['candidate'].encode('utf-8')
    line = DIRECTIVE.encode('ascii')
    require(candidate.startswith(MARKER.encode('ascii')) and candidate.count(line) == 1,
            'Unexpected APT template; STOP.')
    require(module.check_mode or module.params['confirmed'], 'APT-only application was not confirmed.')
    trusted_path(path)
    # Lock the existing inode, avoiding lock-file writes in preview. A competing
    # replacement invalidates the snapshot and requires a new operator review.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as original:
        fcntl.flock(original, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata = trusted_path(path)
        opened = os.fstat(original.fileno())
        require((metadata.st_dev, metadata.st_ino) == (opened.st_dev, opened.st_ino),
                'APT file changed during preflight; STOP.')
        current = original.read(65537)
        require(current in (candidate, candidate.replace(line, b'', 1)),
                'APT diff is wider than the one approved line; STOP.')
        if current == candidate:
            return {'changed': False}
        result = {'changed': True, 'diff': {'before': '', 'after': DIRECTIVE,
                                          'before_header': DESTINATION, 'after_header': DESTINATION}}
        if module.check_mode:
            return result
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix='.portfolio-apt-', dir=path.parent)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(candidate)
                os.fchmod(output.fileno(), 0o644)
                os.fchown(output.fileno(), 0, 0)
                output.flush()
                os.fsync(output.fileno())
            latest = trusted_path(path)
            require(identity(latest) == identity(metadata) and path.read_bytes() == current,
                    'APT file changed after preflight; STOP.')
            module.atomic_move(temporary, str(path), unsafe_writes=False)
            temporary = None
            require(path.read_bytes() == candidate, 'APT write verification failed; STOP, do not retry.')
            trusted_path(path)
        finally:
            if temporary is not None:
                os.unlink(temporary)
        return result


def main():
    module = AnsibleModule(argument_spec={
        'candidate': {'type': 'str', 'required': True},
        'confirmed': {'type': 'bool', 'default': False},
    }, supports_check_mode=True)
    try:
        result = repair(module)
    except ValueError as error:
        module.fail_json(msg=str(error), changed=False)
    except OSError:
        # No file contents, exception text or APT/proxy credentials in errors.
        module.fail_json(msg='APT-only I/O failed; STOP, the file may have changed. Inspect read-only; do not retry blindly.', changed=False)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
