#!/usr/bin/python
"""Validate a complete staged SSH tree before adopting approved legacy Ports."""

DOCUMENTATION = r'''
---
module: portfolio_ssh_adopt
short_description: Adopt exact preflight-approved legacy SSH Ports
description:
  - Preserve unrelated settings and validate staged main configuration and includes before writing.
options:
  sources:
    description: Exact file paths and SHA256 fingerprints from read-only preflight.
    type: list
    elements: dict
    required: true
  adoption:
    description: Exact source path, line number and port approved by preflight.
    type: list
    elements: dict
    required: true
  ssh_ports:
    description: Desired ports including the current inventory route.
    type: list
    elements: int
    required: true
'''
EXAMPLES = r'''
- name: Adopt approved legacy port
  portfolio_ssh_adopt:
    sources: "{{ hardening_before.ssh_sources }}"
    adoption: "{{ hardening_before.ssh_adoption }}"
    ssh_ports: "{{ ssh_listen_ports }}"
'''
RETURN = r'''
changed:
  description: Whether approved configuration was adopted.
  type: bool
  returned: always
'''

import glob
import hashlib
from pathlib import Path
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule

MAIN = '/etc/ssh/sshd_config'
INCLUDES = '/etc/ssh/sshd_config.d/*.conf'
BEGIN = '# BEGIN ANSIBLE PORTFOLIO SSH PORTS'
END = '# END ANSIBLE PORTFOLIO SSH PORTS'


def require(condition):
    if not condition:
        raise ValueError('SSH adoption source changed or is unsupported; repeat read-only preflight.')


def adopt(module):
    records = module.params['adoption']
    if not records:
        return False
    wanted = module.params['ssh_ports']
    require(wanted and all(type(p) is int and 1 <= p <= 65535 for p in wanted) and
            len(wanted) == len(set(wanted)))
    sources = module.params['sources']
    names = [s['path'] for s in sources]
    require(len(names) == len(set(names)) and set(names) == {MAIN, *glob.glob(INCLUDES)})
    original = {}
    for source in sources:
        path = Path(source['path'])
        require(path.is_file() and not path.is_symlink())
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == source['sha256'])
        original[source['path']] = data
    require(BEGIN.encode() not in original[MAIN] and END.encode() not in original[MAIN])
    approved = {}
    for record in records:
        require(set(record) == {'path', 'line', 'port'} and record['path'] in original and
                type(record['line']) is int and record['line'] > 0 and
                type(record['port']) is int and record['port'] in wanted)
        location = (record['path'], record['line'])
        require(location not in approved)
        approved[location] = record['port']
    candidate = dict(original)
    found = set()
    for name, data in original.items():
        lines = data.splitlines(keepends=True)
        matched = False
        includes = 0
        for number, line in enumerate(lines, 1):
            fields = re.split(rb'[\s=]+', line.split(b'#', 1)[0].strip())
            directive = fields[0].lower()
            require(directive != b'listenaddress')
            if directive == b'match':
                matched = True
            if directive == b'include':
                includes += 1
                require(not matched and name == MAIN and includes == 1 and
                        re.fullmatch(rb'[ \t]*Include[ \t]+' + re.escape(INCLUDES.encode()) +
                                     rb'[ \t]*(?:#[^\r\n]*)?(?:\r?\n)?', line, re.I))
            location = (name, number)
            if directive != b'port':
                require(location not in approved)
                continue
            match = re.fullmatch(rb'([ \t]*)Port[ \t]+([0-9]+)[ \t]*(#[^\r\n]*)?(\r?\n)?', line)
            require(not matched and match is not None and location in approved and
                    int(match[2]) == approved[location])
            found.add(location)
            # Preserve every unrelated byte and the approved directive's inline comment.
            lines[number - 1] = (match[1] + match[3] + (match[4] or b'')) if match[3] else b''
        candidate[name] = b''.join(lines)
    require(found == set(approved))
    block = BEGIN + '\n' + ''.join(f'Port {p}\n' for p in sorted(wanted)) + 'PubkeyAuthentication yes\n' + END + '\n'
    candidate[MAIN] = block.encode() + candidate[MAIN]
    with tempfile.TemporaryDirectory(prefix='portfolio-ssh-', dir=module.tmpdir) as directory:
        stage = Path(directory)
        snippets = stage / 'includes'
        snippets.mkdir(mode=0o700)
        for name, data in candidate.items():
            if name != MAIN:
                (snippets / Path(name).name).write_bytes(data)
        # The supported Include is redirected only in the validation copy.
        text = candidate[MAIN]
        text = re.sub(rb'(?im)^([ \t]*Include[ \t]+)' + re.escape(INCLUDES.encode()) + rb'([ \t]*(?:#[^\r\n]*)?\r?)$',
                      lambda m: m[1] + str(snippets / '*.conf').encode() + m[2], text)
        validation = stage / 'sshd_config'
        validation.write_bytes(text)
        rc, _, _ = module.run_command(['/usr/sbin/sshd', '-t', '-f', str(validation)])
        if rc:
            raise ValueError('SSH adoption candidate failed sshd -t; original SSH files are intact.')
        rc, effective, _ = module.run_command(['/usr/sbin/sshd', '-T', '-f', str(validation)])
        actual = [int(line.split()[1]) for line in effective.splitlines() if line.startswith('port ')]
        if rc or set(actual) != set(wanted) or 'pubkeyauthentication yes' not in effective.splitlines():
            raise ValueError('SSH adoption candidate effective ports/authentication differ; original SSH files are intact.')
        # Check the complete inspected tree again immediately before committing.
        require(set(names) == {MAIN, *glob.glob(INCLUDES)})
        for name, data in original.items():
            require(not Path(name).is_symlink() and Path(name).read_bytes() == data)
        if module.check_mode:
            return True
        applied = []
        try:
            # Remove the external directive first; the daemon is not reloaded here.
            for number, name in enumerate([n for n in names if n != MAIN] + [MAIN]):
                if candidate[name] == original[name]:
                    continue
                temporary = stage / f'apply-{number}'
                temporary.write_bytes(candidate[name])
                # Include the attempted file: atomic_move can report failure after replacement.
                applied.append(name)
                module.atomic_move(str(temporary), name)
        except BaseException:
            rollback_failed = False
            for number, name in enumerate(reversed(applied)):
                try:
                    temporary = stage / f'rollback-{number}'
                    temporary.write_bytes(original[name])
                    module.atomic_move(str(temporary), name)
                except BaseException:
                    rollback_failed = True
            if rollback_failed:
                raise ValueError('SSH adoption rollback failed; inspect files through recovery access.')
            raise
    return True


def main():
    module = AnsibleModule(argument_spec={
        'sources': {'type': 'list', 'elements': 'dict', 'required': True},
        'adoption': {'type': 'list', 'elements': 'dict', 'required': True},
        'ssh_ports': {'type': 'list', 'elements': 'int', 'required': True},
    }, supports_check_mode=True)
    try:
        module.exit_json(changed=adopt(module))
    except (ValueError, OSError, KeyError, TypeError):
        import sys
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, ValueError) and str(error).startswith('SSH adoption ') else \
            'Cannot safely apply SSH adoption; inspect files manually.'
        module.fail_json(msg=message)


if __name__ == '__main__':
    main()
