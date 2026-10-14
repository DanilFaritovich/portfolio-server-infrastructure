#!/usr/bin/python
"""Validate final SSH policy against a complete snapshot before atomic activation."""

DOCUMENTATION = r'''
---
module: portfolio_ssh_security
short_description: Validate or install the final portfolio SSH authentication policy
description:
  - Require completed Stage 3 and reject conditional policy exceptions.
  - Validate staged syntax and effective policy before atomic replacement.
options:
  operation:
    description: Inspect, apply, complete a reload, or verify final policy.
    type: str
    choices: [preflight, apply, installed, complete, verify]
    default: preflight
  sources:
    description: Exact source fingerprints from the shared Stage 3 inspector.
    type: list
    elements: dict
    required: true
  ssh_ports:
    description: Existing listening ports which must remain unchanged.
    type: list
    elements: int
    required: true
'''
EXAMPLES = r'''
- name: Verify final SSH policy
  portfolio_ssh_security:
    operation: verify
    sources: "{{ security_before.ssh_sources }}"
    ssh_ports: [2222]
'''
RETURN = r'''
changed:
  description: Whether the managed SSH authentication block was installed.
  returned: always
  type: bool
'''

import fcntl
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from ansible.module_utils.basic import AnsibleModule

MAIN = '/etc/ssh/sshd_config'
INCLUDES = '/etc/ssh/sshd_config.d/*.conf'
PORT_BEGIN = '# BEGIN ANSIBLE PORTFOLIO SSH PORTS'
PORT_END = '# END ANSIBLE PORTFOLIO SSH PORTS'
BEGIN = '# BEGIN ANSIBLE PORTFOLIO SSH SECURITY'
END = '# END ANSIBLE PORTFOLIO SSH SECURITY'
POLICY = {'permitrootlogin': 'no', 'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no'}
BLOCK = BEGIN + '\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' + END + '\n'
PENDING = '/etc/ssh/portfolio-security.pending'


def require(condition, message='Unsupported or changed SSH security source; use recovery access.'):
    if not condition:
        raise ValueError(message)


def safe(path):
    require(not any(p.is_symlink() for p in [path, *path.parents]))
    for parent in path.parents:
        info = parent.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def candidate(original):
    text = original[MAIN].decode()
    require(text.startswith(PORT_BEGIN + '\n') and text.count(PORT_END) == 1,
            'Complete Stage 3 before final SSH hardening.')
    if BEGIN in text or END in text:
        require(text.count(BEGIN) == text.count(END) == 1 and BLOCK in text,
                'Managed final SSH block was changed; investigate before repair.')
        text = text.replace(BLOCK, '', 1)
    location = text.index(PORT_END) + len(PORT_END)
    require(text[location:location + 1] == '\n')
    text = text[:location + 1] + BLOCK + text[location + 1:]
    for name, data in original.items():
        source = data.decode()
        for line in source.splitlines():
            tokens = re.split(r'[\s=]+', line.split('#', 1)[0].strip())
            if not tokens or not tokens[0]:
                continue
            require(tokens[0].lower() != 'match',
                    'Final policy refuses all Match blocks; review conditional SSH configuration separately.')
            if tokens[0].lower() == 'include':
                require(name == MAIN and re.fullmatch(
                    r'\s*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf[ \t]*(?:#.*)?', line, re.I))
    return text.encode()


def effective(module, path=None):
    argv = ['/usr/sbin/sshd', '-T'] + (['-f', str(path)] if path else [])
    rc, output, _ = module.run_command(argv, environ_update={'LC_ALL': 'C'})
    require(rc == 0, 'SSH effective configuration validation failed.')
    result = {}
    for line in output.splitlines():
        name, _, value = line.partition(' ')
        result.setdefault(name, []).append(value)
    return result


def policy_valid(config, ports):
    require(all(config.get(name) == [value] for name, value in POLICY.items()),
            'Effective root/password/keyboard-interactive policy is not secure.')
    require(config.get('pubkeyauthentication') == ['yes'], 'Public-key authentication must remain enabled.')
    require(config.get('authenticationmethods') in (['any'], ['publickey']),
            'Unsupported authentication chain; do not disable required fallback factors.')
    require(set(config.get('port', [])) == {str(port) for port in ports}, 'SSH listening ports changed.')


def snapshot(module):
    sources = module.params['sources']
    names = [s['path'] for s in sources]
    require(len(names) == len(set(names)) and set(names) == {MAIN, *glob.glob(INCLUDES)})
    original = {}
    for source in sources:
        path = Path(source['path'])
        safe(path)
        data = path.read_bytes()
        require(digest(data) == source['sha256'])
        original[str(path)] = data
    return original


def unchanged(original):
    require(set(original) == {MAIN, *glob.glob(INCLUDES)})
    for name, data in original.items():
        safe(Path(name))
        require(Path(name).read_bytes() == data)


def secure(module):
    operation = module.params['operation']
    pending = Path(PENDING)
    original = snapshot(module)
    updated = candidate(original)
    if operation in ('installed', 'complete'):
        require(pending.exists(), 'Missing final SSH reload receipt.')
        safe(pending)
        receipt = json.loads(pending.read_text())
        require(receipt == {'sources': {name: digest(data) for name, data in original.items()}})
        require(updated == original[MAIN], 'Installed SSH policy changed during reload.')
        policy_valid(effective(module), module.params['ssh_ports'])
        unchanged(original)
        if operation == 'complete' and not module.check_mode:
            pending.unlink()
        return False
    require(not pending.exists() and not pending.is_symlink(),
            'Interrupted final SSH activation: use retained session/provider console before retrying.')
    if operation == 'verify':
        require(updated == original[MAIN], 'Final managed SSH policy is absent or misplaced.')
        policy_valid(effective(module), module.params['ssh_ports'])
        return False
    baseline = effective(module)
    # Stage every include so syntax/effective checks do not validate a moving live tree.
    with tempfile.TemporaryDirectory(prefix='portfolio-security-', dir='/etc/ssh') as temporary:
        stage = Path(temporary)
        includes = stage / 'includes'
        includes.mkdir(mode=0o700)
        for name, data in original.items():
            if name != MAIN:
                (includes / Path(name).name).write_bytes(data)
        staged = re.sub(r'(?im)^(\s*Include[ \t]+)/etc/ssh/sshd_config\.d/\*\.conf([ \t]*(?:#.*)?)$',
                        lambda match: match[1] + str(includes / '*.conf') + match[2], updated.decode())
        path = stage / 'sshd_config'
        path.write_text(staged)
        rc, _, _ = module.run_command(['/usr/sbin/sshd', '-t', '-f', str(path)])
        require(rc == 0, 'SSH candidate syntax validation failed; live policy preserved.')
        config = effective(module, path)
        policy_valid(config, module.params['ssh_ports'])
        require({k: v for k, v in baseline.items() if k not in POLICY} ==
                {k: v for k, v in config.items() if k not in POLICY},
                'Candidate changes settings beyond the three final SSH restrictions.')
        unchanged(original)
        if operation == 'preflight' or updated == original[MAIN] or module.check_mode:
            return operation == 'apply' and updated != original[MAIN]
        # Leave a protected receipt if activation is interrupted. No automatic fallback downgrade.
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as target:
            json.dump({'sources': {name: digest(updated if name == MAIN else data)
                                  for name, data in original.items()}}, target)
            target.flush()
            os.fsync(target.fileno())
        replacement = stage / 'installed'
        replacement.write_bytes(updated)
        replacement.chmod(0o644)
        with replacement.open('rb') as source:
            os.fsync(source.fileno())
        unchanged(original)
        os.replace(replacement, MAIN)
        return True


def main():
    module = AnsibleModule(argument_spec={
        'operation': {'type': 'str', 'choices': ['preflight', 'apply', 'installed', 'complete', 'verify'], 'default': 'preflight'},
        'sources': {'type': 'list', 'elements': 'dict', 'required': True},
        'ssh_ports': {'type': 'list', 'elements': 'int', 'required': True},
    }, supports_check_mode=True)
    lock = Path('/etc/ssh/portfolio-security.lock')
    try:
        if module.params['operation'] in ('preflight', 'installed', 'verify'):
            module.exit_json(changed=secure(module))
        if lock.exists() or lock.is_symlink():
            safe(lock)
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as target:
            fcntl.flock(target, fcntl.LOCK_EX)
            changed = secure(module)
        module.exit_json(changed=changed)
    except (ValueError, OSError, KeyError, UnicodeError):
        module.fail_json(msg='Final SSH safety validation failed. Policy may already be installed if activation was interrupted; '
                        'stop and inspect through retained administrator session/provider console. No automatic rollback.')


if __name__ == '__main__':
    main()
