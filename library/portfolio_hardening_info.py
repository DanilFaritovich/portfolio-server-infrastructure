#!/usr/bin/python
"""Read-only host safety inspection shared by hardening and verification."""

DOCUMENTATION = r'''
---
module: portfolio_hardening_info
short_description: Inspect portfolio SSH and UFW state without changing configuration
description:
  - Reject ambiguous unmanaged configuration before provisioning.
options:
  ssh_ports:
    description: Intended SSH listening ports.
    required: true
    type: list
    elements: int
  tcp_ports:
    description: Additional incoming TCP ports.
    required: true
    type: list
    elements: int
  verify:
    description: Require fully converged runtime state.
    type: bool
    default: false
  refresh_rules:
    description: Read fingerprints after role-owned rule changes; still never writes state.
    type: bool
    default: false
'''
EXAMPLES = r'''
- name: Inspect host hardening
  portfolio_hardening_info:
    ssh_ports: [2222]
    tcp_ports: [80, 443]
'''
RETURN = r'''
ufw_installed:
  description: Whether UFW is installed.
  returned: always
  type: bool
baseline:
  description: Fingerprints of protected UFW configuration excluding managed fields.
  returned: when UFW is installed
  type: dict
'''

import glob
import hashlib
import json
from pathlib import Path
import re

from ansible.module_utils.basic import AnsibleModule

MARKER = '# {mark} ANSIBLE PORTFOLIO SSH PORTS'
STATE = Path('/etc/ufw/portfolio-hardening.json')
COMMENT = 'portfolio-host-hardening'
RULE_FILES = ('/etc/ufw/user.rules', '/etc/ufw/user6.rules')
PROTECTED = ('/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/before.rules',
             '/etc/ufw/before6.rules', '/etc/ufw/after.rules', '/etc/ufw/after6.rules',
             '/etc/ufw/sysctl.conf', '/etc/ufw/before.init', '/etc/ufw/after.init')


def require(condition, message):
    if not condition:
        raise ValueError(message + ' Review and migrate manually; no automatic reset/removal.')


def ports(values, empty=False):
    require(isinstance(values, list) and (empty or values) and
            all(type(p) is int and 1 <= p <= 65535 for p in values) and
            len(values) == len(set(values)), 'Use unique integer ports from 1 to 65535.')
    return sorted(values)


def unmanaged_ssh(text, main=False):
    """Only the role's main-file block owns listening directives."""
    begin, end = (MARKER.format(mark=value) for value in ('BEGIN', 'END'))
    if main and (begin in text or end in text):
        require(text.count(begin) == text.count(end) == 1 and text.index(begin) < text.index(end),
                'Malformed managed SSH block.')
        require(text.startswith(begin), 'Managed SSH block must precede all other directives.')
        block = text[text.index(begin) + len(begin):text.index(end)]
        require(all(not line.strip() or re.fullmatch(r'(?:Port [0-9]+|PubkeyAuthentication yes)', line.strip())
                    for line in block.splitlines()), 'Unexpected directives inside managed SSH block.')
        text = text[:text.index(begin)] + text[text.index(end) + len(end):]
    for line in text.splitlines():
        fields = re.split(r'[\s=]+', line.split('#', 1)[0].strip())
        if not fields or not fields[0]:
            continue
        directive = fields[0].lower()
        require(directive not in ('port', 'listenaddress'), 'Unmanaged SSH listening directives detected.')
        if directive == 'include':
            require(main and fields[1:] == ['/etc/ssh/sshd_config.d/*.conf'],
                    'Unsupported SSH Include hierarchy detected.')


def fingerprint(path):
    if not path.exists():
        return None
    require(path.is_file() and not path.is_symlink(), 'Unexpected UFW configuration file type.')
    content = path.read_bytes()
    if path.name == 'ufw' and path.parent.name == 'default':
        content = re.sub(rb'^DEFAULT_(?:INPUT|OUTPUT)_POLICY=.*\n?', b'', content, flags=re.M)
    elif path.name == 'ufw.conf':
        content = re.sub(rb'^ENABLED=.*\n?', b'', content, flags=re.M)
    return hashlib.sha256(content).hexdigest()


def pristine_rules(path):
    """An empty UFW user file may only contain stock chains/logging/limit helpers."""
    if not path.exists():
        return
    text = path.read_text()
    prefix = 'ufw6' if path.name == 'user6.rules' else 'ufw'
    helpers = {
        f'-A {prefix}-user-logging-{direction} -j RETURN' for direction in ('input', 'output', 'forward')
    } | {f'-A {prefix}-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "',
         f'-A {prefix}-user-limit -j REJECT', f'-A {prefix}-user-limit-accept -j ACCEPT'}
    for line in text.splitlines():
        if not line.strip() or line.startswith('#') or line in ('*filter', 'COMMIT') or line in helpers:
            continue
        require(re.fullmatch(r':' + prefix + r'-user-(?:input|output|forward|logging-input|logging-output|logging-forward|limit|limit-accept) - \[0:0\]', line),
                'Unmanaged raw UFW user rules detected.')


def added_ports(text):
    found = []
    for line in text.splitlines():
        if not line.startswith('ufw '):
            continue
        match = re.fullmatch(r"ufw allow (?:in )?(\d+)/tcp comment ['\"]?" + COMMENT + r"['\"]?", line)
        require(match is not None, 'Unknown existing UFW rule detected.')
        found.append(int(match[1]))
    return set(found)


def runtime_ports(text, ipv6=False):
    suffix = r' \(v6\)' if ipv6 else ''
    pattern = r'^\s*(\d+)/tcp' + suffix + r'\s+ALLOW IN\s+Anywhere' + suffix + r'(?:\s+#.*)?\s*$'
    return {int(m[1]) for line in text.splitlines() if (m := re.fullmatch(pattern, line))}


def listeners(text):
    found = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and re.search(r'"sshd(?:-[^"]*)?"', line):
            found.add(int(fields[3].rsplit(':', 1)[1]))
    return found


def inspect(module):
    ssh_ports = ports(module.params['ssh_ports'])
    tcp_ports = ports(module.params['tcp_ports'], empty=True)
    wanted = set(ssh_ports + tcp_ports)

    def run(argv, optional=False):
        rc, stdout, _ = module.run_command(argv, environ_update={'LC_ALL': 'C'})
        require(optional or rc == 0, 'Host inspection command failed: ' + argv[0] + '.')
        return rc, stdout.strip()

    installed = module.get_bin_path('ufw') is not None
    require(re.search(r'^ID=[\"\']?ubuntu[\"\']?$', Path('/etc/os-release').read_text(), re.M),
            'Hardening supports Ubuntu only.')
    for service in ('ssh.service', 'ufw.service') if installed else ('ssh.service',):
        _, unit = run(['systemctl', 'show', service, '--property=FragmentPath,DropInPaths'])
        require('DropInPaths=\n' in unit + '\n' and
                not re.search(r'FragmentPath=/etc/', unit), 'Custom SSH/UFW systemd unit detected.')
    for state in ('is-active', 'is-enabled'):
        rc, output = run(['systemctl', state, 'ssh.socket'], optional=True)
        require(rc != 0 and output in ('inactive', 'disabled', 'masked', 'not-found'),
                'ssh.socket activation must be migrated to ssh.service first.')
    for service in ('ssh.service', 'docker.service', 'containerd.service'):
        _, output = run(['systemctl', 'is-active', service])
        require(output == 'active', 'SSH/Docker/containerd must remain active.')
    run(['/usr/sbin/sshd', '-t'])
    # Do not follow arbitrary include trees or overwrite their listening policy.
    main = Path('/etc/ssh/sshd_config')
    require(main.is_file() and not main.is_symlink(), 'Unsupported main SSH configuration.')
    unmanaged_ssh(main.read_text(), main=True)
    for name in glob.glob('/etc/ssh/sshd_config.d/*.conf'):
        unmanaged_ssh(Path(name).read_text())
    _, effective = run(['/usr/sbin/sshd', '-T'])
    require('pubkeyauthentication yes' in effective.splitlines(), 'Public-key authentication must remain enabled.')
    _, sockets = run(['ss', '-H', '-ltnp'])
    live_ports = listeners(sockets)
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(':', 1)[1].isdigit():
            require(int(fields[3].rsplit(':', 1)[1]) not in ssh_ports or re.search(r'"sshd(?:-[^"]*)?"', line),
                    'A configured SSH port is occupied by another process.')
    if module.params['verify']:
        effective_ports = {int(line.split()[1]) for line in effective.splitlines() if line.startswith('port ')}
        require(effective_ports == set(ssh_ports) == live_ports, 'Effective SSH ports/listeners do not match configuration.')

    result = {'ufw_installed': installed}
    if not installed:
        require(not Path('/etc/systemd/system/ufw.service').exists() and
                not Path('/etc/systemd/system/ufw.service.d').exists(), 'Orphan custom UFW unit detected.')
        require(not Path('/etc/ufw').exists() and not Path('/etc/default/ufw').exists(), 'Orphan UFW configuration detected.')
        require(not module.params['verify'], 'UFW is missing.')
        return result

    _, status = run(['ufw', 'status', 'verbose'])
    require(status.startswith(('Status: active', 'Status: inactive')), 'Unrecognized UFW status.')
    active = status.startswith('Status: active')
    _, added = run(['ufw', 'show', 'added'])
    rules = added_ports(added)
    require(rules <= wanted, 'Existing managed UFW ports were removed from desired configuration.')
    baseline = {name: fingerprint(Path(name)) for name in PROTECTED}
    rule_hashes = {name: fingerprint(Path(name)) for name in RULE_FILES}
    snapshot = {'base': baseline, 'rules': rule_hashes}
    if STATE.exists():
        require(STATE.is_file() and not STATE.is_symlink(), 'Unsafe UFW ownership marker.')
        previous = json.loads(STATE.read_text())
        require(previous['base'] == baseline, 'Protected UFW configuration changed outside the role.')
        require(module.params['refresh_rules'] or previous['rules'] == rule_hashes,
                'Raw UFW user rules changed outside the role.')
    else:
        require(not active and not rules, 'Existing UFW state is not owned by this role.')
        for name in RULE_FILES:
            pristine_rules(Path(name))
        _, conffiles = run(['dpkg-query', '-W', '-f=${Conffiles}', 'ufw'])
        package_files = {m[1]: m[2] for line in conffiles.splitlines()
                         if (m := re.fullmatch(r'\s*(/\S+) ([0-9a-f]{32})(?: obsolete)?', line))}
        for name in PROTECTED:
            path = Path(name)
            if path.exists():
                require(name in package_files and hashlib.md5(path.read_bytes()).hexdigest() == package_files[name],
                        'Unmanaged UFW base configuration detected.')
    defaults = Path('/etc/default/ufw').read_text()
    require(re.search(r'^IPV6=yes$', defaults, re.M) is not None, 'UFW must protect IPv4 and IPv6.')
    incoming = re.findall(r'^DEFAULT_INPUT_POLICY="([A-Z]+)"$', defaults, re.M)
    outgoing = re.findall(r'^DEFAULT_OUTPUT_POLICY="([A-Z]+)"$', defaults, re.M)
    require(len(incoming) == len(outgoing) == 1, 'Ambiguous UFW default policy configuration.')
    result.update(baseline=snapshot, ufw_active=active, marker_exists=STATE.exists(),
                  incoming=incoming[0], outgoing=outgoing[0])
    if module.params['verify']:
        require(STATE.exists() and active and 'ENABLED=yes' in Path('/etc/ufw/ufw.conf').read_text().splitlines(),
                'UFW must be enabled at runtime and boot.')
        require('Default: deny (incoming), allow (outgoing),' in status and
                incoming == ['DROP'] and outgoing == ['ACCEPT'], 'UFW default policies do not match.')
        require(rules == wanted and wanted <= runtime_ports(status) and wanted <= runtime_ports(status, ipv6=True),
                'Configured TCP ports must be allowed at runtime for IPv4 and IPv6.')
    return result


def main():
    module = AnsibleModule(argument_spec={
        'ssh_ports': {'type': 'list', 'elements': 'int', 'required': True},
        'tcp_ports': {'type': 'list', 'elements': 'int', 'required': True},
        'verify': {'type': 'bool', 'default': False},
        'refresh_rules': {'type': 'bool', 'default': False},
    }, supports_check_mode=True)
    try:
        module.exit_json(changed=False, **inspect(module))
    except (ValueError, OSError, KeyError, TypeError):
        # Avoid dumping config, parser input or command stderr into failure output.
        import sys
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, ValueError) and 'Review and migrate manually;' in str(error) else \
            'Cannot safely inspect hardening state. Review configuration manually.'
        module.fail_json(msg=message)


if __name__ == '__main__':
    main()
