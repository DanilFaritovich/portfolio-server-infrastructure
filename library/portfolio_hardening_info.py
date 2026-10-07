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
  socket_candidate:
    description: Validate generated socket listeners before restarting, without requiring live convergence.
    type: bool
    default: false
  current_port:
    description: Current inventory SSH route that must survive the transition.
    type: int
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
ssh_activation:
  description: Observed SSH activation mode, socket or service.
  returned: always
  type: str
baseline:
  description: Fingerprints of protected UFW configuration excluding managed fields.
  returned: when UFW is installed
  type: dict
'''

import glob
import hashlib
import ipaddress
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
        raise ValueError(message + ' Review and reconcile manually; no automatic reset/removal.')


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


def unit_properties(run, name, properties):
    _, text = run(['systemctl', 'show', name, '--property=' + ','.join(properties)])
    result = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    require(all(prop in result for prop in properties), 'Incomplete systemd unit inspection.')
    return result


def stock_unit(unit, name, socket_mode=False, ipv6_only=False):
    require(unit['FragmentPath'] in ('/usr/lib/systemd/system/' + name, '/lib/systemd/system/' + name),
            'Custom systemd unit detected.')
    for filename in unit['DropInPaths'].split():
        path = Path(filename)
        require(path.is_file() and not path.is_symlink(), 'Unsupported systemd drop-in.')
        lines = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        if socket_mode and name == 'ssh.service':
            require(filename in ('/etc/systemd/system/ssh.service.d/00-socket.conf',
                                 '/run/systemd/generator/ssh.service.d/00-socket.conf') and
                    len(lines) == 3 and lines[0] == '[Unit]' and
                    set(lines[1:]) == {'After=ssh.socket', 'Requires=ssh.socket'},
                    'Custom SSH service drop-in detected.')
        elif socket_mode and name == 'ssh.socket':
            require(filename == '/run/systemd/generator/ssh.socket.d/addresses.conf' and
                    len(lines) >= 3 and lines[:2] == ['[Socket]', 'ListenStream='] and
                    all(line.startswith('ListenStream=') and line != 'ListenStream=' for line in lines[2:]),
                    'Custom SSH socket drop-in detected.')
            generated = socket_listeners(' '.join(line.split('=', 1)[1] + ' (Stream)' for line in lines[2:]), ipv6_only)
            effective = socket_listeners(unit['Listen'], ipv6_only)
            require(generated == effective, 'Generated socket file differs semantically from effective listeners.')
        else:
            require(False, 'Custom systemd drop-in detected.')


def wildcard_listener(address, ipv6_only=False):
    """Normalize TCP reachability, including IPv4 coverage of a dual-stack socket."""
    match = re.fullmatch(r'(?:(0\.0\.0\.0|\*|\[[0-9a-fA-F:]+\]):)?([0-9]+)', address)
    require(match is not None, 'Non-wildcard SSH socket listener detected.')
    host, port = match[1], int(match[2])
    ports([port])
    if host == '0.0.0.0':
        return {('tcp', 'ipv4', '*', port)}
    if host not in (None, '*'):
        require(ipaddress.IPv6Address(host[1:-1]).is_unspecified,
                'Non-wildcard SSH socket listener detected.')
    found = {('tcp', 'ipv6', '*', port)}
    if not ipv6_only:
        found.add(('tcp', 'ipv4', '*', port))
    return found


def socket_listeners(text, ipv6_only=False):
    # systemctl's property is a whitespace-separated list, not a unit-file serialization.
    entries = re.findall(r'(\S+)\s+\(Stream\)', text)
    require(entries and ' '.join(address + ' (Stream)' for address in entries) == ' '.join(text.split()),
            'Ambiguous SSH socket Listen configuration.')
    found = set()
    for address in entries:
        found.update(wildcard_listener(address, ipv6_only))
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
    _, active = run(['systemctl', 'is-active', 'ssh.socket'], optional=True)
    _, enabled = run(['systemctl', 'is-enabled', 'ssh.socket'], optional=True)
    socket_mode = active == 'active' and enabled == 'enabled'
    require(socket_mode or (active in ('inactive', 'not-found') and enabled in ('disabled', 'masked', 'not-found')),
            'Ambiguous SSH activation mode.')
    for service in ('ssh.service', 'ufw.service') if installed else ('ssh.service',):
        stock_unit(unit_properties(run, service, ['FragmentPath', 'DropInPaths']), service, socket_mode)
    socket_routes = set()
    ipv6_only = False
    if not socket_mode:
        # Disabled sockets still must not hide custom overrides for a later boot.
        unit = unit_properties(run, 'ssh.socket', ['FragmentPath', 'DropInPaths'])
        if unit['FragmentPath'] in ('', '/dev/null'):
            require(not unit['DropInPaths'] and enabled in ('masked', 'not-found'),
                    'Ambiguous disabled SSH socket unit.')
        else:
            stock_unit(unit, 'ssh.socket')
    if socket_mode:
        unit = unit_properties(run, 'ssh.socket', ['FragmentPath', 'DropInPaths', 'Listen', 'Accept', 'Triggers', 'BindIPv6Only'])
        require(unit['BindIPv6Only'] in ('default', 'both', 'ipv6-only'), 'Ambiguous IPv6 socket binding policy.')
        policy = unit['BindIPv6Only']
        if policy == 'default':
            default = Path('/proc/sys/net/ipv6/bindv6only').read_text().strip()
            require(default in ('0', '1'), 'Ambiguous system IPv6 binding policy.')
            ipv6_only = default == '1'
        else:
            ipv6_only = policy == 'ipv6-only'
        stock_unit(unit, 'ssh.socket', True, ipv6_only)
        require(unit['Accept'] == 'no' and unit['Triggers'] == 'ssh.service', 'Unsupported SSH socket activation.')
        socket_routes = socket_listeners(unit['Listen'], ipv6_only)
        service = unit_properties(run, 'ssh.service', ['Requires', 'After', 'KillMode'])
        require('ssh.socket' in service['Requires'].split() and 'ssh.socket' in service['After'].split() and
                service['KillMode'] == 'process', 'Unsafe SSH socket/service restart relationship.')
        for directory in ('/etc', '/run'):
            generator = Path(directory + '/systemd/system-generators/sshd-socket-generator')
            require(not generator.exists() and not generator.is_symlink(),
                    'Custom or masked SSH socket generator detected.')
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
    socket_ports = {route[3] for route in socket_routes}
    live_routes = set()
    if socket_mode:
        # PID 1 can retain socket ownership alongside sshd. Attribute only the
        # effective ssh.socket ports, never arbitrary systemd listeners.
        for line in sockets.splitlines():
            fields = line.split()
            if len(fields) >= 4 and (re.search(r'"sshd(?:-[^"]*)?"', line) or re.search(r'"systemd",pid=1,', line)):
                port = fields[3].rsplit(':', 1)[1]
                if port.isdigit() and (int(port) in socket_ports or re.search(r'"sshd(?:-[^"]*)?"', line)):
                    live_ports.add(int(port))
                    live_routes.update(wildcard_listener(fields[3], ipv6_only))
    effective_ports = {int(line.split()[1]) for line in effective.splitlines() if line.startswith('port ')}
    candidate = module.params.get('socket_candidate', False)
    if socket_mode:
        require(socket_ports == effective_ports, 'Generated socket listeners differ from sshd configuration.')
        require(socket_ports <= set(ssh_ports), 'Preserve existing SSH socket routes in desired ports.')
        if candidate:
            require(socket_ports == set(ssh_ports), 'Generated socket listeners differ from desired ports.')
        else:
            require(live_routes == socket_routes, 'Live SSH socket listeners differ semantically from effective configuration.')
    require(not candidate or socket_mode, 'Socket candidate requires socket activation.')
    require(live_ports <= set(ssh_ports), 'Preserve existing live SSH routes in desired ports.')
    current_port = module.params.get('current_port')
    if current_port is not None:
        ports([current_port])
        require(current_port in ssh_ports and current_port in live_ports,
                'Current inventory SSH route must remain live and included in desired ports.')
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(':', 1)[1].isdigit():
            require(int(fields[3].rsplit(':', 1)[1]) not in ssh_ports or re.search(r'"sshd(?:-[^"]*)?"', line) or
                    (socket_mode and int(fields[3].rsplit(':', 1)[1]) in socket_ports and
                     re.search(r'"systemd",pid=1,', line)),
                    'A configured SSH port is occupied by another process.')
    if module.params['verify']:
        require(effective_ports == set(ssh_ports) == live_ports, 'Effective SSH ports/listeners do not match configuration.')

    result = {'ufw_installed': installed, 'ssh_activation': 'socket' if socket_mode else 'service'}
    if candidate:
        require(installed, 'SSH socket activation requires the prepared firewall.')
        _, status = run(['ufw', 'status', 'verbose'])
        require(set(ssh_ports) <= runtime_ports(status) and set(ssh_ports) <= runtime_ports(status, ipv6=True),
                'All desired SSH ports must be allowed for IPv4 and IPv6 before socket activation.')
        return result
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
        'socket_candidate': {'type': 'bool', 'default': False},
        'current_port': {'type': 'int'},
    }, supports_check_mode=True)
    try:
        module.exit_json(changed=False, **inspect(module))
    except (ValueError, OSError, KeyError, TypeError):
        # Avoid dumping config, parser input or command stderr into failure output.
        import sys
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, ValueError) and 'Review and reconcile manually;' in str(error) else \
            'Cannot safely inspect hardening state. Review configuration manually.'
        module.fail_json(msg=message)


if __name__ == '__main__':
    main()
