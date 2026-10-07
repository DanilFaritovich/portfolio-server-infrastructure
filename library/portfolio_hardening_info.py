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
    type: raw
  tcp_ports:
    description: Additional incoming TCP ports.
    required: true
    type: raw
  verify:
    description: Require fully converged runtime state.
    type: bool
    default: false
  report_only:
    description: Return all sanitized findings without failing on blocking findings.
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
socket_reload_required:
  description: Whether socket state needs regeneration and activation to converge.
  returned: always
  type: bool
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


MARKER = '# {mark} ANSIBLE PORTFOLIO SSH PORTS'
STATE = Path('/etc/ufw/portfolio-hardening.json')
COMMENT = 'portfolio-host-hardening'
RULE_FILES = ('/etc/ufw/user.rules', '/etc/ufw/user6.rules')
PROTECTED = ('/etc/default/ufw', '/etc/ufw/ufw.conf', '/etc/ufw/before.rules',
             '/etc/ufw/before6.rules', '/etc/ufw/after.rules', '/etc/ufw/after6.rules',
             '/etc/ufw/sysctl.conf', '/etc/ufw/before.init', '/etc/ufw/after.init')


class SafetyError(ValueError):
    """Only reviewed static diagnoses may cross the public reporting boundary."""


def require(condition, message):
    if not condition:
        raise SafetyError(message + ' Review and reconcile manually; no automatic reset/removal.')


def ports(values, empty=False):
    require(isinstance(values, list) and (empty or values) and
            all(type(p) is int and 1 <= p <= 65535 for p in values) and
            len(values) == len(set(values)), 'Use unique integer ports from 1 to 65535.')
    return sorted(values)


def effective_ssh_ports(text):
    """Effective daemon output may repeat ports; desired inventory must not."""
    values = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != 'port':
            continue
        require(len(fields) == 2 and re.fullmatch(r'[0-9]+', fields[1]) is not None,
                'Malformed effective SSH port.')
        value = int(fields[1])
        require(1 <= value <= 65535, 'Effective SSH ports must be integers from 1 to 65535.')
        values.append(value)
    require(values, 'No effective SSH ports found.')
    return set(values)


def unmanaged_ssh(text, main=False, adopt=False, findings=None, label="SSH configuration"):
    """Only the role's main-file block owns listening directives."""
    def validate(condition, message):
        if findings is None:
            require(condition, message)
        elif not condition:
            findings.probe(label, lambda: require(False, message))
        return bool(condition)

    begin, end = (MARKER.format(mark=value) for value in ('BEGIN', 'END'))
    managed = begin in text
    if main and (begin in text or end in text):
        valid_block = validate(text.count(begin) == text.count(end) == 1 and text.index(begin) < text.index(end),
                               'Malformed managed SSH block.')
        if not valid_block:
            # The boundary is ambiguous; scan all remaining directives for independent issues.
            return scan_ssh_directives(text, main, adopt, managed, validate)
        validate(text.startswith(begin), 'Managed SSH block must precede all other directives.')
        block = text[text.index(begin) + len(begin):text.index(end)]
        validate(all(not line.strip() or re.fullmatch(r'(?:Port [0-9]+|PubkeyAuthentication yes)', line.strip())
                    for line in block.splitlines()), 'Unexpected directives inside managed SSH block.')
        text = text[:text.index(begin)] + text[text.index(end) + len(end):]
    return scan_ssh_directives(text, main, adopt, managed, validate)


def scan_ssh_directives(text, main, adopt, managed, validate):
    legacy = []
    matched = False
    includes = 0
    for number, line in enumerate(text.splitlines(), 1):
        fields = re.split(r'[\s=]+', line.split('#', 1)[0].strip())
        if not fields or not fields[0]:
            continue
        directive = fields[0].lower()
        validate(directive != 'listenaddress', 'Unmanaged ListenAddress directive detected.')
        if directive == 'match':
            matched = True
        if directive == 'port':
            if validate(adopt and not matched and re.fullmatch(r'\s*Port[ \t]+[0-9]+[ \t]*(?:#.*)?', line),
                        'Unsupported legacy Port directive detected.'):
                legacy.append({'line': number, 'port': int(fields[1])})
        if directive == 'include':
            includes += 1
            validate(not matched and includes == 1 and main and
                    re.fullmatch(r'\s*Include[ \t]+/etc/ssh/sshd_config\.d/\*\.conf[ \t]*(?:#.*)?', line, re.I),
                    'Unsupported SSH Include hierarchy detected.')
    validate(not legacy or not managed,
            'Legacy Port directive conflicts with managed SSH configuration.')
    return legacy


def fingerprint(path):
    if not safe_file(path, 'Unexpected UFW configuration file type.', optional=True):
        return None
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
    result = {}
    for line in text.splitlines():
        if '=' not in line:
            continue
        prop, value = line.split('=', 1)
        # systemctl show prints one Listen= row per socket, including separate
        # IPv4/IPv6 entries. A dict comprehension silently loses every earlier row.
        if prop == 'Listen' and prop in result:
            result[prop] += ' ' + value
        else:
            require(prop not in result, 'Ambiguous repeated systemd scalar property.')
            result[prop] = value
    require(all(prop in result for prop in properties), 'Incomplete systemd unit inspection.')
    return result


def stock_unit(unit, name, socket_mode=False, ipv6_only=False, findings=None):
    def check(label, operation):
        return findings.probe(label, operation) if findings is not None else operation()

    def fragment():
        require(unit['FragmentPath'] in ('/usr/lib/systemd/system/' + name, '/lib/systemd/system/' + name),
                'Custom systemd unit detected.')
        path = Path(unit['FragmentPath'])
        require(path.is_file() and not path.is_symlink(), 'Unsafe systemd unit file type.')
    check(name + ' package unit file', fragment)
    generated = None
    dropins = set(unit['DropInPaths'].split())
    for root in ('/etc/systemd/system', '/run/systemd/system', '/run/systemd/generator'):
        def override(root=root):
            path = Path(root + '/' + name)
            require(not path.exists() and not path.is_symlink(), 'Custom systemd unit detected.')
        check(name + ' unit override in ' + root, override)
        def directory_files(root=root):
            directory = Path(root + '/' + name + '.d')
            require(not directory.is_symlink() and (not directory.exists() or directory.is_dir()),
                    'Unsupported systemd drop-in directory.')
            return [root + '/' + name + '.d/' + path.name for path in directory.glob('*.conf')]
        files = check(name + ' drop-in directory in ' + root, directory_files)
        if files is not None:
            dropins.update(files)
    for index, filename in enumerate(sorted(dropins), 1):
        def dropin(filename=filename):
            path = Path(filename)
            safe_file(path, 'Unsupported systemd drop-in.')
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
                return socket_listeners(' '.join(line.split('=', 1)[1] + ' (Stream)' for line in lines[2:]), ipv6_only)
            else:
                require(False, 'Custom systemd drop-in detected.')
        routes = check(name + ' drop-in ' + str(index), dropin)
        if routes is not None:
            generated = routes
    return generated


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


class Findings:
    """Independent probes stop locally; their fixed, sanitized diagnoses accumulate."""

    def __init__(self):
        self.items = []

    def probe(self, label, operation, dependencies=True):
        if not dependencies:
            self.items.append({'status': 'FAIL', 'check': label,
                               'detail': 'Cannot evaluate safely until prerequisite findings are resolved.'})
            return None
        failures_before = sum(item['status'] == 'FAIL' for item in self.items)
        try:
            value = operation()
        except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError):
            import sys
            error = sys.exc_info()[1]
            # Only require() messages contain reviewed, static text. Never expose
            # command output, parser errors, file contents or exception arguments.
            detail = str(error).split(' Review and reconcile manually;', 1)[0] if \
                isinstance(error, SafetyError) else \
                'Cannot safely inspect this state; review configuration manually.'
            self.items.append({'status': 'FAIL', 'check': label, 'detail': detail})
            return None
        if sum(item['status'] == 'FAIL' for item in self.items) == failures_before:
            self.items.append({'status': 'PASS', 'check': label})
        return value

    def convergence(self, label, converged, verify, message):
        if verify:
            self.probe(label, lambda: require(converged, message))
        else:
            self.items.append({'status': 'PASS' if converged else 'WARN', 'check': label,
                               **({} if converged else {'detail': message})})

    def result(self):
        blockers = sum(item['status'] == 'FAIL' for item in self.items)
        lines = ['Hardening preflight']
        grouped = set()
        for item in self.items:
            if item['status'] == 'PASS' and (' unit override in ' in item['check'] or
                    ' drop-in directory in ' in item['check'] or item['check'].endswith(' package unit file')):
                continue
            group = next((prefix for prefix in ('UFW base file ', 'UFW raw rules file ',
                         'UFW package base file ', 'pristine raw UFW rules ')
                         if item['check'].startswith(prefix)), None)
            if group and item['status'] == 'PASS':
                if any(other['status'] != 'PASS' and other['check'].startswith(group) for other in self.items):
                    continue
                if group not in grouped:
                    lines.append('PASS  ' + group.strip() + ' checks completed')
                    grouped.add(group)
                continue
            lines.append(item['status'] + '  ' + item['check'] +
                         (': ' + item['detail'] if 'detail' in item else ''))
        lines += ['', 'Result: ' + ('NOT READY' if blockers else 'READY'),
                  str(blockers) + ' blocking findings require handling before harden']
        return {'ready': blockers == 0, 'findings': self.items, 'report': '\n'.join(lines)}


def safe_file(path, message, optional=False):
    # Check symlinks before exists(), including dangling links. Never read devices
    # or FIFOs, nor follow a symlinked configuration directory.
    require(not path.is_symlink() and all(not parent.is_symlink() for parent in path.parents), message)
    require((optional and not path.exists()) or path.is_file(), message)
    return path.exists()


def inspect(module):
    checks = Findings()
    verify = module.params['verify']
    candidate = module.params.get('socket_candidate', False)
    checks.probe('SSH validation phase', lambda: require(not (candidate and verify),
                 'Select either pre-restart socket candidate or post-restart runtime verification.'))

    def run(argv, optional=False):
        rc, stdout, _ = module.run_command(argv, environ_update={'LC_ALL': 'C'})
        require(optional or rc == 0, 'Host inspection command failed: ' + argv[0] + '.')
        return rc, stdout.strip()

    ssh_ports = checks.probe('desired SSH ports', lambda: ports(module.params['ssh_ports']))
    tcp_ports = checks.probe('desired HTTP/HTTPS and additional TCP ports',
                             lambda: ports(module.params['tcp_ports'], empty=True))
    wanted = set(ssh_ports + tcp_ports) if ssh_ports is not None and tcp_ports is not None else None
    checks.probe('Ubuntu host', lambda: require(
        re.search(r'^ID=[\"\']?ubuntu[\"\']?$', Path('/etc/os-release').read_text(), re.M),
        'Hardening supports Ubuntu only.'))
    installed = module.get_bin_path('ufw') is not None

    def activation():
        _, active = run(['systemctl', 'is-active', 'ssh.socket'], optional=True)
        _, enabled = run(['systemctl', 'is-enabled', 'ssh.socket'], optional=True)
        mode = active == 'active' and enabled == 'enabled'
        require(mode or (active in ('inactive', 'not-found') and enabled in ('disabled', 'masked', 'not-found')),
                'Ambiguous SSH activation mode.')
        return mode, enabled

    activation_state = checks.probe('SSH activation mode', activation)
    socket_mode = activation_state[0] if activation_state is not None else None
    for name in ('ssh.service', 'ufw.service') if installed else ('ssh.service',):
        checks.probe(name + ' stock unit and drop-ins', lambda name=name: stock_unit(
            unit_properties(run, name, ['FragmentPath', 'DropInPaths']), name, socket_mode, findings=checks),
            dependencies=socket_mode is not None or name == 'ufw.service')

    socket_routes = None
    generated_routes = None
    ipv6_only = False
    if socket_mode is False:
        def disabled_socket():
            unit = unit_properties(run, 'ssh.socket', ['FragmentPath', 'DropInPaths'])
            if unit['FragmentPath'] in ('', '/dev/null'):
                require(not unit['DropInPaths'] and activation_state[1] in ('masked', 'not-found'),
                        'Ambiguous disabled SSH socket unit.')
                for root in ('/etc/systemd/system', '/run/systemd/system', '/run/systemd/generator'):
                    def dormant_override(root=root):
                        path = Path(root + '/ssh.socket')
                        directory = Path(root + '/ssh.socket.d')
                        require(not directory.exists() and not directory.is_symlink(),
                                'Custom disabled SSH socket drop-ins detected.')
                        require((not path.exists() and not path.is_symlink()) or
                                (activation_state[1] == 'masked' and path.is_symlink() and
                                 str(path.resolve()) == '/dev/null'), 'Custom disabled SSH socket unit detected.')
                    checks.probe('disabled SSH socket overrides in ' + root, dormant_override)
            else:
                stock_unit(unit, 'ssh.socket', findings=checks)
        checks.probe('disabled ssh.socket stock configuration', disabled_socket)
    elif socket_mode is True:
        unit = checks.probe('loaded SSH socket properties', lambda: unit_properties(
            run, 'ssh.socket', ['FragmentPath', 'DropInPaths', 'Listen', 'Accept', 'Triggers', 'BindIPv6Only']))
        def binding():
            policy = unit['BindIPv6Only']
            require(policy in ('default', 'both', 'ipv6-only'), 'Ambiguous IPv6 socket binding policy.')
            if policy == 'default':
                default = Path('/proc/sys/net/ipv6/bindv6only').read_text().strip()
                require(default in ('0', '1'), 'Ambiguous system IPv6 binding policy.')
                return default == '1'
            return policy == 'ipv6-only'
        ipv6_only = checks.probe('SSH socket IPv6 binding', binding, unit is not None)
        generated_routes = checks.probe('generated ssh.socket stock configuration',
            lambda: stock_unit(unit, 'ssh.socket', True, ipv6_only, findings=checks), unit is not None and ipv6_only is not None)
        socket_routes = checks.probe('loaded SSH socket listeners',
            lambda: socket_listeners(unit['Listen'], ipv6_only), unit is not None and ipv6_only is not None)
        checks.probe('SSH socket activation relationship', lambda: require(
            unit['Accept'] == 'no' and unit['Triggers'] == 'ssh.service', 'Unsupported SSH socket activation.'),
            unit is not None)
        def relationship():
            service = unit_properties(run, 'ssh.service', ['Requires', 'After', 'KillMode'])
            require('ssh.socket' in service['Requires'].split() and 'ssh.socket' in service['After'].split() and
                    service['KillMode'] == 'process', 'Unsafe SSH socket/service restart relationship.')
        checks.probe('safe SSH socket/service restart relationship', relationship)
        for directory in ('/etc', '/run'):
            def generator(directory=directory):
                path = Path(directory + '/systemd/system-generators/sshd-socket-generator')
                require(not path.exists() and not path.is_symlink(), 'Custom or masked SSH socket generator detected.')
            checks.probe(directory + ' SSH generator overrides', generator)
    for name in ('ssh.service', 'docker.service', 'containerd.service'):
        def service_active(name=name):
            _, output = run(['systemctl', 'is-active', name], optional=True)
            require(output == 'active', name + ' must remain active.')
        checks.probe(name + ' active', service_active)
    checks.probe('SSH syntax', lambda: run(['/usr/sbin/sshd', '-t']))

    for name in ('/etc/ssh', '/etc/ssh/sshd_config.d'):
        def ssh_directory(name=name):
            path = Path(name)
            require(not path.is_symlink() and (not path.exists() or path.is_dir()),
                    'Unsupported SSH configuration directory type.')
        checks.probe('SSH configuration directory ' + name, ssh_directory)
    sources, legacy = [], []
    main_managed = False
    config_ok = True
    for index, name in enumerate(['/etc/ssh/sshd_config'] + sorted(glob.glob('/etc/ssh/sshd_config.d/*.conf'))):
        def source(name=name, index=index):
            path = Path(name)
            safe_file(path, 'Unsupported main SSH configuration.' if index == 0 else 'Unsupported SSH include file type.')
            data = path.read_bytes()
            text = data.decode()
            records = unmanaged_ssh(text, main=index == 0, adopt=not verify, findings=checks,
                                    label='SSH listening directives in file ' + str(index + 1))
            return data, text, records
        failures_before = sum(item['status'] == 'FAIL' for item in checks.items)
        value = checks.probe('SSH main configuration' if index == 0 else 'SSH standard include ' + str(index), source)
        if value is None:
            config_ok = False
            continue
        if sum(item['status'] == 'FAIL' for item in checks.items) != failures_before:
            config_ok = False
        data, text, records = value
        if index == 0:
            main_managed = MARKER.format(mark='BEGIN') in text
        legacy.extend(dict(record, path=name) for record in records)
        sources.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest()})

    effective_result = checks.probe('effective SSH configuration', lambda: run(['/usr/sbin/sshd', '-T']))
    effective_ports = None
    if effective_result is not None:
        effective = effective_result[1]
        checks.probe('SSH public-key authentication', lambda: require(
            'pubkeyauthentication yes' in effective.splitlines(), 'Public-key authentication must remain enabled.'))
        effective_ports = checks.probe('effective SSH ports', lambda: effective_ssh_ports(effective))
    sockets_result = checks.probe('live SSH listener inspection', lambda: run(['ss', '-H', '-ltnp']))
    live_ports, live_routes = None, None
    socket_ports = {route[3] for route in socket_routes} if socket_routes is not None else set()
    if sockets_result is not None:
        sockets = sockets_result[1]
        def live():
            found = listeners(sockets)
            routes = set()
            if socket_mode:
                require(socket_routes is not None and ipv6_only is not None, 'Cannot attribute SSH socket listeners safely.')
                for line in sockets.splitlines():
                    fields = line.split()
                    if len(fields) >= 4 and (re.search(r'"sshd(?:-[^"]*)?"', line) or re.search(r'"systemd",pid=1,', line)):
                        port = fields[3].rsplit(':', 1)[1]
                        if port.isdigit() and (int(port) in socket_ports or re.search(r'"sshd(?:-[^"]*)?"', line)):
                            found.add(int(port))
                            routes.update(wildcard_listener(fields[3], ipv6_only))
            return found, routes
        value = checks.probe('live SSH listeners', live, socket_mode is not None)
        if value is not None:
            live_ports, live_routes = value
        def occupied():
            for line in sockets.splitlines():
                fields = line.split()
                if len(fields) >= 4 and fields[3].rsplit(':', 1)[1].isdigit():
                    require(int(fields[3].rsplit(':', 1)[1]) not in ssh_ports or re.search(r'"sshd(?:-[^"]*)?"', line) or
                            (socket_mode and int(fields[3].rsplit(':', 1)[1]) in socket_ports and
                             re.search(r'"systemd",pid=1,', line)),
                            'A configured SSH port is occupied by another process.')
        checks.probe('desired SSH ports available', occupied, ssh_ports is not None and socket_mode is not None)
    desired_routes = {('tcp', family, '*', port) for port in ssh_ports for family in ('ipv4', 'ipv6')} if ssh_ports else None
    current_port = module.params.get('current_port')
    def current_route():
        ports([current_port])
        require(current_port in ssh_ports and current_port in live_ports,
                'Current inventory SSH route must remain live and included in desired ports.')
    if current_port is not None:
        checks.probe('current inventory SSH route', current_route, ssh_ports is not None and live_ports is not None)
    checks.probe('preserve live SSH routes', lambda: require(live_ports <= set(ssh_ports),
        'Preserve existing live SSH routes in desired ports.'), ssh_ports is not None and live_ports is not None)
    def adoption():
        require(not legacy or not main_managed, 'Legacy Port directive conflicts with managed SSH configuration.')
        require(all(record['port'] in ssh_ports for record in legacy), 'Legacy Port directive is outside desired SSH ports.')
        require(not legacy or (current_port is not None and effective_ports <= set(ssh_ports)),
                'Legacy Port directive differs from safe effective SSH ports.')
        return bool(legacy)
    adoptable = checks.probe('safe SSH adoption', adoption,
                            config_ok and ssh_ports is not None and effective_ports is not None)
    if config_ok:
        checks.convergence('managed SSH port block', main_managed, False,
                           'Harden can install the validated managed SSH port block.')
    if adoptable:
        checks.convergence('legacy SSH Ports', False, verify, 'Legacy SSH Ports can be adopted after staged validation.')
    if effective_ports is not None and live_ports is not None and ssh_ports is not None:
        checks.convergence('SSH port convergence', effective_ports == set(ssh_ports) == live_ports, verify,
                           'Effective SSH ports/listeners do not match configuration.')
    # Pre-restart validates the generated candidate only. Loaded systemd routes
    # and inherited live descriptors may legitimately retain the old subset.
    # Post-restart verification requires all three independent states to agree.
    if candidate:
        checks.probe('candidate effective SSH ports', lambda: require(effective_ports == set(ssh_ports),
            'Candidate effective SSH ports differ from desired ports.'), ssh_ports is not None and effective_ports is not None)
        checks.probe('generated desired SSH socket routes', lambda: require(
            generated_routes is not None and generated_routes == desired_routes,
            'Generated socket listeners differ from desired ports or generated configuration is missing.'),
            desired_routes is not None)
        checks.probe('safe live SSH socket subset', lambda: require(live_routes <= desired_routes,
            'Existing live SSH socket routes must be a safe subset of desired routes.'),
            live_routes is not None and desired_routes is not None)
    elif socket_mode and socket_routes is not None and live_routes is not None and desired_routes is not None:
        coherent = generated_routes == socket_routes and socket_ports == effective_ports
        checks.convergence('generated/loaded SSH socket state', coherent, verify,
                           'Generated socket file differs semantically from effective listeners or sshd configuration.')
        checks.convergence('live SSH socket state', live_routes == socket_routes == desired_routes, verify,
                           'Live SSH socket listeners differ semantically from effective configuration.')
        checks.convergence('desired SSH socket routes',
                           generated_routes == socket_routes == live_routes == desired_routes, verify,
                           'Generated, loaded or live SSH socket listeners differ from desired routes.')
    checks.probe('socket candidate activation mode', lambda: require(not candidate or socket_mode,
                 'Socket candidate requires socket activation.'))
    result = {'ssh_adoption': legacy, 'ssh_sources': sources, 'ufw_installed': installed,
              'ssh_activation': 'socket' if socket_mode else 'service',
              'socket_reload_required': bool(socket_mode and (socket_routes != desired_routes or
                  live_routes != desired_routes or (generated_routes is not None and generated_routes != socket_routes)))}

    status, rules = None, None
    active = None
    if installed:
        def firewall_status():
            _, text = run(['ufw', 'status', 'verbose'])
            require(text.startswith(('Status: active', 'Status: inactive')), 'Unrecognized UFW status.')
            return text
        status = checks.probe('UFW installed and runtime status', firewall_status)
        if status is not None:
            active = status.startswith('Status: active')
        rules = checks.probe('existing UFW rules', lambda: added_ports(run(['ufw', 'show', 'added'])[1]))
        checks.probe('preserve managed UFW ports', lambda: require(rules <= wanted,
            'Existing managed UFW ports were removed from desired configuration.'), rules is not None and wanted is not None)
    if candidate:
        checks.probe('firewall prepared for socket activation', lambda: require(installed and active is True and status is not None and
            set(ssh_ports) <= runtime_ports(status) and set(ssh_ports) <= runtime_ports(status, ipv6=True),
            'All desired SSH ports must be allowed for IPv4 and IPv6 before socket activation.'), ssh_ports is not None)
    elif not installed:
        for name in ('/etc/systemd/system/ufw.service', '/etc/systemd/system/ufw.service.d',
                     '/run/systemd/system/ufw.service', '/run/systemd/system/ufw.service.d',
                     '/run/systemd/generator/ufw.service', '/run/systemd/generator/ufw.service.d',
                     '/etc/ufw', '/etc/default/ufw'):
            checks.probe('absent UFW orphan check ' + name, lambda name=name: require(
                not Path(name).exists() and not Path(name).is_symlink(), 'Orphan UFW configuration or custom unit detected.'))
        checks.convergence('UFW installed', False, verify, 'UFW is missing; harden can install it.')
    else:
        base = {name: checks.probe('UFW base file ' + name, lambda name=name: fingerprint(Path(name)))
                for index, name in enumerate(PROTECTED, 1)}
        hashes = {name: checks.probe('UFW raw rules file ' + name, lambda name=name: fingerprint(Path(name)))
                  for index, name in enumerate(RULE_FILES, 1)}
        snapshot = {'base': base, 'rules': hashes}
        def marker():
            if not safe_file(STATE, 'Unsafe UFW ownership marker.', optional=True):
                return False
            previous = json.loads(STATE.read_text())
            require(isinstance(previous, dict) and set(previous) == {'base', 'rules'} and
                    isinstance(previous['base'], dict) and isinstance(previous['rules'], dict), 'Unsafe UFW ownership marker.')
            return previous
        previous = checks.probe('UFW ownership marker', marker)
        if isinstance(previous, dict):
            checks.probe('protected UFW base configuration', lambda: require(previous['base'] == base,
                         'Protected UFW configuration changed outside the role.'))
            checks.probe('protected raw UFW rules', lambda: require(module.params['refresh_rules'] or previous['rules'] == hashes,
                         'Raw UFW user rules changed outside the role.'))
        elif previous is False:
            checks.probe('unmanaged UFW ownership', lambda: require(not active and not rules,
                         'Existing UFW state is not owned by this role.'), active is not None and rules is not None)
            for index, name in enumerate(RULE_FILES, 1):
                def raw_rules(name=name):
                    safe_file(Path(name), 'Unexpected UFW configuration file type.', optional=True)
                    pristine_rules(Path(name))
                checks.probe('pristine raw UFW rules ' + name, raw_rules)
        def defaults():
            path = Path('/etc/default/ufw')
            safe_file(path, 'Unexpected UFW configuration file type.')
            text = path.read_text()
            require(re.search(r'^IPV6=yes$', text, re.M) is not None, 'UFW must protect IPv4 and IPv6.')
            incoming = re.findall(r'^DEFAULT_INPUT_POLICY="([A-Z]+)"$', text, re.M)
            outgoing = re.findall(r'^DEFAULT_OUTPUT_POLICY="([A-Z]+)"$', text, re.M)
            require(len(incoming) == len(outgoing) == 1, 'Ambiguous UFW default policy configuration.')
            require(incoming[0] in ('ACCEPT', 'DROP', 'REJECT') and outgoing[0] in ('ACCEPT', 'DROP', 'REJECT'),
                    'Unrecognized UFW default policy configuration.')
            return incoming[0], outgoing[0]
        policies = checks.probe('UFW IPv4/IPv6 and default policy configuration', defaults)
        def boot_enabled():
            path = Path('/etc/ufw/ufw.conf')
            safe_file(path, 'Unexpected UFW configuration file type.')
            enabled = re.findall(r'^ENABLED=(.*)$', path.read_text(), re.M)
            require(len(enabled) == 1 and enabled[0] in ('yes', 'no'), 'Malformed UFW boot configuration.')
            return enabled[0] == 'yes'
        boot = checks.probe('UFW boot configuration', boot_enabled)
        if previous is False and not any(item['status'] == 'FAIL' and
                ('UFW' in item['check'] or 'ufw.service' in item['check']) for item in checks.items):
            # Package bytes are provenance only. Adopt the safe current snapshot,
            # preserving provider files; future runs enforce its normalized hashes.
            try:
                package_result = run(['dpkg-query', '-W', '-f=${Conffiles}', 'ufw'], optional=True)
                package_files = {m[1]: m[2] for line in package_result[1].splitlines()
                                 if (m := re.fullmatch(r'\s*(/\S+) ([0-9a-f]{32})(?: obsolete)?', line))}
                identical = package_result[0] == 0 and all(
                    not Path(name).exists() or hashlib.md5(Path(name).read_bytes()).hexdigest() == package_files.get(name)
                    for name in PROTECTED)
            except (OSError, ValueError, UnicodeError):
                identical = False
            checks.convergence('UFW package baseline', identical, False,
                               'Package baseline differs or is unavailable; existing safe baseline can be adopted.')
        if policies is not None and active is not None and rules is not None and wanted is not None:
            result.update(baseline=snapshot, ufw_active=active, marker_exists=isinstance(previous, dict),
                          incoming=policies[0], outgoing=policies[1])
            checks.convergence('UFW runtime and boot enabled', isinstance(previous, dict) and active and boot is True, verify,
                               'UFW must be enabled at runtime and boot.')
            checks.convergence('UFW default policies', 'Default: deny (incoming), allow (outgoing),' in status and
                               policies == ('DROP', 'ACCEPT'), verify, 'UFW default policies do not match.')
            checks.convergence('desired UFW IPv4/IPv6 TCP rules', rules == wanted and wanted == runtime_ports(status) and
                               wanted == runtime_ports(status, ipv6=True), verify,
                               'Configured TCP ports must be allowed at runtime for IPv4 and IPv6.')

    summary = checks.result()
    if module.params.get('report_only', False):
        # Public inspection exposes only fixed diagnoses, never fingerprints,
        # adoption source paths/records or command/configuration contents.
        return summary
    if not summary['ready']:
        raise SafetyError(summary['report'] + ' Review and reconcile manually; no automatic reset/removal.')
    return result


def inspect_stream(params):
    """SSH stdin entry point: standard library only, no remote Ansible payload files."""
    import os
    import shutil
    import subprocess

    class ReadOnlyHost:
        def __init__(self):
            self.params = params

        @staticmethod
        def get_bin_path(name):
            return shutil.which(name)

        @staticmethod
        def run_command(argv, environ_update):
            environment = os.environ.copy()
            environment.update(environ_update)
            process = subprocess.run(argv, capture_output=True, text=True,
                                     env=environment, check=False)
            return process.returncode, process.stdout, process.stderr

    require(os.geteuid() == 0, 'Managed non-interactive sudo must reach root.')
    print(json.dumps(inspect(ReadOnlyHost())))


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={
        'ssh_ports': {'type': 'raw', 'required': True},
        'tcp_ports': {'type': 'raw', 'required': True},
        'verify': {'type': 'bool', 'default': False},
        'report_only': {'type': 'bool', 'default': False},
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
        message = str(error) if isinstance(error, SafetyError) else \
            'Cannot safely inspect hardening state. Review configuration manually.'
        module.fail_json(msg=message)


if __name__ == '__main__':
    main()
