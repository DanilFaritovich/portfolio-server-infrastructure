#!/usr/bin/python
"""Sanitized read-only operations probes; shared by SSH stdin and Ansible."""
DOCUMENTATION = r'''
---
module: portfolio_operations_info
short_description: Inspect server operations without modifying managed state
description:
  - Collect bounded diagnostics and reject unsafe operations configuration.
options:
  verify:
    description: Require converged operations configuration.
    type: bool
    default: false
'''
EXAMPLES = r'''
- name: Verify operations
  portfolio_operations_info:
    verify: true
'''
RETURN = r'''
report:
  description: Sanitized findings.
  type: str
  returned: always
ready:
  description: No blocking findings.
  type: bool
  returned: always
'''
import glob
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

MARKER = '# Managed by portfolio server_operations'
APT = '/etc/apt/apt.conf.d/99zz-portfolio-security'
JOURNAL = '/etc/systemd/journald.conf.d/99-portfolio.conf'


def command(argv, input_text=None):
    """No shells, writes, log contents or command stderr in the public result."""
    try:
        environment = dict(os.environ, LC_ALL='C')
        environment.pop('APT_CONFIG', None)
        p = subprocess.run(argv, input=input_text, capture_output=True, text=True, check=False,
                           timeout=20, env=environment)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 1, ''


def display_path(path):
    """Paths are diagnostic metadata, never raw config; escape control characters."""
    return json.dumps(str(path), ensure_ascii=True)


def path_state(path):
    p = Path(path)
    try:
        metadata = p.lstat()
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unreadable metadata'
    return metadata_state(metadata)


def metadata_state(metadata):
    kind = ('symlink' if stat.S_ISLNK(metadata.st_mode) else
            'directory' if stat.S_ISDIR(metadata.st_mode) else
            'regular file' if stat.S_ISREG(metadata.st_mode) else 'special file')
    return '%s uid=%d gid=%d mode=%04o' % (
        kind, metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))


def path_safety(path):
    """Absent destinations are safe only when every existing ancestor is safe."""
    target = Path(path)
    entries = (target, *target.parents)
    for index, entry in enumerate(entries):
        try:
            metadata = entry.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False, 'expected readable metadata; actual %s: unreadable metadata' % display_path(entry)
        safe_type = (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)) if index == 0 else stat.S_ISDIR(metadata.st_mode)
        if (not safe_type or metadata.st_uid != 0 or metadata.st_gid != 0 or
                metadata.st_mode & 0o022):
            return False, ('expected root:root regular file/directory, directory ancestors, '
                           'no symlinks or group/other write; actual %s: %s' %
                           (display_path(entry), metadata_state(metadata)))
    return True, 'expected safe root:root path; actual ' + path_state(path)


def trusted_destination(path):
    return path_safety(path)[0]


def owned_file(path):
    p = Path(path)
    return (trusted_destination(path) and p.is_file() and
            p.read_text().startswith(MARKER + '\n'))


SECURITY_CONFIG = '# Managed by portfolio server_operations\nAPT::Periodic::Enable "1";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Origins-Pattern {\n    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";\n};\nUnattended-Upgrade::Automatic-Reboot "false";\nUnattended-Upgrade::Automatic-Reboot-WithUsers "false";\nUnattended-Upgrade::Remove-Unused-Dependencies "false";\nUnattended-Upgrade::Remove-New-Unused-Dependencies "false";\nUnattended-Upgrade::Remove-Unused-Kernel-Packages "false";\n#clear Unattended-Upgrade::Automatic-Reboot-Time;\n'

def apt_includes(text):
    """Only scan include directives; native apt-config owns the complete grammar."""
    i = 0
    while i < len(text):
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end + 1
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end < 0:
                raise ValueError('Unterminated comment')
            i = end + 2
        elif text[i] == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            if i >= len(text):
                raise ValueError('Unterminated string')
            i += 1
        elif text[i] == '#':
            directive = re.match(r'#(include|clear)\b', text[i:], re.I)
            if directive and directive[1].lower() == 'include':
                return True
            if directive:
                i += len(directive[0])
            else:
                end = text.find('\n', i)
                i = len(text) if end < 0 else end + 1
        else:
            i += 1
    return False


def apt_values(dump):
    """Read native flat output, ignoring unrelated hooks/regex/list grammar."""
    result = {}
    prefixes = ('apt::periodic', 'unattended-upgrade', 'dir', 'binary::', 'acquire::', 'apt::get::allowunauthenticated', 'rootdir')
    for line in dump.splitlines():
        if not line.strip():
            continue
        key = line.split(None, 1)[0].lower()
        if not any(key.startswith(prefix) for prefix in prefixes):
            continue
        match = re.fullmatch(r'([^\s"]+) "(.*)";', line)
        if not match:
            raise ValueError('Malformed native configuration output')
        result.setdefault(key, []).append(match[2])
    return result


def ubuntu_release_type(release, lsb=None):
    """Classify local metadata without guessing the current development codename.

    unattended-upgrades uses the description's development-branch marker for
    false/true; auto may enable a development release near its release date.
    Stage 5 provisions only identifiable stable Ubuntu releases.
    """
    def value(data, key):
        return str(data.get(key, '')).strip('\"\'')

    lsb = lsb or {}
    if value(release, 'ID') != 'ubuntu':
        return 'unknown'
    descriptions = [value(release, key).lower() for key in ('VERSION', 'PRETTY_NAME')]
    descriptions.append(value(lsb, 'DISTRIB_DESCRIPTION').lower())
    if any(re.search(r'development branch|\b(alpha|beta|devel|development)\b', text)
           for text in descriptions):
        return 'development'
    supported = {'jammy': '22.04', 'noble': '24.04', 'resolute': '26.04'}
    codename = value(release, 'VERSION_CODENAME')
    version = value(release, 'VERSION_ID')
    if supported.get(codename) != version:
        return 'unknown'
    for key, expected in (('DISTRIB_ID', 'Ubuntu'), ('DISTRIB_CODENAME', codename),
                          ('DISTRIB_RELEASE', version)):
        if key in lsb and value(lsb, key) != expected:
            return 'unknown'
    return 'stable'


def apt_conflicts(values, release_type='unknown'):
    """Unknown policy keys, unsafe flags and unsupported loading cannot converge."""
    conflicts = set()
    periodic = {'enable', 'update-package-lists', 'unattended-upgrade', 'download-upgradeable-packages',
                'autocleaninterval', 'cleaninterval', 'verbose', 'randomsleep', 'minage', 'maxage', 'maxsize',
                'backuparchiveinterval', 'backuparchivelevel'}
    independent = {'minimalsteps', 'installonshutdown', 'onlyonacpower', 'skip-updates-on-metered-connections',
                   'mail', 'mailreport', 'mailonlyonerror', 'syslogenable', 'syslogfacility',
                   'debug', 'verbose', 'allow-apt-mark-fallback', 'allowed-origins', 'origins-pattern',
                   'automatic-reboot-time'}
    dangerous = {'automatic-reboot', 'automatic-reboot-withusers', 'remove-unused-dependencies',
                 'remove-unused-kernel-packages', 'remove-new-unused-dependencies'}
    for key, entries in values.items():
        value = entries[-1]
        if key.startswith('apt::periodic::'):
            suffix = key[len('apt::periodic::'):]
            interval = suffix in {'update-package-lists', 'unattended-upgrade',
                                  'download-upgradeable-packages', 'autocleaninterval',
                                  'cleaninterval', 'backuparchiveinterval'}
            if suffix not in periodic or not (re.fullmatch(r'[0-9]+', value) or
                                              (interval and value.lower() == 'always')):
                conflicts.add(key)
        elif key.startswith('unattended-upgrade::'):
            suffix = key[len('unattended-upgrade::'):]
            root = suffix.split('::', 1)[0]
            if root == 'devrelease':
                # Match the documented strings exactly: auto has a separate
                # upstream code path, so boolean aliases/case guesses are unsafe.
                if (suffix != root or value not in ('auto', 'false', 'true') or
                        release_type not in ('stable', 'development') or
                        (release_type == 'development' and value != 'false')):
                    conflicts.add(key)
            elif root in dangerous:
                if suffix != root or value.lower() not in ('false', 'no', 'off', '0'):
                    conflicts.add(key)
            elif root in ('package-blacklist', 'pre-invoke', 'post-invoke', 'package-whitelist'):
                if any(entries):
                    conflicts.add(key)
            elif root not in independent:
                conflicts.add(key)
        elif key.startswith('binary::') and any(part in key for part in ('::periodic', '::unattended-upgrade', '::dir')):
            conflicts.add(key)
        elif (key.startswith(('acquire::allowinsecure', 'acquire::allowdowngradetoinsecure')) or
              key == 'apt::get::allowunauthenticated') and value.lower() not in ('false', 'no', 'off', '0'):
            conflicts.add(key)
        elif key.startswith('acquire::') and ('::verify-peer' in key or '::verify-host' in key) and value.lower() not in ('true', 'yes', 'on', '1'):
            conflicts.add(key)
    if release_type != 'stable' and 'unattended-upgrade::devrelease' not in values:
        conflicts.add('unattended-upgrade::devrelease')
    # Native queries must describe the same sources we inspected/reconstructed.
    defaults = {'dir': ('/',), 'dir::etc': ('etc/apt', 'etc/apt/', '/etc/apt', '/etc/apt/'),
                'dir::etc::parts': ('apt.conf.d', 'apt.conf.d/', '/etc/apt/apt.conf.d', '/etc/apt/apt.conf.d/'),
                'dir::etc::main': ('apt.conf', '/etc/apt/apt.conf')}
    for key, allowed in defaults.items():
        if key not in values or values[key][-1] not in allowed:
            conflicts.add(key)
    if 'rootdir' in values and values['rootdir'][-1] not in ('', '/'):
        conflicts.add('rootdir')
    return sorted(conflicts)


def apt_security_policy(values):
    def scalar(key, expected):
        value = values.get(key, [''])[-1].lower()
        if expected == 'false':
            return value in ('false', 'no', 'off', '0')
        return value == expected
    origins = [v for k, items in values.items() for v in items if
               k.startswith(('unattended-upgrade::allowed-origins::', 'unattended-upgrade::origins-pattern::')) and v]
    return (origins == ['origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu'] and
            all(scalar('apt::periodic::' + key, '1') for key in ('enable', 'update-package-lists', 'unattended-upgrade')) and
            all(scalar('unattended-upgrade::' + key, 'false') for key in
                ('automatic-reboot', 'automatic-reboot-withusers', 'remove-unused-dependencies',
                 'remove-new-unused-dependencies', 'remove-unused-kernel-packages')))


def apt_candidate(sources):
    """Replay native source order with candidate inserted at its actual pathname.

    -c is parsed after installed configuration. Clear the protected trees before
    replay, so inherited lists cannot contaminate prospective policy. No files,
    hooks, package indexes or shell commands are executed by apt-config dump.
    """
    chunks = ['#clear APT;\n#clear Unattended-Upgrade;\n']
    fragments = sorted((path, text) for path, text in sources if path not in ('/etc/apt/apt.conf', APT))
    for path, text in sorted(fragments + [(APT, SECURITY_CONFIG)]):
        chunks.append('// source: ' + display_path(path) + '\n' + text + '\n')
    chunks.extend('// source: ' + display_path(path) + '\n' + text + '\n'
                  for path, text in sources if path == '/etc/apt/apt.conf')
    return ''.join(chunks)


JOURNAL_RETENTION = {'SystemMaxUse', 'RuntimeMaxUse', 'SystemKeepFree', 'RuntimeKeepFree',
                     'SystemMaxFileSize', 'RuntimeMaxFileSize', 'SystemMaxFiles', 'RuntimeMaxFiles',
                     'MaxRetentionSec', 'MaxFileSec', 'Compress'}
JOURNAL_BOOLEAN = {'ForwardToSyslog', 'ForwardToKMsg', 'ForwardToConsole', 'ForwardToWall',
                   'Seal', 'ReadKMsg', 'Audit'}
JOURNAL_INDEPENDENT = {'Storage', 'SplitMode', 'RateLimitIntervalSec', 'RateLimitBurst',
                       'SyncIntervalSec', 'LineMax', 'MaxLevelStore', 'MaxLevelSyslog',
                       'MaxLevelKMsg', 'MaxLevelConsole', 'MaxLevelWall', 'TTYPath'}


def journal_conflicts(text):
    """Independent system settings coexist; retention/unknown policy is not adopted."""
    conflicts = []
    section = None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line == '[Journal]':
            section = 'Journal'
            continue
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)', line)
        if not match or section != 'Journal':
            conflicts.append((number, 'unsupported statement'))
            continue
        key, value = match.groups()
        if key in JOURNAL_RETENTION:
            conflicts.append((number, key))
        elif key in JOURNAL_BOOLEAN:
            if value.lower() not in ('', 'yes', 'no', 'true', 'false', 'on', 'off', '1', '0'):
                conflicts.append((number, key))
        elif key in JOURNAL_INDEPENDENT:
            if key == 'Storage' and value not in ('', 'auto', 'persistent', 'volatile'):
                conflicts.append((number, key))
        else:
            conflicts.append((number, key))
    return conflicts


def inspect(verify=False):
    findings = []

    def add(status, message):
        findings.append((status, message))

    def probe(ok, message, missing=False):
        add('PASS' if ok else ('WARN' if missing and not verify else 'FAIL'), message)

    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    lsb = {}
    if Path('/etc/lsb-release').exists():
        lsb = dict(line.split('=', 1) for line in Path('/etc/lsb-release').read_text().splitlines() if '=' in line)
    release_type = ubuntu_release_type(release, lsb)
    probe(release_type == 'stable', 'supported stable Ubuntu release: actual ' + release_type)

    def permissions(path, label):
        ok, detail = path_safety(path)
        probe(ok, label + ' ' + display_path(path) + ': ' + detail)
        return ok

    def managed(path):
        p = Path(path)
        safe = permissions(path, 'managed configuration path safety')
        absent = path_state(path) == 'absent'
        if absent:
            probe(False, display_path(path) + ': expected managed regular file with role marker; '
                  'actual absent (setup creates it)', missing=True)
        elif safe:
            regular = p.is_file()
            marker = regular and p.read_text().startswith(MARKER + '\n')
            probe(marker, display_path(path) + ': expected managed regular file with role marker; actual ' +
                  path_state(path) + ('; role marker present' if marker else '; role marker absent'))

    for destination in (APT, JOURNAL):
        managed(destination)
    journal_directory = '/etc/systemd/journald.conf.d'
    directory_safe = permissions(journal_directory, 'managed journald directory safety')
    if path_state(journal_directory) == 'absent':
        probe(False, display_path(journal_directory) + ': expected managed directory; '
              'actual absent (setup creates it)', missing=True)
    elif directory_safe:
        probe(Path(journal_directory).is_dir(), display_path(journal_directory) +
              ': expected directory; actual ' + path_state(journal_directory))
    apt_sources = []
    for path in sorted(glob.glob('/etc/apt/apt.conf.d/*') + ['/etc/apt/apt.conf']):
        if path_state(path) == 'absent':
            continue
        p = Path(path)
        if not permissions(path, 'APT configuration permissions'):
            continue
        if not p.is_file():
            probe(False, display_path(path) + ': expected regular APT file; actual ' + path_state(path))
            continue
        text = p.read_text()
        try:
            includes = apt_includes(text)
        except ValueError:
            probe(False, display_path(path) + ': expected valid APT comments/strings; actual malformed text')
            continue
        probe(not includes, display_path(path) + ': expected no uninspected APT includes; actual ' +
              ('include directive present' if includes else 'no includes'))
        # Apply APT's documented fragment-name rules, not file-specific exceptions.
        if path == '/etc/apt/apt.conf' or (re.fullmatch(r'[A-Za-z0-9_.-]+', p.name) and
                                          ('.' not in p.name or p.name.endswith('.conf'))):
            apt_sources.append((path, text))
    paths = ['/etc/systemd/journald.conf']
    for base in ('/usr/lib', '/usr/local/lib', '/run', '/etc'):
        paths.extend(glob.glob(base + '/systemd/journald.conf.d/*.conf'))
    for path in paths:
        if path == JOURNAL or path_state(path) == 'absent':
            continue
        p = Path(path)
        if not permissions(path, 'journald configuration permissions'):
            continue
        if not p.is_file():
            probe(False, display_path(path) + ': expected regular journald file; actual ' + path_state(path))
            continue
        conflicts = journal_conflicts(p.read_text())
        locations = ['line %d %s' % (number, key) for number, key in conflicts]
        probe(not conflicts, display_path(path) + ': expected independent known settings, no unmanaged retention policy; actual ' +
              (', '.join(locations[:8]) if conflicts else 'no conflicting settings'))
    rc, ssh_policy = command(['sshd', '-T'])
    fields = dict(line.split(None, 1) for line in ssh_policy.splitlines() if ' ' in line)
    probe(rc == 0 and all(fields.get(k) == 'no' for k in
                         ('permitrootlogin', 'passwordauthentication', 'kbdinteractiveauthentication')),
          'Stage 4 final SSH policy preserved')
    rc, dump = command(['apt-config', 'dump'])
    probe(rc == 0, 'native APT syntax and effective configuration readable')
    if rc == 0:
        current = apt_values(dump)
        conflicts = apt_conflicts(current, release_type)
        probe(not conflicts, 'effective APT policy: expected safe known controls; actual ' +
              (', '.join(conflicts[:8]) if conflicts else 'no unsafe or unknown controls'))
        rc, candidate_dump = command(['apt-config', '-c', '/dev/stdin', 'dump'], input_text=apt_candidate(apt_sources))
        probe(rc == 0, 'native prospective APT configuration readable (stdin only)')
        if rc == 0:
            candidate = apt_values(candidate_dump)
            conflicts = apt_conflicts(candidate, release_type)
            probe(not conflicts and apt_security_policy(candidate),
                  'prospective APT policy: expected security-only origins, daily updates, no reboot/removal; actual ' +
                  (', '.join(conflicts[:8]) if conflicts else
                   ('converges safely' if apt_security_policy(candidate) else 'effective policy conflicts with candidate')))
        probe(apt_security_policy(current) and owned_file(APT),
              'effective security-only updates; automatic reboot/removal disabled', missing=True)
    rc, package_state = command(['dpkg-query', '-W', '-f=${Status}', 'unattended-upgrades', 'logrotate'])
    probe(rc == 0 and package_state.count('install ok installed') == 2, 'update and rotation packages installed', missing=True)
    for unit in ('apt-daily.service', 'apt-daily-upgrade.service'):
        rc, state = command(['systemctl', 'is-active', unit])
        probe(state.strip() in ('inactive', 'failed', 'unknown') and rc in (3, 4),
              unit + ' not executing during policy transition' if not verify else unit + ' idle at inspection')
    for unit in ('systemd-journald.service', 'docker.service', 'containerd.service'):
        rc, output = command(['systemctl', 'is-active', unit])
        probe(rc == 0 and output.strip() == 'active', unit + ' active')
    ssh = any(command(['systemctl', 'is-active', unit])[0] == 0
              for unit in ('ssh.service', 'ssh.socket'))
    probe(ssh, 'SSH service or socket active')
    for unit in ('apt-daily.timer', 'apt-daily-upgrade.timer', 'logrotate.timer',
                 'apt-daily.service', 'apt-daily-upgrade.service', 'logrotate.service'):
        rc, metadata = command(['systemctl', 'show', unit, '--property=FragmentPath,DropInPaths', '--no-pager'])
        entries = dict(line.split('=', 1) for line in metadata.splitlines() if '=' in line)
        fragment = entries.get('FragmentPath', '')
        probe(rc == 0 and fragment.startswith(('/lib/systemd/system/', '/usr/lib/systemd/system/')) and
              not entries.get('DropInPaths'), 'stock maintenance unit: ' + unit, missing=not fragment)
        if fragment:
            probe(fragment.startswith(('/lib/systemd/system/', '/usr/lib/systemd/system/')) and
                  not entries.get('DropInPaths'), 'maintenance unit ownership: ' + unit)
    for unit in ('apt-daily.timer', 'apt-daily-upgrade.timer', 'logrotate.timer'):
        enabled = command(['systemctl', 'is-enabled', unit])
        active = command(['systemctl', 'is-active', unit])
        probe(enabled[1].strip() != 'masked', unit + ' unmasked')
        probe(enabled[0] == 0 and enabled[1].strip() == 'enabled' and active[0] == 0,
              unit + ' enabled and active', missing=True)
    for unit in ('apt-daily.service', 'apt-daily-upgrade.service', 'logrotate.service'):
        rc, result = command(['systemctl', 'show', unit, '--property=Result', '--value'])
        probe(rc == 0 and result.strip() in ('success', ''), unit + ' last run succeeded', missing=rc != 0)
    rc, failed = command(['systemctl', '--failed', '--no-legend', '--plain', '--no-pager'])
    probe(rc == 0 and not failed.strip(), 'no failed system units')
    load = os.getloadavg()[0] / max(1, os.cpu_count() or 1)
    add('WARN' if load > 1 else 'PASS', 'CPU 1-minute load/core: %.2f' % load)
    mem = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        mem[key] = int(value.split()[0])
    available = 100 * mem['MemAvailable'] / mem['MemTotal']
    add('WARN' if available < 15 else 'PASS', 'RAM available: %.0f%%' % available)
    swap_used = 100 * (mem['SwapTotal'] - mem['SwapFree']) / max(1, mem['SwapTotal'])
    add('WARN' if not mem['SwapTotal'] or swap_used > 50 else 'PASS', 'swap used: %.0f%%; total: %d MiB' % (swap_used, mem['SwapTotal'] // 1024))
    for path in ('/', '/var', '/var/log', '/var/lib/docker'):
        if not Path(path).exists():
            probe(False, 'required filesystem path available')
            continue
        disk = shutil.disk_usage(path)
        free = disk.free / disk.total * 100
        vfs = os.statvfs(path)
        inode_free = 100 * vfs.f_favail / max(1, vfs.f_files)
        probe(free >= 10 and disk.free >= 512 * 1024**2 and inode_free >= 5,
              path + ' free: %.0f%%; inodes free: %.0f%%' % (free, inode_free))
    # Read-only debug validation; never invoke logrotate without --debug.
    rc, _ = command(['logrotate', '--debug', '/etc/logrotate.conf'])
    rotation = Path('/etc/logrotate.conf')
    probe(rc == 0, 'system logrotate configuration valid', missing=not rotation.exists())
    if rotation.exists():
        global_text = re.sub(r'#[^\n]*', '', rotation.read_text())
        includes = re.findall(r'^\s*include\s+(\S+)\s*$', global_text, re.M)
        probe(all(value == '/etc/logrotate.d' for value in includes), 'supported logrotate includes')
        rotations = re.findall(r'^\s*rotate\s+(-?[0-9]+)\s*$', global_text, re.M)
        probe(bool(rotations) and all(1 <= int(value) <= 52 for value in rotations),
              'bounded global system log retention')
        for path in glob.glob('/etc/logrotate.d/*'):
            file = Path(path)
            if not file.is_file():
                continue
            text = re.sub(r'#[^\n]*', '', file.read_text())
            probe(not re.search(r'^\s*include\s', text, re.M), 'no nested logrotate includes')
            local_rotations = re.findall(r'^\s*rotate\s+(-?[0-9]+)\s*$', text, re.M)
            probe(all(0 <= int(value) <= 52 for value in local_rotations), 'bounded logrotate entry retention')
    probe(owned_file(JOURNAL), 'managed journald retention limits', missing=True)
    rc, effective = command(['systemd-analyze', 'cat-config', 'systemd/journald.conf'])
    values = dict(re.findall(r'^\s*(SystemMaxUse|RuntimeMaxUse|SystemKeepFree|MaxRetentionSec|Compress)\s*=\s*(\S+)\s*$', effective, re.M))
    bounded = (all(re.fullmatch(r'[1-9][0-9]*M', values.get(k, '')) for k in
                   ('SystemMaxUse', 'RuntimeMaxUse', 'SystemKeepFree')) and
               re.fullmatch(r'[1-9][0-9]*day', values.get('MaxRetentionSec', '')) and values.get('Compress') == 'yes')
    limits = {'SystemMaxUse': (16, 4096), 'RuntimeMaxUse': (16, 1024),
              'SystemKeepFree': (128, 16384), 'MaxRetentionSec': (1, 90)}
    if bounded:
        bounded = all(low <= int(re.match(r'[0-9]+', values[key])[0]) <= high
                      for key, (low, high) in limits.items())
    probe(rc == 0 and bool(bounded), 'effective journald limits', missing=True)
    rc, data = command(['docker', 'info', '--format', '{{json .LoggingDriver}}'])
    probe(rc == 0 and data.strip() == '"local"', 'Docker local logging driver')
    try:
        daemon = json.loads(Path('/etc/docker/daemon.json').read_text())
        probe(daemon.get('log-driver') == 'local' and daemon.get('log-opts') == {'max-size': '20m', 'max-file': '5'},
              'Stage 2 Docker logging limits preserved')
    except (OSError, ValueError):
        probe(False, 'Docker logging configuration readable')
    rc, ids = command(['docker', 'ps', '-aq'])
    probe(rc == 0, 'container logging inventory available')
    if rc == 0:
        container_logs_ok = True
        for cid in ids.split():
            if not re.fullmatch('[0-9a-f]{12,64}', cid):
                container_logs_ok = False
                break
            rc, config = command(['docker', 'inspect', '--format', '{{json .HostConfig.LogConfig}}', cid])
            try:
                item = json.loads(config)
                container_logs_ok = container_logs_ok and rc == 0 and item.get('Type') == 'local' and item.get('Config') == {'max-size': '20m', 'max-file': '5'}
            except ValueError:
                container_logs_ok = False
        probe(container_logs_ok, 'all existing containers have bounded local logging')
    probe(not Path('/var/lib/dpkg/updates').exists() or not list(Path('/var/lib/dpkg/updates').glob('[0-9]*')),
          'no incomplete dpkg transaction')
    if Path('/var/run/reboot-required').exists():
        add('WARN', 'reboot pending; use separately confirmed make reboot-host')
    stamp = Path('/var/lib/apt/periodic/update-success-stamp')
    add('PASS' if stamp.exists() and time.time() - stamp.stat().st_mtime < 3 * 86400 else 'WARN',
        'APT package index refreshed within 3 days')
    rc, audit = command(['dpkg', '--audit'])
    probe(rc == 0 and not audit.strip(), 'dpkg package state healthy')
    upgrade_stamp = Path('/var/lib/apt/periodic/unattended-upgrades-stamp')
    add('PASS' if upgrade_stamp.exists() and time.time() - upgrade_stamp.stat().st_mtime < 3 * 86400 else 'WARN',
        'unattended-upgrades run recorded within 3 days')
    ready = not any(status == 'FAIL' for status, _ in findings)
    return {'ready': ready, 'report': 'Operations findings\n' + '\n'.join(
        status + '  ' + message for status, message in findings) + '\nResult: ' + ('READY' if ready else 'NOT READY')}


def safe_inspect(verify=False):
    try:
        return inspect(verify)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ZeroDivisionError, OverflowError):
        return {'ready': False, 'report': 'FAIL  operations inspection unavailable; review manually'}


def inspect_stream(params):
    if os.geteuid() != 0:
        raise ValueError('Root inspection required')
    print(json.dumps(safe_inspect(params.get('verify', False))))


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={'verify': {'type': 'bool', 'default': False}}, supports_check_mode=True)
    result = safe_inspect(module.params['verify'])
    if not result['ready']:
        module.fail_json(msg=result['report'], changed=False)
    module.exit_json(changed=False, **result)


if __name__ == '__main__':
    main()
