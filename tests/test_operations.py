"""Offline Stage 5 regression fixtures; never execute remote or host probes."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


info = load('operations_info', 'library/portfolio_operations_info.py')
access = load('operations_access', 'scripts/access.py')

SECURE_APT_DUMP = '''Dir "/";
Dir::Etc "etc/apt";
Dir::Etc::Parts "apt.conf.d";
Dir::Etc::Main "apt.conf";
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
'''


class OperationsInspectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.write('/etc/logrotate.conf', 'weekly\nrotate 4\ninclude /etc/logrotate.d\n')
        self.write('/etc/os-release', 'ID=ubuntu\nVERSION_CODENAME=noble\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION="24.04 LTS (Noble Numbat)"\n')
        self.write('/proc/meminfo', 'MemTotal: 1024000 kB\nMemAvailable: 512000 kB\nSwapTotal: 512000 kB\nSwapFree: 512000 kB\n')
        self.write('/etc/docker/daemon.json', json.dumps({'log-driver': 'local', 'log-opts': {'max-size': '20m', 'max-file': '5'}}))
        self.write(info.APT, (ROOT / 'roles/server_operations/templates/apt-security.j2').read_text())
        self.write(info.JOURNAL, '# Managed by portfolio server_operations\n[Journal]\nSystemMaxUse=256M\nRuntimeMaxUse=64M\nSystemKeepFree=512M\nMaxRetentionSec=14day\nCompress=yes\n')
        for path in ('/var/log', '/var/lib/docker'):
            (self.root / path.lstrip('/')).mkdir(parents=True, exist_ok=True)
        self.overrides = {}
        self.glob_paths = [info.APT, info.JOURNAL]
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(info, 'Path', side_effect=lambda path: self.root / str(path).lstrip('/')))
        self.stack.enter_context(patch.object(info.glob, 'glob', side_effect=lambda pattern: [p for p in self.glob_paths if p.startswith(pattern.split('*')[0])]))
        real_lstat = Path.lstat

        def fixture_lstat(path, *args, **kwargs):
            if path == self.root or self.root in path.parents:
                metadata = real_lstat(path, *args, **kwargs)
                return os.stat_result((metadata.st_mode, metadata.st_ino, metadata.st_dev,
                                       metadata.st_nlink, 0, 0, metadata.st_size,
                                       metadata.st_atime, metadata.st_mtime, metadata.st_ctime))
            if path in self.root.parents:
                metadata = real_lstat(path, *args, **kwargs)
                return os.stat_result((stat.S_IFDIR | 0o755, metadata.st_ino,
                                       metadata.st_dev, metadata.st_nlink, 0, 0,
                                       metadata.st_size, metadata.st_atime,
                                       metadata.st_mtime, metadata.st_ctime))
            return real_lstat(path, *args, **kwargs)

        self.stack.enter_context(patch.object(Path, 'lstat', fixture_lstat))
        self.real_command = info.command
        self.stack.enter_context(patch.object(info, 'command', side_effect=self.command))
        self.stack.enter_context(patch.object(info.os, 'getloadavg', return_value=(0.1, 0.1, 0.1)))
        self.stack.enter_context(patch.object(info.shutil, 'disk_usage', return_value=SimpleNamespace(total=10 * 1024**3, free=5 * 1024**3)))
        self.stack.enter_context(patch.object(info.os, 'statvfs', return_value=SimpleNamespace(f_favail=100, f_files=200)))

    def write(self, path, text):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def test_release_classifier_requires_consistent_supported_ubuntu_metadata(self):
        stable = {'ID': 'ubuntu', 'VERSION_CODENAME': 'noble', 'VERSION_ID': '24.04',
                  'PRETTY_NAME': 'Ubuntu 24.04 LTS', 'VERSION': '24.04 LTS (Noble Numbat)'}
        self.assertEqual(info.ubuntu_release_type(stable), 'stable')
        self.assertEqual(info.ubuntu_release_type({**stable, 'VERSION_CODENAME': 'jammy'}), 'unknown')
        self.assertEqual(info.ubuntu_release_type({**stable, 'ID': 'debian'}), 'unknown')
        self.assertEqual(info.ubuntu_release_type({**stable, 'VERSION': '24.04 LTS (development branch)'}), 'development')
        self.assertEqual(info.ubuntu_release_type(stable, {'DISTRIB_ID': 'Ubuntu', 'DISTRIB_RELEASE': '22.04'}), 'unknown')
        self.assertEqual(info.ubuntu_release_type(stable, {'DISTRIB_DESCRIPTION': 'Ubuntu noble development branch'}), 'development')

    def test_devrelease_valid_values_and_development_semantics(self):
        for setting in ('auto', 'false', 'true'):
            with self.subTest(setting=setting):
                values = info.apt_values(SECURE_APT_DUMP)
                values['unattended-upgrade::devrelease'] = [setting]
                self.assertEqual(info.apt_conflicts(values, 'stable'), [])
                dump = SECURE_APT_DUMP.replace('DevRelease "auto"', 'DevRelease "%s"' % setting)
                self.overrides[('apt-config', 'dump')] = (0, dump)
                self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, dump)
                for verify in (False, True):
                    result = info.inspect(verify)
                    self.assertTrue(result['ready'], result['report'])
        values = info.apt_values(SECURE_APT_DUMP)
        values['unattended-upgrade::devrelease'] = ['false']
        self.assertEqual(info.apt_conflicts(values, 'development'), [])
        for setting in ('auto', 'true'):
            values['unattended-upgrade::devrelease'] = [setting]
            self.assertIn('unattended-upgrade::devrelease', info.apt_conflicts(values, 'development'))
        for release_type in ('development', 'unknown'):
            self.assertIn('unattended-upgrade::devrelease', info.apt_conflicts({}, release_type))
        values = info.apt_values(SECURE_APT_DUMP)
        values['unattended-upgrade::devrelease::nested'] = ['false']
        self.assertIn('unattended-upgrade::devrelease::nested', info.apt_conflicts(values, 'stable'))

    def test_invalid_devrelease_fails_current_and_candidate_without_value_leak(self):
        for invalid in ('', 'maybe', 'AUTO', 'yes', '0', 'auto ', 'SECRET_DEV_VALUE'):
            for target in (('apt-config', 'dump'), ('apt-config', '-c', '/dev/stdin', 'dump')):
                with self.subTest(value=invalid, target=target):
                    self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP)
                    self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, SECURE_APT_DUMP)
                    malformed = 'Unattended-Upgrade::DevRelease "%s";\n' % invalid
                    bad_dump = SECURE_APT_DUMP.replace('Unattended-Upgrade::DevRelease "auto";\n', malformed)
                    self.overrides[target] = (0, bad_dump)
                    for verify in (False, True):
                        result = info.inspect(verify)
                        self.assertFalse(result['ready'])
                        self.assertIn('unattended-upgrade::devrelease', result['report'])
                        self.assertNotIn(malformed.strip(), result['report'])
                        self.assertNotIn('SECRET_DEV_VALUE', result['report'])

    def test_development_release_blocks_all_inspection_modes(self):
        self.write('/etc/os-release', 'ID=ubuntu\nVERSION_CODENAME=noble\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION="24.04 development branch"\n')
        for setting in ('auto', 'false', 'true'):
            dump = SECURE_APT_DUMP.replace('DevRelease "auto"', 'DevRelease "%s"' % setting)
            self.overrides[('apt-config', 'dump')] = (0, dump)
            self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, dump)
            for verify in (False, True):
                result = info.inspect(verify)
                self.assertFalse(result['ready'])
                self.assertIn('actual development', result['report'])
                if setting != 'false':
                    self.assertIn('unattended-upgrade::devrelease', result['report'])

    def test_unknown_or_inconsistent_release_blocks_all_inspection_modes(self):
        for metadata in ('ID=ubuntu\nVERSION_CODENAME=noble\nVERSION_ID=22.04\n',
                         'ID=debian\nVERSION_CODENAME=noble\nVERSION_ID=24.04\n',
                         'ID=ubuntu\nVERSION_CODENAME=noble\n'):
            self.write('/etc/os-release', metadata)
            for setting in ('auto', 'false', 'true'):
                dump = SECURE_APT_DUMP.replace('DevRelease "auto"', 'DevRelease "%s"' % setting)
                self.overrides[('apt-config', 'dump')] = (0, dump)
                self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, dump)
                for verify in (False, True):
                    self.assertFalse(info.inspect(verify)['ready'])

    def test_lsb_development_or_conflicting_metadata_blocks_stable_os_release(self):
        for description, version in (('Ubuntu Noble (development branch)', '24.04'),
                                     ('Ubuntu 22.04 LTS', '22.04')):
            self.write('/etc/lsb-release', 'DISTRIB_ID=Ubuntu\nDISTRIB_CODENAME=noble\nDISTRIB_RELEASE=%s\nDISTRIB_DESCRIPTION="%s"\n' % (version, description))
            for verify in (False, True):
                self.assertFalse(info.inspect(verify)['ready'])

    def test_candidate_replay_preserves_devrelease_order_and_main_override(self):
        early = ('/etc/apt/apt.conf.d/10early', 'Unattended-Upgrade::DevRelease "auto";')
        main = ('/etc/apt/apt.conf', 'Unattended-Upgrade::DevRelease "true";')
        candidate = info.apt_candidate([main, early])
        self.assertLess(candidate.index('DevRelease "auto"'), candidate.rindex('DevRelease "true"'))
        self.assertEqual(info.SECURITY_CONFIG, (ROOT / 'roles/server_operations/templates/apt-security.j2').read_text())
        for value in ('true', 'maybe'):
            candidate_dump = SECURE_APT_DUMP.replace('DevRelease "auto"', 'DevRelease "%s"' % value)
            self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP)
            self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, candidate_dump)
            self.write('/etc/apt/apt.conf', 'Unattended-Upgrade::DevRelease "%s";' % value)
            result = info.inspect(False)
            self.assertEqual(result['ready'], value == 'true', result['report'])
            if value == 'maybe':
                self.assertIn('unattended-upgrade::devrelease', result['report'])

    def command(self, argv, input_text=None):
        key = tuple(argv)
        if key in self.overrides:
            return self.overrides[key]
        if argv[0] == 'sshd':
            return 0, 'permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n'
        if argv[0] == 'apt-config':
            return 0, SECURE_APT_DUMP
        if argv[0] == 'dpkg-query':
            return 0, 'install ok installedinstall ok installed'
        if argv[:2] == ['systemctl', 'is-active']:
            if argv[2] in ('apt-daily.service', 'apt-daily-upgrade.service'):
                return 3, 'inactive\n'
            return 0, 'active\n'
        if argv[:2] == ['systemctl', 'is-enabled']:
            return 0, 'enabled\n'
        if argv[:2] == ['systemctl', 'show']:
            if '--value' in argv:
                return 0, 'success\n'
            return 0, 'FragmentPath=/usr/lib/systemd/system/' + argv[2] + '\nDropInPaths=\n'
        if argv[0] == 'systemd-analyze':
            return 0, 'SystemMaxUse=256M\nRuntimeMaxUse=64M\nSystemKeepFree=512M\nMaxRetentionSec=14day\nCompress=yes\n'
        if argv[:2] == ['docker', 'info']:
            return 0, '"local"\n'
        return 0, ''

    def test_converged_is_ready_without_writes(self):
        result = info.inspect(True)
        self.assertTrue(result['ready'], result['report'])

    def test_missing_policy_warns_before_setup_and_fails_verification(self):
        self.overrides[('apt-config', 'dump')] = (0, '\n'.join(line for line in SECURE_APT_DUMP.splitlines() if line.startswith('Dir')) + '\n')
        self.assertTrue(info.inspect(False)['ready'])
        self.assertFalse(info.inspect(True)['ready'])

    def test_missing_managed_paths_warn_before_setup_and_fail_verification(self):
        (self.root / info.APT.lstrip('/')).unlink()
        (self.root / info.JOURNAL.lstrip('/')).unlink()
        (self.root / 'etc/systemd/journald.conf.d').rmdir()
        result = info.inspect(False)
        self.assertTrue(result['ready'], result['report'])
        for path in (info.APT, info.JOURNAL, '/etc/systemd/journald.conf.d'):
            self.assertIn(json.dumps(path) + ': expected', result['report'])
            self.assertIn('actual absent', result['report'])
        verified = info.inspect(True)
        self.assertFalse(verified['ready'])
        self.assertNotIn('insecure', verified['report'])

    def test_managed_apt_template_in_glob_is_accepted(self):
        result = info.inspect(True)
        self.assertTrue(result['ready'], result['report'])
        self.assertIn('role marker present', result['report'])
        self.assertNotIn('99zz-portfolio-security: expected no unmanaged', result['report'])

    def test_native_apt_parser_accepts_stock_snippets_and_ignores_unrelated_dump_keys(self):
        snippets = {
            '01autoremove': '''// hash and inline comments
# ignored comment
APT::NeverAutoRemove { "^linux-image-.*"; /* block comment */ };
APT::NeverAutoRemove::Fixture/Scoped-Key "value";
APT::SomeIndependentTree { };
''',
            '50appstream': 'Acquire::IndexTargets::deb::DEP-11 { Contents-deb { MetaKey "main/dep11/Components-amd64.yml"; }; };\n',
            '50command-not-found': 'Acquire::IndexTargets::deb::Commands { Commands { MetaKey "main/cnf/Commands-amd64"; }; };\n',
            '99needrestart': 'DPkg::Post-Invoke { "if command -v needrestart >/dev/null; then needrestart -r a; fi"; };\n',
            '90renamed-stock': 'Acquire::IndexTargets::deb::DEP-11 { Fixture { MetaKey "main/dep11/file"; }; };\n',
        }
        for name, text in snippets.items():
            with self.subTest(name=name):
                path = '/etc/apt/apt.conf.d/' + name
                self.write(path, text)
                self.glob_paths.append(path)
                self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP +
                    'DPkg::Post-Invoke "unrelated shell hook";\n'
                    'Acquire::IndexTargets::deb::DEP-11::MetaKey "regex/with/slashes";\n')
                self.assertTrue(info.inspect(False)['ready'])
                self.glob_paths.remove(path)

    def test_apt_values_reads_native_dump_not_source_grammar(self):
        self.assertEqual(info.apt_values(SECURE_APT_DUMP)['apt::periodic::enable'], ['1'])
        with self.assertRaises(ValueError):
            info.apt_values('APT::Periodic { Enable "1"; };')

    def test_apt_includes_ignores_hash_comments_and_quoted_hook_but_detects_directive(self):
        self.assertFalse(info.apt_includes('# ordinary comment: #include "/ignored"\nDPkg::Post-Invoke "echo #include ignored";'))
        self.assertTrue(info.apt_includes('#include "/etc/apt/parts.conf"'))

    def test_native_apt_syntax_failure_is_reported_by_apt_config(self):
        self.overrides[('apt-config', 'dump')] = (100, '')
        self.assertFalse(info.inspect(False)['ready'])

    def test_candidate_stdin_replay_is_ordered_and_safe(self):
        before = ('/etc/apt/apt.conf.d/90before', 'APT::Periodic::AutocleanInterval "1";')
        after = ('/etc/apt/apt.conf.d/zz-after', 'APT::Periodic::Download-Upgradeable-Packages "1";')
        main = ('/etc/apt/apt.conf', 'APT::Periodic::Update-Package-Lists "1";')
        candidate = info.apt_candidate([after, main, before])
        self.assertLess(candidate.index('AutocleanInterval'), candidate.index(info.APT))
        self.assertLess(candidate.index(info.APT), candidate.index('Download-Upgradeable-Packages'))
        self.assertGreater(candidate.rindex('APT::Periodic::Update-Package-Lists'), candidate.index('Download-Upgradeable-Packages'))
        with patch.dict(info.os.environ, {'APT_CONFIG': '/opaque/untrusted'}), patch.object(
                info.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=SECURE_APT_DUMP)) as run:
            self.real_command(['apt-config', '-c', '/dev/stdin', 'dump'], input_text=candidate)
        self.assertEqual(run.call_args.kwargs['input'], candidate)
        self.assertNotIn('APT_CONFIG', run.call_args.kwargs['env'])
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_early_periodic_controls_converge_and_candidate_failures_are_checked(self):
        for key, value in (('AutocleanInterval', '0'), ('Download-Upgradeable-Packages', '1'), ('Update-Package-Lists', '0')):
            path = '/etc/apt/apt.conf.d/10periodic'
            self.write(path, 'APT::Periodic::%s "%s";\n' % (key, value))
            self.glob_paths.append(path)
            current = SECURE_APT_DUMP
            if key == 'Update-Package-Lists':
                current = current.replace('Update-Package-Lists "1"', 'Update-Package-Lists "0"')
            else:
                current += 'APT::Periodic::%s "%s";\n' % (key, value)
            self.overrides[('apt-config', 'dump')] = (0, current)
            self.assertTrue(info.inspect(False)['ready'])
            self.glob_paths.remove(path)
        candidate_argv = ('apt-config', '-c', '/dev/stdin', 'dump')
        for dump in (SECURE_APT_DUMP + 'Unattended-Upgrade::Unknown-Control "yes";\n',
                     SECURE_APT_DUMP.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"'),
                     SECURE_APT_DUMP + 'Unattended-Upgrade::Origins-Pattern:: "Ubuntu:noble-updates";\n',
                     SECURE_APT_DUMP.replace('APT::Periodic::Enable "1"', 'APT::Periodic::Enable "0"')):
            self.overrides[candidate_argv] = (0, dump)
            self.assertFalse(info.inspect(False)['ready'])
        self.overrides[candidate_argv] = (100, '')
        self.assertFalse(info.inspect(False)['ready'])

    def test_commented_journal_main_is_accepted_without_managed_directory(self):
        (self.root / info.JOURNAL.lstrip('/')).unlink()
        (self.root / 'etc/systemd/journald.conf.d').rmdir()
        self.write('/etc/systemd/journald.conf', '[Journal]\n# SystemMaxUse=8G\n; RuntimeMaxUse=9G\n')
        self.glob_paths.append('/etc/systemd/journald.conf')
        self.assertTrue(info.inspect(False)['ready'])

    def test_active_journal_diagnostic_hides_value(self):
        self.write('/etc/systemd/journald.conf', '[Journal]\nSystemMaxUse=8G SECRET_MARKER\n')
        self.glob_paths.append('/etc/systemd/journald.conf')
        result = info.inspect(False)
        self.assertFalse(result['ready'])
        self.assertIn('/etc/systemd/journald.conf', result['report'])
        self.assertIn('SystemMaxUse', result['report'])
        self.assertIn('line 2', result['report'])
        self.assertNotIn('8G', result['report'])
        self.assertNotIn('SECRET_MARKER', result['report'])

    def test_late_apt_policy_conflict_reports_without_values(self):
        path = '/etc/apt/apt.conf.d/zzcustom'
        self.write(path, 'APT::Periodic::Enable "SECRET_VALUE";')
        self.glob_paths.append(path)
        self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, SECURE_APT_DUMP.replace(
            'APT::Periodic::Enable "1"', 'APT::Periodic::Enable "SECRET_VALUE"'))
        result = info.inspect(False)
        self.assertFalse(result['ready'])
        report = result['report']
        self.assertIn(json.dumps(path), report)
        self.assertIn('prospective APT policy', report)
        self.assertIn('apt::periodic::enable', report)
        self.assertNotIn('SECRET_VALUE', report)

    def test_managed_group_write_is_fail_even_before_setup(self):
        target = self.root / info.APT.lstrip('/')
        target.chmod(0o664)
        result = info.inspect(False)
        self.assertFalse(result['ready'])
        self.assertIn('mode=0664', result['report'])
        self.assertIn('no symlinks or group/other write', result['report'])

    def test_dangling_managed_symlink_is_not_treated_as_absent(self):
        target = self.root / info.JOURNAL.lstrip('/')
        target.unlink()
        target.symlink_to('missing-target')
        result = info.inspect(False)
        self.assertFalse(result['ready'])
        self.assertIn('actual', result['report'])
        self.assertIn('symlink', result['report'])

    def test_nonsecurity_origins_fail_verification(self):
        self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP + 'Unattended-Upgrade::Allowed-Origins:: "Ubuntu:noble-updates";\n')
        self.assertFalse(info.inspect(True)['ready'])

    def test_automatic_reboot_fails_verification(self):
        self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"'))
        self.assertFalse(info.inspect(True)['ready'])

    def test_current_missing_security_policy_warns_preflight_and_fails_verify(self):
        current = SECURE_APT_DUMP.replace('Unattended-Upgrade::Remove-Unused-Dependencies "false";\n', '')
        self.overrides[('apt-config', 'dump')] = (0, current)
        self.assertTrue(info.inspect(False)['ready'])
        self.assertFalse(info.inspect(True)['ready'])

    def test_new_unused_dependencies_policy_current_and_prospective(self):
        flag = 'Unattended-Upgrade::Remove-New-Unused-Dependencies "false";\n'
        current_missing = SECURE_APT_DUMP.replace(flag, '')
        self.overrides[('apt-config', 'dump')] = (0, current_missing)
        self.assertTrue(info.inspect(False)['ready'])
        self.assertFalse(info.inspect(True)['ready'])

        self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP)
        self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, current_missing)
        self.assertFalse(info.inspect(False)['ready'])

        self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, SECURE_APT_DUMP)
        self.assertTrue(info.inspect(False)['ready'])
        unsafe = SECURE_APT_DUMP.replace(flag, flag.replace('"false"', '"true"'))
        for target in (('apt-config', 'dump'), ('apt-config', '-c', '/dev/stdin', 'dump')):
            with self.subTest(target=target):
                self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP)
                self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, SECURE_APT_DUMP)
                self.overrides[target] = (0, unsafe)
                self.assertFalse(info.inspect(False)['ready'])

    def test_unsafe_current_apt_keys_fail_even_if_candidate_is_secure(self):
        for unsafe in ('Unattended-Upgrade::Automatic-Reboot "true";\n',
                       'Unattended-Upgrade::Remove-Unused-Dependencies "true";\n',
                       'Unattended-Upgrade::Package-Blacklist:: "*";\n',
                       'Unattended-Upgrade::Pre-Invoke "hook";\n',
                       'Unattended-Upgrade::Unknown-Policy "value";\n'):
            self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP + unsafe)
            self.assertFalse(info.inspect(False)['ready'], unsafe)

    def test_effective_apt_unknown_controls_and_loading_fail_closed(self):
        for extra in ('APT::Periodic::Unknown-Interval "1";\n',
                      'RootDir "/opaque";\n',
                      'Dir::Etc::Parts "/opaque/uninspected";\n',
                      'Binary::apt-config::Unattended-Upgrade::Automatic-Reboot "false";\n',
                      'Acquire::AllowInsecureRepositories "true";\n',
                      'Acquire::https::Verify-Peer "false";\n'):
            with self.subTest(extra=extra):
                self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP + extra)
                self.assertFalse(info.inspect(False)['ready'])

    def test_main_file_overrides_candidate_policy_and_is_replayed_last(self):
        main = '/etc/apt/apt.conf'
        self.write(main, 'APT::Periodic::Unattended-Upgrade "0";')
        self.overrides[('apt-config', '-c', '/dev/stdin', 'dump')] = (0, SECURE_APT_DUMP.replace(
            'Unattended-Upgrade "1"', 'Unattended-Upgrade "0"'))
        self.assertFalse(info.inspect(False)['ready'])
        candidate = info.apt_candidate([(main, 'APT::Periodic::Unattended-Upgrade "0";')])
        self.assertTrue(candidate.rstrip().endswith('APT::Periodic::Unattended-Upgrade "0";'))

    def test_include_directives_block_regardless_of_fragment_name(self):
        path = '/etc/apt/apt.conf.d/50appstream'
        self.write(path, '#include "/opaque/uninspected";')
        self.glob_paths.append(path)
        self.assertFalse(info.inspect(False)['ready'])

    def test_masked_timer_blocks_preflight(self):
        self.overrides[('systemctl', 'is-enabled', 'logrotate.timer')] = (1, 'masked')
        self.assertFalse(info.inspect(False)['ready'])

    def test_unsafe_managed_path_blocks_preflight(self):
        with patch.object(info, 'path_safety', return_value=(False, 'unsafe fixture')):
            self.assertFalse(info.inspect(False)['ready'])

    def test_markerless_unmanaged_managed_destination_blocks_preflight(self):
        self.write(info.APT, 'APT::Periodic::Enable "0";\n')
        self.assertFalse(info.inspect(False)['ready'])

    def test_path_safety_rejects_unsafe_destination_metadata(self):
        path = self.root / 'fixture'
        path.write_text('safe')
        original = Path.lstat
        for uid, gid, mode in ((1, 0, 0o644), (0, 1, 0o644),
                               (0, 0, 0o664), (0, 0, 0o646)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                def fake_lstat(item, *args, **kwargs):
                    metadata = original(item, *args, **kwargs)
                    if item == path:
                        return os.stat_result((stat.S_IFREG | mode, metadata.st_ino,
                                               metadata.st_dev, metadata.st_nlink,
                                               uid, gid, metadata.st_size,
                                               metadata.st_atime, metadata.st_mtime,
                                               metadata.st_ctime))
                    return metadata
                with patch.object(Path, 'lstat', fake_lstat):
                    safe, detail = info.path_safety('/fixture')
                    self.assertFalse(safe)
                    self.assertIn('uid=%d gid=%d mode=%04o' % (uid, gid, mode), detail)

    def test_path_safety_rejects_symlink_and_missing_or_unsafe_ancestors(self):
        (self.root / 'link').symlink_to('missing-target')
        self.assertFalse(info.path_safety('/link')[0])
        self.assertTrue(info.path_safety('/missing/child')[0])
        original = Path.lstat

        def unsafe_parent(path, *args, **kwargs):
            metadata = original(path, *args, **kwargs)
            if path == self.root:
                return os.stat_result((stat.S_IFDIR | 0o777, metadata.st_ino,
                                       metadata.st_dev, metadata.st_nlink, 0, 0,
                                       metadata.st_size, metadata.st_atime,
                                       metadata.st_mtime, metadata.st_ctime))
            return metadata

        with patch.object(Path, 'lstat', unsafe_parent):
            self.assertFalse(info.path_safety('/missing/child')[0])

    def test_unbounded_logrotate_retention_blocks_setup(self):
        self.write('/etc/logrotate.conf', 'weekly\nrotate -1\n')
        self.assertFalse(info.inspect(False)['ready'])

    def test_unbounded_effective_journal_fails_verification(self):
        self.overrides[('systemd-analyze', 'cat-config', 'systemd/journald.conf')] = (0, 'SystemMaxUse=999999M')
        self.assertFalse(info.inspect(True)['ready'])

    def test_custom_apt_config_blocks_preflight(self):
        path = '/etc/apt/apt.conf.d/90custom'
        self.write(path, 'Unattended-Upgrade::Automatic-Reboot "true";')
        self.glob_paths.append(path)
        self.overrides[('apt-config', 'dump')] = (0, SECURE_APT_DUMP.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"'))
        self.assertFalse(info.inspect(False)['ready'])

    def test_unmanaged_journal_settings_block_preflight(self):
        self.write('/etc/systemd/journald.conf', '[Journal]\nSystemMaxUse=8G\n')
        self.assertFalse(info.inspect(False)['ready'])

    def test_journal_known_independent_settings_and_vendor_path_are_accepted(self):
        for path in ('/usr/lib/systemd/journald.conf.d/syslog.conf', '/run/systemd/journald.conf.d/renamed.conf'):
            self.write(path, '[Journal]\nForwardToSyslog=yes\n')
            self.glob_paths.append(path)
            self.assertTrue(info.inspect(False)['ready'])
            self.glob_paths.remove(path)

    def test_journal_unknown_invalid_retention_and_unsafe_vendor_metadata_fail(self):
        path = '/usr/lib/systemd/journald.conf.d/renamed.conf'
        for content in ('[Journal]\nUnknownSetting=yes\n', '[Journal]\nForwardToSyslog=maybe\n',
                        '[Journal]\nSystemMaxUse=8G\n', '[Journal]\nMaxRetentionSec=1day\n',
                        '[Journal]\nCompress=yes\n'):
            self.write(path, content)
            self.glob_paths.append(path)
            self.assertFalse(info.inspect(False)['ready'], content)
            self.glob_paths.remove(path)
        target = self.root / path.lstrip('/')
        target.chmod(0o664)
        self.glob_paths.append(path)
        self.assertFalse(info.inspect(False)['ready'])
        self.glob_paths.remove(path)
        target.chmod(0o644)
        target.unlink()
        target.symlink_to('missing-target')
        self.glob_paths.append(path)
        self.assertFalse(info.inspect(False)['ready'])

    def test_failed_docker_blocks_setup(self):
        self.overrides[('systemctl', 'is-active', 'docker.service')] = (3, 'failed')
        self.assertFalse(info.inspect(False)['ready'])

    def test_stage4_password_policy_is_required(self):
        self.overrides[('sshd', '-T')] = (0, 'passwordauthentication yes\n')
        self.assertFalse(info.inspect(False)['ready'])

    def test_running_upgrade_blocks_policy_transition(self):
        self.overrides[('systemctl', 'is-active', 'apt-daily-upgrade.service')] = (0, 'active')
        self.assertFalse(info.inspect(False)['ready'])

    def test_custom_timer_dropin_blocks_setup(self):
        self.overrides[('systemctl', 'show', 'apt-daily.timer', '--property=FragmentPath,DropInPaths', '--no-pager')] = (0, 'FragmentPath=/usr/lib/systemd/system/apt-daily.timer\nDropInPaths=/etc/custom.conf\n')
        self.assertFalse(info.inspect(False)['ready'])

    def test_low_disk_blocks_setup(self):
        with patch.object(info.shutil, 'disk_usage', return_value=SimpleNamespace(total=1024**3, free=1024)):
            self.assertFalse(info.inspect(False)['ready'])

    def test_container_logging_override_is_blocker(self):
        self.overrides[('docker', 'ps', '-aq')] = (0, 'abcdef123456\n')
        self.overrides[('docker', 'inspect', '--format', '{{json .HostConfig.LogConfig}}', 'abcdef123456')] = (0, '{"Type":"json-file","Config":{}}')
        self.assertFalse(info.inspect(False)['ready'])

    def test_errors_do_not_expose_captured_output(self):
        with patch.object(info, 'inspect', side_effect=ValueError('SENSITIVE')):
            self.assertNotIn('SENSITIVE', info.safe_inspect()['report'])


class OperationsWrapperTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ('prerequisites', 'check_key', 'known_host'):
            self.stack.enter_context(patch.object(access, name))
        self.stack.enter_context(patch.object(access, 'managed_access', return_value=('ansible', Path('/opaque-key'))))
        self.stack.enter_context(patch.object(access, 'load_host', return_value=('fixture', 'fixture.example.test', 2222, 'root', '/usr/bin/python3')))
        self.stack.enter_context(patch.object(access, 'hardening_inputs', return_value={'ssh_listen_ports': [2222], 'firewall_allowed_tcp_ports': [80, 443]}))
        self.real_probe = access.operations_probe
        self.probe = self.stack.enter_context(patch.object(access, 'operations_probe'))
        self.playbook = self.stack.enter_context(patch.object(access, 'run_playbook'))
        self.stack.enter_context(patch('builtins.print'))

    def test_read_only_modes_never_run_playbook(self):
        for mode in ('inspect-operations', 'verify-operations'):
            access.operations(mode, Path('/fixture'), Path('/opaque-key'))
        self.playbook.assert_not_called()

    def test_confirmation_default_deny(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value=''):
            with self.assertRaises(ValueError):
                access.operations('setup-operations', Path('/fixture'), Path('/opaque-key'))
        self.playbook.assert_not_called()

    def test_noninteractive_setup_denied(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError):
                access.operations('setup-operations', Path('/fixture'), Path('/opaque-key'))
        self.playbook.assert_not_called()

    def test_failed_preflight_never_mutates(self):
        self.probe.side_effect = ValueError('blocked')
        with self.assertRaises(ValueError):
            access.operations('setup-operations', Path('/fixture'), Path('/opaque-key'))
        self.playbook.assert_not_called()

    def test_confirmed_setup_passes_explicit_consent(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'):
            access.operations('setup-operations', Path('/fixture'), Path('/opaque-key'))
        self.assertTrue(self.playbook.call_args.args[2]['server_operations_confirmed'])
        self.assertEqual(self.playbook.call_args.args[3], 'setup-operations.yml')

    def test_stream_payload_and_transport_are_read_only(self):
        result = {'ready': True, 'report': 'PASS'}
        with patch.object(access.subprocess, 'run', side_effect=[SimpleNamespace(returncode=0, stdout='ansible'), SimpleNamespace(returncode=0, stdout=json.dumps(result))]) as run:
            self.real_probe('fixture.example.test', 2222, '/usr/bin/python3', Path('/opaque-key'), 'portfolio_operations_info.py', {'verify': True}, 'ansible')
        self.assertEqual(run.call_count, 2)
        call = run.call_args
        self.assertIn('sudo -n /usr/bin/python3 -I -B -', call.args[0])
        self.assertIn('StrictHostKeyChecking=yes', call.args[0])
        self.assertIn('PasswordAuthentication=no', call.args[0])
        self.assertNotIn('ansible.module_utils.basic import', call.kwargs['input'].split('def main():')[0])

    def test_role_has_no_unconditional_restart_or_upgrade(self):
        tasks = yaml.safe_load((ROOT / 'roles/server_operations/tasks/main.yml').read_text())
        modules = [task for task in tasks if 'ansible.builtin.apt' in task]
        self.assertEqual(modules[0]['ansible.builtin.apt']['state'], 'present')
        self.assertNotIn('update_cache', modules[0]['ansible.builtin.apt'])
        self.assertLess(next(i for i, t in enumerate(tasks) if 'portfolio_operations_info' in t), next(i for i, t in enumerate(tasks) if 'ansible.builtin.apt' in t))
        self.assertFalse(any(t.get('ansible.builtin.systemd_service', {}).get('state') == 'restarted' for t in tasks))
        template = (ROOT / 'roles/server_operations/templates/apt-security.j2').read_text()
        self.assertEqual(template, info.SECURITY_CONFIG)


if __name__ == '__main__':
    unittest.main()
