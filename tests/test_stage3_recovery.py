"""Regression tests for authorized recovery and file trust, entirely offline."""

import json
import multiprocessing
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_hardening as fixtures

access, adoption, info = fixtures.access, fixtures.adoption, fixtures.info


class Stage3RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.host = fixtures.HardeningTests(methodName='runTest')
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)

    @staticmethod
    def raw_rules(ipv6=False, ports=()):
        prefix, address = ('ufw6', '::/0') if ipv6 else ('ufw', '0.0.0.0/0')
        body = ''.join(
            f'\n### tuple ### allow tcp {port} {address} any {address} in '
            f'comment={info.COMMENT.encode().hex()}\n'
            f'-A {prefix}-user-input -p tcp --dport {port} -j ACCEPT\n' for port in ports)
        return (f'*filter\n:{prefix}-user-input - [0:0]\n### RULES ###\n' + body +
                '\n### END RULES ###\nCOMMIT\n')

    def prepared(self, committed=()):
        fake = self.host.inspection_fixture(managed=True, active=False)
        fake.params.update(verify=False, report_only=False)
        for ipv6, name in enumerate(info.RULE_FILES):
            self.host.fixture_path(name).write_text(self.raw_rules(bool(ipv6), committed))
        # The role records an exact baseline before authorizing mutations.
        with self.host.trusted_fixture_metadata():
            with patch.object(info, 'Path', side_effect=self.host.fixture_path):
                baseline = {
                    'base': {name: info.fingerprint(self.host.fixture_path(name)) for name in info.PROTECTED},
                    'rules': {name: info.fingerprint(self.host.fixture_path(name)) for name in info.RULE_FILES},
                    'recovery': {name: info.recovery_rules(self.host.fixture_path(name), {2222, 2200, 80, 443})
                                 for name in info.RULE_FILES},
                    'ports': [80, 443, 2200, 2222]}
        self.host.marker.write_text(json.dumps(baseline))
        self.host.marker.chmod(0o600)
        return fake, baseline

    def test_interrupted_ufw_additions_resume_both_families_and_remain_read_only(self):
        for v4, v6 in (([2222], []), ([2222, 2200], [2222]), ([2222, 2200], [2222, 2200])):
            with self.subTest(v4=v4, v6=v6):
                fake, baseline = self.prepared()
                for name, values in zip(info.RULE_FILES, (v4, v6)):
                    self.host.fixture_path(name).write_text(self.raw_rules(name.endswith('6.rules'), values))
                before = {p: p.read_bytes() for p in self.host.directory.rglob('*') if p.is_file()}
                resumed = self.host.inspect(fake)
                self.assertEqual(resumed['baseline']['base'], baseline['base'])
                self.assertEqual(before, {p: p.read_bytes() for p in self.host.directory.rglob('*') if p.is_file()})
                fake.params.update(verify=True, report_only=True)
                self.assertIn('Interrupted UFW transaction', self.host.inspect(fake)['report'])
                # Persist the finished snapshot, as harden does; repeat is exact.
                self.host.marker.write_text(json.dumps(resumed['baseline']))
                fake.params.update(verify=False, report_only=False)
                self.assertEqual(resumed['baseline'], self.host.inspect(fake)['baseline'])

    def test_interrupted_ufw_never_accepts_foreign_raw_drift_or_rule_removal(self):
        for change in ('raw', 'comment', 'tuple', 'action', 'port', 'family', 'footer', 'whitespace', 'remove'):
            with self.subTest(change=change):
                fake, _ = self.prepared(committed=[2222])
                text = self.raw_rules(ports=[2222, 2200])
                if change == 'raw':
                    text = text.replace('COMMIT', '-A ufw-user-input -j ACCEPT\nCOMMIT')
                elif change == 'comment':
                    text = text.replace(info.COMMENT.encode().hex(), 'foreign')
                elif change == 'tuple':
                    text = text.replace(' any ', ' 123 ')
                elif change == 'action':
                    text = text.replace('-j ACCEPT', '-j DROP')
                elif change == 'port':
                    text = self.raw_rules(ports=[2222, 12345])
                elif change == 'family':
                    text = self.raw_rules(ipv6=True, ports=[2222, 2200])
                elif change == 'footer':
                    text += '# foreign drift\n'
                elif change == 'whitespace':
                    text = text.replace('### END RULES', ' \n### END RULES')
                else:
                    text = self.raw_rules(ports=[2200])
                self.host.fixture_path(info.RULE_FILES[0]).write_text(text)
                fake.params['report_only'] = True
                report = self.host.inspect(fake)
                self.assertFalse(report['ready'], report['report'])
                self.assertIn('FAIL  protected raw UFW rules', report['report'])

    def test_policy_and_boot_interruption_keep_protected_baseline(self):
        fake, baseline = self.prepared()
        self.host.fixture_path('/etc/default/ufw').write_text(
            'IPV6=yes\nDEFAULT_INPUT_POLICY="REJECT"\nDEFAULT_OUTPUT_POLICY="DROP"\n')
        self.host.fixture_path('/etc/ufw/ufw.conf').write_text('ENABLED=no\n')
        self.assertEqual(self.host.inspect(fake)['baseline']['base'], baseline['base'])
        self.host.fixture_path('/etc/ufw/before.rules').write_text('# foreign drift\n')
        fake.params['report_only'] = True
        self.assertIn('FAIL  protected UFW base configuration', self.host.inspect(fake)['report'])

    def test_stock_ufw_first_cli_rewrite_and_default_policy_interruption(self):
        for level in ('low', 'off'):
            for ipv6_limits in (False, True):
                with self.subTest(level=level, ipv6_limits=ipv6_limits):
                    fake = self.host.inspection_fixture(managed=False, active=False)
                    self.host.marker.unlink(missing_ok=True)
                    default = self.host.fixture_path('/etc/default/ufw')
                    default.write_text(default.read_text() + 'DEFAULT_FORWARD_POLICY="DROP"\n')
                    config = self.host.fixture_path('/etc/ufw/ufw.conf')
                    config.write_text(config.read_text() + f'LOGLEVEL={level}\n')
                    for ipv6, name in enumerate(info.RULE_FILES):
                        prefix = 'ufw6' if ipv6 else 'ufw'
                        self.host.fixture_path(name).write_text(info.stock_rule_skeleton(prefix, limits=not ipv6))
                    baseline = self.host.inspect(fake)['baseline']
                    self.host.marker.write_text(json.dumps(baseline))
                    self.host.marker.chmod(0o600)
                    self.host.added = "ufw allow 2222/tcp comment 'portfolio-host-hardening'"
                    for ipv6, name in enumerate(info.RULE_FILES):
                        prefix, address = ('ufw6', '::/0') if ipv6 else ('ufw', '0.0.0.0/0')
                        block = (f'\n### tuple ### allow tcp 2222 {address} any {address} in '
                                 f'comment={info.COMMENT.encode().hex()}\n'
                                 f'-A {prefix}-user-input -p tcp --dport 2222 -j ACCEPT\n')
                        generated = info.stock_rule_skeleton(prefix, True, ipv6_limits if ipv6 else True,
                                                             level, {'input', 'forward'})
                        self.host.fixture_path(name).write_text(generated.replace('### RULES ###\n',
                                                                               '### RULES ###\n' + block))
                    result = self.host.inspect(fake)
                    self.assertEqual(result['baseline']['recovery'][info.RULE_FILES[0]]['sha256'],
                                     baseline['recovery'][info.RULE_FILES[0]]['sha256'])
                    # Unknown scaffolding is never silently blessed as a stock rewrite.
                    path = self.host.fixture_path(info.RULE_FILES[0])
                    path.write_text(path.read_text() + '# foreign scaffold drift\n')
                    fake.params['report_only'] = True
                    self.assertIn('FAIL  protected raw UFW rules', self.host.inspect(fake)['report'])

    def test_legacy_marker_cannot_authorize_stale_raw_rules(self):
        fake, baseline = self.prepared()
        legacy = {key: baseline[key] for key in ('base', 'rules')}
        self.host.marker.write_text(json.dumps(legacy))
        self.assertIn('recovery', self.host.inspect(fake)['baseline'])
        self.host.fixture_path(info.RULE_FILES[0]).write_text(self.raw_rules(ports=[2222]))
        fake.params.update(refresh_rules=True, report_only=True)
        self.assertIn('FAIL  protected raw UFW rules', self.host.inspect(fake)['report'])

    def test_pending_adoption_blocks_preflight_and_direct_retry(self):
        fake, _ = self.prepared()
        pending = self.host.fixture_path('/etc/ssh/portfolio-adoption.pending')
        for text in ('', 'interrupted after includes', 'interrupted after main'):
            pending.write_text(text)
            fake.params['report_only'] = True
            report = self.host.inspect(fake)
            self.assertFalse(report['ready'])
            self.assertIn('Interrupted SSH adoption', report['report'])
            self.assertIn('Do not reload or retry blindly', report['report'])
            with patch.object(adoption, 'Path', side_effect=self.host.fixture_path):
                with self.assertRaisesRegex(ValueError, 'SSH adoption interrupted'):
                    adoption.adopt(Mock(params={'adoption': []}))

    def test_uncatchable_adoption_interruption_remains_fail_closed(self):
        for stop_after in (1, 2):
            with self.subTest(stop_after=stop_after):
                fake = self.host.inspection_fixture(managed=False, active=False)
                source = '/etc/ssh/sshd_config.d/50-provider.conf'
                snippet = self.host.fixture_path(source)
                snippet.parent.mkdir(parents=True, exist_ok=True)
                snippet.write_text('Port 2222\nPasswordAuthentication yes\n')
                self.host.effective = 'port 2222\npubkeyauthentication yes\n'
                with self.host.trusted_fixture_metadata(), \
                        patch.object(info, 'Path', side_effect=self.host.fixture_path), \
                        patch.object(info, 'STATE', self.host.marker), \
                        patch.object(info.glob, 'glob', return_value=[source]):
                    plan = info.inspect(fake)
                module = Mock(params={'ssh_ports': [2222, 2200], 'sources': plan['ssh_sources'],
                                      'adoption': plan['ssh_adoption']},
                              tmpdir=str(self.host.directory), check_mode=False)
                module.run_command.return_value = (0, 'port 2222\nport 2200\npubkeyauthentication yes\n', '')
                replaced = []
                def crash(src, dest):
                    os.replace(src, self.host.fixture_path(dest))
                    replaced.append(dest)
                    if len(replaced) == stop_after:
                        os._exit(77)
                module.atomic_move.side_effect = crash
                with self.host.trusted_fixture_metadata(), \
                        patch.object(adoption, 'Path', side_effect=self.host.fixture_path), \
                        patch.object(adoption.glob, 'glob', return_value=[source]):
                    process = multiprocessing.get_context('fork').Process(target=adoption.adopt, args=(module,))
                    process.start()
                    process.join(10)
                    if process.is_alive():
                        process.terminate()
                        process.join()
                    self.assertEqual(process.exitcode, 77)
                pending = self.host.fixture_path('/etc/ssh/portfolio-adoption.pending')
                self.assertTrue(pending.exists())
                self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
                self.assertNotIn('Port 2222', snippet.read_text())
                fake.params['report_only'] = True
                self.assertIn('Interrupted SSH adoption', self.host.inspect(fake)['report'])
                pending.unlink()  # Only reset this isolated synthetic host between subtests.

    def test_config_metadata_rejects_untrusted_owners_and_writable_modes(self):
        for uid, gid, mode, private in ((1000, 0, 0o644, False), (0, 1000, 0o644, False),
                                      (0, 0, 0o664, False), (0, 0, 0o646, False),
                                      (0, 0, 0o640, True), (0, 0, 0o604, True)):
            with self.subTest(uid=uid, gid=gid, mode=mode, private=private):
                path = Mock()
                path.stat.return_value = SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)
                with self.assertRaises(info.SafetyError):
                    info.trusted_metadata(path, 'Unsafe metadata.', private)
        for mode, private in ((0o644, False), (0o755, False), (0o600, True)):
            path = Mock()
            path.stat.return_value = SimpleNamespace(st_uid=0, st_gid=0, st_mode=mode)
            info.trusted_metadata(path, 'Unsafe metadata.', private)

    def test_inspector_checks_ssh_ufw_systemd_files_and_parent_permissions(self):
        for name in ('/etc/ssh/sshd_config', '/etc/ssh', '/etc/ufw/user.rules', '/etc/ufw',
                     '/etc/ufw/portfolio-hardening.json', '/usr/lib/systemd/system/ssh.service',
                     '/usr/lib/systemd/system', '/etc/systemd/system'):
            with self.subTest(name=name):
                fake = self.host.inspection_fixture()
                path = self.host.fixture_path(name)
                path.mkdir(parents=True, exist_ok=True) if not path.exists() else None
                original = path.stat().st_mode & 0o777
                path.chmod(original | 0o020)
                fake.params['report_only'] = True
                try:
                    report = self.host.inspect(fake)
                    self.assertFalse(report['ready'], report['report'])
                finally:
                    path.chmod(original)

    def test_direct_role_rejects_missing_current_probe_before_mutation(self):
        task = self.host.tasks[0]
        variables = {'ansible_port': 2222, 'ssh_listen_ports': [2222, 2200],
                     'ssh_verify_ports': [2200], 'firewall_allowed_tcp_ports': [80, 443]}
        rejected = self.host.local_ansible([task], variables)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('changed=0', rejected.stdout)
        variables['ssh_verify_ports'] = [2222]
        accepted = self.host.local_ansible([task], variables)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_current_port_is_required_in_external_probes_before_live_calls(self):
        self.host.host['ssh_verify_ports'] = [2200]
        self.host.write_inventory()
        with patch.object(access, 'run_playbook') as run:
            with self.assertRaisesRegex(Exception, 'ansible_port in ssh_verify_ports'):
                access.hardening_inputs(self.host.inventory, 'fixture', 2222)
            run.assert_not_called()
