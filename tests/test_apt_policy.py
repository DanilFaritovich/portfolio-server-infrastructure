"""Offline regression tests for the narrowly scoped APT policy repair."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.loader import init_plugin_loader
from ansible.template import Templar

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load('apt_policy_guard', 'library/portfolio_apt_policy.py')
access = load('apt_policy_access', 'scripts/access.py')
RUN_PLAYBOOK = access.run_playbook
TEMPLATE = (ROOT / 'roles/server_operations/templates/apt-security.j2').read_bytes()
DIRECTIVE = guard.DIRECTIVE.encode()


class FakeAnsibleModule:
    def __init__(self, path, candidate=TEMPLATE, check_mode=False, confirmed=False):
        self.params = {'candidate': candidate.decode(), 'confirmed': confirmed}
        self.check_mode = check_mode
        self.moves = []
        self.path = path

    def atomic_move(self, source, destination, unsafe_writes=False):
        self.moves.append((source, destination, unsafe_writes))
        os.replace(source, destination)


class AptPolicyGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'policy'
        self.path.write_bytes(TEMPLATE.replace(DIRECTIVE, b'', 1))
        self.path.chmod(0o644)
        self.metadata = {}
        real_lstat = Path.lstat

        def synthetic_lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            if path == self.path:
                uid, gid, mode, nlink = self.metadata.get(path, (0, 0, result.st_mode, result.st_nlink))
                return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid,
                                       st_nlink=nlink, st_size=result.st_size,
                                       st_dev=result.st_dev, st_ino=result.st_ino)
            if path in self.path.parents:
                uid, gid, mode, nlink = self.metadata.get(path, (0, 0, stat.S_IFDIR | 0o755, result.st_nlink))
                return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid,
                                       st_nlink=nlink, st_size=result.st_size,
                                       st_dev=result.st_dev, st_ino=result.st_ino)
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                                   st_nlink=result.st_nlink, st_size=result.st_size,
                                   st_dev=result.st_dev, st_ino=result.st_ino)

        self.patch = patch.object(guard.Path, 'lstat', synthetic_lstat)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(guard, 'DESTINATION', str(self.path)))
        self.fchown = self.stack.enter_context(patch.object(guard.os, 'fchown'))

    def invoke(self, candidate=None, check=False, confirmed=False):
        module = FakeAnsibleModule(self.path, candidate or TEMPLATE, check, confirmed)
        result = guard.repair(module)
        return module, result

    def test_preview_reports_only_directive_and_converged_is_unchanged(self):
        with patch.object(guard.tempfile, 'mkstemp') as mkstemp:
            module, result = self.invoke(check=True)
        mkstemp.assert_not_called()
        self.assertTrue(result['changed'])
        self.assertEqual(result['diff']['after'], guard.DIRECTIVE)
        self.assertEqual(result['diff']['before'], '')
        self.assertEqual(module.moves, [])
        self.assertEqual(list(self.path.parent.glob('.portfolio-apt-*')), [])
        self.path.write_bytes(TEMPLATE)
        _, result = self.invoke(check=True)
        self.assertEqual(result, {'changed': False})

    def test_confirmed_replacement_is_atomic_and_preserves_metadata(self):
        module, result = self.invoke(confirmed=True)
        self.assertTrue(result['changed'])
        self.assertEqual(self.path.read_bytes(), TEMPLATE)
        self.assertEqual(len(module.moves), 1)
        self.assertEqual(module.moves[0][1:], (str(self.path), False))
        self.assertEqual(self.fchown.call_args.args[1:], (0, 0))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)
        self.assertEqual(self.invoke(confirmed=True)[1], {'changed': False})

    def test_confirmed_replacement_ignores_atime_changes_during_read(self):
        lstat = guard.Path.lstat
        calls = 0

        def changing_atime(path, *args, **kwargs):
            nonlocal calls
            result = lstat(path, *args, **kwargs)
            if path == self.path:
                calls += 1
                return SimpleNamespace(**{
                    **vars(result),
                    'st_atime': calls,
                    'st_atime_ns': calls * 1_000_000_000,
                })
            return result

        with patch.object(guard.Path, 'lstat', changing_atime):
            module, result = self.invoke(confirmed=True)

        self.assertGreaterEqual(calls, 3)
        self.assertTrue(result['changed'])
        self.assertEqual(module.moves[0][1:], (str(self.path), False))
        self.assertEqual(self.path.read_bytes(), TEMPLATE)

    def test_unconfirmed_and_wider_template_drift_block_before_write(self):
        with self.assertRaisesRegex(ValueError, 'not confirmed'):
            self.invoke()
        cases = {
            'missing another line': TEMPLATE.replace(b'APT::Periodic::Enable', b'# missing', 1),
            'altered known value': TEMPLATE.replace(b'"false"', b'"true"', 1),
            'added unrelated line': TEMPLATE + b'Added::Setting "true";\n',
        }
        approved_drift = TEMPLATE.replace(DIRECTIVE, b'', 1)
        for description, destination in cases.items():
            for check, confirmed in ((True, False), (False, True)):
                with self.subTest(drift=description, check=check):
                    self.path.write_bytes(destination)
                    self.path.chmod(0o644)
                    with patch.object(guard.tempfile, 'mkstemp') as mkstemp:
                        with self.assertRaisesRegex(ValueError, 'wider than the one approved line'):
                            self.invoke(check=check, confirmed=confirmed)
                    mkstemp.assert_not_called()
                    self.assertEqual(self.path.read_bytes(), destination)
        self.path.write_bytes(approved_drift)

    def test_unsafe_metadata_and_absent_or_symlink_destination_block(self):
        for field, value in [('uid', 1000), ('gid', 1000), ('mode', stat.S_IFREG | 0o600), ('nlink', 2)]:
            with self.subTest(field=field):
                uid, gid, mode, nlink = self.metadata.get(self.path, (0, 0, stat.S_IFREG | 0o644, 1))
                values = {'uid': uid, 'gid': gid, 'mode': mode, 'nlink': nlink}
                values[field] = value
                self.metadata[self.path] = (values['uid'], values['gid'], values['mode'], values['nlink'])
                with self.assertRaises(ValueError):
                    self.invoke(check=True)
                self.metadata.clear()
        self.path.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.invoke(check=True)
        target = self.path.with_name('target')
        target.write_bytes(TEMPLATE)
        self.path.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.invoke(check=True)

    def test_oversized_and_parent_hardening_block(self):
        self.path.write_bytes(b'x' * 65537)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.invoke(check=True)
        self.path.write_bytes(TEMPLATE.replace(DIRECTIVE, b'', 1))
        self.path.chmod(0o644)
        parent = self.path.parent
        self.metadata[parent] = (0, 0, stat.S_IFDIR | 0o777, 1)
        with self.assertRaises(ValueError):
            self.invoke(check=True)

    def test_inode_snapshot_content_change_and_lock_contention_block(self):
        original_read = self.path.read_bytes
        with patch.object(guard.Path, 'read_bytes', lambda path: b'changed' if path == self.path else original_read()):
            with self.assertRaises(ValueError):
                self.invoke(confirmed=True)
        with patch.object(guard.fcntl, 'flock', side_effect=BlockingIOError):
            with self.assertRaises(BlockingIOError):
                self.invoke(check=True)
        self.assertEqual(list(self.path.parent.glob('.portfolio-apt-*')), [])

    def test_inode_replacement_during_preflight_blocks_before_write(self):
        lstat = guard.Path.lstat
        seen = 0

        def swapped(path, *args, **kwargs):
            nonlocal seen
            value = lstat(path, *args, **kwargs)
            if path == self.path:
                seen += 1
                if seen >= 2:
                    return SimpleNamespace(**{**vars(value), 'st_ino': value.st_ino + 1})
            return value

        with patch.object(guard.Path, 'lstat', swapped), self.assertRaisesRegex(ValueError, 'changed during preflight'):
            self.invoke(check=True)


class AptPolicyWrapperTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ('prerequisites', 'check_key', 'known_host'):
            self.stack.enter_context(patch.object(access, name))
        self.stack.enter_context(patch.object(access, 'managed_access', return_value=('automation', Path('/synthetic/key'))))
        self.stack.enter_context(patch.object(access, 'load_host', return_value=('fixture', 'example.test', 2222, 'root', '/usr/bin/python3')))
        self.stack.enter_context(patch.object(access, 'hardening_inputs', return_value={'ssh_listen_ports': [2222], 'firewall_allowed_tcp_ports': [80, 443]}))
        self.probe = self.stack.enter_context(patch.object(access, 'operations_probe'))
        self.playbook = self.stack.enter_context(patch.object(access, 'run_playbook'))
        self.stack.enter_context(patch('builtins.print'))

    def test_preview_uses_check_diff_without_confirmation_or_apply_verification(self):
        access.operations('preview-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        args, kwargs = self.playbook.call_args
        self.assertEqual(args[3], 'apt-policy.yml')
        self.assertTrue(kwargs['check'])
        self.assertTrue(kwargs['diff'])
        self.assertFalse(args[2]['portfolio_apt_confirmed'])
        self.assertEqual(self.probe.call_count, 2)

    def test_apply_confirmation_is_default_deny_and_tty_required(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
            access.operations('apply-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='n'), self.assertRaises(ValueError):
            access.operations('apply-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        self.playbook.assert_not_called()

    def test_confirmed_apply_runs_once_then_existing_operations_verification(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'):
            access.operations('apply-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        self.assertEqual(self.playbook.call_count, 1)
        self.assertEqual(self.playbook.call_args.args[3], 'apt-policy.yml')
        self.assertTrue(self.playbook.call_args.args[2]['portfolio_apt_confirmed'])
        self.assertEqual(self.probe.call_count, 3)
        self.assertTrue(self.probe.call_args.args[5]['verify'])

    def test_preflight_and_apply_or_postverification_failure_stop_without_retry(self):
        self.probe.side_effect = ValueError('offline fixture failure')
        with self.assertRaises(ValueError):
            access.operations('preview-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        self.playbook.assert_not_called()
        self.probe.side_effect = None
        self.playbook.side_effect = subprocess.CalledProcessError(1, ['ansible-playbook'])
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'):
            with self.assertRaisesRegex(ValueError, 'STOP'):
                access.operations('apply-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        self.assertEqual(self.playbook.call_count, 1)

    def test_post_apply_verification_failure_stops_without_retry(self):
        self.probe.side_effect = [None, None, ValueError('verification fixture failure')]
        with patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'):
            with self.assertRaisesRegex(ValueError, 'STOP'):
                access.operations('apply-apt-policy', Path('/synthetic/inventory'), Path('/synthetic/key'))
        self.assertEqual(self.playbook.call_count, 1)
        self.assertEqual(self.probe.call_count, 3)

    def test_run_playbook_forwards_check_and_diff_with_mocked_subprocess(self):
        runner = SimpleNamespace(run=unittest.mock.Mock())
        with patch.object(access, 'subprocess', runner):
            RUN_PLAYBOOK(Path('/synthetic/inventory'), 'fixture', {'ansible_user': 'automation', 'safe_input': True}, 'apt-policy.yml', check=True, diff=True)
        self.assertEqual(runner.run.call_count, 1)
        command = runner.run.call_args.args[0]
        self.assertIn('--check', command)
        self.assertIn('--diff', command)
        self.assertEqual(runner.run.call_args.kwargs['check'], True)

    def test_playbook_has_only_guarded_policy_change_and_make_syntax_target(self):
        playbook = yaml.safe_load((ROOT / 'playbooks/apt-policy.yml').read_text())
        serialized = json.dumps(playbook).lower()
        for forbidden in ('apt:', 'systemd_service', 'timer', 'journal', 'user:'):
            self.assertNotIn(forbidden, serialized)
        self.assertIn('playbooks/apt-policy.yml', (ROOT / 'Makefile').read_text())

    def test_template_lookup_equivalent_preserves_final_newline(self):
        init_plugin_loader()
        loader = DataLoader()
        loader.set_basedir(str(ROOT / 'playbooks'))
        templar = Templar(loader=loader, variables={})
        expression = "{{ lookup('ansible.builtin.template', '../roles/server_operations/templates/apt-security.j2') }}"
        rendered = templar.template(expression, fail_on_undefined=True)
        self.assertIsInstance(rendered, str)
        self.assertEqual(rendered.encode('utf-8'), TEMPLATE)
        self.assertTrue(TEMPLATE.endswith(b'\n'))


if __name__ == '__main__':
    unittest.main()
