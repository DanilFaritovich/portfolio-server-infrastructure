"""Offline checks of the package path and isolated legacy imports."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_access(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/access.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


access = load_access('package_compat_access')
from portfolio_cli import cli, keys, operations, provisioning, verification


class PackageTests(unittest.TestCase):
    def test_legacy_imports_keep_mock_globals_isolated_from_package(self):
        other = load_access('other_compat_access')
        with patch.object(access, 'require', side_effect=ValueError('isolated')):
            with self.assertRaisesRegex(ValueError, 'isolated'):
                access.validate_ports([22])
            other.validate_ports([22])
        self.assertIsNot(access.validate_ports.__globals__, other.validate_ports.__globals__)
        self.assertIs(keys.key_path.__globals__, vars(keys))
        self.assertIs(provisioning.live.__globals__, vars(provisioning))
        self.assertEqual(keys.ROOT, ROOT)

    def test_legacy_context_managers_keep_mock_globals_and_cleanup(self):
        with patch.object(access, 'validate_public_key_text') as validate, \
                patch.object(access, 'public_key_file', side_effect=Path):
            with access.public_key_snapshot('public fixture\n') as path:
                self.assertEqual(path.read_text(), 'public fixture\n')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.exists())
            validate.assert_called_once_with('public fixture\n')
        with patch.object(access, 'public_key_snapshot') as snapshot, \
                patch.object(access, 'public_key_file', return_value=Path('/fixture.pub')), \
                patch.object(access, 'read_public_key', return_value='public fixture\n'), \
                patch.dict(access.os.environ, HUMAN_PUBLIC_KEY='/fixture.pub'):
            snapshot.return_value.__enter__.return_value = Path('/fixture.pub')
            with access.add_user_public_key() as public:
                self.assertEqual(public, Path('/fixture.pub'))
        snapshot.assert_called_once_with('public fixture\n')

    def test_native_dispatch_for_every_public_command(self):
        modes = {
            'setup_inventory': ('setup',),
            'server_trust': ('show-server-trust', 'copy-server-trust', 'trust-server'),
            'local_key': ('generate-user-key', 'load-user-key', 'show-public-key', 'copy-public-key'),
            'cli_connection': ('show-controller', 'connect-controller', 'connect-user'),
            'operations': ('preview-apt-policy', 'apply-apt-policy', 'inspect-operations',
                           'setup-operations', 'verify-operations'),
            'user_management': cli.USER_MANAGEMENT_MODES,
            'human_access': ('add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'),
            'live': ('bootstrap-user', 'verify-access', 'docker-host', 'verify-docker',
                     'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host'),
        }
        for handler, commands in modes.items():
            for command in commands:
                with self.subTest(command=command), \
                        patch.object(sys, 'argv', ['access.py', command, '--inventory', '/fixture.yml']), \
                        patch.object(cli.os, 'umask'), patch.object(cli, handler) as run, \
                        patch.object(cli, 'pipeline_lock', contextlib.nullcontext):
                    self.assertEqual(cli.main(), 0)
                    if handler == 'setup_inventory':
                        run.assert_called_once_with(Path('/fixture.yml'))
                    elif handler in ('server_trust',):
                        run.assert_called_once_with(command, Path('/fixture.yml'))
                    elif handler == 'local_key':
                        run.assert_called_once_with(command)
                    else:
                        run.assert_called_once_with(command, Path('/fixture.yml'), None)

    def test_legacy_pipeline_lock_keeps_mock_globals_isolated(self):
        other = load_access('other_pipeline_lock_access')
        with tempfile.TemporaryDirectory() as first_home, tempfile.TemporaryDirectory() as second_home:
            with patch.object(access, 'Path') as first_path, patch.object(other, 'Path') as second_path:
                first_path.home.return_value = Path(first_home)
                second_path.home.return_value = Path(second_home)
                with access.pipeline_lock(), other.pipeline_lock():
                    pass
            self.assertTrue((Path(first_home) / '.portfolio-infrastructure.pipeline.lock').exists())
            self.assertTrue((Path(second_home) / '.portfolio-infrastructure.pipeline.lock').exists())

    def test_native_managed_failure_stops_docker_mutation(self):
        with patch.object(provisioning, 'managed_access', return_value=('controller', Path('/fixture.key'))), \
                patch.object(provisioning, 'prerequisites'), patch.object(provisioning, 'check_key'), \
                patch.object(provisioning, 'load_host', return_value=('portfolio', 'fixture.test', 2222, 'root', '/usr/bin/python3')), \
                patch.object(provisioning, 'known_host'), \
                patch.object(provisioning, 'run_playbook', side_effect=subprocess.CalledProcessError(1, 'fixture')) as run, \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            provisioning.live('docker-host', Path('/fixture.yml'))
        self.assertEqual([call.args[3] for call in run.call_args_list], ['verify.yml'])

    def test_native_verification_uses_each_port_then_stops_on_failure(self):
        with patch.object(verification, 'run_playbook', side_effect=[None, None, subprocess.CalledProcessError(1, 'fixture')]) as run, \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            verification.verify_hardening(Path('/fixture.yml'), 'portfolio', 'fixture.test', 2222,
                                          {'ansible_ssh_args': access.SSH_BASE},
                                          {'ssh_verify_ports': [2222, 2200]})
        self.assertEqual([(call.args[2]['ansible_port'], call.args[3]) for call in run.call_args_list],
                         [(2222, 'verify.yml'), (2222, 'verify-hardening.yml'), (2200, 'verify.yml')])

    def test_native_operations_decline_stops_before_ansible(self):
        with patch.object(operations, 'managed_access', return_value=('controller', Path('/fixture.key'))), \
                patch.object(operations, 'prerequisites'), patch.object(operations, 'check_key'), \
                patch.object(operations, 'load_host', return_value=('portfolio', 'fixture.test', 2222, 'root', '/usr/bin/python3')), \
                patch.object(operations, 'hardening_inputs', return_value={'ssh_listen_ports': [2222], 'firewall_allowed_tcp_ports': []}), \
                patch.object(operations, 'known_host'), patch.object(operations, 'operations_probe', return_value={'plan': {'changes': {'/etc/apt/apt.conf.d/99zz-portfolio-security': True}, 'token': 'fixed'}}) as probe, \
                patch.object(operations, 'run_playbook') as run, patch.object(sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(ValueError, 'declined'):
            operations.operations('setup-operations', Path('/fixture.yml'))
        self.assertEqual(probe.call_count, 2)
        run.assert_not_called()

    def test_entry_point_from_another_directory_keeps_cli_and_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            help_result = subprocess.run([sys.executable, str(ROOT / 'scripts/access.py'), '--help'],
                                         cwd=directory, capture_output=True, text=True, check=False)
            invalid = subprocess.run([sys.executable, str(ROOT / 'scripts/access.py'), 'not-a-command'],
                                     cwd=directory, capture_output=True, text=True, check=False)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('never store passwords.', ' '.join(help_result.stdout.split()))
        self.assertEqual(invalid.returncode, 2)
        self.assertIn('invalid choice', invalid.stderr)
