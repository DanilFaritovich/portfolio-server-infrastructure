"""Offline regression tests: synthetic inventories and mocked SSH/Ansible processes."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ansible.errors import AnsibleConnectionFailure
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader, init_plugin_loader
import paramiko
import yaml

SPEC = importlib.util.spec_from_file_location('access', Path(__file__).parents[1] / 'scripts/access.py')
access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(access)


class AccessTests(unittest.TestCase):
    def setUp(self):
        output = patch('builtins.print')
        output.start()
        self.addCleanup(output.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.inventory = self.directory / 'fixture.yml'
        self.key = self.directory / 'automation'
        self.host = {'ansible_host': 'fixture.example.test', 'ansible_port': 2222, 'ansible_user': 'root'}
        self.write_inventory()

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {'portfolio': self.host}}}}}))

    def pair(self):
        # Opaque fixture bytes, never SSH key material. No private-key reads occur.
        self.key.touch(mode=0o600)
        Path(str(self.key) + '.pub').touch(mode=0o600)

    def test_setup_preserves_existing_file(self):
        self.inventory.write_text('operator configuration')
        access.setup_inventory(self.inventory)
        self.assertEqual(self.inventory.read_text(), 'operator configuration')

    def test_setup_creates_private_inventory(self):
        self.inventory.unlink()
        with patch.object(access, 'prepare_key') as prepare, patch.object(access.subprocess, 'run') as run:
            access.setup_inventory(self.inventory)
            prepare.assert_not_called()
            run.assert_not_called()
        self.assertEqual(self.inventory.stat().st_mode & 0o777, 0o600)

    def test_bootstrap_prerequisites_without_sshpass(self):
        with patch.object(access.shutil, 'which', side_effect=lambda name: None if name == 'sshpass' else '/fixture/' + name) as which, \
                patch.object(access.Path, 'is_file', return_value=True), \
                patch.object(access.Path, 'is_dir', return_value=True):
            access.prerequisites('bootstrap')
            self.assertNotIn('sshpass', [call.args[0] for call in which.call_args_list])

    def test_default_root_and_host_validation(self):
        del self.host['ansible_user']
        self.write_inventory()
        self.assertEqual(access.load_host(self.inventory)[3], 'root')
        for value in ('vps.example.invalid', '-option', '{{ lookup("pipe", "bad") }}'):
            self.host['ansible_host'] = value
            self.write_inventory()
            with self.assertRaises(ValueError):
                access.load_host(self.inventory)

    def test_port_and_credentials_rejected(self):
        for value in (0, 65536, True, '22'):
            self.host['ansible_port'] = value
            self.write_inventory()
            with self.assertRaises(ValueError):
                access.load_host(self.inventory)
        self.host['ansible_port'] = 22
        self.host['ansible_password'] = 'synthetic forbidden value'
        self.write_inventory()
        with self.assertRaises(ValueError):
            access.load_host(self.inventory)

    def test_key_never_overwritten_and_partial_pair_fails(self):
        self.pair()
        with patch.object(access.subprocess, 'run') as run:
            access.prepare_key(self.key)
            run.assert_not_called()
            Path(str(self.key) + '.pub').unlink()
            with self.assertRaises(ValueError):
                access.prepare_key(self.key)
            run.assert_not_called()

    def test_key_creation_and_unsafe_paths(self):
        def create(command, **kwargs):
            self.assertEqual(command[command.index('-N') + 1], '')
            self.pair()
        with patch.object(access.subprocess, 'run', side_effect=create) as run:
            access.prepare_key(self.key)
            self.assertEqual(run.call_count, 1)
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            access.check_key(self.key)
        with self.assertRaises(ValueError):
            access.key_path(str(access.ROOT / 'accidental_key'))
        link = self.directory / 'link'
        link.symlink_to(self.key)
        with self.assertRaises(ValueError):
            access.key_path(str(link))

    def test_bootstrap_handoff_and_failure_stop(self):
        with patch.object(access, 'prerequisites'), patch.object(access, 'known_host'), \
                patch.object(access, 'prepare_key'), patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.object(access, 'run_playbook') as run:
            access.live('bootstrap', self.inventory, self.key)
            initial, verify = run.call_args_list
            self.assertEqual(initial.args[2]['ansible_user'], 'root')
            self.assertEqual(initial.args[2]['ansible_connection'], 'ansible.builtin.paramiko_ssh')
            self.assertTrue(initial.args[2]['ansible_paramiko_host_key_checking'])
            self.assertEqual(initial.args[2]['ansible_paramiko_private_key_file'], '')
            self.assertTrue(initial.kwargs['ask_pass'])
            self.assertTrue(initial.args[2]['bootstrap_user_allow_passwordless_sudo'])
            self.assertNotIn('ansible_become', initial.args[2])
            self.assertNotIn('ansible_private_key_file', initial.args[2])
            self.assertEqual(verify.args[2]['ansible_user'], 'ansible')
            self.assertEqual(verify.args[2]['ansible_connection'], 'ssh')
            self.assertEqual(verify.args[2]['ansible_private_key_file'], str(self.key))
            self.assertIn('BatchMode=yes', verify.args[2]['ansible_ssh_args'])
            self.assertIn('PreferredAuthentications=publickey', verify.args[2]['ansible_ssh_args'])
            self.assertIn('PasswordAuthentication=no', verify.args[2]['ansible_ssh_args'])
            self.assertIn('ControlPath=none', verify.args[2]['ansible_ssh_args'])
            self.assertNotIn('ask_pass', verify.kwargs)
            run.reset_mock()
            run.side_effect = subprocess.CalledProcessError(1, 'mocked')
            with self.assertRaises(subprocess.CalledProcessError):
                access.live('bootstrap', self.inventory, self.key)
            self.assertEqual(run.call_count, 1)

    def test_verify_never_creates_key_or_runs_role(self):
        self.pair()
        with patch.object(access, 'prerequisites'), patch.object(access, 'known_host'), \
                patch.object(access, 'prepare_key') as prepare, patch.object(access, 'run_playbook') as run:
            access.live('verify', self.inventory, self.key)
            prepare.assert_not_called()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[3], 'verify.yml')
            self.assertEqual(run.call_args.args[2]['ansible_user'], 'ansible')

    def test_ansible_command_uses_native_prompt_and_no_shell(self):
        with patch.object(access, 'prerequisites'), patch.object(access, 'known_host'), \
                patch.object(access, 'prepare_key') as prepare, patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.dict(os.environ, {'FIXTURE_MARKER': 'unchanged'}, clear=True), \
                patch.object(access.subprocess, 'run') as run:
            access.live('bootstrap', self.inventory, self.key)
            prepare.assert_called_once_with(self.key)
            initial, verify = run.call_args_list
            self.assertIn('--ask-pass', initial.args[0])
            self.assertNotIn('--ask-pass', verify.args[0])
            for call in (initial, verify):
                variables = json.loads(call.args[0][call.args[0].index('-e') + 1])
                self.assertFalse(any('password' in name or name.endswith('_pass') for name in variables
                                     if name != 'bootstrap_user_allow_passwordless_sudo'))
                self.assertNotIn('shell', call.kwargs)
                self.assertNotIn('input', call.kwargs)
            self.assertEqual(initial.kwargs['env'], {
                'FIXTURE_MARKER': 'unchanged', 'ANSIBLE_PARAMIKO_LOOK_FOR_KEYS': 'False',
                'ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD': 'False', 'ANSIBLE_PARAMIKO_RECORD_HOST_KEYS': 'False',
            })
            self.assertEqual(verify.kwargs['env'], {'FIXTURE_MARKER': 'unchanged'})
            self.assertEqual(dict(os.environ), {'FIXTURE_MARKER': 'unchanged'})

    def test_pinned_paramiko_plugin_password_and_host_key_behavior(self):
        # Simulate Ansible's in-memory prompt result; never use a real credential or network.
        init_plugin_loader()
        with patch.dict(os.environ, {'ANSIBLE_PARAMIKO_LOOK_FOR_KEYS': 'False',
                                     'ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD': 'False'}, clear=True), \
                patch.object(paramiko, 'SSHClient') as client:
            connection = connection_loader.get('ansible.builtin.paramiko_ssh', PlayContext(), io.StringIO())
            connection.set_options(var_options={
                'ansible_host': 'fixture.example.test', 'ansible_port': 2222, 'ansible_user': 'root',
                'ansible_password': 'synthetic prompt result', 'ansible_paramiko_private_key_file': '',
                'ansible_paramiko_host_key_checking': True, 'ansible_paramiko_proxy_command': '',
            })
            connection._connect_uncached()
            arguments = client.return_value.connect.call_args.kwargs
            self.assertEqual(arguments['password'], 'synthetic prompt result')
            self.assertFalse(arguments['allow_agent'])
            self.assertFalse(arguments['look_for_keys'])
            self.assertIsNone(arguments['key_filename'])
            self.assertEqual(arguments['port'], 2222)
            client.return_value.load_system_host_keys.assert_any_call()
            client.return_value.connect.side_effect = paramiko.ssh_exception.BadHostKeyException(
                'fixture.example.test', None, None)
            with self.assertRaisesRegex(AnsibleConnectionFailure, 'host key mismatch'):
                connection._connect_uncached()


class HostTrustTests(unittest.TestCase):
    # Synthetic public-only key encoding. Never generate or read private keys.
    BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.path = self.home / '.ssh/known_hosts'
        self.host = 'fixture.example.test'
        self.scan_result = subprocess.CompletedProcess([], 0, f'{self.host} ssh-ed25519 {self.BLOB}\n', '')
        original_run = subprocess.run

        def run(command, **kwargs):
            if command[0] == 'ssh-keyscan':
                return self.scan_result
            self.assertEqual(command[0], 'ssh-keygen')
            # Only offline OpenSSH lookup/fingerprint commands with synthetic public data.
            return original_run(command, **kwargs)

        for mock in (patch.object(access.Path, 'home', return_value=self.home),
                     patch.object(access.sys.stdin, 'isatty', return_value=True),
                     patch.object(access.subprocess, 'run', side_effect=run),
                     patch('builtins.input', return_value='yes'), patch('builtins.print')):
            value = mock.start()
            self.addCleanup(mock.stop)
            if mock.attribute == 'run':
                self.run = value
            elif mock.attribute == 'input':
                self.prompt = value
            elif mock.attribute == 'print':
                self.output = value

    def write_trust(self, name=None):
        self.path.parent.mkdir(mode=0o700)
        self.path.write_text(f'{name or self.host} ssh-ed25519 {self.BLOB}\n')

    def test_existing_trust_is_preserved_without_scan_or_prompt(self):
        self.write_trust()
        before = self.path.read_bytes()
        access.known_host(self.host, 22, allow_trust=True)
        self.assertEqual(self.path.read_bytes(), before)
        self.prompt.assert_not_called()
        self.assertEqual(self.run.call_count, 1)

    def test_new_host_confirmation_saves_displayed_key(self):
        access.known_host(self.host, 22, allow_trust=True)
        self.assertEqual(self.path.read_text(), f'{self.host} ssh-ed25519 {self.BLOB}\n')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        displayed = ' '.join(str(call.args) for call in self.output.call_args_list)
        for value in (self.host, 'port=22', 'ssh-ed25519', 'SHA256:', 'FIRST TRUST', 'provider'):
            self.assertIn(value, displayed)
        self.prompt.assert_called_once_with('Trust this host? [y/N] ')
        self.run.reset_mock()
        access.known_host(self.host, 22)
        self.assertEqual(self.run.call_count, 1)

    def test_rejection_and_eof_stop_before_key_or_provisioning(self):
        for answer in ('no', '', 'maybe', EOFError()):
            with self.subTest(answer=answer), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'load_host', return_value=('portfolio', self.host, 22, 'root', '/usr/bin/python3')), \
                    patch.object(access, 'prepare_key') as key, patch.object(access, 'run_playbook') as playbook:
                self.prompt.side_effect = answer if isinstance(answer, Exception) else None
                self.prompt.return_value = answer
                with self.assertRaisesRegex(ValueError, 'trust declined'):
                    access.live('bootstrap', self.home / 'fixture.yml', self.home / 'automation')
                key.assert_not_called()
                playbook.assert_not_called()
                self.assertFalse(self.path.parent.exists())

    def test_confirmation_precedes_key_generation_and_bootstrap(self):
        def prepare(path):
            self.assertTrue(self.path.exists())
            self.prompt.assert_called_once()

        with patch.object(access, 'prerequisites'), \
                patch.object(access, 'load_host', return_value=('portfolio', self.host, 22, 'root', '/usr/bin/python3')), \
                patch.object(access, 'prepare_key', side_effect=prepare) as key, \
                patch.object(access, 'run_playbook') as playbook:
            access.live('bootstrap', self.home / 'fixture.yml', self.home / 'automation')
            key.assert_called_once()
            self.assertEqual([call.args[3] for call in playbook.call_args_list], ['bootstrap.yml', 'verify.yml'])

    def test_retrieval_failures_do_not_prompt_or_write(self):
        for code, text in ((1, ''), (0, ''), (0, 'malformed'),
                           (0, f'{self.host} ssh-ed25519 not-valid-base64!\n'),
                           (0, f'{self.host} ssh-ed25519 AAAA\n')):
            with self.subTest(code=code, text=text):
                self.scan_result = subprocess.CompletedProcess([], code, text, '')
                with self.assertRaises(ValueError):
                    access.known_host(self.host, 22, allow_trust=True)
                self.prompt.assert_not_called()
                self.assertFalse(self.path.parent.exists())

    def test_scan_timeout_stops_without_trust(self):
        self.run.side_effect = subprocess.TimeoutExpired('ssh-keyscan', 60)
        with self.assertRaises(subprocess.TimeoutExpired):
            access.known_host(self.host, 22, allow_trust=True)
        self.prompt.assert_not_called()
        self.assertFalse(self.path.parent.exists())

    def test_invalid_fingerprint_stops_without_trust(self):
        original_side_effect = self.run.side_effect

        def run(command, **kwargs):
            if '-l' in command:
                return subprocess.CompletedProcess(command, 0, '256 MD5:unexpected', '')
            return original_side_effect(command, **kwargs)

        self.run.side_effect = run
        with self.assertRaisesRegex(ValueError, 'Invalid SSH fingerprint'):
            access.known_host(self.host, 22, allow_trust=True)
        self.prompt.assert_not_called()
        self.assertFalse(self.path.parent.exists())

    def test_nondefault_port_preserves_other_entries(self):
        self.write_trust('other.example.test')
        before = self.path.read_text().rstrip('\n')
        self.path.write_text(before)
        access.known_host(self.host, 2222, allow_trust=True)
        self.assertEqual(self.path.read_text(), before + f'\n[{self.host}]:2222 ssh-ed25519 {self.BLOB}\n')
        scan = next(call for call in self.run.call_args_list if call.args[0][0] == 'ssh-keyscan')
        self.assertEqual(scan.args[0], ['ssh-keyscan', '-T', '15', '-p', '2222', '-t', 'ed25519,ecdsa,rsa', self.host])
        self.run.reset_mock()
        access.known_host(self.host, 2222, allow_trust=True)
        self.assertEqual(self.run.call_count, 1)

    def test_first_trust_requires_tty_and_verify_never_offers_trust(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False):
            with self.assertRaisesRegex(ValueError, 'interactive terminal'):
                access.known_host(self.host, 22, allow_trust=True)
        with self.assertRaisesRegex(ValueError, 'not trusted'):
            access.known_host(self.host, 22)
        self.run.assert_not_called()
        self.prompt.assert_not_called()
        self.assertFalse(self.path.parent.exists())


if __name__ == '__main__':
    unittest.main()
