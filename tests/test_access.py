"""Offline regression tests: synthetic inventories and mocked SSH/Ansible processes."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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
        access.setup_inventory(self.inventory)
        self.assertEqual(self.inventory.stat().st_mode & 0o777, 0o600)

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
            self.assertTrue(initial.kwargs['ask_pass'])
            self.assertTrue(initial.args[2]['bootstrap_user_allow_passwordless_sudo'])
            self.assertNotIn('ansible_become', initial.args[2])
            self.assertNotIn('ansible_private_key_file', initial.args[2])
            self.assertEqual(verify.args[2]['ansible_user'], 'ansible')
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
        with patch.object(access.subprocess, 'run') as run:
            access.run_playbook(self.inventory, 'portfolio', {'bootstrap_user_public_key_path': '/synthetic path/key.pub'},
                                'bootstrap.yml', ask_pass=True)
            command = run.call_args.args[0]
            self.assertIn('--ask-pass', command)
            self.assertNotIn('shell', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
