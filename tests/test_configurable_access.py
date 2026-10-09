"""Offline custom automation identity, migration and fail-closed regressions."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

SPEC = importlib.util.spec_from_file_location('configurable_access', Path(__file__).parents[1] / 'scripts/access.py')
access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(access)


class ConfigurableAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.inventory = self.directory / 'candidate.yml'
        self.key = self.directory / 'operator_ed25519'
        self.key.touch(mode=0o600)
        Path(str(self.key) + '.pub').touch(mode=0o600)
        self.host = {'ansible_host': 'fixture.example.test', 'ansible_port': 2222,
                     'bootstrap_login_user': 'root', 'ansible_user': 'automation',
                     'ansible_private_key_file': str(self.key)}
        self.write_inventory()
        for target in ('prerequisites', 'known_host'):
            mock = patch.object(access, target)
            mock.start()
            self.addCleanup(mock.stop)
        output = patch('builtins.print')
        output.start()
        self.addCleanup(output.stop)

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {'portfolio': self.host}}}}}))

    def test_bootstrap_separates_initial_login_and_managed_identity(self):
        self.host['bootstrap_login_user'] = 'provider_admin'
        self.write_inventory()
        with patch.object(access, 'prepare_key') as prepare, \
                patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.object(access, 'run_playbook') as run:
            access.live('bootstrap-user', self.inventory)
        prepare.assert_called_once_with(self.key)
        initial, verified = run.call_args_list
        self.assertEqual(initial.args[2]['ansible_user'], 'provider_admin')
        self.assertEqual(initial.args[2]['bootstrap_user_name'], 'automation')
        self.assertEqual(initial.args[2]['bootstrap_user_public_key_path'], str(self.key) + '.pub')
        self.assertTrue(initial.args[2]['bootstrap_user_allow_passwordless_sudo'])
        self.assertTrue(initial.kwargs['ask_become'])
        self.assertEqual(verified.args[2]['ansible_user'], 'automation')
        self.assertEqual(verified.args[2]['ansible_private_key_file'], str(self.key))
        self.assertIn('PasswordAuthentication=no', verified.args[2]['ansible_ssh_args'])

    def test_bootstrap_failed_new_access_does_not_claim_success(self):
        with patch.object(access, 'prepare_key'), patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.object(access, 'run_playbook', side_effect=[None, subprocess.CalledProcessError(1, 'mock')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                access.live('bootstrap-user', self.inventory)
        self.assertEqual([call.args[3] for call in run.call_args_list], ['bootstrap.yml', 'verify.yml'])

    def test_stage_1_to_3_and_reboot_use_inventory_identity_and_key(self):
        for mode in ('verify-access', 'docker-host', 'verify-docker', 'harden', 'verify-hardening', 'reboot-host'):
            with self.subTest(mode=mode), patch.object(access, 'run_playbook') as run, \
                    patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'), \
                    patch.object(access, 'prepare_key') as prepare:
                access.live(mode, self.inventory)
                prepare.assert_not_called()
                self.assertTrue(run.call_count)
                for call in run.call_args_list:
                    self.assertEqual(call.args[2]['ansible_user'], 'automation')
                    self.assertEqual(call.args[2]['ansible_private_key_file'], str(self.key))
                    self.assertFalse(call.kwargs.get('ask_pass', False))

    def test_stage_4_checks_selected_automation_and_admin_runtime_policy(self):
        env = {'HUMAN_USER': 'person', 'HUMAN_SUDO': 'admin', 'HUMAN_KEY': str(self.directory / 'person')}
        with patch.dict(access.os.environ, env, clear=True), patch.object(access, 'check_key'), \
                patch.object(access, 'public_key_file'), patch.object(access, 'run_playbook') as run, \
                patch.object(access, 'verify_auth_methods') as auth:
            access.human_access('verify-ssh-security', self.inventory)
        for call in run.call_args_list:
            variables = call.args[2]
            expected = 'person' if call.args[3] == 'verify-user.yml' else 'automation'
            self.assertEqual(variables['ansible_user'], expected)
            if expected == 'automation':
                self.assertEqual(variables['ansible_private_key_file'], str(self.key))
            else:
                self.assertEqual(variables['portfolio_automation_user'], 'automation')
        self.assertEqual([call.args[2] for call in auth.call_args_list], ['automation', 'person'])

    def test_add_user_imported_key_is_installed_but_remains_unverified(self):
        public_key = self.directory / 'import.pub'
        content = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfixture synthetic\n'
        public_key.write_text(content)
        probes = []

        def user_probe(host, port, interpreter, key, controller, params):
            probes.append(params)
            return {'token': 'synthetic-token'}

        env = {'HUMAN_USER': 'person', 'HUMAN_SUDO': 'admin', 'HUMAN_KEY': str(self.directory / 'person'),
               'HUMAN_PUBLIC_KEY': str(public_key)}
        with patch.dict(access.os.environ, env, clear=True), patch.object(access, 'check_key'), \
                patch.object(access, 'public_key_file', side_effect=lambda value: Path(value)), \
                patch.object(access, 'verify_hardening'), patch.object(access, 'user_probe', side_effect=user_probe), \
                patch.object(access, 'verify_human') as verify, patch.object(access, 'run_playbook') as run, \
                patch('builtins.print'):
            access.human_access('add-user', self.inventory)

        self.assertEqual([probe['action'] for probe in probes], ['preflight-add-user', 'show-user', 'add-user-key'])
        self.assertEqual(probes[2]['key'], content.strip())
        self.assertEqual(probes[2]['token'], 'synthetic-token')
        self.assertEqual(run.call_args.args[3], 'add-user.yml')
        verify.assert_not_called()

    def test_human_identity_and_groups_cannot_collide_with_selected_automation(self):
        for env in ({'HUMAN_USER': 'automation'}, {'HUMAN_USER': 'person', 'HUMAN_GROUPS': 'automation'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                access.human_inputs(env, managed_user='automation')
        self.assertEqual(access.human_inputs({'HUMAN_USER': 'ansible'}, managed_user='automation')['human_access_user_name'], 'ansible')

    def test_streamed_stages_use_inventory_identity_and_reject_other_login(self):
        for mode in ('inspect-hardening', 'inspect-operations', 'verify-operations', 'setup-operations'):
            with self.subTest(mode=mode):
                def command(argv, **kwargs):
                    self.assertIn('automation@fixture.example.test', argv)
                    self.assertEqual(argv[argv.index('-i') + 1], str(self.key))
                    output = 'automation\n' if argv[-1] == 'id -un' else json.dumps({'ready': True, 'report': 'PASS'})
                    return subprocess.CompletedProcess(argv, 0, output, '')
                with patch.object(access.subprocess, 'run', side_effect=command), \
                        patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='yes'), \
                        patch.object(access, 'run_playbook') as run:
                    if mode == 'inspect-hardening':
                        access.live(mode, self.inventory)
                    else:
                        access.operations(mode, self.inventory)
                    if mode == 'setup-operations':
                        self.assertEqual(run.call_args.args[2]['ansible_user'], 'automation')
                        self.assertEqual(run.call_args.args[2]['ansible_private_key_file'], str(self.key))
                with patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ansible\n', '')) as ssh:
                    with self.assertRaises(ValueError):
                        if mode == 'inspect-hardening':
                            access.live(mode, self.inventory)
                        else:
                            access.operations(mode, self.inventory)
                    self.assertEqual(ssh.call_count, 1)

    def test_invalid_contract_and_conflicting_key_fail_before_remote_contact(self):
        original = dict(self.host)
        cases = [{'ansible_user': 'root'}, {'ansible_user': '-option'},
                 {'ansible_private_key_file': 'relative/key'}, {'ansible_private_key_file': '{{ secret }}'},
                 {'ansible_private_key_file': '/synthetic/key%r'},
                 {'ansible_private_key_file': '/synthetic/${USER}/key'},
                 {'ansible_private_key_file': True}, {'bootstrap_login_user': '-option'}]
        for missing in ('ansible_user', 'bootstrap_login_user', 'ansible_private_key_file'):
            invalid = dict(original)
            del invalid[missing]
            cases.append(invalid)
        for invalid in cases:
            self.host = original | invalid if len(invalid) == 1 else invalid
            self.write_inventory()
            with self.subTest(invalid=invalid), patch.object(access, 'run_playbook') as run, self.assertRaises(ValueError):
                access.live('verify-access', self.inventory)
            run.assert_not_called()
        self.host = original
        self.write_inventory()
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            access.live('verify-access', self.inventory, self.directory / 'different-key')

    def test_candidate_inventory_verification_never_rewrites_old_inventory_or_accounts(self):
        old = self.directory / 'old.yml'
        old.write_text('old operator inventory')
        candidate = self.inventory.read_bytes()
        with patch.object(access, 'prepare_key') as prepare, patch.object(access, 'run_playbook') as run:
            access.live('verify-access', self.inventory)
        prepare.assert_not_called()
        self.assertEqual([call.args[3] for call in run.call_args_list], ['verify.yml'])
        self.assertEqual(self.inventory.read_bytes(), candidate)
        self.assertEqual(old.read_text(), 'old operator inventory')


if __name__ == '__main__':
    unittest.main()
