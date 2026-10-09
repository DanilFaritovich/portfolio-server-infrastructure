"""Offline user/key regression fixtures; every remote probe is mocked."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
engine = types.ModuleType('user_engine')
source = (ROOT / 'library/portfolio_human_info.py').read_text().split('def main():')[0]
exec(compile(source.replace('from ansible.module_utils.basic import AnsibleModule', ''), 'human_info', 'exec'), engine.__dict__)
exec(compile((ROOT / 'scripts/user_management.py').read_text(), 'user_management', 'exec'), engine.__dict__)
runner_run_command = engine.Runner.run_command
spec = importlib.util.spec_from_file_location('management_access', ROOT / 'scripts/access.py')
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)


def key(seed):
    kind = b'ssh-ed25519'
    blob = struct.pack('>I', len(kind)) + kind + struct.pack('>I', 32) + bytes([seed]) * 32
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' fixture-' + str(seed)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.state = self.root / 'state'
        self.sudo = self.root / 'sudo'
        for directory in (self.home, self.state, self.sudo):
            directory.mkdir(mode=0o700)
        self.login_defs = self.root / 'login.defs'
        self.login_defs.write_text('# stock fixture\n')
        self.deleted = False
        for name in ('operator', 'recovery'):
            directory = self.home / name / '.ssh'
            directory.mkdir(parents=True, mode=0o700)
            (self.home / name).chmod(0o750)
            (directory / 'authorized_keys').write_text(key(1) + '\n')
            (directory / 'authorized_keys').chmod(0o600)
            record = {'name': name, 'groups': [], 'sudo': 'admin', 'commands': ['ALL'],
                      'uid': os.getuid(), 'gid': os.getgid()}
            (self.state / (name + '.json')).write_text(json.dumps(record))
            (self.state / (name + '.keys.json')).write_text(json.dumps([key(1)]))
            (self.sudo / ('portfolio-human-' + name)).write_text(name + ' ALL=(ALL:ALL) NOPASSWD: ALL\n')
        for name, value in (('HOME_ROOT', self.home), ('STATE_ROOT', self.state), ('SUDO_ROOT', self.sudo), ('LOGIN_DEFS', self.login_defs), ('USERDEL_HOOKS', ())):
            mocked = patch.object(engine, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        for mocked in (patch.object(engine, 'safe'), patch.object(engine, 'inspect'), patch.object(engine, 'ssh_sources', return_value=[]),
                       patch.object(engine.Runner, 'run_command', side_effect=self.command)):
            mocked.start()
            self.addCleanup(mocked.stop)

    def command(self, argv, **kwargs):
        if argv[0] == 'id':
            return 0, argv[-1] + '\n', ''
        if argv[0] == 'sudo':
            self.assert_sudo_argv(argv)
            return 0, '    (ALL : ALL) NOPASSWD: ALL\n', ''
        if argv[0] == '/usr/sbin/sshd':
            return 0, ('authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n'
                       'authorizedkeyscommand none\ntrustedusercakeys none\nauthorizedprincipalsfile none\n'), ''
        if argv[0] == 'pgrep':
            return 1, '', ''
        if argv[0] == '/usr/sbin/userdel':
            self.deleted = True
            return 0, '', ''
        if argv[0] == 'getent':
            return 2 if self.deleted else 0, '', ''
        self.fail('Unexpected command: ' + repr(argv))

    def assert_sudo_argv(self, argv):
        self.assertEqual(['sudo', '-n', '-l', '-U', argv[-1]], argv)

    def params(self, action, **extra):
        before = engine.read_account('operator', 'controller')[0]
        recovery = engine.read_account('recovery', 'controller')[0]
        return {'action': action, 'name': 'operator', 'controller': 'controller', 'confirmed': True,
                'token': before['token'], 'recovery_user': 'recovery', 'recovery_token': recovery['token']} | extra

    def test_add_preserves_legacy_keys_and_repeat_is_unchanged(self):
        path = self.home / 'operator/.ssh/authorized_keys'
        path.write_text('# preserved\n' + key(1) + '\n' + key(3) + '\n')
        result = engine.execute(self.params('add-user-key', key=key(2)))
        self.assertTrue(result['changed'])
        self.assertIn(key(3), path.read_text())
        self.assertEqual([True, False, True], [entry['managed'] for entry in result['keys']])
        self.assertFalse(engine.execute(self.params('add-user-key', key=key(2)))['changed'])

    def test_revoke_exact_owned_key_preserves_other_entries(self):
        engine.execute(self.params('add-user-key', key=key(2)))
        params = self.params('revoke-user-key', fingerprint=engine.fingerprint(key(1)))
        result = engine.execute(params)
        self.assertEqual([key(2)], [entry['key'] for entry in result['keys']])
        self.assertFalse(engine.execute(self.params('revoke-user-key', fingerprint=engine.fingerprint(key(1))))['changed'])

    def test_unmanaged_key_cannot_be_revoked_or_removed(self):
        path = self.home / 'operator/.ssh/authorized_keys'
        path.write_text(key(3) + '\n')
        for action, extra in (('revoke-user-key', {'fingerprint': engine.fingerprint(key(3))}), ('remove-user', {})):
            with self.assertRaises(engine.PreflightError):
                engine.execute(self.params(action, **extra))
        self.assertEqual(key(3) + '\n', path.read_text())

    def test_explicit_add_adopts_exact_legacy_key(self):
        (self.state / 'operator.keys.json').unlink()
        self.assertFalse(engine.read_account('operator', 'controller')[0]['keys'][0]['managed'])
        result = engine.execute(self.params('add-user-key', key=key(1)))
        self.assertTrue(result['keys'][0]['managed'])

    def test_failed_ledger_write_preserves_access_and_requires_explicit_registration(self):
        with patch.object(engine, 'write_ledger', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                engine.execute(self.params('add-user-key', key=key(2)))
        account = engine.read_account('operator', 'controller')[0]
        self.assertEqual([True, False], [entry['managed'] for entry in account['keys']])
        with self.assertRaises(engine.PreflightError):
            engine.execute(self.params('revoke-user-key', fingerprint=engine.fingerprint(key(2))))
        self.assertTrue(engine.execute(self.params('add-user-key', key=key(2)))['changed'])
        self.assertFalse(engine.execute(self.params('add-user-key', key=key(2)))['changed'])

    def test_two_controllers_share_server_ownership_and_preserve_each_other_keys(self):
        engine.execute(self.params('add-user-key', key=key(2)))
        result = engine.execute(self.params('add-user-key', key=key(3), controller='second_controller'))
        self.assertTrue(all(entry['managed'] for entry in result['keys']))
        result = engine.execute(self.params('revoke-user-key', fingerprint=engine.fingerprint(key(2)),
                                            controller='second_controller'))
        self.assertEqual([key(1), key(3)], [entry['key'] for entry in result['keys']])

    def test_options_and_duplicate_identity_are_not_replaced(self):
        path = self.home / 'operator/.ssh/authorized_keys'
        for content in ('restrict ' + key(1) + '\n', key(1) + '\n' + key(1) + '\n'):
            path.write_text(content)
            with self.assertRaises(engine.PreflightError):
                engine.execute(self.params('add-user-key', key=key(1)))
            self.assertEqual(content, path.read_text())

    def test_stale_target_and_recovery_proofs_block_mutation(self):
        for field in ('token', 'recovery_token'):
            with self.assertRaises(engine.PreflightError):
                engine.execute(self.params('remove-user', **{field: 'stale'}))
        self.assertFalse(self.deleted)

    def test_root_controller_and_unmanaged_accounts_are_protected(self):
        for name in ('root', 'controller'):
            with self.assertRaises(engine.PreflightError):
                engine.read_account(name, 'controller')
        with self.assertRaises(FileNotFoundError):
            engine.read_account('unknown', 'controller')

    def test_remove_retains_files_revokes_keys_sudo_and_is_idempotent(self):
        retained = self.home / 'operator/work.txt'
        retained.write_text('keep')
        result = engine.execute(self.params('remove-user'))
        self.assertTrue(result['files_preserved'])
        self.assertEqual('keep', retained.read_text())
        self.assertEqual('', (self.home / 'operator/.ssh/authorized_keys').read_text())
        self.assertFalse((self.sudo / 'portfolio-human-operator').exists())
        repeat = engine.execute({'action': 'remove-user', 'name': 'operator', 'controller': 'controller'})
        self.assertFalse(repeat['changed'])

    def test_remove_does_not_force_busy_account(self):
        with patch.object(engine.Runner, 'run_command', side_effect=lambda argv, **kw:
                          (0, '123', '') if argv[0] == 'pgrep' else self.command(argv, **kw)):
            with self.assertRaises(engine.PreflightError):
                engine.execute(self.params('remove-user'))
        self.assertFalse(self.deleted)
        self.assertTrue((self.sudo / 'portfolio-human-operator').exists())

    def test_userdel_failure_reports_partial_revocation_without_receipt(self):
        params = self.params('remove-user')
        with patch.object(engine.Runner, 'run_command', side_effect=lambda argv, **kw:
                          (1, '', '') if argv[0] == '/usr/sbin/userdel' else self.command(argv, **kw)):
            with self.assertRaisesRegex(engine.PreflightError, 'after credentials were revoked'):
                engine.execute(params)
        self.assertEqual('', (self.home / 'operator/.ssh/authorized_keys').read_text())
        self.assertFalse((self.sudo / 'portfolio-human-operator').exists())
        self.assertTrue((self.state / 'operator.json').exists())
        self.assertFalse((self.state / 'operator.removed').exists())

    def test_regular_user_keys_can_be_managed_without_granting_sudo(self):
        record = json.loads((self.state / 'operator.json').read_text())
        record.update(sudo='none', commands=[])
        (self.state / 'operator.json').write_text(json.dumps(record))
        (self.sudo / 'portfolio-human-operator').unlink()
        def denied(argv, **kwargs):
            if argv[0] == 'sudo' and argv[-1] == 'operator':
                self.assert_sudo_argv(argv)
                return 1, '', ''
            return self.command(argv, **kwargs)
        with patch.object(engine.Runner, 'run_command', side_effect=denied):
            result = engine.execute(self.params('add-user-key', key=key(2)))
        self.assertEqual('none', result['sudo'])
        self.assertFalse((self.sudo / 'portfolio-human-operator').exists())

    def test_sudo_listing_requires_success_for_admin_even_with_valid_grant_output(self):
        for rc in (1, -9):
            def failed_listing(argv, **kwargs):
                if argv[0] == 'sudo':
                    self.assert_sudo_argv(argv)
                    return rc, '(ALL : ALL) NOPASSWD: ALL\n', ''
                return self.command(argv, **kwargs)
            with patch.object(engine.Runner, 'run_command', side_effect=failed_listing):
                with self.assertRaisesRegex(engine.PreflightError, 'Cannot inspect effective sudo grants; sudo listing failed'):
                    engine.read_account('operator', 'controller')

    def test_sudo_listing_execution_errors_are_sanitized(self):
        diagnostic = 'Cannot inspect effective sudo grants; sudo listing failed.'
        for error in (OSError('private stderr detail'), subprocess.TimeoutExpired('sudo', 30)):
            def broken_listing(argv, **kwargs):
                if argv[0] == 'sudo':
                    self.assert_sudo_argv(argv)
                    raise error
                return self.command(argv, **kwargs)
            with patch.object(engine.Runner, 'run_command', side_effect=broken_listing):
                with self.assertRaises(engine.PreflightError) as raised:
                    engine.read_account('operator', 'controller')
            self.assertEqual(diagnostic, str(raised.exception))
            self.assertNotIn('private stderr detail', str(raised.exception))

    def test_sudo_grant_matching_rejects_extra_missing_and_unmanaged_entries(self):
        cases = (
            (0, '(ALL : ALL) NOPASSWD: ALL\n(root) NOPASSWD: ALL\n'),
            (0, ''),
            (0, '(root) NOPASSWD: ALL\n'),
        )
        for rc, output in cases:
            def altered_listing(argv, **kwargs):
                if argv[0] == 'sudo':
                    self.assert_sudo_argv(argv)
                    return rc, output, ''
                return self.command(argv, **kwargs)
            with patch.object(engine.Runner, 'run_command', side_effect=altered_listing):
                with self.assertRaises(engine.PreflightError):
                    engine.read_account('operator', 'controller')

    def test_regular_user_only_accepts_denied_listing_without_grants(self):
        record = json.loads((self.state / 'operator.json').read_text())
        record.update(sudo='none', commands=[])
        (self.state / 'operator.json').write_text(json.dumps(record))
        for rc, output, should_raise in ((1, '', False), (2, '', True), (1, '(root) ALL\n', True)):
            def ordinary_listing(argv, **kwargs):
                if argv[0] == 'sudo':
                    self.assert_sudo_argv(argv)
                    return rc, output, ''
                return self.command(argv, **kwargs)
            with patch.object(engine.Runner, 'run_command', side_effect=ordinary_listing):
                if should_raise:
                    with self.assertRaises(engine.PreflightError):
                        engine.read_account('operator', 'controller')
                else:
                    self.assertEqual('none', engine.read_account('operator', 'controller')[0]['sudo'])

    def test_admin_sudo_listing_uses_exact_argv_and_accepts_expected_grant(self):
        with patch.object(engine.Runner, 'run_command', side_effect=self.command) as run:
            account = engine.read_account('operator', 'controller')[0]
        run.assert_any_call(['sudo', '-n', '-l', '-U', 'operator'])
        self.assertEqual('admin', account['sudo'])
        self.assertEqual(['ALL'], account['commands'])

    def test_runner_subprocess_call_keeps_bounded_timeout(self):
        completed = subprocess.CompletedProcess(['id'], 0, '', '')
        with patch.object(engine.subprocess, 'run', return_value=completed) as run:
            self.assertEqual((0, '', ''), runner_run_command(engine.Runner({}), ['id']))
        self.assertEqual(30, run.call_args.kwargs['timeout'])
        self.assertEqual(['id'], run.call_args.args[0])

    def test_mutations_require_confirmation_and_retained_admin(self):
        for extra in ({'confirmed': False}, {'recovery_user': 'operator'}, {'recovery_user': 'controller'}):
            with self.assertRaises(engine.PreflightError):
                engine.execute(self.params('remove-user', **extra))

    def test_unmanaged_groups_and_ssh_sources_block(self):
        for command, output in (('id', 'operator docker'), ('/usr/sbin/sshd', 'authorizedkeyscommand /custom'),
                                ('sudo', '(root) NOPASSWD: ALL')):
            def altered_probe(argv, **kwargs):
                if argv[0] == 'sudo':
                    self.assert_sudo_argv(argv)
                return (0, output, '') if argv[0] == command else self.command(argv, **kwargs)
            with patch.object(engine.Runner, 'run_command', side_effect=altered_probe):
                with self.assertRaises(engine.PreflightError):
                    engine.read_account('operator', 'controller')

    def test_atomic_writer_rejects_symlink_directory(self):
        path = self.home / 'operator/.ssh'
        path.rename(self.home / 'saved')
        path.symlink_to(self.home / 'saved', target_is_directory=True)
        with self.assertRaises(OSError):
            engine.atomic_keys('operator', '', os.getuid(), os.getgid())
        self.assertEqual(key(1) + '\n', (self.home / 'saved/authorized_keys').read_text())

    def test_listing_uses_server_records_without_mutation(self):
        result = engine.execute({'action': 'list-users', 'controller': 'controller'})
        self.assertEqual(['controller', 'operator', 'recovery'], [user['name'] for user in result['users']])
        self.assertTrue(result['users'][0]['protected'])
        self.assertFalse(result['changed'])


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller_key = Path(self.temp.name) / 'controller'
        self.recovery_key = Path(self.temp.name) / 'recovery'
        for path, identity in ((Path(str(self.controller_key) + '.pub'), key(1)),
                               (Path(str(self.recovery_key) + '.pub'), key(2))):
            path.write_text(identity + '\n')
            path.chmod(0o600)
        self.key = self.controller_key
        self.inputs = {'ssh_listen_ports': [2222], 'ssh_verify_ports': [2222], 'firewall_allowed_tcp_ports': []}
        for name, kwargs in (
            ('managed_access', {'return_value': ('controller', self.key)}), ('prerequisites', {}),
            ('check_key', {}), ('known_host', {}),
            ('human_key_path', {'return_value': self.recovery_key}),
            ('load_host', {'return_value': ('portfolio', 'host.test', 2222, 'root', '/usr/bin/python3')}),
            ('hardening_inputs', {'return_value': self.inputs}),
            ('operations_probe', {'side_effect': lambda *args: self.events.append('managed-proof')}),
            ('verify_human', {'side_effect': lambda *args: self.events.append('recovery-proof')}),
            ('user_probe', {'side_effect': self.probe}),
        ):
            mocked = patch.object(access, name, **kwargs)
            mocked.start()
            self.addCleanup(mocked.stop)
        for mocked in (patch.dict(os.environ, {'HUMAN_USER': 'operator', 'RECOVERY_USER': 'recovery'}, clear=True),
                       patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.print')):
            mocked.start()
            self.addCleanup(mocked.stop)

    def probe(self, host, port, interpreter, key, controller, params):
        self.assertEqual('controller', controller)
        self.assertEqual(self.key, key)
        self.events.append('mutate' if params.get('confirmed') else 'inspect')
        return {'token': 'fresh', 'sudo': 'admin', 'groups': []}

    def test_remove_proves_recovery_before_confirmation_and_verifies_after(self):
        with patch('builtins.input', side_effect=lambda *args: self.events.append('confirm') or 'yes'):
            access.user_management('remove-user', Path('/synthetic/inventory'))
        self.assertEqual(['managed-proof', 'inspect', 'inspect', 'recovery-proof', 'confirm', 'mutate', 'managed-proof'], self.events)

    def test_existing_user_import_skips_account_role_and_never_needs_import_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / 'other-pc.pub'
            public.write_text(key(2))
            with patch.dict(os.environ, HUMAN_PUBLIC_KEY=str(public), HUMAN_SUDO='admin'), \
                    patch.object(access, 'public_key_file', return_value=public), \
                    patch.object(access, 'verify_hardening'), \
                    patch.object(access, 'user_probe', return_value={'existing': True, 'token': 'fresh'}) as probe, \
                    patch.object(access, 'run_playbook') as playbook:
                access.human_access('add-user', Path('/synthetic/inventory'))
            playbook.assert_not_called()
            self.assertEqual(['preflight-add-user', 'add-user-key'], [call.args[-1]['action'] for call in probe.call_args_list])
            self.assertEqual(key(2), probe.call_args.args[-1]['key'])
        self.assertNotIn('recovery-proof', self.events)

    def test_default_deny_and_non_tty_never_mutate(self):
        with patch('builtins.input', return_value=''):
            with self.assertRaises(ValueError):
                access.user_management('remove-user', Path('/synthetic/inventory'))
        with patch.object(access.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError):
                access.user_management('remove-user', Path('/synthetic/inventory'))
        self.assertNotIn('mutate', self.events)

    def test_copied_controller_identity_cannot_be_used_as_recovery(self):
        Path(str(self.recovery_key) + '.pub').write_text(key(1) + ' different-comment')
        with patch('builtins.input') as confirmation, self.assertRaisesRegex(ValueError, 'different SSH key identities'):
            access.user_management('remove-user', Path('/synthetic/inventory'))
        confirmation.assert_not_called()
        self.assertNotIn('recovery-proof', self.events)
        self.assertNotIn('mutate', self.events)

    def test_recovery_ssh_or_sudo_failure_never_confirms_or_mutates(self):
        for error in (ValueError('SSH failed'), subprocess.CalledProcessError(1, 'sudo')):
            with patch.object(access, 'verify_human', side_effect=error), patch('builtins.input') as confirmation:
                with self.assertRaises(type(error)):
                    access.user_management('remove-user', Path('/synthetic/inventory'))
            confirmation.assert_not_called()
        self.assertNotIn('mutate', self.events)

    def test_public_key_confirmation_escapes_terminal_controls(self):
        public = Path(self.temp.name) / 'import.pub'
        public.write_text(key(3) + ' \x1b[2J')
        public.chmod(0o600)
        with patch.dict(os.environ, HUMAN_PUBLIC_KEY=str(public)), \
                patch('builtins.input', return_value='no'), patch('builtins.print') as output:
            with self.assertRaises(ValueError):
                access.user_management('add-user-key', Path('/synthetic/inventory'))
        display = [call.args[0] for call in output.call_args_list if call.args and
                   str(call.args[0]).startswith('Public key to add:')][0]
        self.assertNotIn('\x1b', display)
        self.assertIn('\\u001b', display)
        self.assertNotIn('mutate', self.events)

    def test_read_only_command_never_mutates(self):
        access.user_management('list-users', Path('/synthetic/inventory'))
        self.assertEqual(['inspect'], self.events)

    def test_bad_fingerprint_and_protected_controller_fail_before_contact(self):
        with self.assertRaises(ValueError):
            access.user_management('revoke-user-key', Path('/synthetic/inventory'))
        with patch.dict(os.environ, HUMAN_USER='controller'):
            with self.assertRaises(ValueError):
                access.user_management('show-user', Path('/synthetic/inventory'))
        self.assertEqual([], self.events)

    def test_failed_mutation_stops_without_retry(self):
        def failure(*args):
            params = args[-1]
            if params.get('confirmed'):
                self.events.append('mutate')
                raise ValueError('incomplete')
            return {'token': 'fresh', 'sudo': 'admin', 'groups': []}
        with patch.object(access, 'user_probe', side_effect=failure), patch('builtins.input', return_value='yes'):
            with self.assertRaises(ValueError):
                access.user_management('remove-user', Path('/synthetic/inventory'))
        self.assertEqual(1, self.events.count('mutate'))
        self.assertEqual(1, self.events.count('managed-proof'))


class SafetySurfaceTests(unittest.TestCase):
    def test_recovery_verification_selects_only_the_requested_agent_identity(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        selected = Path(temporary.name) / 'recovery'
        selected.touch(mode=0o600)
        managed = {'ansible_user': 'controller', 'ansible_ssh_args': access.SSH_BASE +
                   ' -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none'
                   ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                   ' -o KbdInteractiveAuthentication=no'}
        with patch.object(access, 'check_key'), patch.object(access, 'public_key_file'), \
                patch.object(access, 'run_playbook') as playbook:
            access.verify_human(Path('/synthetic/inventory'), 'portfolio', 'host.test', 2222,
                                managed, {'ssh_verify_ports': [2222, 2223]},
                                {'human_access_user_name': 'recovery', 'human_access_user_sudo': 'admin'},
                                selected)
        for call in playbook.call_args_list:
            connection = call.args[2]
            # OpenSSH -G parses local options only; no network or private-key reads.
            result = subprocess.run(['ssh', '-G', *shlex.split(connection['ansible_ssh_args']),
                                     '-i', connection['ansible_private_key_file'], '-p', str(connection['ansible_port']),
                                     'recovery@host.test'], capture_output=True, text=True, check=True)
            settings = result.stdout.splitlines()
            self.assertEqual(['identityfile ' + str(selected)],
                             [line for line in settings if line.startswith('identityfile ')])
            for setting in ('identitiesonly yes', 'forwardagent no', 'clearallforwardings yes',
                            'passwordauthentication no', 'kbdinteractiveauthentication no',
                            'stricthostkeychecking true', 'hostkeyalias [host.test]:2222'):
                self.assertIn(setting, settings)
            self.assertNotIn('identityagent none', settings)

    def test_make_commands_forward_selected_inputs_without_host_contact(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / 'bin').mkdir()
            python = directory / 'bin/python'
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" "$HUMAN_USER" "$HUMAN_PUBLIC_KEY" "$KEY_FINGERPRINT" "$RECOVERY_USER" "$RECOVERY_KEY"\n')
            python.chmod(0o700)
            for mode in access.USER_MANAGEMENT_MODES:
                result = subprocess.run(['make', '--no-print-directory', '-s', '-f', str(ROOT / 'Makefile'), mode,
                                         'VENV=' + str(directory), 'INVENTORY=/synthetic/inventory',
                                         'HUMAN_USER=operator', 'HUMAN_PUBLIC_KEY=/synthetic/other PC.pub',
                                         'KEY_FINGERPRINT=SHA256:fixture', 'RECOVERY_USER=recovery',
                                         'RECOVERY_KEY=/synthetic/recovery'], cwd=ROOT,
                                        capture_output=True, text=True, check=True)
                self.assertIn(mode, result.stdout.splitlines())
                self.assertIn('/synthetic/other PC.pub', result.stdout.splitlines())
                self.assertIn('SHA256:fixture', result.stdout.splitlines())
                self.assertIn('/synthetic/recovery', result.stdout.splitlines())

    def test_stream_transport_is_strict_and_payload_has_no_ansible_dependency(self):
        import subprocess
        with patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess(
                [], 0, '{"ready": true, "result": {"changed": false}}', '')) as run:
            access.user_probe('host.test', 2222, '/usr/bin/python3', Path('/synthetic/controller'),
                              'controller', {'action': 'list-users'})
        command = run.call_args.args[0]
        self.assertIn('controller@host.test', command)
        for option in ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'IdentitiesOnly=yes',
                       'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'ControlMaster=no'):
            self.assertIn(option, command)
        self.assertEqual('sudo -n /usr/bin/python3 -I -B -', command[-1])
        payload = run.call_args.kwargs['input']
        self.assertNotIn('from ansible', payload)
        compile(payload, 'stream', 'exec')

    def test_ssh_match_unsupported_include_and_pending_activation_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / 'sshd_config'
            includes = root / 'sshd_config.d'
            includes.mkdir()
            pending = root / 'pending'
            with patch.object(engine, 'SSH_MAIN', main), patch.object(engine, 'SSH_INCLUDES', includes), \
                    patch.object(engine, 'SSH_PENDING', pending), patch.object(engine, 'safe'):
                for content in ('Match User operator\n', 'Include /unmanaged/*.conf\n'):
                    main.write_text(content)
                    with self.assertRaises(engine.PreflightError):
                        engine.ssh_sources()
                main.write_text('PubkeyAuthentication yes\n')
                self.assertTrue(engine.ssh_sources())
                pending.write_text('{}')
                with self.assertRaises(engine.PreflightError):
                    engine.ssh_sources()

    def test_key_comment_quotes_do_not_change_fingerprint(self):
        self.assertEqual(engine.fingerprint(key(1)), engine.fingerprint(key(1) + ' unbalanced"comment'))
