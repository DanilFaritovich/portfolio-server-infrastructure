"""Stage 4 regression fixtures; no live hosts, inventories or private-key reads."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import paramiko
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


access = load('human_access_wrapper', 'scripts/access.py')
security = load('ssh_security_module', 'library/portfolio_ssh_security.py')
human_info = load('human_info_module', 'library/portfolio_human_info.py')


class HumanWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.key = self.directory / 'human_ed25519'
        self.automation = self.directory / 'automation_ed25519'
        self.inventory = self.directory / 'synthetic-inventory.yml'
        self.inputs = {'ssh_listen_ports': [2222, 2200], 'ssh_verify_ports': [2222, 2200],
                       'firewall_allowed_tcp_ports': [80, 443]}
        self.env = {'HUMAN_USER': 'operator', 'HUMAN_SUDO': 'admin', 'HUMAN_KEY': str(self.key)}
        self.events = []
        for name, options in (
            ('prerequisites', {}), ('check_key', {}), ('known_host', {}),
            ('managed_access', {'return_value': ('ansible', self.automation)}),
            ('load_host', {'return_value': ('portfolio', 'fixture.example.test', 2222, 'root', '/usr/bin/python3')}),
            ('hardening_inputs', {'return_value': self.inputs}),
            ('public_key_file', {'side_effect': lambda value: Path(value)}),
            ('prepare_key', {'side_effect': lambda *a, **kw: self.events.append('generate')}),
            ('verify_hardening', {'side_effect': lambda *a: self.events.append('automation')}),
            ('verify_human', {'side_effect': lambda *a: self.events.append('human')}),
            ('verify_auth_methods', {}),
            ('run_playbook', {'side_effect': lambda *a: self.events.append(a[3])}),
        ):
            mocked = patch.object(access, name, **options)
            setattr(self, name, mocked.start())
            self.addCleanup(mocked.stop)
        for mocked in (patch.dict(os.environ, self.env, clear=True), patch('builtins.print'),
                       patch.object(access.sys.stdin, 'isatty', return_value=True)):
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_privilege_inputs_reject_sudo_injection_and_system_groups(self):
        for bad in ({'HUMAN_USER': 'root'}, {'HUMAN_USER': 'ansible'}, {'HUMAN_GROUPS': 'docker'},
                    {'HUMAN_GROUPS': 'operators,operators'}, {'HUMAN_SUDO': 'none', 'HUMAN_GROUPS': 'sudo'},
                    {'HUMAN_SUDO': 'restricted', 'HUMAN_SUDO_COMMANDS': '/bin/id,ALL'},
                    {'HUMAN_SUDO': 'restricted', 'HUMAN_SUDO_COMMANDS': '/bin/id\nroot ALL=ALL'},
                    {'HUMAN_SUDO': 'restricted', 'HUMAN_SUDO_COMMANDS': '/bin/../bin/id'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                access.human_inputs(self.env | bad)
        valid = access.human_inputs({'HUMAN_USER': 'reader', 'HUMAN_SUDO': 'restricted',
                                    'HUMAN_SUDO_COMMANDS': '/usr/bin/id', 'HUMAN_GROUPS': 'readers'})
        self.assertEqual(valid['human_access_user_sudo_commands'], ['/usr/bin/id'])

    def test_key_storage_boundary_and_separate_automation_key(self):
        with patch.object(access.Path, 'home', return_value=self.directory):
            self.assertEqual(access.human_key_path('', 'operator'),
                             self.directory / '.ssh/portfolio-infra/operator_ed25519')
        access.human_key_path(str(ROOT / 'secrets/portfolio-infra/operator_ed25519'), 'operator')
        with self.assertRaises(ValueError):
            access.human_key_path(str(ROOT / 'accidental-private'), 'operator')
        with patch.dict(os.environ, {'HUMAN_KEY': str(self.automation)}), self.assertRaises(ValueError):
            access.human_access('add-user', self.inventory, self.automation)
        self.run_playbook.assert_not_called()

    def test_add_user_preflight_creation_and_fresh_verification(self):
        access.human_access('add-user', self.inventory, self.automation)
        self.assertEqual(self.events, ['automation', 'generate', 'add-user.yml', 'human'])
        variables = self.run_playbook.call_args.args[2]
        self.assertEqual(variables['human_access_user_public_key_path'], str(self.key) + '.pub')
        self.assertNotIn('ansible_become', variables)
        self.assertEqual(variables['ansible_user'], 'ansible')

    def test_public_only_import_never_generates_or_claims_verified_access(self):
        with patch.dict(os.environ, {'HUMAN_PUBLIC_KEY': str(self.directory / 'import.pub')}):
            access.human_access('add-user', self.inventory, self.automation)
        self.assertEqual(self.events, ['automation', 'add-user.yml'])
        self.prepare_key.assert_not_called()
        self.verify_human.assert_not_called()

    def test_access_failure_blocks_any_ssh_mutation(self):
        self.verify_human.side_effect = subprocess.CalledProcessError(1, ['fixture'])
        with self.assertRaises(subprocess.CalledProcessError):
            access.human_access('secure-ssh', self.inventory, self.automation)
        self.run_playbook.assert_not_called()

    def test_confirmation_default_deny_preserves_policy(self):
        with patch('builtins.input', return_value=''), self.assertRaises(ValueError):
            access.human_access('secure-ssh', self.inventory, self.automation)
        self.assertEqual(self.events, ['automation', 'human'])
        self.run_playbook.assert_not_called()

    def test_secure_order_and_post_activation_failure_stops_later_checks(self):
        with patch('builtins.input', return_value='yes'):
            access.human_access('secure-ssh', self.inventory, self.automation)
        self.assertEqual(self.events, ['automation', 'human', 'secure-ssh.yml', 'automation', 'human',
                                       'verify-ssh-security.yml'])
        self.assertEqual(self.verify_auth_methods.call_count, 4)
        self.events.clear()
        self.verify_auth_methods.reset_mock()
        self.run_playbook.side_effect = subprocess.CalledProcessError(1, ['fixture'])
        with patch('builtins.input', return_value='yes'), self.assertRaisesRegex(ValueError, 'may already be installed'):
            access.human_access('secure-ssh', self.inventory, self.automation)
        self.assertEqual(self.events, ['automation', 'human'])
        self.verify_auth_methods.assert_not_called()

    def test_independent_verification_covers_every_selected_port(self):
        self.verify_human.side_effect = None
        # Call the real function while its process and key boundaries remain mocked.
        original = load('human_access_unpatched', 'scripts/access.py')
        human = access.human_inputs(self.env)
        with patch.object(original, 'check_key'), patch.object(original, 'public_key_file'), \
                patch.object(original, 'run_playbook') as run:
            original.verify_human(self.inventory, 'portfolio', 'fixture.example.test', 2222,
                                  {'ansible_user': 'ansible', 'ansible_ssh_args': access.SSH_BASE + ' -o IdentityAgent=none'},
                                  self.inputs, human, self.key)
        self.assertEqual([call.args[2]['ansible_port'] for call in run.call_args_list], [2222, 2200])
        for call in run.call_args_list:
            self.assertEqual(call.args[2]['ansible_user'], 'operator')
            self.assertIn('HostKeyAlias=[fixture.example.test]:2222', call.args[2]['ansible_ssh_args'])


class SSHCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.main = self.directory / 'sshd_config'
        self.includes = self.directory / 'conf.d'
        self.includes.mkdir()
        self.pending = self.directory / 'pending'
        self.text = (security.PORT_BEGIN + '\nPort 2222\nPubkeyAuthentication yes\n' + security.PORT_END +
                     '\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n')
        self.main.write_text(self.text)
        for name, value in (('MAIN', str(self.main)), ('INCLUDES', str(self.includes / '*.conf')),
                            ('PENDING', str(self.pending))):
            mocked = patch.object(security, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        # This test models content/transaction behavior; metadata is tested separately.
        mocked = patch.object(security, 'safe')
        mocked.start()
        self.addCleanup(mocked.stop)
        self.config = {'port': ['2222'], 'pubkeyauthentication': ['yes'], 'authenticationmethods': ['any'],
                       **{key: [value] for key, value in security.POLICY.items()}}
        self.module = Mock(check_mode=False)
        self.module.params = {'operation': 'apply', 'ssh_ports': [2222]}
        self.module.run_command.return_value = (0, '', '')
        self.refresh()

    def refresh(self):
        self.module.params['sources'] = [{'path': str(p), 'sha256': security.digest(p.read_bytes())}
                                         for p in [self.main, *sorted(self.includes.glob('*.conf'))]]

    def stage(self, operation):
        self.module.params['operation'] = operation
        # Keep temporary files in the isolated fixture instead of the real /etc/ssh.
        factory = tempfile.TemporaryDirectory
        with patch.object(security.tempfile, 'TemporaryDirectory',
                          side_effect=lambda **kw: factory(dir=self.directory)), \
                patch.object(security, 'effective', return_value=self.config):
            return security.secure(self.module)

    def test_candidate_preserves_stage3_ports_and_is_idempotent(self):
        self.assertTrue(self.stage('apply'))
        installed = self.main.read_text()
        self.assertTrue(installed.startswith(security.PORT_BEGIN))
        self.assertIn('Port 2222', installed)
        self.assertEqual(installed.count(security.BLOCK), 1)
        self.assertTrue(self.pending.exists())
        self.refresh()
        self.assertFalse(self.stage('installed'))
        self.assertTrue(self.pending.exists())
        self.assertFalse(self.stage('complete'))
        self.assertFalse(self.pending.exists())
        self.assertFalse(self.stage('apply'))
        self.assertFalse(self.stage('verify'))

    def test_invalid_candidate_never_writes_live_configuration(self):
        self.module.run_command.return_value = (1, '', 'sensitive diagnostic fixture')
        with self.assertRaises(ValueError):
            self.stage('apply')
        self.assertEqual(self.main.read_text(), self.text)
        self.assertFalse(self.pending.exists())

    def test_conditional_policy_and_changed_snapshot_fail_closed(self):
        for suffix in ('Match User root\n PermitRootLogin yes\n', 'Include /tmp/custom.conf\n'):
            self.main.write_text(self.text + suffix)
            self.refresh()
            with self.assertRaises(ValueError):
                self.stage('apply')
            self.assertFalse(self.pending.exists())
        self.main.write_text(self.text)
        self.refresh()
        (self.includes / 'new.conf').write_text('# concurrent new source\n')
        with self.assertRaises(ValueError):
            self.stage('apply')

    def test_interrupted_activation_blocks_retry_and_verification(self):
        self.pending.write_text(json.dumps({'sha256': 'unapproved'}))
        for mode in ('preflight', 'apply', 'verify', 'complete', 'installed'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.stage(mode)
        self.assertEqual(self.main.read_text(), self.text)

    def test_effective_policy_rejects_password_factors_and_port_changes(self):
        for change in ({'permitrootlogin': ['yes']}, {'kbdinteractiveauthentication': ['yes']},
                       {'passwordauthentication': ['yes']}, {'authenticationmethods': ['publickey,password']},
                       {'port': ['22']}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                security.policy_valid(self.config | change, [2222])


class HumanAccountPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for name in ('HOME_ROOT', 'STATE_ROOT', 'SUDO_ROOT'):
            path = self.directory / name
            path.mkdir()
            mocked = patch.object(human_info, name, path)
            mocked.start()
            self.addCleanup(mocked.stop)
        mocked = patch.object(human_info, 'safe')
        mocked.start()
        self.addCleanup(mocked.stop)
        self.module = Mock()
        self.module.params = {'name': 'operator', 'groups': [], 'sudo': 'admin', 'commands': ['ALL']}
        self.module.run_command.side_effect = self.command
        self.passwd = None
        self.group = None

    def command(self, argv, **kwargs):
        if argv[0].endswith('visudo'):
            return 0, '', ''
        result = self.passwd if argv[1] == 'passwd' else self.group
        return (0, result, '') if result else (2, '', '')

    def test_fresh_account_is_accepted_without_writing_state(self):
        self.assertFalse(human_info.inspect(self.module))
        self.assertFalse(list(human_info.STATE_ROOT.iterdir()))
        self.assertFalse(list(human_info.HOME_ROOT.iterdir()))


    def test_existing_unmanaged_account_and_orphan_home_are_rejected(self):
        self.passwd = f'operator:x:1000:1000::{human_info.HOME_ROOT / "operator"}:/bin/bash'
        with self.assertRaisesRegex(ValueError, 'unmanaged/system'):
            human_info.inspect(self.module)
        self.passwd = None
        (human_info.HOME_ROOT / 'operator').mkdir()
        with self.assertRaisesRegex(ValueError, 'Orphan'):
            human_info.inspect(self.module)

    def test_unmanaged_sudo_and_primary_groups_are_rejected(self):
        fragment = human_info.SUDO_ROOT / 'portfolio-human-operator'
        fragment.write_text('operator ALL=(ALL:ALL) NOPASSWD: ALL\n')
        with self.assertRaisesRegex(ValueError, 'sudo fragment'):
            human_info.inspect(self.module)
        fragment.unlink()
        self.group = 'operator:x:1000:'
        with self.assertRaisesRegex(human_info.PreflightError, 'unmanaged group'):
            human_info.inspect(self.module)

    def test_fresh_system_and_unmanaged_groups_are_separately_refused(self):
        for gid, phrase in ((37, 'system group'), (1000, 'unmanaged group')):
            with self.subTest(gid=gid):
                self.group = f'operator:x:{gid}:'
                self.module.run_command.reset_mock()
                with self.assertRaisesRegex(human_info.PreflightError, phrase) as caught:
                    human_info.inspect(self.module)
                self.assertIn(f'GID {gid}', str(caught.exception))
                self.assertFalse(list(human_info.HOME_ROOT.iterdir()))
                self.assertFalse(list(human_info.STATE_ROOT.iterdir()))
                self.assertFalse(any(call.args[0][0] in ('useradd', 'groupadd', 'install', 'mkdir')
                                     for call in self.module.run_command.call_args_list))

    def test_main_reports_stock_group_conflict_without_account_mutation(self):
        self.group = 'operator:x:37:'
        self.module.fail_json.side_effect = RuntimeError('captured refusal')
        with patch.object(human_info, 'AnsibleModule', return_value=self.module):
            with self.assertRaisesRegex(RuntimeError, 'captured refusal'):
                human_info.main()
        result = self.module.fail_json.call_args.kwargs
        self.assertFalse(result['changed'])
        self.assertIn('system group operator (GID 37)', result['msg'])
        self.assertIn('choose an unused HUMAN_USER', result['msg'])
        self.module.exit_json.assert_not_called()
        self.assertFalse(list(human_info.HOME_ROOT.iterdir()))
        self.assertFalse(list(human_info.STATE_ROOT.iterdir()))

    def test_invalid_sudo_policy_diagnostic_does_not_echo_command_output(self):
        self.module.run_command.side_effect = lambda *a, **kw: (1, 'synthetic secret output', 'synthetic secret stderr')
        with self.assertRaisesRegex(human_info.PreflightError, 'sudo validator failed') as caught:
            human_info.inspect(self.module)
        self.assertNotIn('synthetic secret', str(caught.exception))

    def test_existing_unmanaged_account_names_unused_user_action(self):
        self.passwd = f'operator:x:1000:1000::{human_info.HOME_ROOT / "operator"}:/bin/bash'
        with self.assertRaisesRegex(human_info.PreflightError, 'choose an unused HUMAN_USER'):
            human_info.inspect(self.module)

    def test_privilege_migration_and_group_removal_fail_closed(self):
        record = human_info.STATE_ROOT / 'operator.json'
        record.write_text(json.dumps({'name': 'operator', 'groups': [], 'sudo': 'none', 'commands': []}))
        with self.assertRaisesRegex(ValueError, 'privilege policy'):
            human_info.inspect(self.module)
        record.write_text(json.dumps(self.module.params | {'groups': ['readers']}))
        with self.assertRaisesRegex(ValueError, 'Group removal'):
            human_info.inspect(self.module)

    def test_untrusted_metadata_is_rejected(self):
        original = load('human_metadata_unpatched', 'library/portfolio_human_info.py')
        path = Mock(parents=[])
        path.is_symlink.return_value = False
        path.stat.return_value = Mock(st_uid=1000, st_mode=0o100600)
        with self.assertRaisesRegex(ValueError, 'ownership'):
            original.safe(path)
        parent = Mock()
        parent.is_symlink.return_value = False
        parent.stat.return_value = Mock(st_uid=0, st_mode=0o40777)
        path.parents = [parent]
        path.stat.return_value = Mock(st_uid=0, st_mode=0o100755)
        with self.assertRaisesRegex(ValueError, 'parent'):
            original.safe(path)

    def test_safe_metadata_diagnostics_include_labels_without_paths(self):
        original = load('human_metadata_labels', 'library/portfolio_human_info.py')
        for metadata_error, expected in ((OSError('synthetic secret'), 'metadata unavailable'),
                                         (None, 'symlinks are unsupported'),
                                         ('parent', 'unsafe parent')):
            path = Mock(parents=[])
            parent = Mock()
            parent.is_symlink.return_value = False
            parent.stat.return_value = Mock(st_uid=1000, st_mode=0o40700)
            path.parents = [parent] if metadata_error == 'parent' else []
            path.is_symlink.return_value = metadata_error is None
            if isinstance(metadata_error, OSError):
                path.stat.side_effect = metadata_error
            else:
                path.stat.return_value = Mock(st_uid=0, st_mode=0o100755)
            with self.subTest(expected=expected), self.assertRaisesRegex(original.PreflightError, expected) as caught:
                original.safe(path, label='sudo validator /usr/sbin/visudo')
            self.assertIn('sudo validator /usr/sbin/visudo', str(caught.exception))
            self.assertNotIn('synthetic secret', str(caught.exception))

    def test_main_keeps_reviewed_reason_and_hides_unexpected_details(self):
        for error, expected, forbidden in (
                (human_info.PreflightError('choose unused HUMAN_USER'), 'choose unused HUMAN_USER', 'secret'),
                (ValueError('synthetic secret'), 'unable to safely inspect state', 'synthetic secret'),
                (OSError('synthetic secret'), 'unable to safely inspect state', 'synthetic secret'),
                (UnicodeError('synthetic secret'), 'unable to safely inspect state', 'synthetic secret'),
                (json.JSONDecodeError('synthetic secret', 'x', 0),
                 'unable to safely inspect state', 'synthetic secret')):
            module = Mock()
            module.params = {}
            module.fail_json.side_effect = RuntimeError('captured')
            with patch.object(human_info, 'AnsibleModule', return_value=module), \
                    patch.object(human_info, 'inspect', side_effect=error):
                with self.assertRaisesRegex(RuntimeError, 'captured'):
                    human_info.main()
            kwargs = module.fail_json.call_args.kwargs
            self.assertFalse(kwargs['changed'])
            self.assertIn(expected, kwargs['msg'])
            self.assertNotIn(forbidden, kwargs['msg'])


class StageFourSourceStructureTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text()

    def yaml(self, relative):
        return yaml.safe_load(self.read(relative))

    def test_human_access_defaults_are_namespaced_and_old_names_are_absent(self):
        defaults = self.yaml('roles/human_access/defaults/main.yml')
        self.assertTrue(defaults)
        self.assertTrue(all(name.startswith('human_access_user_') for name in defaults))
        relevant = [
            'scripts/access.py', 'roles/human_access/defaults/main.yml', 'roles/human_access/tasks/main.yml',
            'roles/human_access/tasks/verify.yml', 'roles/ssh_security/tasks/main.yml',
            'roles/ssh_security/handlers/main.yml', 'playbooks/verify-user.yml',
        ]
        for relative in relevant:
            with self.subTest(path=relative):
                self.assertNotIn('human_user_', self.read(relative))

    def test_standalone_and_secure_verification_resolve_role_task_file(self):
        standalone = self.yaml('playbooks/verify-user.yml')[0]['tasks'][0]['ansible.builtin.import_role']
        self.assertEqual(standalone, {'name': 'human_access', 'tasks_from': 'verify'})
        secure_tasks = self.yaml('roles/ssh_security/tasks/main.yml')
        reproving = next(task for task in secure_tasks if task['name'].startswith('Re-prove human'))
        include = reproving['ansible.builtin.include_role']
        self.assertEqual(include['name'], 'human_access')
        self.assertEqual(include['tasks_from'], 'verify')
        self.assertEqual(include['apply'], {'become': False})
        self.assertNotIn('ansible_become', reproving.get('vars', {}))
        self.assertEqual(reproving['vars']['ansible_user'], '{{ human_access_user_name }}')
        self.assertEqual(reproving['vars']['ansible_private_key_file'], '{{ human_access_user_private_key_path }}')
        self.assertEqual(reproving['vars']['ansible_ssh_args'], '{{ human_access_user_ssh_args }}')

    def test_controller_key_include_uses_local_non_become_overlay(self):
        tasks = self.yaml('roles/human_access/tasks/main.yml')
        controller = next(task for task in tasks if task['name'].startswith('Load the public key'))
        include = controller['ansible.builtin.include_role']
        self.assertEqual(include['apply'], {'delegate_to': 'localhost', 'become': False})
        self.assertEqual(controller['vars']['ansible_connection'], 'local')
        self.assertEqual(controller['vars']['ansible_python_interpreter'], '{{ ansible_playbook_python }}')
        self.assertNotIn('ansible_become', controller['vars'])

    def test_reload_handler_orders_checks_reload_and_receipt(self):
        tasks = self.yaml('roles/ssh_security/tasks/main.yml')
        handlers = self.yaml('roles/ssh_security/handlers/main.yml')
        self.assertEqual(handlers[0]['ansible.builtin.command']['argv'], ['/usr/sbin/sshd', '-t'])
        self.assertTrue(handlers[1]['portfolio_hardening_info']['verify'])
        self.assertEqual(handlers[2]['portfolio_ssh_security']['operation'], 'installed')
        self.assertEqual(handlers[3]['ansible.builtin.systemd_service'],
                         {'name': 'ssh.service', 'state': 'reloaded'})
        self.assertTrue(handlers[4]['portfolio_hardening_info']['verify'])
        self.assertEqual(handlers[4]['register'], 'security_after')
        for handler in handlers:
            self.assertEqual(handler['listen'], 'Reload final SSH authentication policy')
        install = next(task for task in tasks if task['name'] == 'Install the validated final SSH authentication policy')
        install_index = tasks.index(install)
        flush_index = next(i for i, task in enumerate(tasks)
                           if task.get('ansible.builtin.meta') == 'flush_handlers')
        self.assertIn('Reload final SSH authentication policy', install['notify'])
        self.assertLess(install_index, flush_index)
        receipt = handlers[-1]
        self.assertEqual(receipt['portfolio_ssh_security']['operation'], 'complete')
        self.assertEqual(receipt['portfolio_ssh_security']['sources'], '{{ security_after.ssh_sources }}')
        self.assertNotIn('when', receipt)
        self.assertNotIn('security_installed', self.read('roles/ssh_security/tasks/main.yml'))
        self.assertNotIn('when', next(handler for handler in handlers if handler['name'].startswith('Read the installed')))

    def test_make_public_names_remain_human_environment_and_targets(self):
        makefile = self.read('Makefile')
        for name in ('HUMAN_USER', 'HUMAN_GROUPS', 'HUMAN_SUDO', 'HUMAN_SUDO_COMMANDS',
                     'HUMAN_KEY', 'HUMAN_PUBLIC_KEY', 'add-user', 'verify-user', 'secure-ssh',
                     'verify-ssh-security'):
            with self.subTest(name=name):
                self.assertIn(name, makefile)


class RuntimeProbeTests(unittest.TestCase):
    def test_probe_rejects_forbidden_methods_and_untrusted_host_keys(self):
        remote = Mock()
        remote.get_name.return_value = 'ssh-ed25519'
        for offered in (['publickey'], ['publickey', 'password'], ['publickey', 'keyboard-interactive']):
            with patch.object(access.socket, 'create_connection'), patch.object(paramiko, 'HostKeys') as keys, \
                    patch.object(paramiko, 'Transport') as transport:
                keys.return_value.lookup.return_value = {'ssh-ed25519': remote}
                transport.return_value.get_security_options.return_value.key_types = ('ssh-ed25519',)
                transport.return_value.get_remote_server_key.return_value = remote
                transport.return_value.auth_none.side_effect = paramiko.BadAuthenticationType('fixture', offered)
                if offered == ['publickey']:
                    access.verify_auth_methods('fixture.example.test', 2222, 'operator', '[fixture.example.test]:2222')
                else:
                    with self.assertRaises(ValueError):
                        access.verify_auth_methods('fixture.example.test', 2222, 'operator', '[fixture.example.test]:2222')
                transport.return_value.close.assert_called_once()
        with patch.object(access.socket, 'create_connection'), patch.object(paramiko, 'HostKeys') as keys, \
                patch.object(paramiko, 'Transport') as transport:
            keys.return_value.lookup.return_value = {}
            with self.assertRaises(ValueError):
                access.verify_auth_methods('fixture.example.test', 2222, 'operator', '[fixture.example.test]:2222')
            transport.return_value.auth_none.assert_not_called()


if __name__ == '__main__':
    unittest.main()
