"""Offline local-key commands and interactive SSH construction; never contact hosts."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('cli_access', ROOT / 'scripts/access.py')
access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(access)
PUBLIC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'


class CLIConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cli home ')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / '.ssh').mkdir(mode=0o700)
        self.key = self.home / '.ssh/portfolio-infra/person_ed25519'
        self.inventory = self.home / 'synthetic.yml'
        self.host = {'ansible_host': 'fixture.example.test', 'ansible_port': 2222,
                     'bootstrap_login_user': 'root', 'ansible_user': 'automation',
                     'ansible_private_key_file': str(self.home / '.ssh/controller_ed25519')}
        self.write_inventory()
        for mock in (patch.object(access.Path, 'home', return_value=self.home),
                     patch.object(access.shutil, 'which', side_effect=lambda name: '/fixture/' + name),
                     patch.dict(os.environ, {'HUMAN_USER': 'person'}, clear=True)):
            mock.start()
            self.addCleanup(mock.stop)

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {'portfolio': self.host}}}}}))

    def pair(self, key=None):
        key = key or self.key
        key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key.touch(mode=0o600)
        Path(str(key) + '.pub').write_text(PUBLIC + ' synthetic-public\n')
        Path(str(key) + '.pub').chmod(0o644)
        return key

    def trust(self):
        folder = self.home / '.ssh'
        folder.mkdir(mode=0o700, exist_ok=True)
        trusted = folder / 'known_hosts'
        trusted.write_text('[fixture.example.test]:2222 ' + PUBLIC + '\n')
        trusted.chmod(0o600)

    def local_run(self, command, **kwargs):
        self.assertEqual(command[0], 'ssh-keygen', 'Only local public-key operations may execute here')
        if '-F' in command:
            self.assertEqual(command[command.index('-F') + 1], '[fixture.example.test]:2222')
            return subprocess.CompletedProcess(command, 0, '', '')
        return subprocess.CompletedProcess(command, 0, '256 SHA256:synthetic fingerprint (ED25519)\n', '')

    def test_generate_default_key_is_local_prompts_without_exposing_passphrase(self):
        def generate(command, **kwargs):
            if '-t' in command:
                self.assertEqual(command[command.index('-t') + 1], 'ed25519')
                self.assertNotIn('-N', command)
                self.assertNotIn('input', kwargs)
                self.assertEqual(command[command.index('-f') + 1], str(self.key))
                self.pair()
            return self.local_run(command, **kwargs)
        with patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.object(access.subprocess, 'run', side_effect=generate), \
                patch.object(access, 'load_host', side_effect=AssertionError('Inventory is not needed')), \
                patch.object(access, 'prerequisites', side_effect=AssertionError('Ansible is not needed')), \
                patch.object(access.Path, 'read_bytes', side_effect=AssertionError('Private bytes must not be read')), \
                contextlib.redirect_stdout(io.StringIO()):
            access.local_key('generate-user-key')
        self.assertEqual(self.key.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_existing_pair_preserved_and_partial_pair_never_replaced(self):
        self.pair()
        before = self.key.stat()
        with patch.object(access.subprocess, 'run', side_effect=self.local_run) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            access.local_key('generate-user-key')
            self.assertFalse(any('-t' in call.args[0] for call in run.call_args_list))
            self.assertEqual(self.key.stat().st_mtime_ns, before.st_mtime_ns)
            Path(str(self.key) + '.pub').unlink()
            run.reset_mock()
            with self.assertRaises(ValueError):
                access.local_key('generate-user-key')
            run.assert_not_called()
        self.key.unlink()
        Path(str(self.key) + '.pub').write_text(PUBLIC)
        with patch.object(access.subprocess, 'run') as run, self.assertRaises(ValueError):
            access.local_key('generate-user-key')
        run.assert_not_called()

    def test_generation_requires_terminal_only_for_new_pair(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False), patch.object(access.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'terminal'):
                access.local_key('generate-user-key')
            run.assert_not_called()

    def test_key_name_and_explicit_path_selection(self):
        with patch.dict(os.environ, {'KEY_NAME': 'laptop_ed25519'}):
            self.assertEqual(access.cli_human_key(), ('person', self.key.parent / 'laptop_ed25519'))
            with patch.dict(os.environ, {'HUMAN_KEY': str(self.home / 'explicit/key')}):
                self.assertEqual(access.cli_human_key(), ('person', self.home / 'explicit/key'))
        for value in ('../bad', '/tmp/key', '-option', 'public.pub', 'a\nb', 'a%h', '${KEY}'):
            with self.subTest(value=value), patch.dict(os.environ, {'KEY_NAME': value}), self.assertRaises(ValueError):
                access.cli_human_key()
        for value in ('', 'root', '-option', 'user;touch', 'a/b'):
            with self.subTest(user=value), patch.dict(os.environ, {'HUMAN_USER': value}), self.assertRaises(ValueError):
                access.cli_human_key()
        for value in ('bad\nkey', 'key%h', '${KEY}'):
            with patch.dict(os.environ, {'HUMAN_KEY': str(self.home / value)}), self.assertRaises(ValueError):
                access.cli_human_key()

    def test_public_key_and_sha256_only_never_read_private_material(self):
        self.pair()
        original = Path.read_text
        def read(path, *args, **kwargs):
            self.assertNotEqual(path, self.key)
            return original(path, *args, **kwargs)
        with patch.object(access.Path, 'read_text', read), \
                patch.object(access.subprocess, 'run', side_effect=self.local_run) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.local_key('show-public-key')
        self.assertEqual(output.getvalue().splitlines(), [PUBLIC, 'SHA256 fingerprint: SHA256:synthetic'])
        self.assertIn('-E', run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][run.call_args.args[0].index('-E') + 1], 'sha256')
        self.assertTrue(all(str(self.key) + '.pub' in call.args[0] for call in run.call_args_list))

    def test_unsafe_key_metadata_symlinks_and_public_options_are_rejected(self):
        self.pair()
        for path, mode in ((self.key, 0o644), (self.key.parent, 0o755), (Path(str(self.key) + '.pub'), 0o666)):
            before = path.stat().st_mode & 0o777
            path.chmod(mode)
            with patch.object(access.subprocess, 'run') as run, self.assertRaises(ValueError):
                access.local_key('show-public-key')
            run.assert_not_called()
            path.chmod(before)
        public = Path(str(self.key) + '.pub')
        public.unlink()
        public.symlink_to(self.inventory)
        with patch.object(access.subprocess, 'run') as run, self.assertRaises(ValueError):
            access.local_key('generate-user-key')
        run.assert_not_called()
        public.unlink()
        public.write_text('command="bad" ' + PUBLIC)
        with patch.object(access.subprocess, 'run') as run, self.assertRaises(ValueError):
            access.local_key('show-public-key')
        run.assert_not_called()

    def test_show_controller_uses_inventory_and_prints_reusable_command_without_ssh(self):
        self.pair(Path(self.host['ansible_private_key_file']))
        self.trust()
        with patch.object(access.subprocess, 'run', side_effect=self.local_run), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.cli_connection('show-controller', self.inventory)
        summary, command = output.getvalue().split('SSH command: ')
        self.assertIn('ansible_user: automation', summary)
        self.assertIn('server: fixture.example.test', summary)
        self.assertIn('port: 2222', summary)
        argv = shlex.split(command)
        self.assertEqual(argv[-1], 'automation@fixture.example.test')
        self.assertEqual(argv[argv.index('-i') + 1], self.host['ansible_private_key_file'])
        self.assertEqual(argv[argv.index('-p') + 1], '2222')
        for option in ('StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'PasswordAuthentication=no',
                       'KbdInteractiveAuthentication=no', 'BatchMode=yes', 'ForwardAgent=no',
                       'UpdateHostKeys=no', 'ClearAllForwardings=yes'):
            self.assertIn(option, argv)
        self.assertEqual(argv[argv.index('-F') + 1], '/dev/null')
        self.assertNotIn('IdentityAgent=none', argv)
        self.assertIn('UserKnownHostsFile="' + str(self.home / '.ssh/known_hosts') + '"', argv)

    def test_openssh_offline_config_parser_preserves_selected_paths(self):
        self.pair(Path(self.host['ansible_private_key_file']))
        self.trust()
        with patch.object(access.subprocess, 'run', side_effect=self.local_run):
            command = access.interactive_ssh_command('fixture.example.test', 2222, 'automation',
                                                     Path(self.host['ansible_private_key_file']))
        # -G only prints local configuration; it never opens an SSH connection.
        result = subprocess.run([command[0], '-G', *command[1:]], capture_output=True, text=True, check=True)
        settings = dict(line.split(' ', 1) for line in result.stdout.splitlines())
        self.assertEqual(settings['user'], 'automation')
        self.assertEqual(settings['hostname'], 'fixture.example.test')
        self.assertEqual(settings['port'], '2222')
        self.assertEqual(settings['identityfile'], self.host['ansible_private_key_file'])
        self.assertEqual(settings['userknownhostsfile'], str(self.home / '.ssh/known_hosts'))
        self.assertEqual(settings['stricthostkeychecking'], 'true')

    def test_connections_support_selected_agent_identity_and_propagate_failure(self):
        self.pair()
        self.pair(Path(self.host['ansible_private_key_file']))
        self.trust()
        for mode, user, key in (('connect-controller', 'automation', self.host['ansible_private_key_file']),
                                ('connect-user', 'person', str(self.key))):
            with self.subTest(mode=mode):
                def run(argv, **kwargs):
                    if argv[0] != 'ssh':
                        return self.local_run(argv, **kwargs)
                    self.assertEqual(argv[-1], user + '@fixture.example.test')
                    self.assertEqual(argv[argv.index('-i') + 1], key)
                    self.assertNotIn('IdentityAgent=none', argv)
                    self.assertNotIn('env', kwargs)  # Preserve SSH_AUTH_SOCK from the caller.
                    self.assertTrue(kwargs['check'])
                    raise subprocess.CalledProcessError(255, argv)
                with patch.object(access.sys.stdin, 'isatty', return_value=True), \
                        patch.dict(os.environ, {'SSH_AUTH_SOCK': '/fixture/agent.sock'}), \
                        patch.object(access.subprocess, 'run', side_effect=run), self.assertRaises(subprocess.CalledProcessError):
                    access.cli_connection(mode, self.inventory)

    def test_unknown_or_unsafe_trust_and_nonterminal_never_execute_ssh(self):
        self.pair(Path(self.host['ansible_private_key_file']))
        with patch.object(access.subprocess, 'run', side_effect=self.local_run) as run:
            with self.assertRaisesRegex(ValueError, 'trust'):
                access.cli_connection('show-controller', self.inventory)
            self.assertFalse(any(call.args[0][0] == 'ssh' for call in run.call_args_list))
        self.trust()
        with patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.object(access.subprocess, 'run', side_effect=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', '')) as run, \
                patch.object(access, 'public_key_file'):
            with self.assertRaises(ValueError):
                access.cli_connection('connect-controller', self.inventory)
            self.assertEqual(run.call_args.args[0][0], 'ssh-keygen')
            self.assertIn('-F', run.call_args.args[0])
        (self.home / '.ssh/known_hosts').chmod(0o666)
        with patch.object(access.subprocess, 'run', side_effect=self.local_run) as run, self.assertRaises(ValueError):
            access.cli_connection('show-controller', self.inventory)
        self.assertFalse(any(call.args[0][0] == 'ssh' for call in run.call_args_list))
        with patch.object(access.sys.stdin, 'isatty', return_value=False), patch.object(access.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'terminal'):
                access.cli_connection('connect-controller', self.inventory)
            run.assert_not_called()

    def test_legacy_controller_keeps_original_managed_user_and_override(self):
        self.host = {'ansible_host': 'fixture.example.test', 'ansible_port': 2222, 'ansible_user': 'root'}
        self.write_inventory()
        self.pair()
        self.trust()
        with patch.object(access.subprocess, 'run', side_effect=self.local_run), contextlib.redirect_stdout(io.StringIO()) as output:
            access.cli_connection('show-controller', self.inventory, self.key)
        self.assertIn('ansible_user: ansible', output.getvalue())
        self.assertIn('ansible@fixture.example.test', output.getvalue())


if __name__ == '__main__':
    unittest.main()
