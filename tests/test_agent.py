"""Offline tests for selected local OpenSSH agent identities."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_cli_connections import access, PUBLIC

FINGERPRINT = 'SHA256:synthetic'


class AgentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='agent home ')
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.ssh = self.home / '.ssh'
        self.ssh.mkdir(mode=0o700)
        self.key = self.ssh / 'person_ed25519'
        self.key.touch(mode=0o600)
        self.public = Path(str(self.key) + '.pub')
        self.public.write_text(PUBLIC + ' test\n')
        self.public.chmod(0o644)
        self.env = {'HUMAN_USER': 'person', 'HUMAN_KEY': str(self.key), 'KEY_NAME': '',
                    'AGENT_LOAD': 'ask', 'SSH_AUTH_SOCK': '/fixture/agent.sock'}

    def fingerprint(self, command, **kwargs):
        self.assertEqual(command[:2], ['ssh-keygen', '-l'])
        self.assertEqual(command[command.index('-f') + 1], str(self.public))
        return subprocess.CompletedProcess(command, 0, '256 ' + FINGERPRINT + ' (ED25519)\n', '')

    def run_local_key(self, answer, policy='ask', tty=True, add_result=0, existing=False):
        calls = []
        loaded = existing

        def run(command, **kwargs):
            nonlocal loaded
            calls.append((command, kwargs))
            if command[0] == 'ssh-keygen':
                if '-f' in command:
                    return self.fingerprint(command, **kwargs)
                return subprocess.CompletedProcess(command, 0, '256 ' + FINGERPRINT + ' (ED25519)\n', '')
            if command[:2] == ['ssh-add', '-l']:
                return subprocess.CompletedProcess(command, 0 if loaded else 1,
                                                   ('256 ' + FINGERPRINT + ' (ED25519)\n') if loaded else '', '')
            if command[0] == 'ssh-add':
                loaded = add_result == 0
                return subprocess.CompletedProcess(command, add_result, '', '')
            self.fail('Unexpected command: ' + command[0])

        with patch.object(access.Path, 'home', return_value=self.home), \
                patch.object(access.shutil, 'which', return_value='/fixture/tool'), \
                patch.dict(os.environ, {**self.env, 'AGENT_LOAD': policy}, clear=True), \
                patch.object(access.sys.stdin, 'isatty', return_value=tty), \
                patch.object(access.subprocess, 'run', side_effect=run), \
                patch('builtins.input', side_effect=answer if isinstance(answer, list) else [answer]) as prompt, \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()):
            access.local_key('generate-user-key')
        return calls, prompt, output.getvalue()

    def test_new_pair_yes_enter_and_no_prompt_choices(self):
        for answer, wants_add in [('Y', True), ('', True), ('N', False)]:
            with self.subTest(answer=answer):
                self.key.unlink()
                self.public.unlink()
                self.key.touch(mode=0o600)
                self.public.write_text(PUBLIC + ' test\n')
                self.public.chmod(0o644)
                with patch.object(access, 'prepare_human_key', return_value=True):
                    calls, prompt, output = self.run_local_key(answer)
                self.assertEqual(any(command[0] == 'ssh-add' and command[1] != '-l'
                                     for command, _ in calls), wants_add)
                self.assertEqual(prompt.call_count, 1)
                self.assertEqual('SSH key added to ssh-agent successfully.' in output, wants_add)

    def test_no_tty_never_prompts_or_loads_but_loaded_identity_succeeds(self):
        with patch.object(access, 'prepare_human_key', return_value=True):
            calls, prompt, _ = self.run_local_key('', tty=False)
        self.assertFalse(any(command[0] == 'ssh-add' for command, _ in calls))
        prompt.assert_not_called()
        with patch.object(access, 'prepare_human_key', return_value=False):
            calls, prompt, _ = self.run_local_key('', tty=False, existing=True)
        self.assertFalse(any(command[0] == 'ssh-add' and command[1] != '-l' for command, _ in calls))
        prompt.assert_not_called()

    def test_agent_load_policy_and_generation_prompt_validation(self):
        for policy in ('yes', 'no'):
            with self.subTest(policy=policy), patch.object(access, 'prepare_human_key', return_value=True):
                calls, prompt, _ = self.run_local_key('n', policy=policy)
                self.assertEqual(any(command[0] == 'ssh-add' and command[1] != '-l'
                                     for command, _ in calls), policy == 'yes')
                prompt.assert_not_called()
        with patch.object(access, 'prepare_human_key', return_value=True), \
                self.assertRaisesRegex(ValueError, 'AGENT_LOAD'):
            with patch.dict(os.environ, {**self.env, 'AGENT_LOAD': 'maybe'}, clear=True):
                access.local_key('generate-user-key')
        with patch.object(access, 'prepare_human_key', return_value=True), \
                patch.dict(os.environ, {**self.env, 'AGENT_LOAD': 'ask'}, clear=True), \
                patch.object(access.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value='?'), \
                self.assertRaisesRegex(ValueError, 'Answer Y or N'):
            access.local_key('generate-user-key')

    def test_load_errors_fingerprint_selection_and_post_add_confirmation(self):
        for code in (1, 2):
            with self.subTest(code=code), patch.object(access.shutil, 'which', return_value='/fixture/ssh-add'), \
                    patch.object(access.subprocess, 'run', side_effect=[self.fingerprint(
                        ['ssh-keygen', '-l', '-E', 'sha256', '-f', str(self.public)]),
                        subprocess.CompletedProcess(['ssh-add', '-l'], 1, '', ''),
                        subprocess.CompletedProcess(['ssh-add'], code, '', '')]) as run, \
                    patch.object(access.sys.stdin, 'isatty', return_value=True), \
                    patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(ValueError, 'cancelled'):
                access.load_agent_key(self.key, self.public)
        with patch.object(access.shutil, 'which', return_value='/fixture/ssh-add'), \
                patch.object(access.subprocess, 'run', side_effect=[self.fingerprint(
                    ['ssh-keygen', '-l', '-E', 'sha256', '-f', str(self.public)]),
                    subprocess.CompletedProcess(['ssh-add', '-l'], 2, '', '')]), \
                patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(ValueError, 'unavailable'):
            access.load_agent_key(self.key, self.public)
        with patch.object(access.shutil, 'which', return_value='/fixture/ssh-add'), \
                patch.object(access.subprocess, 'run', side_effect=[self.fingerprint(
                    ['ssh-keygen', '-l', '-E', 'sha256', '-f', str(self.public)]),
                    subprocess.CompletedProcess(['ssh-add'], 1, '', '')]) as run, \
                patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(ValueError, 'terminal'):
            access.load_agent_key(self.key, self.public)
        self.assertEqual(len(run.call_args_list), 2)

        other = 'SHA256:otherFingerprint'
        responses = [self.fingerprint(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(self.public)]),
                     subprocess.CompletedProcess(['ssh-add', '-l'], 0, '256 ' + other + ' (ED25519)\n', ''),
                     subprocess.CompletedProcess(['ssh-add'], 0, '', ''),
                     subprocess.CompletedProcess(['ssh-add', '-l'], 0,
                                                 '256 ' + other + ' (ED25519)\n256 ' + FINGERPRINT + ' (ED25519)\n', '')]
        with patch.object(access.shutil, 'which', return_value='/fixture/ssh-add'), \
                patch.object(access.subprocess, 'run', side_effect=responses) as run, \
                patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            access.load_agent_key(self.key, self.public)
        load_call = next(call for call in run.call_args_list if call.args[0][0] == 'ssh-add' and call.args[0][1] != '-l')
        command, kwargs = load_call.args[0], load_call.kwargs
        self.assertEqual(command, ['ssh-add', '-q', str(self.key)])
        self.assertNotIn('input', kwargs)
        self.assertNotIn('SSH_ASKPASS_REQUIRE', os.environ)
        self.assertEqual(kwargs['env']['SSH_ASKPASS_REQUIRE'], 'never')
        self.assertNotIn(FINGERPRINT, str(kwargs))

    def test_invalid_key_metadata_rejected_before_agent_loading_and_show_never_loads(self):
        for invalid in ('missing', 'permissions'):
            with self.subTest(invalid=invalid):
                if invalid == 'missing':
                    self.key.unlink()
                else:
                    self.key.chmod(0o644)
                with patch.object(access.Path, 'home', return_value=self.home), \
                        patch.object(access.shutil, 'which', return_value='/fixture/ssh-keygen'), \
                        patch.object(access.subprocess, 'run') as run, \
                        patch.dict(os.environ, self.env, clear=True), self.assertRaises(ValueError):
                    access.local_key('load-user-key')
                run.assert_not_called()
                if invalid == 'missing':
                    self.key.touch(mode=0o600)
                else:
                    self.key.chmod(0o600)
        self.key.chmod(0o600)
        with patch.object(access.Path, 'home', return_value=self.home), \
                patch.object(access.shutil, 'which', return_value='/fixture/ssh-keygen'), \
                patch.object(access.subprocess, 'run', side_effect=self.fingerprint), \
                patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(access, 'load_agent_key') as load:
            access.local_key('show-public-key')
        load.assert_not_called()

    def test_loaded_selected_key_without_terminal_preserves_other_agent_keys(self):
        responses = [self.fingerprint(['ssh-keygen', '-l', '-f', str(self.public)]),
                     subprocess.CompletedProcess(['ssh-add', '-l'], 0,
                                                 '256 SHA256:other comment\n256 ' + FINGERPRINT + ' comment\n', '')]
        with patch.object(access.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(access.subprocess, 'run', side_effect=responses) as run, \
                patch.object(access.sys.stdin, 'isatty', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.load_agent_key(self.key, self.public)
        self.assertEqual(run.call_count, 2)
        self.assertIn('already loaded', output.getvalue())
        self.assertNotIn('SHA256:other', output.getvalue())

    def test_agent_timeout_cancel_and_wrong_post_add_identity(self):
        fingerprint = self.fingerprint(['ssh-keygen', '-l', '-f', str(self.public)])
        empty = subprocess.CompletedProcess(['ssh-add', '-l'], 1, '', '')
        cases = [([fingerprint, subprocess.TimeoutExpired(['ssh-add', '-l'], 10)], '10 seconds'),
                 ([fingerprint, empty, KeyboardInterrupt()], 'cancelled'),
                 ([fingerprint, empty, subprocess.CompletedProcess(['ssh-add'], 0), empty], 'selected public identity')]
        for responses, message in cases:
            with self.subTest(message=message), patch.object(access.shutil, 'which', return_value='/fixture/tool'), \
                    patch.object(access.subprocess, 'run', side_effect=responses), \
                    patch.object(access.sys.stdin, 'isatty', return_value=True), self.assertRaisesRegex(ValueError, message):
                access.load_agent_key(self.key, self.public)

    def test_managed_ansible_transport_keeps_selected_identity_and_agent_socket(self):
        overlays = []

        def run(command, **kwargs):
            overlays.append(json.loads(Path(command[-1]).read_text())['all']['hosts']['portfolio'])
            self.assertEqual(kwargs['env']['SSH_AUTH_SOCK'], '/fixture/agent.sock')
            self.assertNotIn('--ask-pass', command)
            self.assertNotIn('--ask-become-pass', command)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(access, 'managed_access', return_value=('person', self.key)), \
                patch.object(access, 'load_host', return_value=('portfolio', 'fixture.example.test', 2222, 'root', '/usr/bin/python3')), \
                patch.object(access, 'prerequisites'), patch.object(access, 'known_host'), \
                patch.dict(os.environ, self.env, clear=True), patch.object(access.subprocess, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()):
            access.live('verify-access', self.home / 'synthetic.yml')
        self.assertEqual(len(overlays), 1)
        self.assertEqual(overlays[0]['ansible_private_key_file'], str(self.key))
        args = overlays[0]['ansible_ssh_args']
        self.assertNotIn('IdentityAgent=none', args)
        for option in ('IdentitiesOnly=yes', 'BatchMode=yes', 'StrictHostKeyChecking=yes',
                       'ForwardAgent=no', 'ClearAllForwardings=yes', '-F /dev/null'):
            self.assertIn(option, args)


if __name__ == '__main__':
    unittest.main()
