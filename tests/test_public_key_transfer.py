"""Offline clipboard and pasted-key registration; no desktop or host access."""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_cli_connections import access, PUBLIC


class PublicKeyTransferTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='public transfer ')
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.key = self.home / '.ssh/portfolio-infra/person_ed25519'
        self.key.parent.mkdir(mode=0o700, parents=True)
        self.public = Path(str(self.key) + '.pub')
        self.content = PUBLIC + ' laptop-2\n'
        self.public.write_text(self.content)
        self.public.chmod(0o600)
        self.env = {'HUMAN_USER': 'person', 'HUMAN_SUDO': 'admin'}
        self.calls = []
        for mock in (patch.dict(os.environ, self.env, clear=True),
                     patch.object(access.sys, 'platform', 'linux'),
                     patch.object(access.Path, 'home', return_value=self.home),
                     patch.object(access.sys.stdin, 'isatty', return_value=False),
                     patch('builtins.input', side_effect=AssertionError('Unexpected prompt')),
                     patch.object(access.shutil, 'which', return_value='/fixture/tool'),
                     patch.object(access.subprocess, 'run', side_effect=self.run_command),
                     patch.object(access, 'managed_access', return_value=('controller', self.home / 'controller')),
                     patch.object(access, 'human_access_stage', side_effect=self.stage),
                     patch.object(access, 'load_host', side_effect=AssertionError('No host lookup')),
                     patch.object(access, 'prerequisites', side_effect=AssertionError('No host prerequisites'))):
            started = mock.start()
            self.addCleanup(mock.stop)
            if getattr(mock, 'attribute', None) == 'human_access_stage':
                self.register = started

    def run_command(self, command, **kwargs):
        self.calls.append((command, kwargs))
        self.assertEqual(command[0], 'ssh-keygen')
        self.assertIn('-l', command)
        self.assertTrue(command[command.index('-f') + 1].endswith('.pub'))
        return subprocess.CompletedProcess(command, 0, '256 SHA256:synthetic (ED25519)\n', '')

    def stage(self, mode, inventory, override, public):
        self.snapshot = public
        self.assertEqual(public.stat().st_mode & 0o777, 0o600)
        self.assertEqual(public.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(public.read_text(), self.content)
        self.assertNotEqual(public, self.public)

    def test_copy_backends_and_selection_only_need_public_member(self):
        cases = [({'WAYLAND_DISPLAY': 'wayland-0'}, 'wl-copy', ['wl-copy']),
                 ({'WAYLAND_DISPLAY': 'wayland-0', 'DISPLAY': ':0'}, 'wl-copy', ['wl-copy']),
                 ({'WAYLAND_DISPLAY': 'wayland-0', 'DISPLAY': ':0'}, 'xclip', ['xclip', '-selection', 'clipboard']),
                 ({'DISPLAY': ':0'}, 'xclip', ['xclip', '-selection', 'clipboard']),
                 ({'DISPLAY': ':0'}, 'xsel', ['xsel', '--clipboard', '--input'])]
        for env, tool, argv in cases:
            for selection in ({'KEY_NAME': 'person_ed25519'}, {'HUMAN_KEY': str(self.key)}):
                with self.subTest(tool=tool, selection=selection):
                    def run(command, **kwargs):
                        if command[0] == 'ssh-keygen':
                            return self.run_command(command, **kwargs)
                        self.assertEqual(command, argv)
                        self.assertEqual(kwargs['input'], self.content.encode())
                        self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
                        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
                        self.assertNotIn('shell', kwargs)
                        return subprocess.CompletedProcess(command, 0, b'', b'')
                    with patch.dict(os.environ, {**env, **selection}), \
                            patch.object(access.shutil, 'which', side_effect=lambda name: '/fixture/' + name if name in ('ssh-keygen', tool) else None), \
                            patch.object(access.subprocess, 'run', side_effect=run), \
                            patch.object(access, 'check_key', side_effect=AssertionError('Private metadata forbidden')), \
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        access.local_key('copy-public-key')
                    self.assertIn('copied to clipboard', output.getvalue())
                    self.assertIn('SHA256:synthetic', output.getvalue())
                    self.assertFalse(self.key.exists())
                    self.register.assert_not_called()

    def test_copy_missing_utility_or_session_and_process_errors(self):
        for env in ({}, {'WAYLAND_DISPLAY': 'wayland-0'}, {'DISPLAY': ':0'}):
            with self.subTest(env=env), patch.dict(os.environ, env), \
                    patch.object(access.shutil, 'which', side_effect=lambda name: '/fixture/tool' if name == 'ssh-keygen' else None), \
                    self.assertRaisesRegex(ValueError, 'make show-public-key'):
                access.local_key('copy-public-key')
        for failure in (subprocess.CompletedProcess(['wl-copy'], 1, b'', b'failed'),
                        OSError('failed'), subprocess.TimeoutExpired(['wl-copy'], 10)):
            def run(command, **kwargs):
                if command[0] == 'ssh-keygen':
                    return self.run_command(command, **kwargs)
                if isinstance(failure, Exception):
                    raise failure
                return failure
            with self.subTest(failure=failure), patch.dict(os.environ, {'WAYLAND_DISPLAY': 'wayland-0'}), \
                    patch.object(access.subprocess, 'run', side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    self.assertRaisesRegex(ValueError, 'Clipboard copy failed'):
                access.local_key('copy-public-key')
            self.assertNotIn('copied', output.getvalue())

    def installation_mocks(self, env, answer='', result=0, available=True, root=False):
        """Mock the full local path, including backend discovery after APT."""
        if hasattr(self, 'installation_stack'):
            self.installation_stack.close()
        stack = contextlib.ExitStack()
        self.installation_stack = stack
        self.addCleanup(stack.close)
        installed = False
        tool = 'wl-copy' if env.get('WAYLAND_DISPLAY') else 'xclip'
        def which(name):
            if name == tool:
                return '/fixture/' + name if installed and available else None
            return '/fixture/' + name if name in ('ssh-keygen', 'sudo', 'apt-get') else None
        def run(command, **kwargs):
            nonlocal installed
            if command[0] == 'ssh-keygen':
                return self.run_command(command, **kwargs)
            self.calls.append((command, kwargs))
            self.assertNotIn('shell', kwargs)
            if 'apt-get' in command:
                self.assertNotIn('input', kwargs)
                if isinstance(result, Exception):
                    raise result
                installed = result == 0
                return subprocess.CompletedProcess(command, result)
            self.assertTrue(installed)
            self.assertEqual(kwargs['input'], self.content.encode())
            return subprocess.CompletedProcess(command, 0)
        stack.enter_context(patch.dict(os.environ, env))
        stack.enter_context(patch.object(access.sys.stdin, 'isatty', return_value=True))
        prompt = stack.enter_context(patch('builtins.input', side_effect=[answer]))
        stack.enter_context(patch.object(access.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu'}))
        stack.enter_context(patch.object(access.os, 'geteuid', return_value=0 if root else 1000))
        stack.enter_context(patch.object(access.shutil, 'which', side_effect=which))
        stack.enter_context(patch.object(access.subprocess, 'run', side_effect=run))
        output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return prompt, output

    def test_install_confirmation_retries_copy_for_wayland_and_x11(self):
        for env, package, argv in (({'WAYLAND_DISPLAY': 'fixture'}, 'wl-clipboard', ['wl-copy']),
                                   ({'DISPLAY': ':0'}, 'xclip', ['xclip', '-selection', 'clipboard'])):
            for answer in ('', 'Y', 'yes'):
                for root in (False, True):
                    with self.subTest(env=env, answer=answer, root=root):
                        self.calls.clear()
                        prompt, output = self.installation_mocks(env, answer, root=root)
                        access.local_key('copy-public-key')
                        prompt.assert_called_once_with('Install now? [Y/n]: ')
                        installer = (['sudo'] if not root else []) + ['apt-get', 'install', '-y', package]
                        self.assertEqual([c for c, _ in self.calls if c[0] != 'ssh-keygen'], [installer, argv])
                        self.assertIn('Required package: ' + package, output.getvalue())
                        self.assertIn('copied to clipboard', output.getvalue())
                        self.assertIn('SHA256:synthetic', output.getvalue())

    def test_install_decline_or_cancel_never_installs_or_copies(self):
        for answer in ('n', 'N', 'no', 'unexpected', EOFError(), KeyboardInterrupt()):
            with self.subTest(answer=answer):
                self.calls.clear()
                _, output = self.installation_mocks({'WAYLAND_DISPLAY': 'fixture'}, answer)
                with self.assertRaisesRegex(ValueError, 'declined|cancelled'):
                    access.local_key('copy-public-key')
                self.assertTrue(all(c[0] == 'ssh-keygen' for c, _ in self.calls))
                self.assertNotIn('copied', output.getvalue())

    def test_install_failure_never_copies_or_reports_success(self):
        for failure in (1, OSError('failed'), subprocess.TimeoutExpired(['apt-get'], 300)):
            with self.subTest(failure=failure):
                self.calls.clear()
                _, output = self.installation_mocks({'DISPLAY': ':0'}, result=failure)
                with self.assertRaisesRegex(ValueError, 'installation failed'):
                    access.local_key('copy-public-key')
                self.assertFalse(any(c[0] == 'xclip' for c, _ in self.calls))
                self.assertNotIn('copied', output.getvalue())

    def test_install_success_requires_backend_to_be_available(self):
        _, output = self.installation_mocks({'WAYLAND_DISPLAY': 'fixture'}, available=False)
        with self.assertRaisesRegex(ValueError, 'still unavailable'):
            access.local_key('copy-public-key')
        self.assertNotIn('copied', output.getvalue())

    def test_copy_failure_after_installation_never_reports_success(self):
        _, output = self.installation_mocks({'WAYLAND_DISPLAY': 'fixture'})
        installed_run = access.subprocess.run
        def run(command, **kwargs):
            if command == ['wl-copy']:
                return subprocess.CompletedProcess(command, 1)
            return installed_run(command, **kwargs)
        with patch.object(access.subprocess, 'run', side_effect=run), \
                self.assertRaisesRegex(ValueError, 'Clipboard copy failed'):
            access.local_key('copy-public-key')
        self.assertNotIn('copied', output.getvalue())

    def test_installed_macos_pbcopy_needs_no_linux_display_or_installation(self):
        def run(command, **kwargs):
            if command[0] == 'ssh-keygen':
                return self.run_command(command, **kwargs)
            self.assertEqual(command, ['pbcopy'])
            self.assertEqual(kwargs['input'], self.content.encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(access.sys, 'platform', 'darwin'), \
                patch.object(access.subprocess, 'run', side_effect=run), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.local_key('copy-public-key')
        self.assertIn('SHA256:synthetic', output.getvalue())

    def test_headless_never_offers_install_even_with_tty(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=True), \
                self.assertRaisesRegex(ValueError, 'headless.*make show-public-key'):
            access.local_key('copy-public-key')

    def test_noninteractive_missing_backend_never_prompts_or_installs(self):
        for env, package in (({'WAYLAND_DISPLAY': 'fixture'}, 'wl-clipboard'), ({'DISPLAY': ':0'}, 'xclip')):
            with self.subTest(env=env), patch.dict(os.environ, env), \
                    patch.object(access.shutil, 'which', return_value=None), \
                    self.assertRaisesRegex(ValueError, package + '.*Non-interactive'):
                access.copy_public_key(self.public)
        self.assertTrue(all(c[0] == 'ssh-keygen' for c, _ in self.calls))

    def test_unsupported_installation_environment_never_prompts(self):
        for release in ({'ID': 'fedora'}, OSError('no os-release')):
            with self.subTest(release=release):
                self.installation_mocks({'DISPLAY': ':0'})
                with patch.object(access.platform, 'freedesktop_os_release',
                                  **({'side_effect': release} if isinstance(release, Exception) else {'return_value': release})), \
                        patch('builtins.input', side_effect=AssertionError('Unexpected prompt')), \
                        self.assertRaisesRegex(ValueError, 'requires Ubuntu/Debian'):
                    access.local_key('copy-public-key')

    def test_copy_missing_or_invalid_public_key_never_uses_clipboard(self):
        self.public.unlink()
        with self.assertRaises(FileNotFoundError):
            access.local_key('copy-public-key')
        self.assertFalse(self.calls)
        for invalid in ('PRIVATE KEY', 'ssh-dss AAAA', PUBLIC + '\n' + PUBLIC, 'command="id" ' + PUBLIC):
            self.public.write_text(invalid)
            self.public.chmod(0o600)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                access.local_key('copy-public-key')
        self.assertFalse(self.calls)
        self.public.write_text('ssh-ed25519 AAAA')
        with patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), self.assertRaisesRegex(ValueError, 'invalid'):
            access.local_key('copy-public-key')

    def test_paste_confirmation_and_cleanup(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', side_effect=[self.content, 'yes']) as prompt, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.human_access('add-user', self.home / 'inventory')
        self.assertEqual(prompt.call_count, 2)
        self.register.assert_called_once()
        self.assertFalse(self.snapshot.parent.exists())
        for value in ('person', 'HUMAN_SUDO: admin', 'SHA256:synthetic'):
            self.assertIn(value, output.getvalue())

    def test_decline_cancel_or_invalid_input_never_registers(self):
        for answers in ([self.content, ''], [self.content, 'no'], [self.content, EOFError()],
                        [self.content, KeyboardInterrupt()], [EOFError()], ['PRIVATE KEY'],
                        ['ssh-dss AAAA'], [PUBLIC + '\n' + PUBLIC]):
            with self.subTest(answers=answers), patch.object(access.sys.stdin, 'isatty', return_value=True), \
                    patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(ValueError):
                access.human_access('add-user', self.home / 'inventory')
            self.register.assert_not_called()

    def test_invalid_crypto_is_rejected_for_file_and_paste_before_registration(self):
        self.public.write_text('ssh-ed25519 AAAA\n')
        for imported in (False, True):
            env = {'HUMAN_PUBLIC_KEY': str(self.public)} if imported else {}
            with self.subTest(imported=imported), patch.dict(os.environ, env), \
                    patch.object(access.sys.stdin, 'isatty', return_value=True), \
                    patch('builtins.input', return_value='ssh-ed25519 AAAA') as prompt, \
                    patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'invalid'):
                access.human_access('add-user', self.home / 'inventory')
            self.assertEqual(prompt.call_count, int(not imported))
            self.register.assert_not_called()

    def test_clipboard_preserves_comment_and_line_endings(self):
        content = self.content.replace('\n', '\r\n')
        self.public.write_bytes(content.encode())
        def run(command, **kwargs):
            if command[0] == 'ssh-keygen':
                return self.run_command(command, **kwargs)
            self.assertEqual(kwargs['input'], content.encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'fixture'}), \
                patch.object(access.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            access.local_key('copy-public-key')

    def test_copy_never_inspects_private_metadata(self):
        original_stat = Path.stat
        original_lstat = Path.lstat
        def checked_stat(path, *args, **kwargs):
            self.assertNotEqual(path, self.key, 'Private metadata must not be inspected')
            return original_stat(path, *args, **kwargs)
        def checked_lstat(path, *args, **kwargs):
            self.assertNotEqual(path, self.key, 'Private metadata must not be inspected')
            return original_lstat(path, *args, **kwargs)
        def run(command, **kwargs):
            if command[0] == 'ssh-keygen':
                return self.run_command(command, **kwargs)
            return subprocess.CompletedProcess(command, 0)
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'fixture'}), \
                patch.object(access.subprocess, 'run', side_effect=run), \
                patch.object(Path, 'stat', checked_stat), patch.object(Path, 'lstat', checked_lstat), \
                contextlib.redirect_stdout(io.StringIO()):
            access.local_key('copy-public-key')

    def test_noninteractive_missing_key_fails_and_file_import_stays_supported(self):
        with self.assertRaisesRegex(ValueError, 'HUMAN_PUBLIC_KEY'):
            access.human_access('add-user', self.home / 'inventory')
        self.assertFalse(self.calls)
        self.register.assert_not_called()
        with patch.dict(os.environ, {'HUMAN_PUBLIC_KEY': str(self.public)}), contextlib.redirect_stdout(io.StringIO()):
            access.human_access('add-user', self.home / 'inventory')
        self.register.assert_called_once()
        self.assertFalse(self.snapshot.parent.exists())

    def test_file_import_in_terminal_requires_confirmation_and_failure_cleans_snapshot(self):
        with patch.dict(os.environ, {'HUMAN_PUBLIC_KEY': str(self.public)}), \
                patch.object(access.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', return_value='no') as prompt, \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'declined'):
            access.human_access('add-user', self.home / 'inventory')
        prompt.assert_called_once()
        self.register.assert_not_called()
        def failed(*args):
            self.stage(*args)
            raise ValueError('stage failed')
        with patch.dict(os.environ, {'HUMAN_PUBLIC_KEY': str(self.public)}), \
                patch.object(access, 'human_access_stage', side_effect=failed), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, 'stage failed'):
            access.human_access('add-user', self.home / 'inventory')
        self.assertFalse(self.snapshot.parent.exists())


if __name__ == '__main__':
    unittest.main()
