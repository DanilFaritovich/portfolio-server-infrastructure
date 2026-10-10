"""Cross-port host identity and clipboard tests: synthetic trust, mocked network/APT."""

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import paramiko
import yaml

from tests.test_cli_connections import access, PUBLIC


class PortTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='port trust ')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.path = self.home / '.ssh/known_hosts'
        self.path.parent.mkdir(mode=0o700)
        self.host = 'fixture.example.test'
        self.old_port, self.port = 2222, 22
        self.inventory = self.home / 'inventory.yml'
        self.key = self.home / '.ssh/controller'
        self.key.touch(mode=0o600)
        Path(str(self.key) + '.pub').write_text(PUBLIC + '\n')
        Path(str(self.key) + '.pub').chmod(0o644)
        values = {'ansible_host': self.host, 'ansible_port': self.port, 'bootstrap_login_user': 'root',
                  'ansible_user': 'automation', 'ansible_private_key_file': str(self.key)}
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {'portfolio': values}}}}}))
        self.fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(PUBLIC.split()[1])).digest()).decode().rstrip('=')
        self.keys = {'ssh-ed25519': {'public_key': PUBLIC, 'fingerprint': self.fingerprint}}
        self.write(f'# preserve\n[{self.host}]:{self.old_port} {PUBLIC}\nother.test {PUBLIC}\n')
        native_run = subprocess.run
        def run(argv, **kwargs):
            self.assertEqual(argv[0], 'ssh-keygen', 'Unexpected external operation')
            return native_run(argv, **kwargs)
        for mock in (patch.object(access.Path, 'home', return_value=self.home),
                     patch.object(access.sys.stdin, 'isatty', return_value=True),
                     patch.object(access.subprocess, 'run', side_effect=run),
                     patch.object(access.socket, 'create_connection') ,
                     patch.object(paramiko, 'Transport')):
            mock.start()
            self.addCleanup(mock.stop)
        self.transport = paramiko.Transport.return_value
        self.transport.get_security_options.return_value.key_types = ('ssh-ed25519', 'rsa-sha2-512', 'ssh-rsa')
        remote = self.transport.get_remote_server_key.return_value
        remote.get_name.return_value = 'ssh-ed25519'
        remote.get_base64.return_value = PUBLIC.split()[1]
        self.output = io.StringIO()
        capture = contextlib.redirect_stdout(self.output)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)

    def write(self, content):
        self.path.write_text(content)
        self.path.chmod(0o600)

    def transfer(self, answer='y'):
        with patch('builtins.input', side_effect=[answer]) as prompt:
            access.transfer_port_trust(self.host, self.port)
        return prompt

    def test_verified_transfer_preserves_original_and_repeat_is_noop(self):
        before = self.path.read_bytes()
        self.transfer()
        self.assertEqual(self.path.read_bytes(), before + f'{self.host} {PUBLIC}\n'.encode())
        self.transport.start_client.assert_called_once_with(timeout=15)
        self.transport.close.assert_called_once()
        self.transport.auth_publickey.assert_not_called()
        self.transport.open_session.assert_not_called()
        self.assertEqual(self.transport.get_security_options.return_value.key_types, ('ssh-ed25519',))
        access.socket.create_connection.assert_called_once_with((self.host, 22), timeout=15)
        after = access.trust_snapshot(self.path)
        access.socket.create_connection.reset_mock()
        with patch('builtins.input', side_effect=AssertionError('No repeat prompt')):
            access.transfer_port_trust(self.host, self.port)
        access.socket.create_connection.assert_not_called()
        self.assertEqual(access.trust_snapshot(self.path), after)

    def test_hashed_source_nonstandard_destination(self):
        endpoint = f'[{self.host}]:{self.old_port}'
        salt = b'01234567890123456789'
        hashed = '|1|' + base64.b64encode(salt).decode() + '|' + base64.b64encode(hmac.digest(salt, endpoint.encode(), 'sha1')).decode()
        self.write(f'{hashed} {PUBLIC}\n')
        self.port = 2244
        self.transfer()
        self.assertEqual(self.path.read_text(), f'{hashed} {PUBLIC}\n[{self.host}]:2244 {PUBLIC}\n')

    def test_decline_and_cancellation_preserve_snapshot(self):
        for answer in ('', 'n', 'no', EOFError(), KeyboardInterrupt()):
            before = access.trust_snapshot(self.path)
            with self.subTest(answer=answer), self.assertRaisesRegex(ValueError, 'declined|cancelled'):
                self.transfer(answer)
            self.assertEqual(access.trust_snapshot(self.path), before)

    def test_unreachable_and_invalid_handshake_never_prompt_or_save(self):
        for failure in (ConnectionRefusedError(), socket.timeout(), paramiko.SSHException('bad signature'), EOFError()):
            before = access.trust_snapshot(self.path)
            if isinstance(failure, OSError):
                target = access.socket.create_connection
            else:
                target = self.transport.start_client
            target.side_effect = failure
            with self.subTest(failure=failure), patch('builtins.input') as prompt, \
                    self.assertRaisesRegex(ValueError, 'verification failed'):
                access.transfer_port_trust(self.host, self.port)
            prompt.assert_not_called()
            self.assertEqual(access.trust_snapshot(self.path), before)
            target.side_effect = None

    def test_incomplete_exchange_and_mismatched_identity_fail(self):
        for kind, blob, failure in (('ssh-ed25519', 'AAAA', None), ('ssh-rsa', PUBLIC.split()[1], None),
                                    ('ssh-ed25519', PUBLIC.split()[1], paramiko.SSHException('No existing session'))):
            remote = self.transport.get_remote_server_key.return_value
            remote.get_name.return_value, remote.get_base64.return_value = kind, blob
            self.transport.get_remote_server_key.side_effect = failure
            before = access.trust_snapshot(self.path)
            with self.subTest(kind=kind, failure=failure), patch('builtins.input') as prompt, self.assertRaises(ValueError):
                access.transfer_port_trust(self.host, self.port)
            prompt.assert_not_called()
            self.assertEqual(access.trust_snapshot(self.path), before)

    def test_noninteractive_missing_source_and_markers_fail_before_network(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False), self.assertRaisesRegex(ValueError, 'terminal'):
            access.transfer_port_trust(self.host, self.port)
        for content in (f'other.test {PUBLIC}\n', f'@revoked [{self.host}]:2222 {PUBLIC}\n',
                        f'[{self.host}]:2222 {PUBLIC}\n[{self.host}]:2222 ssh-ed25519 AAAA\n'):
            self.write(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                access.transfer_port_trust(self.host, self.port)
        access.socket.create_connection.assert_not_called()

    def test_concurrent_change_blocks_save(self):
        def answer(_):
            self.write(self.path.read_text() + '# concurrent\n')
            return 'y'
        with patch('builtins.input', side_effect=answer), self.assertRaisesRegex(ValueError, 'changed since review'):
            access.transfer_port_trust(self.host, self.port)
        self.assertNotIn(f'\n{self.host} ', self.path.read_text())

    def test_controller_continues_strict_ssh_after_confirmation(self):
        native_run = access.subprocess.run
        def run(argv, **kwargs):
            if argv[0] != 'ssh':
                return native_run(argv, **kwargs)
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('ForwardAgent=no', argv)
            self.assertIn('IdentitiesOnly=yes', argv)
            self.assertEqual(argv[-1], 'automation@' + self.host)
            self.assertIn(f'{self.host} {PUBLIC}', self.path.read_text())
            return subprocess.CompletedProcess(argv, 0)
        with patch('builtins.input', return_value='yes'), patch.object(access.subprocess, 'run', side_effect=run):
            access.cli_connection('connect-controller', self.inventory)

    def test_show_controller_and_verification_do_not_transfer(self):
        before = access.trust_snapshot(self.path)
        with self.assertRaisesRegex(ValueError, 'not trusted'):
            access.cli_connection('show-controller', self.inventory)
        with self.assertRaisesRegex(ValueError, 'not trusted'):
            access.known_host(self.host, self.port)
        access.socket.create_connection.assert_not_called()
        self.assertEqual(access.trust_snapshot(self.path), before)

    def test_multiple_algorithms_only_verified_key_is_saved_and_rsa_sha2_is_eligible(self):
        keys = self.keys | {'ssh-rsa': {'public_key': 'ssh-rsa synthetic', 'fingerprint': 'unused'}}
        verified = access.verify_port_identity(self.host, self.port, keys)
        self.assertEqual(verified, self.keys)
        self.assertEqual(self.transport.get_security_options.return_value.key_types,
                         ('ssh-ed25519', 'rsa-sha2-512', 'ssh-rsa'))

    def test_pinned_transport_rejects_invalid_exchange_signature(self):
        # Exercise real signature verification with an in-memory socket mock.
        transport = paramiko.transport.Transport(MagicMock())
        self.addCleanup(transport.close)
        signing_key = paramiko.RSAKey.generate(1024)
        transport.host_key_type = 'rsa-sha2-512'
        transport.H = b'synthetic exchange hash'
        signature = signing_key.sign_ssh_data(transport.H, algorithm='rsa-sha2-512').asbytes()
        transport._verify_key(signing_key.asbytes(), signature)
        self.assertEqual(transport.host_key, signing_key)
        transport.H = b'different exchange hash'
        with self.assertRaisesRegex(paramiko.SSHException, 'Signature verification'):
            transport._verify_key(signing_key.asbytes(), signature)

    def test_conflicting_identities_across_ports_block(self):
        with patch.object(access, 'trusted_host_keys', side_effect=[{}, self.keys,
                {'ssh-ed25519': {'public_key': 'different', 'fingerprint': 'different'}}]), \
                patch.object(access, 'previous_trust_ports', return_value=[2222, 2244]), \
                self.assertRaisesRegex(ValueError, 'Conflicting host identities'):
            access.transfer_port_trust(self.host, self.port)
        access.socket.create_connection.assert_not_called()

    def test_copy_server_json_uses_shared_clipboard_and_reports_identity(self):
        self.port = self.old_port
        values = yaml.safe_load(self.inventory.read_text())
        values['all']['children']['bootstrap']['hosts']['portfolio']['ansible_port'] = self.port
        self.inventory.write_text(yaml.safe_dump(values))
        before = access.trust_snapshot(self.path)
        native_run = access.subprocess.run
        def run(argv, **kwargs):
            if argv[0] == 'wl-copy':
                self.assertEqual(json.loads(kwargs['input']), {'version': 1, 'host': self.host, 'port': self.port,
                                                             'keys': list(self.keys.values())})
                self.assertNotIn(b'\n', kwargs['input'])
                return subprocess.CompletedProcess(argv, 0)
            return native_run(argv, **kwargs)
        with patch.dict(os.environ, {'WAYLAND_DISPLAY': 'fixture'}, clear=True), \
                patch.object(access.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(access.subprocess, 'run', side_effect=run):
            access.server_trust('copy-server-trust', self.inventory)
        self.assertIn('JSON copied', self.output.getvalue())
        self.assertIn(self.fingerprint, self.output.getvalue())
        self.assertIn(str(self.port), self.output.getvalue())
        self.assertEqual(access.trust_snapshot(self.path), before)

    def test_server_clipboard_install_consent_decline_and_failures(self):
        for answer in ('', 'Y', 'n'):
            installed = False
            calls = []
            def which(tool):
                return '/fixture/' + tool if tool != 'wl-copy' or installed else None
            def run(argv, **kwargs):
                nonlocal installed
                calls.append(argv)
                if argv[0] == 'apt-get':
                    installed = True
                else:
                    self.assertEqual(kwargs['input'], b'{"fixture":true}')
                return subprocess.CompletedProcess(argv, 0)
            with self.subTest(answer=answer), patch.dict(os.environ, {'WAYLAND_DISPLAY': 'fixture'}, clear=True), \
                    patch.object(access.shutil, 'which', side_effect=which), \
                    patch.object(access.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu'}), \
                    patch.object(access.os, 'geteuid', return_value=0), patch('builtins.input', return_value=answer), \
                    patch.object(access.subprocess, 'run', side_effect=run):
                if answer == 'n':
                    with self.assertRaisesRegex(ValueError, 'declined'):
                        access.copy_clipboard('{"fixture":true}', 'show-server-trust')
                    self.assertEqual(calls, [])
                else:
                    access.copy_clipboard('{"fixture":true}', 'show-server-trust')
                    self.assertEqual(calls, [['apt-get', 'install', '-y', 'wl-clipboard'], ['wl-copy']])

    def test_server_clipboard_noninteractive_and_installation_failure(self):
        with patch.dict(os.environ, {'DISPLAY': ':0'}, clear=True), \
                patch.object(access.shutil, 'which', side_effect=lambda tool: None if tool == 'xclip' or tool == 'xsel' else '/fixture/' + tool), \
                patch.object(access.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu'}), \
                patch.object(access.sys.stdin, 'isatty', return_value=False), patch('builtins.input') as prompt, \
                self.assertRaisesRegex(ValueError, 'Non-interactive.*show-server-trust'):
            access.copy_clipboard('{}', 'show-server-trust')
        prompt.assert_not_called()
        with patch.dict(os.environ, {'DISPLAY': ':0'}, clear=True), \
                patch.object(access.shutil, 'which', side_effect=lambda tool: None if tool in ('xclip', 'xsel') else '/fixture/' + tool), \
                patch.object(access.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu'}), \
                patch.object(access.os, 'geteuid', return_value=0), patch('builtins.input', return_value='y'), \
                patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess(['apt-get'], 1)) as run, \
                self.assertRaisesRegex(ValueError, 'installation failed'):
            access.copy_clipboard('{}', 'show-server-trust')
        self.assertEqual(run.call_count, 1)

    def test_server_copy_errors_and_headless_never_report_success(self):
        # Destination has no trust yet: copy must refuse before clipboard access.
        with patch.object(access, 'copy_clipboard') as copy, self.assertRaises(ValueError):
            access.server_trust('copy-server-trust', self.inventory)
        copy.assert_not_called()
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'headless.*show-server-trust'):
            access.copy_clipboard('{}', 'show-server-trust')
        for failure in (OSError(), subprocess.TimeoutExpired(['wl-copy'], 10), None):
            with patch.object(access, 'clipboard_command', return_value=['wl-copy']), \
                    patch.object(access.subprocess, 'run', side_effect=failure,
                                 return_value=subprocess.CompletedProcess(['wl-copy'], 1)), \
                    self.assertRaisesRegex(ValueError, 'Clipboard copy failed'):
                access.copy_clipboard('{}', 'show-server-trust')
        with patch.object(access, 'load_host', return_value=('portfolio', self.host, self.old_port, 'root', '/usr/bin/python3')), \
                patch.object(access, 'copy_clipboard', side_effect=ValueError('Clipboard copy failed')), self.assertRaises(ValueError):
            access.server_trust('copy-server-trust', self.inventory)
        self.assertNotIn('copied', self.output.getvalue())


if __name__ == '__main__':
    unittest.main()
