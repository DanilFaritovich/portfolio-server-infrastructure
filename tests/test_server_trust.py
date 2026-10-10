"""Offline host-trust transfer using synthetic public keys and local OpenSSH parsing."""

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from tests.test_cli_connections import access, PUBLIC, ROOT


class ServerTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='server trust ')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.path = self.home / '.ssh/known_hosts'
        self.inventory = self.home / 'inventory.yml'
        self.host = 'fixture.example.test'
        self.port = 2244
        values = {'ansible_host': self.host, 'ansible_port': self.port, 'ansible_user': 'root'}
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {'portfolio': values}}}}}))
        self.fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(PUBLIC.split()[1])).digest()).decode().rstrip('=')
        self.data = {'version': 1, 'host': self.host, 'port': self.port,
                     'keys': [{'public_key': PUBLIC, 'fingerprint': self.fingerprint}]}
        self.calls = []
        self.native_run = subprocess.run
        def run(command, **kwargs):
            self.calls.append(command)
            self.assertEqual(command[0], 'ssh-keygen', 'No network or private-key operations permitted')
            self.assertTrue('-F' in command or '-l' in command)
            return self.native_run(command, **kwargs)
        for mock in (patch.object(access.Path, 'home', return_value=self.home),
                     patch.object(access.sys.stdin, 'isatty', return_value=True),
                     patch.object(access.subprocess, 'run', side_effect=run),
                     patch.object(access, 'managed_access', side_effect=AssertionError('No private key lookup')),
                     patch.object(access, 'prerequisites', side_effect=AssertionError('No Ansible required'))):
            mock.start()
            self.addCleanup(mock.stop)

    def write_trust(self, content):
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        self.path.write_bytes(content.encode())
        self.path.chmod(0o600)

    def import_trust(self, answers=None):
        with patch('builtins.input', side_effect=answers or [json.dumps(self.data), 'yes']), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.server_trust('trust-server', self.inventory)
        return output.getvalue()

    def test_export_plain_and_hashed_nonstandard_port(self):
        name = f'[{self.host}]:{self.port}'
        salt = b'01234567890123456789'
        hashed = '|1|' + base64.b64encode(salt).decode() + '|' + base64.b64encode(hmac.digest(salt, name.encode(), 'sha1')).decode()
        for identity in (name, hashed):
            with self.subTest(identity=identity):
                self.write_trust(f'{identity} {PUBLIC}\n')
                before = self.path.read_bytes()
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    access.server_trust('show-server-trust', self.inventory)
                self.assertEqual(json.loads(output.getvalue().splitlines()[-1]), self.data)
                self.assertIn(self.fingerprint, output.getvalue())
                self.assertEqual(self.path.read_bytes(), before)

    def test_import_creates_safe_trust_without_local_identity(self):
        output = self.import_trust()
        self.assertEqual(self.path.read_text(), f'[{self.host}]:{self.port} {PUBLIC}\n')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertIn('Host trust saved', output)
        self.assertIn('Strict host-key checking remains enabled', output)
        access.known_host(self.host, self.port)

    def test_import_unblocks_show_controller_with_strict_existing_transport(self):
        key = self.home / '.ssh/controller_ed25519'
        key.parent.mkdir(mode=0o700)
        key.touch(mode=0o600)  # Synthetic metadata only; no private key bytes.
        public = Path(str(key) + '.pub')
        public.write_text(PUBLIC + '\n')
        public.chmod(0o600)
        with patch.object(access, 'managed_access', return_value=('automation', key)):
            with self.assertRaisesRegex(ValueError, 'Existing known_hosts trust is required'):
                access.cli_connection('show-controller', self.inventory)
            self.import_trust()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                access.cli_connection('show-controller', self.inventory)
        self.assertIn('ansible_user: automation', output.getvalue())
        self.assertIn('StrictHostKeyChecking=yes', output.getvalue())
        self.assertIn('GlobalKnownHostsFile=/dev/null', output.getvalue())
        self.assertIn('known_hosts', output.getvalue())

    def test_repeat_and_hashed_repeat_preserve_bytes_and_inode(self):
        self.import_trust()
        for hashed in (False, True):
            if hashed:
                salt = b'01234567890123456789'
                name = f'[{self.host}]:{self.port}'
                identity = '|1|' + base64.b64encode(salt).decode() + '|' + base64.b64encode(hmac.digest(salt, name.encode(), 'sha1')).decode()
                self.write_trust(f'{identity} {PUBLIC}\n')
            before = access.trust_snapshot(self.path)
            self.assertIn('already present', self.import_trust())
            self.assertEqual(access.trust_snapshot(self.path), before)

    def test_preserve_unrelated_entries_comments_and_missing_final_newline(self):
        before = '# existing comment\nother.example.test ' + PUBLIC
        self.write_trust(before)
        self.import_trust()
        self.assertEqual(self.path.read_text(), before + f'\n[{self.host}]:{self.port} {PUBLIC}\n')

    def test_multiple_algorithms_export_and_additive_import(self):
        def wire(value):
            return len(value).to_bytes(4, 'big') + value
        blob = wire(b'ssh-rsa') + wire(b'\x01\x00\x01') + wire(b'\x00\x80' + b'\x01' * 255)
        public = 'ssh-rsa ' + base64.b64encode(blob).decode()
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        self.data['keys'].append({'public_key': public, 'fingerprint': fingerprint})
        self.write_trust(f'[{self.host}]:{self.port} {PUBLIC}\n')
        self.import_trust()
        self.assertEqual(self.path.read_text().count(PUBLIC), 1)
        self.assertEqual(self.path.read_text().count(public), 1)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            access.server_trust('show-server-trust', self.inventory)
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1]), self.data)

    def test_default_port_and_ipv6_inventory_identity(self):
        for host, port, name in (('192.0.2.10', 22, '192.0.2.10'), ('2001:db8::10', 2200, '[2001:db8::10]:2200')):
            with self.subTest(host=host), patch.object(access, 'load_host', return_value=('portfolio', host, port, 'root', '/usr/bin/python3')):
                self.data.update(host=host, port=port)
                self.path.unlink(missing_ok=True)
                self.import_trust()
                self.assertEqual(self.path.read_text(), name + ' ' + PUBLIC + '\n')
                access.known_host(host, port)

    def test_decline_eof_interrupt_never_create_known_hosts(self):
        for answers in ([json.dumps(self.data), ''], [json.dumps(self.data), 'no'],
                        [EOFError()], [KeyboardInterrupt()], [json.dumps(self.data), EOFError()],
                        [json.dumps(self.data), KeyboardInterrupt()]):
            with self.subTest(answers=answers), self.assertRaisesRegex(ValueError, 'declined|cancelled'):
                self.import_trust(answers)
            self.assertFalse(self.path.parent.exists())

    def test_noninteractive_import_never_waits_or_writes(self):
        with patch.object(access.sys.stdin, 'isatty', return_value=False), \
                patch('builtins.input', side_effect=AssertionError('No prompt')), \
                self.assertRaisesRegex(ValueError, 'interactive terminal'):
            access.server_trust('trust-server', self.inventory)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.calls)

    def test_invalid_transfer_mismatch_and_private_material_are_rejected(self):
        cases = ['not JSON', 'PRIVATE KEY', '{}']
        for change in ({'host': 'different.example.test'}, {'port': 22}, {'port': True}, {'version': 2},
                       {'keys': []}, {'keys': [self.data['keys'][0]] * 2},
                       {'keys': [{'public_key': PUBLIC, 'fingerprint': 'SHA256:wrong'}]},
                       {'keys': [{'public_key': 'ssh-ed25519 AAAA', 'fingerprint': self.fingerprint}]},
                       {'keys': [{'public_key': PUBLIC + '\n', 'fingerprint': self.fingerprint}]},
                       {'keys': [{'public_key': 'command="id" ' + PUBLIC, 'fingerprint': self.fingerprint}]}):
            cases.append(json.dumps(self.data | change))
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.import_trust([text])
            self.assertFalse(self.path.exists())

    def test_conflicting_and_marked_existing_trust_blocks_without_confirmation(self):
        blob = base64.b64decode(PUBLIC.split()[1])
        other = 'ssh-ed25519 ' + base64.b64encode(blob[:-1] + b'\x01').decode()
        for record in (other, PUBLIC + '\n' + f'[{self.host}]:{self.port} ' + other,
                       PUBLIC):
            for marker in ('', '@revoked ', '@cert-authority '):
                if record == PUBLIC and not marker:
                    continue
                self.write_trust(marker + f'[{self.host}]:{self.port} {record}\n')
                before = self.path.read_bytes()
                with self.subTest(marker=marker, record=record), self.assertRaisesRegex(ValueError, 'conflict|Conflicting|unsupported'):
                    self.import_trust([json.dumps(self.data)])
                self.assertEqual(self.path.read_bytes(), before)

    def test_unsafe_paths_permissions_hardlinks_and_nonregular_files_block(self):
        self.write_trust('other.example.test ' + PUBLIC + '\n')
        for path in (self.path, self.path.parent):
            original = path.stat().st_mode & 0o777
            path.chmod(0o777)
            with self.assertRaises(ValueError):
                self.import_trust()
            path.chmod(original)
        linked = self.home / 'linked'
        os.link(self.path, linked)
        with self.assertRaisesRegex(ValueError, 'hardlinks'):
            self.import_trust()
        linked.unlink()
        self.path.unlink()
        self.path.symlink_to(self.home / 'missing')
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            self.import_trust()
        self.path.unlink()
        os.mkfifo(self.path, mode=0o600)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.import_trust()

    def test_concurrent_change_during_confirmation_stops_without_overwrite(self):
        self.write_trust('# original\n')
        def answer(prompt):
            if prompt.startswith('Host trust data:'):
                return json.dumps(self.data)
            self.path.write_text('# changed externally\n')
            return 'yes'
        with patch('builtins.input', side_effect=answer), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(ValueError, 'changed since review'):
            access.server_trust('trust-server', self.inventory)
        self.assertEqual(self.path.read_text(), '# changed externally\n')

    def test_atomic_replace_failure_preserves_original_and_removes_temp(self):
        self.write_trust('# original\n')
        with patch.object(access.os, 'replace', side_effect=OSError('mock failure')), self.assertRaises(OSError):
            self.import_trust()
        self.assertEqual(self.path.read_text(), '# original\n')
        self.assertFalse(list(self.path.parent.glob('.known_hosts-*')))

    def test_concurrent_write_during_staging_stops_and_cleans_temp(self):
        self.write_trust('# original\n')
        def concurrent_write(descriptor):
            self.path.write_text('# changed during staging\n')
        with patch.object(access.os, 'fsync', side_effect=concurrent_write), \
                self.assertRaisesRegex(ValueError, 'changed during write'):
            self.import_trust()
        self.assertEqual(self.path.read_text(), '# changed during staging\n')
        self.assertFalse(list(self.path.parent.glob('.known_hosts-*')))

    def test_local_openssh_error_never_reports_success(self):
        with patch.object(access.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'failed')), \
                self.assertRaisesRegex(ValueError, 'Invalid public SSH host key'):
            self.import_trust()
        self.assertFalse(self.path.exists())
        with patch.object(access.sys, 'argv', ['access.py', 'trust-server', '--inventory', str(self.inventory)]), \
                patch.object(access.os, 'umask'), \
                patch('builtins.input', side_effect=[json.dumps(self.data), 'yes']), \
                patch.object(access.os, 'replace', side_effect=OSError('mock failure')), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(access.main(), 1)
        self.assertIn('Local host-trust operation failed', error.getvalue())
        self.assertNotIn('Host trust saved', output.getvalue())

    def test_missing_source_explains_admin_or_provider_console(self):
        for content in (None, 'other.example.test ' + PUBLIC + '\n'):
            if content:
                self.write_trust(content)
            with self.assertRaisesRegex(ValueError, 'administrator.*VPS provider console'):
                access.server_trust('show-server-trust', self.inventory)

    def test_make_export_and_noninteractive_import(self):
        self.write_trust(f'[{self.host}]:{self.port} {PUBLIC}\n')
        env = os.environ | {'HOME': str(self.home), 'INVENTORY': str(self.inventory)}
        result = self.native_run(['make', '--no-print-directory', 'show-server-trust'], cwd=ROOT,
                                 env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[-1]), self.data)
        before = self.path.read_bytes()
        result = self.native_run(['make', '--no-print-directory', 'trust-server'], cwd=ROOT,
                                 env=env, text=True, capture_output=True, check=False, input=json.dumps(self.data))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interactive terminal', result.stderr)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
