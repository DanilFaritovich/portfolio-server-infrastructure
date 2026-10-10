"""Exercise local operator Make wrappers with isolated controller fixtures."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).parents[1]
PUBLIC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'


class CLIMakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='make cli home ')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.bin = self.home / 'fake bin'
        self.bin.mkdir(mode=0o700)
        self.calls = self.home / 'calls'
        self.inventory = self.home / 'inventory with spaces.yml'
        self.key = self.home / '.ssh/portfolio-infra/person_ed25519'
        self.controller_key = self.home / '.ssh/controller keys/automation_ed25519'
        self.host = 'fixture.example.test'
        self.port = 2244
        values = {'ansible_host': self.host, 'ansible_port': self.port,
                  'bootstrap_login_user': 'root', 'ansible_user': 'automation',
                  'ansible_private_key_file': str(self.controller_key)}
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {
            'bootstrap': {'hosts': {'portfolio': values}}}}}))
        self.pair(self.key)
        self.pair(self.controller_key)
        trust_dir = self.home / '.ssh'
        trust_dir.mkdir(mode=0o700, exist_ok=True)
        trust_dir.chmod(0o700)
        (trust_dir / 'known_hosts').write_text(f'[{self.host}]:{self.port} {PUBLIC}\n')
        (trust_dir / 'known_hosts').chmod(0o600)
        self.executable('ssh-keygen', """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_CALLS"
case " $* " in
  *' -F '*) exit 0 ;;
  *' -l '*) printf '%s\\n' '256 SHA256:synthetic (ED25519)' ;;
  *) exit 2 ;;
esac
""")
        self.executable('ssh', """#!/bin/sh
printf '%s\\n' 'unexpected ssh invocation' >> "$FAKE_CALLS"
exit 97
""")
        self.executable('ssh-add', """#!/bin/sh
printf 'ssh-add %s\\n' "$*" >> "$FAKE_CALLS"
if [ "$1" = '-l' ]; then
  if [ -f "$AGENT_IDENTITIES" ]; then cat "$AGENT_IDENTITIES"; exit 0; fi
  exit 1
fi
printf '%s\\n' '256 SHA256:synthetic (ED25519)' > "$AGENT_IDENTITIES"
exit 0
""")

    def executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def pair(self, key):
        key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        key.touch(mode=0o600)
        key.chmod(0o600)
        Path(str(key) + '.pub').write_text(PUBLIC + ' synthetic-public\n')
        Path(str(key) + '.pub').chmod(0o644)

    def make(self, target, **extra):
        env = os.environ.copy()
        env.update({'HOME': str(self.home), 'PATH': str(self.bin) + os.pathsep + env['PATH'],
                    'INVENTORY': str(self.inventory), 'FAKE_CALLS': str(self.calls),
                    'AGENT_IDENTITIES': str(self.home / 'agent-identities'),
                    'HUMAN_USER': 'person', 'HUMAN_KEY': '', 'KEY_NAME': '',
                    'AUTOMATION_KEY': ''})
        env.update({key: str(value) for key, value in extra.items()})
        return subprocess.run(['make', '--no-print-directory', target], cwd=ROOT, env=env,
                              text=True, capture_output=True, check=False)

    def test_generate_existing_pair_preserves_metadata_without_terminal(self):
        before = (self.key.stat().st_mode, self.key.stat().st_mtime_ns,
                  Path(str(self.key) + '.pub').stat().st_mode,
                  Path(str(self.key) + '.pub').stat().st_mtime_ns)
        result = self.make('generate-user-key', HUMAN_KEY=self.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        after = (self.key.stat().st_mode, self.key.stat().st_mtime_ns,
                 Path(str(self.key) + '.pub').stat().st_mode,
                 Path(str(self.key) + '.pub').stat().st_mtime_ns)
        self.assertEqual(after, before)
        self.assertIn('Existing human person key preserved.', result.stdout)
        self.assertNotIn('unexpected ssh invocation', self.calls.read_text() if self.calls.exists() else '')

    def test_show_public_key_prints_key_and_sha256_fingerprint(self):
        result = self.make('show-public-key', KEY_NAME='person_ed25519')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         [PUBLIC, 'SHA256 fingerprint: SHA256:synthetic'])
        self.assertNotIn('unexpected ssh invocation', self.calls.read_text())

    def test_copy_public_key_wrapper_uses_mock_clipboard_without_ssh(self):
        self.executable('wl-copy', '#!/bin/sh\ncat > "$FAKE_CLIPBOARD"\n')
        clipboard = self.home / 'clipboard'
        result = self.make('copy-public-key', HUMAN_KEY=self.key, WAYLAND_DISPLAY='fixture',
                           FAKE_CLIPBOARD=clipboard)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(clipboard.read_text(), Path(str(self.key) + '.pub').read_text())
        self.assertIn('SHA256:synthetic', result.stdout)
        self.assertNotIn('unexpected ssh invocation', self.calls.read_text())

    def test_show_controller_uses_selected_inventory_without_ssh(self):
        result = self.make('show-controller')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ansible_user: automation', result.stdout)
        self.assertIn(f'server: {self.host}', result.stdout)
        self.assertIn(f'port: {self.port}', result.stdout)
        self.assertIn(f'key: {self.controller_key}', result.stdout)
        self.assertIn(f'automation@{self.host}', result.stdout)
        self.assertNotIn('unexpected ssh invocation', self.calls.read_text())

    def test_missing_human_user_fails_without_ssh(self):
        result = self.make('show-public-key', HUMAN_USER='')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HUMAN_USER', result.stderr)
        self.assertFalse(self.calls.exists(), 'validation must fail before external SSH tools run')

    def test_load_user_key_uses_only_local_mocked_ssh_add(self):
        (self.home / 'agent-identities').write_text('256 SHA256:synthetic (ED25519)\n')
        result = self.make('load-user-key', HUMAN_KEY=self.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text()
        self.assertIn('ssh-add -l -E sha256', calls)
        self.assertNotIn('ssh-add -q ' + str(self.key), calls)
        self.assertIn('SSH key already loaded in ssh-agent.', result.stdout)
        self.assertNotIn('unexpected ssh invocation', calls)
        self.assertNotIn('ansible-playbook', calls)


if __name__ == '__main__':
    unittest.main()
