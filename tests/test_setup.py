"""Offline shell setup tests with isolated PATH and fake release/uv commands."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'fixture-bin'
        self.bin.mkdir()
        (self.root / 'scripts').mkdir()
        (self.root / 'inventories').mkdir()
        for name in ('setup.sh', 'install-uv.sh', 'install-actionlint.sh', 'access.py'):
            shutil.copy(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        shutil.copy(ROOT / 'inventories/production.example.yml', self.root / 'inventories/production.example.yml')
        for name in ('requirements-dev.txt', 'requirements.yml'):
            shutil.copy(ROOT / name, self.root / name)
        self.log = self.root / 'calls'
        self.env = dict(os.environ, PATH=str(self.bin), CALL_LOG=str(self.log),
                        FIXTURE_ROOT=str(self.root), FIXTURE_PYTHON=sys.executable)
        for name in ('sh', 'make', 'tar', 'gzip', 'mkdir', 'mktemp', 'chmod', 'mv', 'rm', 'head', 'cp', 'cat'):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ('ssh', 'ssh-keygen', 'scp', 'sftp'):
            self.executable(self.bin / name, 'exit 99')
        self.executable(self.bin / 'uname', 'case "$1" in -s) echo Linux ;; -m) echo "${FIXTURE_ARCH:-x86_64}" ;; esac')
        self.executable(self.bin / 'sha256sum', '''cat >/dev/null
printf 'checksum\n' >> "$CALL_LOG"
[ "${CHECKSUM_FAIL:-0}" != 1 ]''')
        self.executable(self.bin / 'curl', '''printf 'download\n' >> "$CALL_LOG"
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then cp "$FIXTURE_ROOT/release.tar.gz" "$2"; exit; fi
    shift
done
exit 1''')
        self.version = re.search(r'^version=(.+)$', (ROOT / 'scripts/install-uv.sh').read_text(), re.M)[1]
        self.uv_body = '''printf 'uv %s\n' "$*" >> "$CALL_LOG"
if [ "$1" = --version ]; then echo "uv ${UV_VERSION} (fixture build)"; exit "${UV_EXIT:-0}"; fi
[ "$1" = --no-config ] || exit 90
shift
case "$1 $2" in
    'python find')
        [ -x "$UV_PYTHON_INSTALL_DIR/fixture/bin/python3.12" ] || exit 1
        printf '%s/fixture/bin/python3.12\n' "$UV_PYTHON_INSTALL_DIR"
        ;;
    'python install')
        mkdir -p "$UV_PYTHON_INSTALL_DIR/fixture/bin"
        cp "$FIXTURE_ROOT/python-stub" "$UV_PYTHON_INSTALL_DIR/fixture/bin/python3.12"
        ;;
    'venv --python')
        mkdir -p .venv/bin
        cp "$FIXTURE_ROOT/python-stub" .venv/bin/python
        cp "$FIXTURE_ROOT/galaxy-stub" .venv/bin/ansible-galaxy
        ;;
    'pip install') ;;
    *) exit 91 ;;
esac'''
        self.env['UV_VERSION'] = self.version
        self.executable(self.root / 'python-stub', '''printf 'python %s\n' "$*" >> "$CALL_LOG"
if [ "$1" = -c ]; then [ "${PYTHON_BAD:-0}" != 1 ]; exit; fi
exec "$FIXTURE_PYTHON" "$@"''')
        self.executable(self.root / 'galaxy-stub', 'printf "galaxy %s\n" "$*" >> "$CALL_LOG"')
        self.executable(self.root / 'actionlint-stub', 'echo 1.7.7')
        (self.root / '.tools/bin').mkdir(parents=True)
        shutil.copy(self.root / 'actionlint-stub', self.root / '.tools/bin/actionlint')
        self.archive()

    def executable(self, path, body):
        path.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
        path.chmod(0o755)

    def archive(self):
        release = self.root / 'release'
        release.mkdir(exist_ok=True)
        for arch in ('x86_64', 'aarch64'):
            target = release / f'uv-{arch}-unknown-linux-gnu'
            target.mkdir(exist_ok=True)
            self.executable(target / 'uv', self.uv_body)
        with tarfile.open(self.root / 'release.tar.gz', 'w:gz') as archive:
            for target in release.iterdir():
                archive.add(target, arcname=target.name)

    def run_setup(self, mode='setup'):
        result = subprocess.run(['/bin/sh', 'scripts/setup.sh', mode], cwd=self.root,
                                env=self.env, capture_output=True, text=True)
        return result

    def calls(self):
        return self.log.read_text() if self.log.exists() else ''

    def test_fresh_setup_without_system_python_and_repeated_setup(self):
        self.assertIsNone(shutil.which('python3.12', path=str(self.bin)))
        self.assertIsNone(shutil.which('uv', path=str(self.bin)))
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertLess(calls.index('checksum'), calls.index('uv --version'))
        self.assertIn('uv --no-config python install 3.12 --no-bin', calls)
        self.assertIn('--system --managed-python --no-python-downloads', calls)
        self.assertIn(f'uv --no-config venv --python {self.root}/.tools/python/', calls)
        inventory = self.root / 'inventories/production.yml'
        inventory.write_text('existing operator configuration')
        self.log.unlink()
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(inventory.read_text(), 'existing operator configuration')
        for forbidden in ('download\n', 'python install', 'venv --python'):
            self.assertNotIn(forbidden, self.calls())

    def test_deps_does_not_create_inventory(self):
        result = self.run_setup('deps')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'inventories/production.yml').exists())

    def test_archive_checksum_failure_stops_before_uv_execution(self):
        self.env['CHECKSUM_FAIL'] = '1'
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum verification failed', result.stderr)
        self.assertNotIn('uv --version', self.calls())
        self.assertFalse((self.root / '.tools/bin/uv').exists())
        self.assertFalse((self.root / 'inventories/production.yml').exists())

    def test_downloaded_version_failure_stops(self):
        self.env['UV_VERSION'] = 'unexpected'
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unexpected version', result.stderr)
        self.assertNotIn('python install', self.calls())
        self.assertFalse((self.root / '.tools/bin/uv').exists())

    def test_failed_version_command_stops_even_with_matching_output(self):
        self.env['UV_EXIT'] = '1'
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('version check failed', result.stderr)
        self.assertNotIn('python install', self.calls())
        self.assertFalse((self.root / '.tools/bin/uv').exists())

    def test_existing_wrong_uv_and_python_stop(self):
        self.executable(self.root / '.tools/bin/uv', 'echo "uv incompatible"')
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Existing local uv', result.stderr)
        self.assertNotIn('download', self.calls())
        (self.root / '.tools/bin/uv').unlink()
        self.env['PYTHON_BAD'] = '1'
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('managed Python must be 3.12', result.stderr)
        self.assertFalse((self.root / '.venv').exists())

    def test_missing_prerequisite_stops_before_download(self):
        (self.bin / 'curl').unlink()
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing curl', result.stderr)
        self.assertEqual(self.calls(), '')

    def test_arm64_archive(self):
        self.env['FIXTURE_ARCH'] = 'aarch64'
        result = self.run_setup('deps')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / '.tools/bin/uv').exists())


if __name__ == '__main__':
    unittest.main()
