"""Offline check regressions using synthetic projects, never real inventories."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('Makefile', '.ansible-lint', '.yamllint.yml', 'ansible.cfg', 'collections.yml'):
            shutil.copy(ROOT / name, self.root / name)
        (self.root / 'scripts').mkdir()
        shutil.copy(ROOT / 'scripts/check-step.sh', self.root / 'scripts/check-step.sh')
        (self.root / 'inventories').mkdir()
        shutil.copy(ROOT / 'inventories/production.example.yml',
                    self.root / 'inventories/production.example.yml')
        (self.root / 'playbooks').mkdir()
        tasks = self.root / 'roles/bootstrap_user/tasks'
        tasks.mkdir(parents=True)
        (tasks / 'main.yml').write_text('---\n- name: Fixture task\n  ansible.builtin.debug:\n    msg: fixture\n')
        self.playbook = self.root / 'playbooks/fixture.yml'

    def lint(self, module):
        self.playbook.write_text(
            f'---\n- name: Offline fixture\n  hosts: all\n  tasks:\n'
            f'    - name: Fixture task\n      {module}:\n        msg: fixture\n')
        # Promote deprecations to errors in this fixture to catch regressions.
        environment = dict(os.environ, ANSIBLE_CONFIG=str(self.root / 'ansible.cfg'),
                           PYTHONWARNINGS='error::DeprecationWarning')
        environment.pop('ANSIBLE_LINT_NODEPS', None)
        return subprocess.run(['make', 'lint-ansible', f'VENV={ROOT / ".venv"}'],
                              cwd=self.root, env=environment, capture_output=True, text=True)

    def test_offline_lint_without_setup_warnings(self):
        result = self.lint('ansible.builtin.debug')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('WARNING', result.stderr)
        self.assertNotIn('DeprecationWarning', result.stderr)

    def test_missing_collection_still_fails_offline_lint(self):
        result = self.lint('fixture_missing.collection.module')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('syntax-check', result.stdout + result.stderr)
        self.assertIn('fixture_missing.collection.module', result.stdout + result.stderr)

    def test_make_sets_tool_path_and_preserves_warning_and_failure(self):
        binaries = self.root / '.venv/bin'
        binaries.mkdir(parents=True)
        tool = binaries / 'ansible-lint'
        tool.write_text('''#!/bin/sh
set -eu
[ "$1" = --offline ]
[ "$ANSIBLE_INVENTORY" = "$PWD/inventories/production.example.yml" ]
[ "${PATH%%:*}" = "$PWD/.venv/bin" ]
[ "$(command -v ansible-playbook)" = "$PWD/.venv/bin/ansible-playbook" ]
echo 'WARNING fixture diagnostic' >&2
exit 17
''')
        tool.chmod(0o755)
        playbook = binaries / 'ansible-playbook'
        playbook.write_text('#!/bin/sh\nexit 99\n')
        playbook.chmod(0o755)
        # Simulate a different activated environment; Make must prefer its own tools.
        foreign = self.root / 'foreign/bin'
        foreign.mkdir(parents=True)
        shutil.copy(playbook, foreign / 'ansible-playbook')
        result = subprocess.run(['make', 'lint-ansible'], cwd=self.root,
                                env=dict(os.environ, PATH=f'{foreign}:{os.environ["PATH"]}'),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('WARNING fixture diagnostic', result.stderr)
        # Make translates the error label according to the caller's locale.
        self.assertRegex(result.stderr, r'\b17\b')

    def mock_check_tools(self):
        for name in ('yamllint', 'ansible-lint', 'ansible-playbook', 'python', 'actionlint'):
            directory = '.tools/bin' if name == 'actionlint' else '.venv/bin'
            tool = self.root / directory / name
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text('''#!/bin/sh
echo "${0##*/} $*" >> "$CHECK_CALLS"
echo 'routine successful output'
if [ "${0##*/}" = "${FAIL_TOOL:-}" ]; then
    echo 'WARNING useful fixture diagnostic' >&2
    exit 17
fi
if [ "${0##*/}" = python ]; then
    echo 'Ran 7 tests in 0.001s' >&2
    echo 'OK' >&2
fi
''')
            tool.chmod(0o755)

    def test_check_is_compact_and_dispatches_only_offline_tools(self):
        self.mock_check_tools()
        calls = self.root / 'calls'
        result = subprocess.run(['make', '--no-print-directory', 'check'], cwd=self.root, stdin=subprocess.DEVNULL,
                                env=dict(os.environ, CHECK_CALLS=str(calls)),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')
        lines = result.stdout.splitlines()
        self.assertEqual([line.split(' PASS')[0].strip() for line in lines[:5]],
                         ['YAML lint', 'Ansible lint', 'Syntax check', 'Actions lint', 'Unit tests'])
        self.assertIn('PASS (7 tests)', lines[4])
        self.assertEqual(lines[5:], ['', 'make check: PASSED'])
        commands = calls.read_text().splitlines()
        self.assertEqual(len(commands), 20)
        self.assertTrue(all(command.startswith(('yamllint ', 'ansible-lint --offline ',
                                                'ansible-playbook --syntax-check ',
                                                'actionlint ', 'python -m unittest '))
                            for command in commands))
        self.assertIn('python -m unittest discover -s tests -b -q', commands)
        self.assertNotIn('scripts/e2e.py', calls.read_text())

    def test_check_failure_retains_diagnostics_and_stops_later_steps(self):
        self.mock_check_tools()
        calls = self.root / 'calls'
        result = subprocess.run(['make', 'check'], cwd=self.root, stdin=subprocess.DEVNULL,
                                env=dict(os.environ, CHECK_CALLS=str(calls), FAIL_TOOL='ansible-lint'),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Ansible lint', result.stderr)
        self.assertIn('FAIL', result.stderr)
        self.assertIn('WARNING useful fixture diagnostic', result.stderr)
        self.assertIn('17', result.stderr)
        self.assertNotIn('PASSED', result.stdout)
        self.assertEqual(len(calls.read_text().splitlines()), 2)

    def test_buffered_unittest_failure_retains_name_traceback_and_output(self):
        fixture = self.root / 'test_diagnostic.py'
        fixture.write_text('''import sys
import unittest

class DiagnosticTests(unittest.TestCase):
    def test_failure_diagnostic(self):
        print('fixture stdout detail')
        print('fixture stderr detail', file=sys.stderr)
        self.fail('fixture assertion detail')
''')
        result = subprocess.run(['sh', 'scripts/check-step.sh', 'Unit tests',
                                 str(ROOT / '.venv/bin/python'), '-m', 'unittest',
                                 'discover', '-s', '.', '-b', '-q'],
                                cwd=self.root, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        for diagnostic in ('test_failure_diagnostic', 'Traceback', 'fixture assertion detail',
                           'fixture stdout detail', 'fixture stderr detail', 'FAILED (failures=1)'):
            self.assertIn(diagnostic, result.stderr)
        self.assertNotIn('PASS', result.stdout)

    def test_successful_check_preserves_warnings(self):
        result = subprocess.run(['sh', 'scripts/check-step.sh', 'Fixture check', 'sh', '-c',
                                 "echo 'WARNING successful fixture diagnostic' >&2"],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS', result.stdout)
        self.assertIn('WARNING successful fixture diagnostic', result.stderr)


if __name__ == '__main__':
    unittest.main()
