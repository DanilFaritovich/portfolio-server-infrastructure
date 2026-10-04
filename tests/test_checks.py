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


if __name__ == '__main__':
    unittest.main()
