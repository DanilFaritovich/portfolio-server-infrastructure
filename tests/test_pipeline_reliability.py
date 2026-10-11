"""Offline failure boundaries using native CLI modules and local Ansible fixtures."""

import contextlib
import io
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from portfolio_cli import ansible, cli, human_access, operations, provisioning


def hold_lock(home, ready):
    with patch.object(ansible.Path, 'home', return_value=Path(home)), ansible.pipeline_lock():
        ready.set()
        # Parent terminates this process to simulate an uncatchable interruption.
        ready.wait()
        multiprocessing.Event().wait(30)


class PipelineLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.lock = self.home / '.portfolio-infrastructure.pipeline.lock'
        self.patch = patch.object(ansible.Path, 'home', return_value=self.home)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_process_contention_and_uncatchable_interruption_release_same_inode(self):
        context = multiprocessing.get_context('fork')
        ready = context.Event()
        process = context.Process(target=hold_lock, args=(str(self.home), ready))
        process.start()
        try:
            self.assertTrue(ready.wait(5))
            inode = self.lock.stat().st_ino
            with self.assertRaisesRegex(ValueError, 'Another server stage'):
                with ansible.pipeline_lock():
                    self.fail('Concurrent stage acquired the lock')
        finally:
            process.terminate()
            process.join(5)
        self.assertFalse(process.is_alive())
        with ansible.pipeline_lock():
            self.assertEqual(self.lock.stat().st_ino, inode)
        self.assertEqual(self.lock.stat().st_mode & 0o777, 0o600)

    def test_exception_releases_lock_without_unlinking(self):
        with self.assertRaises(KeyboardInterrupt), ansible.pipeline_lock():
            raise KeyboardInterrupt
        with ansible.pipeline_lock():
            self.assertTrue(self.lock.is_file())

    def test_unsafe_lock_paths_fail_closed(self):
        self.home.chmod(0o777)
        try:
            with self.assertRaisesRegex(ValueError, 'Unsafe local pipeline lock directory'), ansible.pipeline_lock():
                pass
            self.assertFalse(self.lock.exists())
        finally:
            self.home.chmod(0o700)
        target = self.home / 'unrelated'
        target.write_text('preserved')
        self.lock.symlink_to(target)
        with self.assertRaises(OSError), ansible.pipeline_lock():
            pass
        self.assertEqual(target.read_text(), 'preserved')
        self.lock.unlink()
        self.lock.touch(mode=0o644)
        self.lock.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'Unsafe local pipeline lock'), ansible.pipeline_lock():
            pass
        self.lock.chmod(0o600)
        os.link(self.lock, self.home / 'hardlink')
        with self.assertRaisesRegex(ValueError, 'Unsafe local pipeline lock'), ansible.pipeline_lock():
            pass

    def test_cli_contention_blocks_dispatch_and_interrupt_returns_handled_failure(self):
        with patch.object(sys, 'argv', ['access.py', 'docker-host']), \
                patch.object(cli, 'live') as run, contextlib.redirect_stderr(io.StringIO()) as output:
            with ansible.pipeline_lock():
                self.assertEqual(cli.main(), 1)
            run.assert_not_called()
            run.side_effect = KeyboardInterrupt
            self.assertEqual(cli.main(), 1)
            self.assertIn('Remote work may already', output.getvalue())
        with ansible.pipeline_lock():
            pass


class NativeStageTests(unittest.TestCase):
    def stage_fixture(self, stack, module):
        for name, value in (
                ('managed_access', ('controller', Path('/fixture.key'))),
                ('load_host', ('portfolio', 'fixture.test', 2222, 'root', '/usr/bin/python3')),
                ('hardening_inputs', {'ssh_listen_ports': [2222], 'ssh_verify_ports': [2222],
                                     'firewall_allowed_tcp_ports': []})):
            stack.enter_context(patch.object(module, name, return_value=value))
        for name in ('prerequisites', 'check_key', 'known_host'):
            stack.enter_context(patch.object(module, name))
        stack.enter_context(patch.object(sys.stdin, 'isatty', return_value=True))
        stack.enter_context(patch('builtins.input', return_value='yes'))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def test_native_operations_failures_and_repetition_use_fresh_probes(self):
        for failure_at in ('preflight', 'mutation', 'postflight', None):
            with self.subTest(failure_at=failure_at), contextlib.ExitStack() as stack:
                self.stage_fixture(stack, operations)
                error = subprocess.CalledProcessError(1, 'fixture')
                probes = [error] if failure_at == 'preflight' else [None, None, error] if failure_at == 'postflight' else None
                probe = stack.enter_context(patch.object(operations, 'operations_probe', side_effect=probes))
                run = stack.enter_context(patch.object(operations, 'run_playbook', side_effect=error if failure_at == 'mutation' else None))
                if failure_at:
                    with self.assertRaises(subprocess.CalledProcessError):
                        operations.operations('setup-operations', Path('/fixture.yml'))
                    self.assertEqual(run.call_count, 0 if failure_at == 'preflight' else 1)
                    self.assertEqual(probe.call_count, {'preflight': 1, 'mutation': 2, 'postflight': 3}[failure_at])
                else:
                    for _ in range(2):
                        operations.operations('setup-operations', Path('/fixture.yml'))
                    self.assertEqual(probe.call_count, 6)
                    self.assertEqual(run.call_count, 2)

    def test_native_final_ssh_preflight_and_mutation_failures_stop_dependent_work(self):
        for failure_at in ('preflight', 'mutation', 'postflight'):
            with self.subTest(failure_at=failure_at), contextlib.ExitStack() as stack:
                self.stage_fixture(stack, human_access)
                stack.enter_context(patch.dict(os.environ, {'HUMAN_PUBLIC_KEY': ''}))
                stack.enter_context(patch.object(human_access, 'human_inputs', return_value={
                    'human_access_user_name': 'operator', 'human_access_user_sudo': 'admin'}))
                stack.enter_context(patch.object(human_access, 'human_key_path', return_value=Path('/human.key')))
                stack.enter_context(patch.object(human_access, 'require_independent_key'))
                error = subprocess.CalledProcessError(1, 'fixture')
                verify = stack.enter_context(patch.object(human_access, 'verify_hardening',
                    side_effect=[error] if failure_at == 'preflight' else [None, error] if failure_at == 'postflight' else None))
                human = stack.enter_context(patch.object(human_access, 'verify_human'))
                auth = stack.enter_context(patch.object(human_access, 'verify_auth_methods'))
                run = stack.enter_context(patch.object(human_access, 'run_playbook',
                                                      side_effect=error if failure_at == 'mutation' else None))
                with self.assertRaises(ValueError if failure_at == 'mutation' else subprocess.CalledProcessError):
                    human_access.human_access('secure-ssh', Path('/fixture.yml'))
                self.assertEqual(run.call_count, 0 if failure_at == 'preflight' else 1)
                self.assertEqual(human.call_count, 0 if failure_at == 'preflight' else 1)
                self.assertEqual(verify.call_count, 2 if failure_at == 'postflight' else 1)
                auth.assert_not_called()

    def test_docker_postflight_failure_never_reports_success_or_retries(self):
        for failure in (subprocess.CalledProcessError(1, 'fixture'), subprocess.TimeoutExpired('fixture', 1)):
            for failing_call in (2, 3):
                with self.subTest(failure=type(failure).__name__, phase=failing_call), \
                        patch.object(provisioning, 'managed_access', return_value=('controller', Path('/fixture.key'))), \
                        patch.object(provisioning, 'prerequisites'), patch.object(provisioning, 'check_key'), \
                        patch.object(provisioning, 'load_host', return_value=('portfolio', 'fixture.test', 2222, 'root', '/usr/bin/python3')), \
                        patch.object(provisioning, 'known_host'), \
                        patch.object(provisioning, 'run_playbook', side_effect=[None] * (failing_call - 1) + [failure]) as run, \
                        contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(type(failure)):
                    provisioning.live('docker-host', Path('/fixture.yml'))
                self.assertEqual([call.args[3] for call in run.call_args_list],
                                 ['verify.yml', 'docker-host.yml', 'verify-docker.yml'][:failing_call])
                self.assertNotIn('completed', output.getvalue())

    def test_ansible_overlay_is_removed_after_failure_and_interrupt(self):
        for failure in (subprocess.CalledProcessError(1, 'fixture'), KeyboardInterrupt()):
            paths = []

            def fail(command, **kwargs):
                paths.append(Path(command[-1]))
                self.assertTrue(paths[-1].is_file())
                raise failure

            with patch.object(ansible.subprocess, 'run', side_effect=fail), self.assertRaises(type(failure)):
                ansible.run_playbook(Path('/fixture.yml'), 'fixture', {}, 'verify.yml')
            self.assertFalse(paths[0].exists())


class ActivationReceiptTests(unittest.TestCase):
    def run_fixture(self, directory, tasks, handlers, variables):
        playbook = directory / 'playbook.yml'
        playbook.write_text(yaml.safe_dump([{'name': 'Offline activation fixture', 'hosts': 'localhost',
                                            'gather_facts': False, 'vars': variables,
                                            'tasks': tasks, 'handlers': handlers}]))
        return subprocess.run([str(ROOT / '.venv/bin/ansible-playbook'), '-i', 'localhost,', '-c', 'local',
                               '-e', 'ansible_python_interpreter=' + str(ROOT / '.venv/bin/python'), str(playbook)],
                              cwd=ROOT, capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, ANSIBLE_HOME=str(directory / 'ansible'),
                                       ANSIBLE_LOCAL_TEMP=str(directory / 'tmp'),
                                       ANSIBLE_REMOTE_TEMP=str(directory / 'remote'), ANSIBLE_NOCOLOR='1'))

    def test_real_modules_preserve_pending_after_failure_and_converge_on_success(self):
        for role, preview, install, result in (
                ('docker_host', 'Preview validated bounded container logging configuration',
                 'Install validated bounded container logging configuration', 'local'),
                ('server_operations', 'Preview bounded journald retention', 'Configure bounded journald retention', 'active')):
            for failure_phase in (None, 'before-write', 'restart', 'postflight'):
                failed = failure_phase is not None
                with self.subTest(role=role, failed=failed), tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    source = yaml.safe_load((ROOT / 'roles' / role / 'tasks/main.yml').read_text())
                    selected = [task for task in source if task['name'] in (preview, install)
                                or task['name'].startswith('Record pending')]
                    handlers = yaml.safe_load((ROOT / 'roles' / role / 'handlers/main.yml').read_text())
                    variables = yaml.safe_load((ROOT / 'roles' / role / 'defaults/main.yml').read_text())
                    for task in selected + handlers:
                        task.pop('become', None)
                        for module in ('ansible.builtin.copy', 'ansible.builtin.template', 'ansible.builtin.file'):
                            if module not in task:
                                continue
                            options = task[module]
                            options.pop('owner', None)
                            options.pop('group', None)
                            field = 'path' if module == 'ansible.builtin.file' else 'dest'
                            options[field] = str(directory / ('pending' if 'pending' in options[field] else 'config'))
                            if 'validate' in options:
                                options['validate'] = '/bin/true %s'
                            if 'src' in options:
                                options['src'] = str(ROOT / 'roles' / role / 'templates' / options['src'])
                        if 'ansible.builtin.systemd_service' in task:
                            del task['ansible.builtin.systemd_service']
                            task['ansible.builtin.command'] = {'argv': ['/bin/false' if failure_phase == 'restart' else '/bin/true']}
                        elif 'ansible.builtin.command' in task:
                            task['ansible.builtin.command'] = {'argv': ['/usr/bin/printf', 'unconfirmed' if failure_phase == 'postflight' else result]}
                    # An unchanged preview must not leave a marker or notify a restart.
                    verification = yaml.safe_load((ROOT / 'playbooks/verify-docker.yml').read_text())[0]['tasks']
                    tasks = [task for task in verification if task['name'] in (
                        'Inspect pending Docker activation', 'Refuse unconfirmed Docker activation')]
                    tasks[0].pop('become')
                    tasks[0]['ansible.builtin.stat']['path'] = str(directory / 'pending')
                    if failure_phase == 'before-write':
                        selected.insert(2, {'name': 'Interrupt before file write',
                                            'ansible.builtin.fail': {'msg': 'Synthetic interruption'}})
                    tasks += selected + [{'name': 'Activate fixture', 'ansible.builtin.meta': 'flush_handlers'}]
                    first = self.run_fixture(directory, tasks, handlers, variables)
                    self.assertEqual(first.returncode == 0, not failed, first.stdout + first.stderr)
                    self.assertEqual((directory / 'config').is_file(), failure_phase != 'before-write')
                    self.assertEqual((directory / 'pending').exists(), failed)
                    snapshot = (directory / 'config').read_bytes() if (directory / 'config').exists() else None
                    second = self.run_fixture(directory, tasks, handlers, variables)
                    self.assertEqual(second.returncode == 0, not failed, second.stdout + second.stderr)
                    self.assertEqual((directory / 'config').read_bytes() if (directory / 'config').exists() else None, snapshot)
                    if not failed:
                        self.assertIn('changed=0', second.stdout)
                    else:
                        self.assertIn('Refuse unconfirmed Docker activation', second.stdout)
