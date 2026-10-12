"""Offline orchestration tests; synthetic inputs and mocked stage execution only."""

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_cli_package import load_access
from portfolio_cli import cli, initialization as init, plans


class InitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.stack.enter_context(contextlib.redirect_stderr(self.output))
        self.stack.enter_context(patch.object(sys.stdin, 'isatty', return_value=True))
        self.stack.enter_context(patch.dict(os.environ, {'INIT_FROM': 'bootstrap'}, clear=True))
        self.stack.enter_context(patch.object(init, 'managed_access', return_value=('automation', Path('/synthetic'))))
        self.stack.enter_context(patch.object(init, 'human_inputs', return_value={
            'human_access_user_sudo': 'admin', 'human_access_user_name': 'person'}))
        self.stack.enter_context(patch.object(init, 'plan_snapshot', return_value=('fixed',)))
        self.stack.enter_context(patch.object(init, 'load_host', return_value=('fixture', 'example.test', 22, 'root', '/usr/bin/python3')))
        self.stack.enter_context(patch.object(init, 'hardening_inputs', return_value={'ssh_listen_ports': [22]}))
        self.check_key = self.stack.enter_context(patch.object(init, 'check_key'))
        self.stack.enter_context(patch.object(init, 'human_key_path', return_value=Path('/synthetic-human')))
        self.answer = self.stack.enter_context(patch('builtins.input', return_value='yes'))
        factory = tempfile.NamedTemporaryFile
        self.stack.enter_context(patch.object(init.tempfile, 'NamedTemporaryFile',
                                             side_effect=lambda **kw: factory(dir=self.temp.name, **kw)))
        self.real_init_stage = init.init_stage
        self.stage = Mock()
        def dispatch(mode, *args):
            if mode in plans.PLAN_ACTIONS:
                plans.stage_consent(mode, *args)
            return self.stage(mode, *args)
        self.stack.enter_context(patch.object(init, 'init_stage', side_effect=dispatch))

    def run_init(self):
        init.init_server(Path('/synthetic-inventory'), Path('/synthetic-key'))

    def calls(self):
        return [call.args[0] for call in self.stage.call_args_list]

    def events(self):
        paths = list(Path(self.temp.name).glob('*.jsonl'))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)
        return [json.loads(line) for line in paths[0].read_text().splitlines()]

    def test_full_pipeline_orders_mutations_inspection_and_verifiers(self):
        self.run_init()
        self.assertEqual(self.calls(), ['bootstrap-user', 'verify-access', 'docker-host', 'verify-docker',
                                       'inspect-hardening', 'harden', 'verify-hardening', 'add-user', 'verify-user',
                                       'secure-ssh', 'verify-ssh-security', 'setup-operations', 'verify-operations'])
        self.assertEqual(self.events()[-1]['status'], 'completed')
        self.assertIn('Applications remain separate', self.output.getvalue())

    def test_phase_events_and_stage_durations_are_independent_of_run_duration(self):
        seconds = [0]
        def execute(mode, *_):
            seconds[0] += 2 if mode.startswith('verify-') else (0 if mode == 'inspect-hardening' else 3)
        self.stage.side_effect = execute
        with patch.object(init.time, 'monotonic', side_effect=lambda: seconds[0]):
            self.run_init()
        events = self.events()
        for stage, *_ in init.INIT_STAGES:
            rows = [row for row in events if row['stage'] == stage]
            self.assertEqual([row['status'] for row in rows], ['applying', 'verifying', 'completed'])
            self.assertEqual([row['elapsed_seconds'] for row in rows], [0, 3, 5])
        self.assertEqual(events[-1]['elapsed_seconds'], 30)

    def test_verification_failure_records_phase_and_elapsed_time_without_error_text(self):
        seconds = [0]
        def execute(mode, *_):
            seconds[0] += 2 if mode.startswith('verify-') else 3
            if mode == 'verify-docker':
                raise ValueError('secret remote reason')
        self.stage.side_effect = execute
        with patch.object(init.time, 'monotonic', side_effect=lambda: seconds[0]):
            with self.assertRaisesRegex(ValueError, r'docker \(verify-docker\)'):
                self.run_init()
        rows = [row for row in self.events() if row['stage'] == 'docker']
        self.assertEqual([row['status'] for row in rows], ['applying', 'verifying', 'failed'])
        self.assertEqual([row['elapsed_seconds'] for row in rows], [0, 3, 5])
        self.assertNotIn('secret', json.dumps(rows))

    def test_application_failure_does_not_claim_verification(self):
        self.stage.side_effect = ValueError('Registration declined; no VPS changes requested.')
        with self.assertRaisesRegex(ValueError, 'Registration declined'):
            self.run_init()
        self.assertEqual([row['status'] for row in self.events()], ['started', 'applying', 'failed'])

    def test_verification_only_logs_fresh_stage_elapsed_time(self):
        seconds = [0]
        self.stage.side_effect = lambda *_: seconds.__setitem__(0, seconds[0] + 2)
        with patch.dict(os.environ, INIT_FROM='verify'), \
                patch.object(init.time, 'monotonic', side_effect=lambda: seconds[0]):
            self.run_init()
        events = self.events()
        for stage, *_ in init.INIT_STAGES:
            rows = [row for row in events if row['stage'] == stage]
            self.assertEqual([row['status'] for row in rows], ['verifying', 'verified_skip'])
            self.assertEqual([row['elapsed_seconds'] for row in rows], [0, 2])
        self.assertEqual(events[-1]['elapsed_seconds'], 12)

    def test_safe_cause_reaches_cli_terminal_but_never_log(self):
        reason = 'Managed key-only SSH access failed.'
        self.stage.side_effect = ValueError(reason)
        with patch.object(cli, 'pipeline_lock', contextlib.nullcontext), \
                patch.object(sys, 'argv', ['access.py', 'init-server', '--inventory', '/fixture']):
            self.assertEqual(cli.main(), 1)
        self.assertIn(reason, self.output.getvalue())
        self.assertIn('bootstrap-user', self.output.getvalue())
        self.assertNotIn(reason, json.dumps(self.events()))

    def test_untrusted_exception_details_are_not_echoed_in_diagnostics(self):
        errors = [ValueError('Managed key-only SSH access failed. secret\x1b[31m'),
                  subprocess.CalledProcessError(7, ['secret-command'], output='secret stdout', stderr='secret stderr'),
                  subprocess.TimeoutExpired(['secret-command'], 3, output='secret stdout', stderr='secret stderr'),
                  OSError(errno.ENOSPC, 'secret message', '/secret/path')]
        expected = ['Stage validation or execution failed', 'exit status 7', 'timed out', 'ENOSPC']
        for error, cause in zip(errors, expected):
            with self.subTest(error=type(error)):
                self.stage.side_effect = error
                with self.assertRaises(ValueError) as caught:
                    self.run_init()
                self.assertIn(cause, str(caught.exception))
                self.assertNotIn('secret', str(caught.exception))
        self.assertNotIn('secret', self.output.getvalue())
        for path in Path(self.temp.name).glob('*.jsonl'):
            self.assertNotIn('secret', path.read_text())

    def test_eof_at_selection_or_plan_is_clean_cli_cancellation_without_dispatch(self):
        for selection, answers in (('', [EOFError]), ('bootstrap', [EOFError]),
                                   ('', ['bootstrap', EOFError])):
            with self.subTest(selection=selection), patch.dict(os.environ, INIT_FROM=selection), \
                    patch.object(cli, 'pipeline_lock', contextlib.nullcontext), \
                    patch.object(sys, 'argv', ['access.py', 'init-server', '--inventory', '/fixture']):
                self.answer.side_effect = answers
                self.assertEqual(cli.main(), 1)
        self.assertIn('Initialization cancelled (end of input); no mutation authorized.', self.output.getvalue())
        self.assertNotIn('Traceback', self.output.getvalue())
        self.stage.assert_not_called()
        for path in Path(self.temp.name).glob('*.jsonl'):
            self.assertIn('failed', path.read_text())

    def test_every_continuation_verifies_dependencies_and_preserves_remaining_order(self):
        for boundary, frontier in enumerate([row[0] for row in init.INIT_STAGES] + ['verify']):
            with self.subTest(frontier=frontier):
                self.stage.reset_mock()
                with patch.dict(os.environ, INIT_FROM=frontier):
                    self.run_init()
                expected = []
                for index, (stage, apply, verify) in enumerate(init.INIT_STAGES):
                    if index >= boundary:
                        if stage == 'hardening':
                            expected.append('inspect-hardening')
                        expected.append(apply)
                    expected.append(verify)
                self.assertEqual(self.calls(), expected)

    def test_repeated_verification_uses_fresh_server_checks_without_mutation(self):
        with patch.dict(os.environ, INIT_FROM='verify'):
            self.run_init()
            self.run_init()
        self.assertEqual(self.calls(), [row[2] for row in init.INIT_STAGES] * 2)

    def test_each_failure_or_interruption_stops_all_later_calls(self):
        modes = ['bootstrap-user', 'verify-access', 'docker-host', 'verify-docker', 'inspect-hardening',
                 'harden', 'verify-hardening', 'add-user', 'verify-user', 'secure-ssh',
                 'verify-ssh-security', 'setup-operations', 'verify-operations']
        for failure in (ValueError, KeyboardInterrupt):
            for position, mode in enumerate(modes):
                with self.subTest(failure=failure, mode=mode):
                    self.stage.reset_mock()
                    def execute(selected, *_):
                        if selected == mode:
                            raise failure('secret stderr inventory password')
                    self.stage.side_effect = execute
                    with self.assertRaises(failure):
                        self.run_init()
                    self.assertEqual(self.calls(), modes[:position + 1])
        self.assertNotIn('secret stderr', self.output.getvalue())
        for path in Path(self.temp.name).glob('*.jsonl'):
            content = path.read_text()
            self.assertNotIn('secret', content)
            self.assertNotIn('synthetic-inventory', content)
            self.assertNotIn('synthetic-key', content)
            events = [json.loads(line) for line in content.splitlines()]
            self.assertIn(events[-1]['status'], ('failed', 'interrupted'))
            self.assertTrue(all(set(row) == {'schema', 'stage', 'status', 'elapsed_seconds'} for row in events))

    def test_failed_dependency_never_falls_back_to_mutation(self):
        with patch.dict(os.environ, INIT_FROM='operations'):
            self.stage.side_effect = ValueError('pending or unknown state')
            with self.assertRaises(ValueError):
                self.run_init()
        self.assertEqual(self.calls(), ['verify-access'])

    def test_missing_human_key_stops_before_any_mutation(self):
        self.check_key.side_effect = ValueError('missing key')
        with self.assertRaises(ValueError):
            self.run_init()
        self.stage.assert_not_called()
        self.answer.assert_not_called()

    def test_lock_contention_stops_before_confirmation_and_dispatch(self):
        with patch.object(cli, 'pipeline_lock', side_effect=ValueError('locked')), \
                patch.object(sys, 'argv', ['access.py', 'init-server', '--inventory', '/fixture']):
            self.assertEqual(cli.main(), 1)
        self.stage.assert_not_called()
        self.answer.assert_not_called()

    def test_abort_does_not_authorize_resume_from_log(self):
        self.stage.side_effect = ValueError('pending')
        with self.assertRaises(ValueError):
            self.run_init()
        self.stage.reset_mock()
        self.stage.side_effect = None
        with patch.dict(os.environ, INIT_FROM='verify'):
            self.run_init()
        self.assertEqual(self.calls(), [row[2] for row in init.INIT_STAGES])

    def test_decline_invalid_frontier_and_no_tty_never_contact_host(self):
        for answer in ('', 'n', 'no'):
            self.answer.return_value = answer
            with self.assertRaises(ValueError):
                self.run_init()
        with patch.dict(os.environ, INIT_FROM='unsafe'):
            with self.assertRaises(ValueError):
                self.run_init()
        with patch.object(sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError):
                self.run_init()
        self.stage.assert_not_called()

    def test_explicit_interactive_selection_and_retained_stage_confirmations(self):
        with patch.dict(os.environ, INIT_FROM=''):
            self.answer.side_effect = ['operations', 'yes']
            self.run_init()
        self.assertEqual(self.calls()[-2:], ['setup-operations', 'verify-operations'])
        with patch.object(init, 'human_access', side_effect=ValueError('recovery declined')) as human:
            with self.assertRaises(ValueError):
                with patch.object(init, 'init_stage', self.real_init_stage):
                    init.init_stage('secure-ssh', Path('/fixture'), None)
        human.assert_called_once_with('secure-ssh', Path('/fixture'), None)

    def test_log_failure_stops_before_dispatch(self):
        with patch.object(init.os, 'fsync', side_effect=OSError('disk full secret')):
            with self.assertRaises(ValueError):
                self.run_init()
        self.stage.assert_not_called()

    def test_native_cli_holds_one_lock_over_whole_run(self):
        held = []
        @contextlib.contextmanager
        def lock():
            held.append(True)
            yield
            held.pop()
        def execute(*_):
            self.assertEqual(held, [True])
        with patch.object(cli, 'pipeline_lock', side_effect=lock) as mutex, \
                patch.object(sys, 'argv', ['access.py', 'init-server', '--inventory', '/fixture']), \
                patch.object(init, 'init_stage', side_effect=execute):
            self.assertEqual(cli.main(), 0)
        mutex.assert_called_once()
        self.assertEqual(held, [])

    def test_legacy_import_uses_isolated_orchestration_globals(self):
        with patch.object(init, 'init_stage', self.real_init_stage):
            legacy = load_access('init_compat')
            other = load_access('init_other_compat')
        with patch.object(legacy, 'live') as live:
            legacy.init_stage('verify-access', Path('/fixture'), None)
        live.assert_called_once_with('verify-access', Path('/fixture'), None)
        self.assertIsNot(legacy.init_server.__globals__, other.init_server.__globals__)
