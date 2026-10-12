"""Offline consent boundaries, scope isolation and guarded child transfer."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_cli_package import load_access
from portfolio_cli import plans, operations


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(sys.stdin, 'isatty', return_value=True))
        self.answer = self.stack.enter_context(patch('builtins.input', return_value='y'))
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.inventory = Path(self.temp) / 'inventory'
        self.inventory.write_text('synthetic inventory snapshot')

    def test_empty_plan_and_lazy_noop_do_not_prompt(self):
        plans.plan_confirm([])
        with plans.plan_scope(['harden'], lambda: 'fixed', lazy=True):
            pass
        self.answer.assert_not_called()

    def test_one_consent_for_all_listed_mutations_and_no_persistent_consent(self):
        with plans.plan_scope(['harden', 'secure-ssh'], lambda: 'fixed', lazy=True):
            plans.stage_consent('harden', self.inventory)
            plans.stage_consent('secure-ssh', self.inventory)
            plans.stage_consent('harden', self.inventory)
        self.answer.assert_called_once_with('Apply this plan? [y/N] ')
        plans.stage_consent('harden', self.inventory)
        self.assertEqual(self.answer.call_count, 2)

    def test_changed_inputs_during_confirmation_stop_before_dispatch(self):
        def change(_):
            self.inventory.write_text('changed')
            return 'y'
        self.answer.side_effect = change
        with self.assertRaisesRegex(ValueError, 'changed'):
            with plans.plan_scope(['harden'], lambda: plans.plan_snapshot(self.inventory)):
                self.fail('Changed plan was dispatched')
        self.assertIsNone(plans.PLAN_SCOPE.get())

    def test_changed_inputs_between_stages_stop(self):
        with plans.plan_scope(['harden', 'secure-ssh'], lambda: plans.plan_snapshot(self.inventory)):
            plans.stage_consent('harden', self.inventory)
            self.inventory.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                plans.stage_consent('secure-ssh', self.inventory)
        self.answer.assert_called_once()

    def test_unknown_mutation_and_wider_nested_plan_stop(self):
        with plans.plan_scope(['harden'], lambda: 'fixed'):
            with self.assertRaisesRegex(ValueError, 'outside'):
                plans.stage_consent('reboot-host', self.inventory)
            with self.assertRaisesRegex(ValueError, 'outside'):
                with plans.plan_scope(['reboot-host'], lambda: 'fixed'):
                    self.fail('Nested plan expanded consent')

    def test_nested_plan_narrows_authority_and_binds_its_own_inputs(self):
        state = ['original']
        with plans.plan_scope(['harden', 'reboot-host'], lambda: 'parent', lazy=True):
            with plans.plan_scope(['harden'], lambda: state[0]):
                with self.assertRaisesRegex(ValueError, 'outside'):
                    plans.planned_action('reboot-host')
                plans.planned_action('harden')
                state[0] = 'changed'
                with self.assertRaisesRegex(ValueError, 'changed'):
                    plans.validate_current_plan()
            plans.planned_action('reboot-host')
        self.answer.assert_called_once()

    def test_failures_reset_scope_and_never_approve_another_legacy_import(self):
        legacy = load_access('plans_legacy')
        other = load_access('plans_other')
        with legacy.plan_scope(['harden'], lambda: 'fixed'):
            self.assertIsNone(other.PLAN_SCOPE.get())
            self.assertIsNone(plans.PLAN_SCOPE.get())
            legacy.stage_consent('harden', self.inventory)
        self.assertIsNone(legacy.PLAN_SCOPE.get())

    def test_no_tty_decline_eof_and_interrupt_are_default_deny(self):
        for answer in ('', 'no', 'anything', EOFError(), KeyboardInterrupt()):
            self.answer.side_effect = answer if isinstance(answer, BaseException) else None
            self.answer.return_value = answer
            with self.assertRaisesRegex(ValueError, 'declined'):
                plans.plan_confirm(['Modify a specific file'])
        with patch.object(sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
            plans.plan_confirm(['Modify a specific file'])

    def test_anonymous_e2e_grant_is_bound_and_consumed(self):
        environment = {'PORTFOLIO_E2E_ROOT': self.temp, 'INIT_FROM': 'hardening'}
        with patch.dict(os.environ, environment, clear=True), plans.plan_scope(['harden'], lambda: 'fixed'):
            with plans.e2e_plan_pipe(self.inventory, dict(os.environ), 'init-server') as (env, descriptors):
                # Use a real child process to verify descriptor inheritance and closure.
                code = ('from pathlib import Path; import os; from portfolio_cli.plans import e2e_child_plan, planned_action; '
                        'scope=e2e_child_plan(Path(os.environ["TEST_INVENTORY"]), "init-server"); '
                        'scope.__enter__(); assert planned_action("harden"); scope.__exit__(None,None,None); '
                        'assert "PORTFOLIO_E2E_PLAN_FD" not in os.environ')
                env.update(PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'scripts'), TEST_INVENTORY=str(self.inventory))
                result = subprocess.run([sys.executable, '-c', code], env=env, pass_fds=descriptors,
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        self.answer.assert_called_once()

    def test_e2e_grant_cannot_authorize_other_mode(self):
        with patch.dict(os.environ, {'PORTFOLIO_E2E_ROOT': self.temp}, clear=True), plans.plan_scope(['harden'], lambda: 'fixed'):
            with plans.e2e_plan_pipe(self.inventory, dict(os.environ), 'init-server') as (env, descriptors):
                # Duplicate so parent still owns the descriptor it closes.
                env['PORTFOLIO_E2E_PLAN_FD'] = str(os.dup(descriptors[0]))
                with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(ValueError, 'operation changed'):
                    with plans.e2e_child_plan(self.inventory, 'reboot-host'):
                        self.fail('Foreign operation authorized')


class OperationsPlanTests(unittest.TestCase):
    def run_stage(self, plan, *, change=False):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(sys.stdin, 'isatty', return_value=True))
            answer = stack.enter_context(patch('builtins.input', return_value='y'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            for name in ('prerequisites', 'check_key', 'known_host'):
                stack.enter_context(patch.object(operations, name))
            stack.enter_context(patch.object(operations, 'managed_access', return_value=('automation', Path('/synthetic-key'))))
            stack.enter_context(patch.object(operations, 'load_host', return_value=('fixture', 'example.test', 22, 'root', '/usr/bin/python3')))
            stack.enter_context(patch.object(operations, 'hardening_inputs', return_value={'ssh_listen_ports': [22], 'firewall_allowed_tcp_ports': [22]}))
            result = {'ready': True, 'report': 'PASS', 'plan': plan}
            values = [result, result, result | {'plan': plan | {'token': 'changed'}}] if change else None
            stack.enter_context(patch.object(operations, 'operations_probe', return_value=result, side_effect=values))
            playbook = stack.enter_context(patch.object(operations, 'run_playbook'))
            if change:
                with self.assertRaisesRegex(ValueError, 'plan changed'):
                    operations.operations('setup-operations', Path('/synthetic-inventory'))
            else:
                operations.operations('setup-operations', Path('/synthetic-inventory'))
            return answer.call_count, playbook.call_count

    def test_exact_noop_never_prompts_or_applies(self):
        self.assertEqual(self.run_stage({'changes': {'/etc/apt/apt.conf.d/99zz-portfolio-security': False}, 'token': 'fixed'}), (0, 0))

    def test_concurrent_server_change_stops_after_one_consent(self):
        self.assertEqual(self.run_stage({'changes': {'/etc/apt/apt.conf.d/99zz-portfolio-security': True}, 'token': 'fixed'}, change=True), (1, 0))
