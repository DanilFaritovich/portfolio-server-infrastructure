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
from portfolio_cli import plans, operations, e2e


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


class E2EMakePlanTests(unittest.TestCase):
    """Real repository Make recipes/FD/CLI guard; no hypervisor or host dispatch."""

    def setUp(self):
        PlanTests.setUp(self)
        self.stand = e2e.Stand(Path(self.temp) / '.local/share/portfolio-e2e')
        (self.stand.root / 'home/.ssh').mkdir(parents=True, mode=0o700)
        (self.stand.root / 'home').chmod(0o700)
        (self.stand.root / 'tmp').mkdir(mode=0o700)
        self.stand.inventory.write_text('synthetic E2E inventory')
        self.inventory = self.stand.inventory
        self.venv = Path(self.temp) / 'probe-venv'
        (self.venv / 'bin').mkdir(parents=True)
        probe = self.venv / 'bin/python'
        # Replace only the interpreter boundary. Run the actual access.py guard,
        # parser and grant receiver, mocking VM proofs and operation dispatch.
        probe.write_text('#!' + sys.executable + '\n' + r'''import contextlib
import json
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path.cwd() / 'scripts'))
from portfolio_cli import cli, e2e, plans
expected = json.loads(Path(os.environ['TEST_SNAPSHOT']).read_text())
inventory = Path(os.environ['INVENTORY'])
fd = int(os.environ['PORTFOLIO_E2E_PLAN_FD'])
# Check Make's exports before the guard can sanitize them.
if os.environ.get('TEST_EXPECT_MATCH') == 'yes':
    assert json.dumps(plans.plan_snapshot(inventory), sort_keys=True) == expected
stand = e2e.Stand(Path(os.environ['PORTFOLIO_E2E_ROOT']))
def check_inventory(selected):
    assert selected == inventory == stand.inventory
    assert selected.read_text() == 'synthetic E2E inventory'
def dispatch(args, selected):
    assert selected == inventory
    assert 'PORTFOLIO_E2E_PLAN_FD' not in os.environ
    try:
        os.fstat(fd)
    except OSError:
        pass
    else:
        raise AssertionError('consumed grant FD is still open')
    assert json.dumps(plans.plan_snapshot(selected), sort_keys=True) == expected
    stages = {'generate-user-key': ['generate-user-key'],
              'init-server': ['bootstrap-user', 'docker-host', 'harden', 'add-user',
                              'secure-ssh', 'setup-operations', 'setup-deployment-prerequisites'],
              'reboot-host': ['reboot-host']}
    for stage in stages.get(args.mode, [args.mode]):
        assert plans.planned_action(stage)
    try:
        plans.planned_action('apply-apt-policy')
    except ValueError:
        pass
    else:
        raise AssertionError('grant widened authority')
    os.environ['HUMAN_SUDO'] = 'changed-after-receipt'
    try:
        plans.validate_current_plan()
    except ValueError:
        pass
    else:
        raise AssertionError('grant accepted changed inputs')
    if args.mode == 'generate-user-key' and os.environ['HUMAN_USER'] != 'e2e_admin':
        public = Path(os.environ['HUMAN_KEY'] + '.pub')
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text('synthetic planned public output')
    print('OFFLINE DISPATCH ' + args.mode)
    return 0
sys.argv = sys.argv[1:]
with contextlib.ExitStack() as stack:
    stack.enter_context(patch.object(e2e, 'Stand', return_value=stand))
    stack.enter_context(patch.object(stand, 'ready'))
    stack.enter_context(patch.object(stand, 'check_inventory', side_effect=check_inventory))
    stack.enter_context(patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(stand.root.parents[2]))))
    stack.enter_context(patch.object(e2e, 'command', side_effect=AssertionError('unexpected external command')))
    stack.enter_context(patch.object(cli, 'pipeline_lock', side_effect=contextlib.nullcontext))
    stack.enter_context(patch.object(cli, 'dispatch', side_effect=dispatch))
    runpy.run_path('scripts/access.py', run_name='__main__')
''')
        probe.chmod(0o700)
        self.modes = ['generate-user-key', 'bootstrap-user', 'docker-host', 'harden',
                      'add-user', 'secure-ssh', 'setup-operations', 'setup-deployment-prerequisites', 'reboot-host']

    def make_child(self, mode, *, target=None, overrides=None, change=None, user_inputs=None):
        env = self.stand.child_env(user_inputs)
        if mode == 'init-server':
            env['INIT_FROM'] = 'bootstrap'
        with contextlib.nullcontext() if plans.PLAN_SCOPE.get() else plans.plan_scope(self.modes, lambda: 'fixed'):
            with plans.e2e_plan_pipe(self.inventory, env, mode) as (child_env, descriptors):
                expected_file = Path(self.temp) / 'expected-snapshot.json'
                with patch.dict(os.environ, env, clear=True):
                    expected_file.write_text(json.dumps(json.dumps(plans.plan_snapshot(self.inventory), sort_keys=True)))
                child_env['TEST_SNAPSHOT'] = str(expected_file)
                child_env['TEST_EXPECT_MATCH'] = 'no' if overrides or change else 'yes'
                if change:
                    change()
                return subprocess.run(
                    ['make', '--no-print-directory', mode if target is None else target,
                     'VENV=' + str(self.venv),
                     *(name + '=' + value for name, value in (overrides or {}).items())],
                    cwd=e2e.ROOT, env=child_env, pass_fds=descriptors,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)

    def test_real_make_preserves_exact_policy_environment_and_consumes_fd(self):
        # The ambient parent's policy must never leak into the isolated child.
        with patch.dict(os.environ, {'INIT_FROM': 'operations', 'AGENT_LOAD': 'no',
                                     'RECOVERY_USER': 'foreign', 'KEY_NAME': 'foreign',
                                     'HUMAN_SUDO_COMMANDS': 'foreign', 'HUMAN_EXTRA': 'foreign'}), \
                plans.plan_scope(self.modes, lambda: 'one approved E2E scenario'):
            for mode in ('generate-user-key', 'init-server', 'reboot-host'):
                with self.subTest(mode=mode):
                    result = self.make_child(mode)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('OFFLINE DISPATCH ' + mode, result.stdout)
        self.answer.assert_called_once()

    def test_real_make_user_mutations_receive_single_mode_scoped_grants(self):
        modes = ['generate-user-key', 'add-user', 'add-user-key', 'revoke-user-key', 'remove-user']
        inputs = {'HUMAN_USER': 'disposable', 'HUMAN_KEY': str(self.stand.root / 'home/.ssh/human/disposable'), 'HUMAN_SUDO': 'restricted',
                  'HUMAN_SUDO_COMMANDS': '/usr/bin/id', 'RECOVERY_USER': 'e2e_admin',
                  'KEY_FINGERPRINT': 'SHA256:synthetic'}
        env = self.stand.child_env(inputs)
        operations = [(mode, self.inventory, env) for mode in modes]
        with plans.e2e_execution_plan(operations, ['exact offline user lifecycle'], lambda: 'fixed'):
            for mode in modes:
                result = self.make_child(mode, user_inputs=inputs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('OFFLINE DISPATCH ' + mode, result.stdout)
        self.answer.assert_called_once_with('Authorize this E2E execution plan? [y/N] ')

    def test_real_make_rejects_substituted_operation_and_frontier(self):
        for mode in ('generate-user-key', 'init-server', 'reboot-host'):
            for target, overrides in [('reboot-host' if mode != 'reboot-host' else 'init-server', {}),
                                      (mode, {'INIT_FROM': 'verify'})]:
                with self.subTest(mode=mode, target=target, overrides=overrides):
                    result = self.make_child(mode, target=target, overrides=overrides)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('E2E child operation changed; STOP.', result.stderr)
                    self.assertNotIn('OFFLINE DISPATCH', result.stdout)

    def test_real_make_rejects_substituted_policy_inputs_before_dispatch(self):
        inputs = ['AUTOMATION_KEY', 'HUMAN_USER', 'HUMAN_KEY', 'HUMAN_PUBLIC_KEY',
                  'HUMAN_GROUPS', 'HUMAN_GROUPS_APPROVED', 'HUMAN_SUDO', 'HUMAN_SUDO_COMMANDS',
                  'KEY_NAME', 'KEY_FINGERPRINT', 'RECOVERY_USER', 'RECOVERY_KEY', 'AGENT_LOAD',
                  'HUMAN_EXTRA', 'SSH_AUTH_SOCK', 'INVENTORY', 'HOME', 'TMPDIR', 'ANSIBLE_CONFIG']
        for mode in ('generate-user-key', 'init-server', 'reboot-host'):
            for name in inputs:
                with self.subTest(mode=mode, input=name):
                    result = self.make_child(mode, overrides={name: 'foreign'})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('OFFLINE DISPATCH', result.stdout)
                    self.assertIn('guard failed' if name != 'SSH_AUTH_SOCK' else 'plan inputs changed', result.stderr)

    def test_real_make_rejects_inventory_and_public_identity_drift(self):
        public = Path(self.stand.child_env()['HUMAN_PUBLIC_KEY'])
        public.parent.mkdir(parents=True)
        public.write_text('synthetic public identity')
        for mode in ('generate-user-key', 'init-server', 'reboot-host'):
            with self.subTest(mode=mode):
                result = self.make_child(mode, change=lambda: public.write_text('changed public identity'))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('plan inputs changed', result.stderr)
                self.assertNotIn('OFFLINE DISPATCH', result.stdout)
                public.write_text('synthetic public identity')
        result = self.make_child('init-server', change=lambda: self.inventory.write_text('changed inventory'))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('OFFLINE DISPATCH', result.stdout)


class ExactE2EPlanTests(unittest.TestCase):
    setUp = PlanTests.setUp

    def environment(self, **values):
        return {'PORTFOLIO_E2E_ROOT': self.temp, 'INIT_FROM': '', 'HUMAN_USER': 'disposable',
                'HUMAN_SUDO': 'admin', 'RECOVERY_USER': 'e2e_admin',
                'RECOVERY_KEY': '/fixture/recovery', 'AGENT_LOAD': 'no'} | values

    def invoke(self, mode, env):
        with plans.e2e_plan_pipe(self.inventory, env, mode) as (child, descriptors):
            self.assertEqual(len(descriptors), 1)
            # Receiver consumes its own inherited copy, as a real child would.
            child['PORTFOLIO_E2E_PLAN_FD'] = str(os.dup(descriptors[0]))
            with patch.dict(os.environ, child, clear=True), plans.e2e_child_plan(self.inventory, mode):
                self.assertTrue(plans.planned_action(mode))
                with self.assertRaisesRegex(ValueError, 'outside'):
                    plans.planned_action('apply-apt-policy')

    def test_exact_sequence_prompts_once_and_authority_expires(self):
        env = self.environment()
        modes = ['add-user', 'add-user', 'add-user-key', 'revoke-user-key', 'remove-user', 'remove-user']
        operations = [(mode, self.inventory, env) for mode in modes]
        with plans.e2e_execution_plan(operations, ['exact synthetic lifecycle'], lambda: 'fixed'):
            for mode in modes:
                self.invoke(mode, env)
            with self.assertRaisesRegex(ValueError, 'Additional'):
                self.invoke('remove-user', env)
        self.answer.assert_called_once_with('Authorize this E2E execution plan? [y/N] ')
        self.assertIsNone(plans.E2E_EXECUTION.get())
        self.assertFalse(plans.planned_action('remove-user'))

    def test_decline_eof_and_interrupt_do_not_open_child_grant(self):
        for response in ('n', EOFError(), KeyboardInterrupt()):
            with self.subTest(response=response), patch('builtins.input', side_effect=[response]), \
                    patch.object(plans.os, 'pipe') as pipe:
                with self.assertRaisesRegex(ValueError, 'declined'):
                    with plans.e2e_execution_plan([('remove-user', self.inventory, self.environment())],
                                                  ['remove disposable'], lambda: 'fixed'):
                        self.fail('declined plan dispatched')
                pipe.assert_not_called()
                self.assertIsNone(plans.E2E_EXECUTION.get())

    def test_changed_user_policy_key_recovery_profile_and_order_stop(self):
        env = self.environment(HUMAN_PUBLIC_KEY='/fixture/exact.pub')
        changes = [{'HUMAN_USER': 'foreign'}, {'HUMAN_SUDO': 'none'},
                   {'HUMAN_PUBLIC_KEY': '/foreign.pub'}, {'RECOVERY_USER': 'foreign'},
                   {'RECOVERY_KEY': '/foreign'}, {'AGENT_LOAD': 'yes'}]
        for change in changes:
            with self.subTest(change=change), plans.e2e_execution_plan(
                    [('add-user', self.inventory, env)], ['exact account/key/policy'], lambda: 'fixed'):
                with self.assertRaisesRegex(ValueError, 'operation/inputs changed'), patch.object(plans.os, 'pipe') as pipe:
                    self.invoke('add-user', env | change)
                pipe.assert_not_called()
        with plans.e2e_execution_plan([('setup-swap', self.inventory, env)], ['512 MiB'], lambda: 'fixed'):
            with self.assertRaisesRegex(ValueError, 'operation/inputs changed'):
                with plans.e2e_plan_pipe(Path(self.temp) / '1024-profile', env, 'setup-swap'):
                    self.fail('profile substitution accepted')
            with self.assertRaisesRegex(ValueError, 'operation/inputs changed'):
                self.invoke('reboot-host', env)
            with self.assertRaisesRegex(ValueError, 'Additional'):
                self.invoke('connect-controller', env)

    def test_generated_key_output_is_bound_to_following_registration_and_revocation(self):
        private = Path(self.temp) / 'new-key'
        public = Path(str(private) + '.pub')
        generate = self.environment(HUMAN_KEY=str(private))
        register = self.environment(HUMAN_PUBLIC_KEY=str(public))
        revoke = self.environment(KEY_FINGERPRINT=lambda: 'SHA256:planned')
        operations = [('generate-user-key', self.inventory, generate),
                      ('add-user-key', self.inventory, register), ('revoke-user-key', self.inventory, revoke)]
        with self.assertRaisesRegex(ValueError, 'identity changed'), \
                plans.e2e_execution_plan(operations, ['generate/register/revoke exact new identity'], lambda: 'fixed'):
            with plans.e2e_plan_pipe(self.inventory, generate, 'generate-user-key'):
                public.write_text('synthetic PUBLIC identity')
            self.invoke('add-user-key', register)
            self.invoke('revoke-user-key', self.environment(KEY_FINGERPRINT='SHA256:planned'))
            public.write_text('substituted PUBLIC identity')
            plans.validate_current_plan()
        self.answer.assert_called_once()

    def test_fixture_state_and_child_policy_drift_stop_before_dispatch(self):
        state = Path(self.temp) / 'state.json'
        state.write_text('synthetic owned UUID')
        env = self.environment()
        with plans.e2e_execution_plan([('remove-user', self.inventory, env)], ['remove disposable'], lambda: 'fixed'):
            with plans.e2e_plan_pipe(self.inventory, env, 'remove-user') as (child, descriptors):
                child['PORTFOLIO_E2E_PLAN_FD'] = str(os.dup(descriptors[0]))
                state.write_text('different VM UUID')
                with patch.dict(os.environ, child, clear=True), self.assertRaisesRegex(ValueError, 'inputs changed'):
                    with plans.e2e_child_plan(self.inventory, 'remove-user'):
                        self.fail('foreign VM accepted')


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
