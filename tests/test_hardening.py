"""Stage 3 tests use synthetic inventories/files and prohibit real SSH/UFW calls."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import yaml

import test_docker

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


access = load('hardening_access', 'scripts/access.py')
info = load('hardening_info', 'library/portfolio_hardening_info.py')
adoption = load('ssh_adoption', 'library/portfolio_ssh_adopt.py')


class HardeningTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.inventory = self.directory / 'fixture.yml'
        self.host = {'ansible_host': 'fixture.example.test', 'ansible_port': 2222,
                     'ansible_user': 'root', 'ssh_listen_ports': [2222, 2200],
                     'firewall_allowed_tcp_ports': [80, 443, 8080]}
        self.write_inventory()
        self.key = self.directory / 'opaque-key'
        self.key.touch(mode=0o600)
        Path(str(self.key) + '.pub').touch(mode=0o600)
        self.tasks = yaml.safe_load((ROOT / 'roles/host_hardening/tasks/main.yml').read_text())

    def write_inventory(self):
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {
            'hosts': {'fixture': self.host}}}}}))

    def local_ansible(self, tasks, variables):
        return test_docker.DockerTests.local_ansible(self, tasks, variables)

    def test_inspection_aggregates_independent_blockers_and_redacts_contents(self):
        fake = self.inspection_fixture(managed=False, active=False)
        fake.params['report_only'] = True
        self.service = 'inactive'
        self.fixture_path('/etc/ssh/sshd_config').write_text(
            'ListenAddress 127.0.0.1 # secret-ssh-content\nInclude /secret-path/*.conf\n')
        self.fixture_path('/etc/ufw/before.rules').write_text('secret-base-content')
        self.fixture_path('/etc/ufw/user.rules').write_text('-A secret-raw-content\n')
        self.added = 'ufw allow from secret-rule-content'
        before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        result = self.inspect(fake)
        self.assertFalse(result['ready'])
        for diagnostic in ('ListenAddress', 'Include hierarchy', 'docker.service', 'containerd.service',
                           'raw UFW', 'package baseline', 'Unknown existing UFW rule'):
            self.assertIn(diagnostic, result['report'])
        for secret in ('secret-', 'sha256', 'ssh_sources'):
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(set(result), {'ready', 'findings', 'report'})
        self.assertEqual(before, {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
        allowed = {('systemctl', 'show'), ('systemctl', 'is-active'), ('systemctl', 'is-enabled'),
                   ('/usr/sbin/sshd', '-t'), ('/usr/sbin/sshd', '-T'), ('ss', '-H'),
                   ('ufw', 'status'), ('ufw', 'show'), ('dpkg-query', '-W')}
        self.assertTrue(all(tuple(call.args[0][:2]) in allowed for call in fake.run_command.call_args_list))
        fake.params['report_only'] = False
        with self.assertRaisesRegex(ValueError, 'NOT READY'):
            self.inspect(fake)

    def test_inspection_warns_only_on_safely_convergeable_state(self):
        fake = self.inspection_fixture(managed=False, active=False)
        fake.params['report_only'] = True
        self.fixture_path('/etc/ssh/sshd_config').write_text('Port 2222\n')
        self.effective = 'port 2222\npubkeyauthentication yes\n'
        self.sockets = self.sockets.replace(':2200', ':2222')
        result = self.inspect(fake)
        self.assertTrue(result['ready'], result['report'])
        self.assertIn('WARN  legacy SSH Ports', result['report'])
        self.assertIn('WARN  UFW runtime', result['report'])
        fake.params['report_only'] = False
        self.assertTrue(self.inspect(fake)['ssh_adoption'])
        fake.params.update(verify=True, report_only=True)
        self.assertFalse(self.inspect(fake)['ready'])
        fake = self.inspection_fixture(managed=True, active=True)
        fake.params.update(verify=False, report_only=True)
        result = self.inspect(fake)
        self.assertTrue(result['ready'], result['report'])
        self.assertTrue(all(item['status'] == 'PASS' for item in result['findings']), result['report'])

    def test_inspection_socket_staleness_is_warn_but_custom_overrides_block(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        self.enable_socket()
        self.generated_socket_fixture([2222])
        result = self.inspect(fake)
        self.assertTrue(result['ready'], result['report'])
        self.assertIn('WARN  generated/loaded SSH socket state', result['report'])
        fake.params['report_only'] = False
        self.assertTrue(self.inspect(fake)['socket_reload_required'])
        fake.params.update(verify=True, report_only=True)
        self.assertFalse(self.inspect(fake)['ready'])
        fake.params['verify'] = False
        self.fixture_path(self.socket_dropins).write_text('[Socket]\nListenStream=127.0.0.1:2222\n')
        self.assertFalse(self.inspect(fake)['ready'])
        fake.params['report_only'] = False
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_inspection_rejects_unsafe_files_without_reading_them(self):
        for filename in ('/etc/ssh/sshd_config', '/etc/ufw/user.rules', '/etc/ufw/before.rules',
                         '/etc/ufw/portfolio-hardening.json'):
            fake = self.inspection_fixture()
            fake.params.update(verify=False, report_only=True)
            path = self.fixture_path(filename)
            path.unlink()
            path.symlink_to(self.directory / 'does-not-exist')
            with self.subTest(filename=filename):
                result = self.inspect(fake)
                self.assertFalse(result['ready'], result['report'])
                self.assertNotIn('does-not-exist', result['report'])
                path.unlink()
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        path = self.fixture_path('/etc/ufw/user.rules')
        path.unlink()
        os.mkfifo(path)
        self.assertFalse(self.inspect(fake)['ready'])

    def test_inspection_continues_after_invalid_ports_and_malformed_marker(self):
        fake = self.inspection_fixture()
        fake.params.update(ssh_ports=['sensitive-port'], tcp_ports=[False], verify=False, report_only=True)
        self.marker.write_text('{"secret-invalid-json')
        self.service = 'inactive'
        result = self.inspect(fake)
        self.assertFalse(result['ready'])
        for label in ('desired SSH ports', 'desired HTTP/HTTPS', 'UFW ownership marker', 'docker.service'):
            self.assertIn('FAIL  ' + label, result['report'])
        self.assertNotIn('sensitive-port', result['report'])
        self.assertNotIn('secret-invalid-json', result['report'])

    def test_inspection_parser_errors_cannot_impersonate_safe_diagnoses(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        self.effective = 'port secret Review and reconcile manually;\npubkeyauthentication yes\n'
        result = self.inspect(fake)
        self.assertFalse(result['ready'])
        self.assertNotIn('secret', json.dumps(result))

    def test_inspection_detects_unloaded_systemd_overrides_and_generated_state(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        self.enable_socket()
        path = self.generated_socket_fixture([2222])
        self.socket_dropins = ''  # generated file is newer than the loaded unit
        result = self.inspect(fake)
        self.assertTrue(result['ready'], result['report'])
        self.assertIn('WARN  generated/loaded SSH socket state', result['report'])
        path.unlink()
        custom = self.fixture_path('/etc/systemd/system/ufw.service.d/unsafe.conf')
        custom.parent.mkdir(parents=True, exist_ok=True)
        custom.write_text('[Service]\nExecStart=secret-service-override\n')
        result = self.inspect(fake)
        self.assertFalse(result['ready'])
        self.assertIn('FAIL  ufw.service drop-in', result['report'])
        self.assertNotIn('secret-service-override', result['report'])
        fake.params['report_only'] = False
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_inspection_collects_all_dormant_masked_socket_overrides(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        self.socket_enabled = 'masked'
        stock_command = fake.run_command.side_effect

        def command(argv, **kwargs):
            if argv[:3] == ['systemctl', 'show', 'ssh.socket']:
                return 0, 'FragmentPath=/dev/null\nDropInPaths=\n', ''
            return stock_command(argv, **kwargs)

        fake.run_command.side_effect = command
        self.assertTrue(self.inspect(fake)['ready'])
        for root in ('/etc', '/run'):
            path = self.fixture_path(root + '/systemd/system/ssh.socket.d/unsafe.conf')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('[Socket]\nListenStream=secret-listener\n')
        result = self.inspect(fake)
        self.assertFalse(result['ready'])
        self.assertEqual(result['report'].count('Custom disabled SSH socket drop-ins detected.'), 2)
        self.assertNotIn('secret-listener', result['report'])
        fake.params['report_only'] = False
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_inspection_wrapper_streams_shared_code_without_remote_files(self):
        import contextlib
        import io
        fake = self.inspection_fixture()
        fake.params.update(verify=False, report_only=True)
        self.host['ssh_listen_ports'] = [2222, 2200]
        self.host['firewall_allowed_tcp_ports'] = [80, 443]
        self.write_inventory()
        before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        calls = []

        def command(argv, **kwargs):
            if argv[0] != 'ssh':
                rc, stdout, stderr = fake.run_command(argv, environ_update={'LC_ALL': 'C'})
                return subprocess.CompletedProcess(argv, rc, stdout, stderr)
            calls.append(argv)
            self.assertEqual(argv[argv.index('-p') + 1], '2222')
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('IdentityAgent=none', argv)
            self.assertIn('PasswordAuthentication=no', argv)
            if argv[-1] == 'id -un':
                return subprocess.CompletedProcess(argv, 0, 'ansible\n', '')
            self.assertEqual(argv[-1], 'sudo -n /usr/bin/python3 -I -B -')
            payload = kwargs['input']
            self.assertIn((ROOT / 'library/portfolio_hardening_info.py').read_text(), payload)
            # Execute exactly the streamed entry point, only remapping paths to fixtures.
            namespace = {'fixture_path': self.fixture_path}
            payload = payload.replace('from pathlib import Path', 'Path = fixture_path')
            output = io.StringIO()
            with patch.object(info.glob, 'glob', return_value=[]), \
                    patch('shutil.which', return_value='/usr/sbin/ufw'), patch('os.geteuid', return_value=0), \
                    contextlib.redirect_stdout(output):
                exec(compile(payload, '<ssh-stdin-fixture>', 'exec'), namespace)
            return subprocess.CompletedProcess(argv, 0, output.getvalue(), '')

        with patch.object(access, 'prerequisites'), patch.object(access, 'known_host') as trust, \
                patch.object(access, 'run_playbook') as playbook, \
                patch.object(access.subprocess, 'run', side_effect=command), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            access.live('inspect-hardening', self.inventory, self.key)
        self.assertIn('PASS  managed SSH access', output.getvalue())
        self.assertIn('Result: READY', output.getvalue())
        self.assertEqual(len(calls), 2)
        playbook.assert_not_called()
        trust.assert_called_once_with('fixture.example.test', 2222, allow_trust=False)
        self.assertEqual(before, {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
        result = subprocess.run(['make', '-n', 'inspect-hardening'], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('scripts/access.py inspect-hardening ', result.stdout)

    def test_inspection_public_exit_codes_and_transport_redaction(self):
        import contextlib
        import io
        for ready, expected in ((True, 0), (False, 1)):
            result = {'ready': ready, 'report': 'Hardening preflight\n' +
                      ('WARN  safe convergence\nResult: READY' if ready else 'FAIL  blocking state\nResult: NOT READY')}
            with self.subTest(ready=ready), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host'), patch.object(access.subprocess, 'run', side_effect=[
                        subprocess.CompletedProcess([], 0, 'ansible\n', ''),
                        subprocess.CompletedProcess([], 0, json.dumps(result), 'sensitive-stderr')]), \
                    patch.object(access.sys, 'argv', ['access.py', 'inspect-hardening', '--inventory',
                                                     str(self.inventory), '--key', str(self.key)]), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(access.main(), expected)
            self.assertNotIn('sensitive-stderr', output.getvalue() + error.getvalue())
        for login_ok in (False, True):
            responses = [subprocess.CompletedProcess([], 0 if login_ok else 1,
                                                   'ansible\n' if login_ok else 'sensitive-stdout', 'secret-stderr')]
            if login_ok:
                responses.append(subprocess.CompletedProcess([], 1, 'sensitive-stdout', 'secret-stderr'))
            with patch.object(access.subprocess, 'run', side_effect=responses), \
                    contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(ValueError):
                access.inspect_host('fixture.example.test', 2222, '/usr/bin/python3', self.key,
                                    {'ssh_listen_ports': [2222], 'firewall_allowed_tcp_ports': [80, 443]})
            self.assertIn('NOT READY', output.getvalue())
            self.assertNotIn('sensitive-stdout', output.getvalue())
            self.assertNotIn('secret-stderr', output.getvalue())

    def test_live_entrypoints_preserve_key_only_transport_and_verify_every_port(self):
        for mode in ('harden', 'verify-hardening'):
            with self.subTest(mode=mode), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host') as trust, patch.object(access, 'prepare_key') as prepare, \
                    patch.object(access.subprocess, 'run') as run, patch('builtins.print'):
                calls = []

                def capture(command, **kwargs):
                    self.assertNotIn('--ask-pass', command)
                    self.assertNotIn('--ask-become-pass', command)
                    overlay = json.loads(Path(command[-1]).read_text())['all']['hosts']
                    self.assertEqual(Path(command[-1]).stat().st_mode & 0o777, 0o600)
                    remote, local = overlay['fixture'], overlay['localhost']
                    self.assertEqual(local['ansible_connection'], 'local')
                    self.assertFalse(local['ansible_become'])
                    self.assertEqual(local['ansible_python_interpreter'], access.sys.executable)
                    self.assertEqual(remote['ansible_user'], 'ansible')
                    self.assertEqual(remote['ansible_private_key_file'], str(self.key))
                    for option in ('StrictHostKeyChecking=yes', 'ControlMaster=no', 'ControlPath=none',
                                   'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                                   'BatchMode=yes', 'IdentityAgent=none', 'IdentitiesOnly=yes'):
                        self.assertIn(option, remote['ansible_ssh_args'])
                    inputs = json.loads(command[command.index('-e') + 1])
                    self.assertFalse(any(key.startswith('ansible_') for key in inputs))
                    calls.append((Path(command[3]).name, remote, inputs))

                run.side_effect = capture
                access.live(mode, self.inventory, self.key)
                names = ['verify.yml'] + (['harden.yml'] if mode == 'harden' else []) + \
                    ['verify.yml', 'verify-hardening.yml'] * 2
                self.assertEqual([c[0] for c in calls], names)
                self.assertEqual([c[1]['ansible_port'] for c in calls[-4:]], [2222, 2222, 2200, 2200])
                for _, remote, _ in calls[-4:]:
                    self.assertIn('HostKeyAlias=[fixture.example.test]:2222', remote['ansible_ssh_args'])
                    self.assertNotIn('ansible_become', remote)
                    self.assertEqual(remote['ansible_become_flags'], '-n')
                prepare.assert_not_called()
                trust.assert_called_once_with('fixture.example.test', 2222, allow_trust=False)

    def test_invalid_inputs_or_failed_access_stop_before_hardening(self):
        for values in ([], [22], [2222, 2222], [True], ['2222'], [0], [65536], '2222'):
            with self.subTest(values=values):
                self.host['ssh_listen_ports'] = values
                self.write_inventory()
                with patch.object(access, 'prerequisites'), patch.object(access, 'run_playbook') as run, \
                        patch.object(access, 'known_host') as trust:
                    with self.assertRaises(ValueError):
                        access.live('harden', self.inventory, self.key)
                    run.assert_not_called()
                    trust.assert_not_called()
        self.host['ssh_listen_ports'] = [2222, 2200]
        self.write_inventory()
        for failed_stage in ('verify.yml', 'harden.yml', 'verify-hardening.yml'):
            calls = []

            def failure(*args, **kwargs):
                calls.append(args[3])
                if args[3] == failed_stage:
                    raise subprocess.CalledProcessError(1, 'fixture')

            with self.subTest(failed_stage=failed_stage), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host'), patch.object(access, 'run_playbook', side_effect=failure), \
                    patch('builtins.print'):
                with self.assertRaises(subprocess.CalledProcessError):
                    access.live('harden', self.inventory, self.key)
                self.assertEqual(calls[-1], failed_stage)
        self.host['firewall_allowed_tcp_ports'] = []
        self.write_inventory()
        self.assertEqual(access.hardening_inputs(self.inventory, 'fixture', 2222)['firewall_allowed_tcp_ports'], [])

    def test_firewall_order_and_converged_rerun_with_real_local_ansible(self):
        commands = [copy.deepcopy(t) for t in self.tasks if 'ansible.builtin.command' in t]
        enable_index = next(i for i, t in enumerate(commands) if '--force' in t['ansible.builtin.command']['argv'])
        self.assertGreater(enable_index, 1)
        self.assertEqual(commands[0]['loop'], '{{ ssh_listen_ports }}')
        self.assertEqual(commands[0]['ansible.builtin.command']['argv'][1:3], ['allow', 'in'])
        state = self.directory / 'ufw-state.json'
        state.write_text(json.dumps({'ports': [], 'incoming': 'ACCEPT', 'outgoing': 'DROP', 'enabled': False}))
        executable = self.directory / 'ufw'
        executable.write_text(f'''#!{ROOT / '.venv/bin/python'}
import json, sys
from pathlib import Path
path = Path({str(state)!r})
state = json.loads(path.read_text())
args = sys.argv[1:]
if args[0] == 'allow':
    port = int(args[2].split('/')[0])
    if port in state['ports']:
        print('Skipping adding existing rule')
    else:
        state['ports'].append(port)
        print('Rule added')
elif args[0] == 'default':
    state[args[2]] = 'DROP' if args[1] == 'deny' else 'ACCEPT'
else:
    assert {{2222, 2200}} <= set(state['ports']), 'SSH must be allowed before enable'
    state['enabled'] = True
path.write_text(json.dumps(state))
''')
        executable.chmod(0o700)
        for task in commands:
            task.pop('become', None)
            task['ansible.builtin.command']['argv'][0] = str(executable)
        variables = {'ssh_listen_ports': [2222, 2200], 'firewall_allowed_tcp_ports': [80, 443],
                     'hardening_firewall': {'incoming': 'ACCEPT', 'outgoing': 'DROP', 'ufw_active': False}}
        first = self.local_ansible(commands, variables)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('changed=5', first.stdout)
        variables['hardening_firewall'] = {'incoming': 'DROP', 'outgoing': 'ACCEPT', 'ufw_active': True}
        second = self.local_ansible(commands, variables)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn('changed=0', second.stdout)
        self.assertEqual(set(json.loads(state.read_text())['ports']), {2222, 2200, 80, 443})

    def test_invalid_ssh_candidate_is_not_installed_or_notified_and_rerun_converges(self):
        original = next(t for t in self.tasks if 'ansible.builtin.blockinfile' in t)
        self.assertEqual(original['ansible.builtin.blockinfile']['validate'], '/usr/sbin/sshd -t -f %s')
        self.assertEqual(sum('notify' in task for task in self.tasks), 3)
        handlers = yaml.safe_load((ROOT / 'roles/host_hardening/handlers/main.yml').read_text())
        self.assertEqual(handlers[0]['ansible.builtin.command']['argv'], ['/usr/sbin/sshd', '-t'])
        self.assertIs(handlers[0]['changed_when'], False)
        self.assertEqual(handlers[0]['listen'], original['notify'])
        handler = handlers[1]
        self.assertEqual(handler['ansible.builtin.systemd_service'], {'name': 'ssh.service', 'state': 'reloaded'})
        dest = self.directory / 'sshd_config'
        fallback = 'PermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\n'
        dest.write_text(fallback)
        validator = self.directory / 'validate-sshd'
        validator.write_text(f'''#!{ROOT / '.venv/bin/python'}
import sys
from pathlib import Path
sys.exit(1 if 'Port 99999' in Path(sys.argv[1]).read_text() else 0)
''')
        validator.chmod(0o700)
        task = copy.deepcopy(original)
        task.pop('become')
        # Inspect the real handler above; local fixtures never touch a service.
        task.pop('notify')
        task['ansible.builtin.blockinfile'].update(path=str(dest), owner=os.getuid(), group=os.getgid(),
                                                 mode='0600', validate=f'{validator} %s')
        invalid = self.local_ansible([task], {'ssh_listen_ports': [2222, 99999]})
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn('changed=0', invalid.stdout)
        self.assertEqual(dest.read_text(), fallback)
        first = self.local_ansible([task], {'ssh_listen_ports': [2222, 2200]})
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('changed=1', first.stdout)
        second = self.local_ansible([task], {'ssh_listen_ports': [2222, 2200]})
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn('changed=0', second.stdout)
        self.assertTrue(dest.read_text().endswith(fallback))
        self.assertIn('Port 2200\nPort 2222\nPubkeyAuthentication yes', dest.read_text())

    def test_real_handler_notifications_order_candidates_and_convergence(self):
        task = copy.deepcopy(next(t for t in self.tasks if 'ansible.builtin.blockinfile' in t))
        task.pop('become')
        task['ansible.builtin.blockinfile'].update(
            path=str(self.directory / 'sshd_config'), owner=os.getuid(), group=os.getgid(), mode='0600',
            validate=f'{self.directory / "validate-sshd"} %s')
        dest = Path(task['ansible.builtin.blockinfile']['path'])
        dest.write_text('PermitRootLogin yes\nPasswordAuthentication yes\n')
        validator = self.directory / 'validate-sshd'
        validator.write_text(f'''#!{ROOT / '.venv/bin/python'}
import sys
from pathlib import Path
sys.exit(1 if 'Port 99999' in Path(sys.argv[1]).read_text() else 0)
''')
        validator.chmod(0o700)

        handlers = yaml.safe_load((ROOT / 'roles/host_hardening/handlers/main.yml').read_text())
        reload_task = copy.deepcopy(next(t for t in self.tasks if t.get('name', '').startswith(
            'Schedule socket convergence')))
        events = self.directory / 'events.jsonl'
        reject_generated = self.directory / 'reject-generated'
        spy = self.directory / 'spy'
        spy.write_text(f'''#!{ROOT / '.venv/bin/python'}
import json, sys
from pathlib import Path
with Path({str(events)!r}).open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
if Path({str(reject_generated)!r}).exists() and sys.argv[1].startswith('Validate effective generated socket'):
    sys.exit(1)
''')
        spy.chmod(0o700)
        # Keep real handler metadata and ordering; substitute only their side-effecting modules.
        for handler in handlers:
            handler.pop('become', None)
            if 'ansible.builtin.command' in handler:
                handler['ansible.builtin.command'] = {'argv': [str(spy), handler['name']]}
            elif 'ansible.builtin.systemd_service' in handler:
                if handler['ansible.builtin.systemd_service'].get('daemon_reload'):
                    handler['ansible.builtin.command'] = {'argv': [str(spy), handler['name']]}
                    handler.pop('ansible.builtin.systemd_service')
                    handler['changed_when'] = False
                else:
                    handler['ansible.builtin.command'] = {'argv': [str(spy), handler['name']]}
                    handler.pop('ansible.builtin.systemd_service')
            elif 'portfolio_hardening_info' in handler:
                handler['ansible.builtin.command'] = {'argv': [str(spy), handler['name']]}
                handler.pop('portfolio_hardening_info')
        playbook = self.directory / 'local.yml'
        def run(activation, ports, reload_required=False):
            variables = {'ssh_listen_ports': ports, 'hardening_before': {
                'ssh_activation': activation, 'socket_reload_required': reload_required}}
            playbook.write_text(yaml.safe_dump([{'name': 'Local hardening fixture', 'hosts': 'localhost',
                'gather_facts': False, 'vars': variables, 'tasks': [task, reload_task], 'handlers': handlers}]))
            return subprocess.run([str(ROOT / '.venv/bin/ansible-playbook'), '-i', 'localhost,', '-c', 'local',
                '-e', json.dumps({'ansible_python_interpreter': str(ROOT / '.venv/bin/python')}), str(playbook)],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
                env=dict(os.environ, ANSIBLE_NOCOLOR='1', ANSIBLE_HOME=str(self.directory / 'ansible'),
                         ANSIBLE_LOCAL_TEMP=str(self.directory / 'tmp'), ANSIBLE_REMOTE_TEMP=str(self.directory / 'remote')))

        task['notify'] = handlers[0]['listen']
        reload_task['notify'] = handlers[0]['listen']
        invalid = run('socket', [2222, 99999], True)
        self.assertNotEqual(invalid.returncode, 0, invalid.stdout + invalid.stderr)
        self.assertFalse(events.exists())
        self.assertEqual(dest.read_text(), 'PermitRootLogin yes\nPasswordAuthentication yes\n')
        reject_generated.touch()
        rejected = run('socket', [2222, 2200], True)
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
        self.assertEqual([json.loads(line)[0] for line in events.read_text().splitlines()],
                         [handlers[i]['name'] for i in (0, 2, 3)])
        reject_generated.unlink()
        events.unlink()
        installed = dest.read_bytes()
        # Installed block is already converged; reload_required alone schedules
        # validation, daemon-reload, candidate validation, and listener restart.
        first = run('socket', [2222, 2200], True)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(dest.read_bytes(), installed)
        self.assertEqual([json.loads(line)[0] for line in events.read_text().splitlines()],
            [handlers[i]['name'] for i in (0, 2, 3, 4)])
        events.unlink()
        repeated = run('socket', [2222, 2200], False)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn('changed=0', repeated.stdout)
        self.assertFalse(events.exists())
        dest.write_text('PermitRootLogin yes\nPasswordAuthentication yes\n')
        events.unlink(missing_ok=True)
        service = run('service', [2222, 2200])
        self.assertEqual(service.returncode, 0, service.stdout + service.stderr)
        self.assertEqual([json.loads(line)[0] for line in events.read_text().splitlines()],
                         [handlers[i]['name'] for i in (0, 1)])

    def test_offline_make_and_verification_have_no_mutation_or_live_calls(self):
        for target in ('harden', 'verify-hardening', 'check', 'ci'):
            result = subprocess.run(['make', '-n', target], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            if target in ('check', 'ci'):
                self.assertNotIn('scripts/access.py', result.stdout)
                self.assertNotIn('inventories/production.yml', result.stdout)
                for playbook in ('harden', 'verify-hardening'):
                    self.assertIn(f'--syntax-check -i inventories/production.example.yml playbooks/{playbook}.yml', result.stdout)
            else:
                self.assertIn(f'scripts/access.py {target} ', result.stdout)
        tasks = yaml.safe_load((ROOT / 'playbooks/verify-hardening.yml').read_text())[0]['tasks']
        self.assertEqual(len(tasks), 2)
        self.assertTrue(tasks[-1]['portfolio_hardening_info']['verify'])
        self.assertFalse(any('refresh_rules' in task.get('portfolio_hardening_info', {}) for task in tasks))
        self.assertLess(next(i for i, t in enumerate(self.tasks) if 'portfolio_hardening_info' in t),
                        next(i for i, t in enumerate(self.tasks) if 'ansible.builtin.apt' in t))
        self.assertNotIn('state: absent', (ROOT / 'roles/host_hardening/tasks/main.yml').read_text())

    def fixture_path(self, name):
        return self.directory / str(name).lstrip('/') if str(name).startswith(('/etc/', '/run/', '/proc/', '/usr/lib/systemd/')) else Path(name)

    def inspection_fixture(self, managed=True, active=True):
        import shutil
        # Each call models a fresh host snapshot, including unloaded disk state.
        for root in ('/etc/systemd', '/run/systemd'):
            shutil.rmtree(self.fixture_path(root), ignore_errors=True)
        files = {'/etc/os-release': 'ID=ubuntu\n', '/etc/ssh/sshd_config': 'Include /etc/ssh/sshd_config.d/*.conf\n',
                 '/proc/sys/net/ipv6/bindv6only': '0\n',
                 '/etc/default/ufw': 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n',
                 '/etc/ufw/ufw.conf': 'ENABLED=yes\n'}
        for name in ('ssh.service', 'ssh.socket', 'ufw.service'):
            files['/usr/lib/systemd/system/' + name] = '# stock unit fixture\n'
        if managed:
            files['/etc/ssh/sshd_config'] = (info.MARKER.format(mark='BEGIN') +
                '\nPort 2200\nPort 2222\nPubkeyAuthentication yes\n' + info.MARKER.format(mark='END') +
                '\nInclude /etc/ssh/sshd_config.d/*.conf\n')
        for name in info.PROTECTED + info.RULE_FILES:
            files.setdefault(name, '# stock fixture\n')
        for name, content in files.items():
            path = self.fixture_path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        fake = Mock(params={'ssh_ports': [2222, 2200], 'tcp_ports': [80, 443], 'verify': managed,
                            'refresh_rules': False, 'current_port': 2222})
        fake.get_bin_path.return_value = '/usr/sbin/ufw'
        self.status = ('Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n' +
                       '\n'.join(f'{p}/tcp{family} ALLOW IN Anywhere{family} # portfolio-host-hardening'
                                 for p in [2222, 2200, 80, 443] for family in ['', ' (v6)'])) if active else 'Status: inactive'
        self.added = '\n'.join(f"ufw allow {p}/tcp comment 'portfolio-host-hardening'" for p in [2222, 2200, 80, 443]) if managed else ''
        self.socket = 'inactive'
        self.socket_enabled = 'disabled'
        self.socket_listen = '0.0.0.0:2222 (Stream) [::]:2222 (Stream) 0.0.0.0:2200 (Stream) [::]:2200 (Stream)'
        self.socket_dropins = ''
        self.ipv6_policy = 'both'
        self.service_dropins = ''
        self.socket_relationship = 'Requires=ssh.socket\nAfter=ssh.socket\nKillMode=process\n'
        self.service = 'active'
        self.effective = 'port 2222\nport 2200\npubkeyauthentication yes\n'
        self.sockets = '\n'.join(line for p in [2222, 2200] for line in (
            f'LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:* users:(("sshd",pid=10,fd=3))',
            f'LISTEN 0 128 [::]:{p} [::]:* users:(("sshd",pid=10,fd=4))'))

        package_conffiles = '\n'.join(f' {name} {hashlib.md5(self.fixture_path(name).read_bytes()).hexdigest()}'
                                      for name in info.PROTECTED)

        def command(argv, **kwargs):
            if argv == ['/usr/bin/lsb_release', '-is']:
                return 0, 'Ubuntu', ''
            if argv[:2] == ['systemctl', 'show']:
                if argv[3] == '--property=Requires,After,KillMode':
                    return 0, self.socket_relationship, ''
                name = argv[2]
                dropins = self.socket_dropins if name == 'ssh.socket' else self.service_dropins if name == 'ssh.service' else ''
                text = f'FragmentPath=/usr/lib/systemd/system/{name}\nDropInPaths={dropins}\n'
                if name == 'ssh.socket':
                    text += f'Listen={self.socket_listen}\nAccept=no\nTriggers=ssh.service\nBindIPv6Only={self.ipv6_policy}\n'
                return 0, text, ''
            if argv[0] == 'systemctl' and argv[2] == 'ssh.socket':
                state = self.socket if argv[1] == 'is-active' else self.socket_enabled
                return (0 if state in ('active', 'enabled') else 1), state, ''
            if argv[:2] == ['systemctl', 'is-active']:
                return (0 if self.service == 'active' else 1), self.service, ''
            if argv == ['/usr/sbin/sshd', '-t']:
                return 0, '', ''
            if argv == ['/usr/sbin/sshd', '-T']:
                return 0, self.effective, ''
            if argv == ['ss', '-H', '-ltnp']:
                return 0, self.sockets, ''
            if argv == ['ufw', 'status', 'verbose']:
                return 0, self.status, ''
            if argv == ['ufw', 'show', 'added']:
                return 0, self.added, ''
            if argv[0] == 'dpkg-query':
                return 0, package_conffiles, ''
            self.fail(f'Unexpected or mutating command: {argv}')

        fake.run_command.side_effect = command
        self.marker = self.fixture_path('/etc/ufw/portfolio-hardening.json')
        if managed:
            with patch.object(info, 'Path', side_effect=self.fixture_path):
                baseline = {'base': {name: info.fingerprint(self.fixture_path(name)) for name in info.PROTECTED},
                            'rules': {name: info.fingerprint(self.fixture_path(name)) for name in info.RULE_FILES}}
            self.marker.write_text(json.dumps(baseline))
        return fake

    def inspect(self, fake):
        with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                patch.object(info.glob, 'glob', return_value=[]):
            return info.inspect(fake)

    def test_readonly_inspection_requires_all_security_and_runtime_properties(self):
        fake = self.inspection_fixture()
        before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        result = self.inspect(fake)
        self.assertTrue(result['ufw_active'])
        self.assertEqual(before, {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
        mutations = [lambda: setattr(self, 'service', 'inactive'),
                     lambda: setattr(self, 'status', self.status.replace('deny (incoming)', 'allow (incoming)')),
                     lambda: setattr(self, 'status', self.status.replace('80/tcp (v6) ALLOW IN', '80/tcp (v6) DENY IN')),
                     lambda: setattr(self, 'sockets', self.sockets.replace('0.0.0.0:2200', '0.0.0.0:2201')),
                     lambda: setattr(self, 'effective', self.effective.replace('port 2200', 'port 2201')),
                     lambda: setattr(self, 'sockets', self.sockets.replace('\"sshd\"', '\"other\"')),
                     lambda: setattr(self, 'added', self.added + '\nufw allow 1234/tcp'),
                     lambda: self.fixture_path('/etc/ufw/before.rules').write_text('custom rules'),
                     lambda: self.fixture_path('/etc/ufw/user.rules').write_text('custom raw user rules')]
        for mutate in mutations:
            fake = self.inspection_fixture()
            mutate()
            with self.assertRaises(ValueError):
                self.inspect(fake)

    def enable_socket(self):
        self.socket = 'active'
        self.socket_enabled = 'enabled'
        self.service_dropins = '/etc/systemd/system/ssh.service.d/00-socket.conf'
        path = self.fixture_path(self.service_dropins)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[Unit]\nAfter=ssh.socket\nRequires=ssh.socket\n')

    def test_socket_listener_semantics_and_ipv6_binding_policy(self):
        self.assertEqual(info.socket_listeners('0.0.0.0:22 (Stream) [::]:22 (Stream)'),
                         {('tcp', 'ipv4', '*', 22), ('tcp', 'ipv6', '*', 22)})
        self.assertEqual(info.socket_listeners('[0000:0000:0000:0000:0000:0000:0000:0000]:22 (Stream)'),
                         info.socket_listeners('0.0.0.0:22 (Stream) [::]:22 (Stream)'))
        self.assertNotEqual(info.socket_listeners('[::]:22 (Stream)', True),
                            info.socket_listeners('0.0.0.0:22 (Stream) [::]:22 (Stream)', True))
        self.assertEqual(info.socket_listeners('0.0.0.0:22 (Stream) [::]:22 (Stream)', True),
                         info.socket_listeners('0.0.0.0:22 (Stream)', True) |
                         info.socket_listeners('[::]:22 (Stream)', True))
        for text in ('0.0.0.0:22 (Datagram)', '127.0.0.1:22 (Stream)', '[::1]:22 (Stream)',
                     '[::]:0 (Stream)', '[::]:65536 (Stream)', '22 (Stream) junk'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                info.socket_listeners(text)

    def socket_fixture_routes(self, ports):
        self.socket_listen = ' '.join(f'{addr}:{port} (Stream)' for port in ports
                                      for addr in ('0.0.0.0', '[::]'))
        self.effective = ''.join(f'port {port}\n' for port in ports) + 'pubkeyauthentication yes\n'
        self.sockets = '\n'.join(f'LISTEN 0 128 {addr}:{port} {addr}:* users:(("systemd",pid=1,fd=3),("sshd",pid=10,fd=3))'
                                 for port in ports for addr in ('0.0.0.0', '[::]'))

    def generated_socket_fixture(self, ports):
        self.socket_dropins = '/run/systemd/generator/ssh.socket.d/addresses.conf'
        path = self.fixture_path(self.socket_dropins)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Automatically generated by sshd-socket-generator\n\n[Socket]\nListenStream=\n' +
                        ''.join(f'ListenStream={addr}:{port}\n' for port in ports
                                for addr in ('0.0.0.0', '[::]')))
        return path

    def test_ubuntu_generated_entries_and_effective_listen_are_semantically_equivalent(self):
        fake = self.inspection_fixture()
        self.enable_socket()
        self.generated_socket_fixture([2222, 2200])
        for listen in ('2200 (Stream) 2222 (Stream)', '*:2222 (Stream) *:2200 (Stream)',
                       '[::]:2200 (Stream)   [::]:2222 (Stream)',
                       '[0:0:0:0:0:0:0:0]:2222 (Stream) [::]:2200 (Stream)', self.socket_listen):
            with self.subTest(listen=listen):
                self.socket_listen = listen
                self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        self.socket_listen = '[::]:2222 (Stream) [::]:2200 (Stream)'
        self.ipv6_policy = 'default'
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        self.fixture_path('/proc/sys/net/ipv6/bindv6only').write_text('1\n')
        with self.assertRaisesRegex(ValueError, 'differs semantically'):
            self.inspect(fake)
        self.ipv6_policy = 'ipv6-only'
        with self.assertRaisesRegex(ValueError, 'differs semantically'):
            self.inspect(fake)
        self.socket_fixture_routes([2222, 2200])
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        self.sockets = self.sockets.splitlines()[0]
        fake.params['verify'] = True
        with self.assertRaisesRegex(ValueError, 'Live SSH socket listeners differ'):
            self.inspect(fake)

    def test_current_route_pretransition_candidate_and_final_readonly_convergence(self):
        fake = self.inspection_fixture()
        desired = [22, 2222, 2200]
        fake.params.update(verify=False, ssh_ports=desired)
        self.enable_socket()
        self.socket_fixture_routes([2222])
        self.generated_socket_fixture([2222])
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        fake.params['verify'] = True
        with self.assertRaisesRegex(ValueError, 'Effective SSH ports/listeners'):
            self.inspect(fake)
        fake.params.update(verify=False, socket_candidate=True)
        old_live = self.sockets
        self.socket_fixture_routes(desired)
        self.sockets = old_live  # daemon-reload changes the candidate, not the live routes
        self.generated_socket_fixture(desired)
        allowed = desired + fake.params['tcp_ports']
        self.status = ('Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n' +
                       '\n'.join(f'{port}/tcp{family} ALLOW IN Anywhere{family} # portfolio-host-hardening'
                                 for port in allowed for family in ('', ' (v6)')))
        self.added = '\n'.join(f"ufw allow {port}/tcp comment 'portfolio-host-hardening'" for port in allowed)
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        fake.params['socket_candidate'] = False
        fake.params['verify'] = True
        with self.assertRaisesRegex(ValueError, 'Live SSH socket listeners differ'):
            self.inspect(fake)
        fake.params['verify'] = False
        self.socket_fixture_routes(desired)
        fake.params['verify'] = True
        before = {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()}
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        self.assertEqual(before, {path: path.read_bytes() for path in self.directory.rglob('*') if path.is_file()})

    def test_preflight_allows_socket_reload_drift_but_reports_required(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, ssh_ports=[2222, 2200])
        self.enable_socket()
        self.socket_fixture_routes([2222])
        self.generated_socket_fixture([2200])
        # Loaded routes may lag sshd configuration before daemon-reload.
        self.effective = 'port 2222\nport 2200\npubkeyauthentication yes\n'
        before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
        self.assertEqual(self.inspect(fake)['socket_reload_required'], True)
        self.assertEqual(before, {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
        fake.params['verify'] = True
        with self.assertRaisesRegex(ValueError, 'Generated socket file differs semantically'):
            self.inspect(fake)
        fake.params.update(verify=False, socket_candidate=True)
        with self.assertRaisesRegex(ValueError, 'Generated socket file differs semantically'):
            self.inspect(fake)
        self.socket_fixture_routes([2222, 2200])
        self.generated_socket_fixture([2222, 2200])
        fake.params.update(socket_candidate=False, verify=True)
        self.assertFalse(self.inspect(fake)['socket_reload_required'])

    def test_preflight_requires_current_route_and_limits_live_ports_to_desired(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, ssh_ports=[2222, 2200], current_port=2222)
        self.enable_socket()
        self.socket_fixture_routes([2222, 2200, 2022])
        with self.assertRaisesRegex(ValueError, 'Preserve existing live SSH routes'):
            self.inspect(fake)
        self.socket_fixture_routes([2200])
        with self.assertRaisesRegex(ValueError, 'Current inventory SSH route'):
            self.inspect(fake)

    def test_preflight_rejects_malformed_generated_socket_dropins(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, ssh_ports=[2222, 2200])
        self.enable_socket()
        path = self.generated_socket_fixture([2222, 2200])
        for malformed in ('[Socket]\nAccept=yes\n', '[Other]\nListenStream=2222\n',
                          '[Socket]\nListenStream=not-a-listener\n'):
            with self.subTest(malformed=malformed):
                path.write_text(malformed)
                with self.assertRaises(ValueError):
                    self.inspect(fake)

    def test_candidate_requires_desired_routes_even_when_generated_and_loaded_agree(self):
        fake = self.inspection_fixture()
        fake.params.update(verify=False, socket_candidate=True)
        self.enable_socket()
        self.socket_fixture_routes([2222])
        self.generated_socket_fixture([2222])
        with self.assertRaisesRegex(ValueError, 'Generated socket listeners differ from desired ports'):
            self.inspect(fake)

    def test_current_route_and_candidate_firewall_failures_are_rejected(self):
        for desired, live in (([2222, 2200], [2200]), ([2200], [2200])):
            fake = self.inspection_fixture()
            fake.params.update(verify=False, ssh_ports=desired)
            self.socket_fixture_routes(live)
            with self.assertRaisesRegex(ValueError, 'Current inventory SSH route'):
                self.inspect(fake)
        fake = self.inspection_fixture()
        self.enable_socket()
        fake.params.update(verify=False, socket_candidate=True)
        for family in ('', ' (v6)'):
            original = self.status
            self.status = self.status.replace(f'2200/tcp{family} ALLOW IN', f'2200/tcp{family} DENY IN')
            with self.assertRaisesRegex(ValueError, 'All desired SSH ports'):
                self.inspect(fake)
            self.status = original

    def test_verify_hardening_wrapper_timeout_reports_route_and_rethrows_without_mutation(self):
        for mode in ('harden', 'verify-hardening'):
            with self.subTest(mode=mode), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host'), patch.object(access, 'prepare_key'), \
                    patch.object(access.subprocess, 'run') as run, patch('builtins.print') as output:
                calls = []
                def timeout(command, **kwargs):
                    calls.append(Path(command[3]).name)
                    if command[3].endswith('verify.yml') and len(calls) > (2 if mode == 'harden' else 1):
                        raise subprocess.CalledProcessError(124, command, stderr='timed out')
                run.side_effect = timeout
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    access.live(mode, self.inventory, self.key)
                self.assertEqual(raised.exception.returncode, 124)
                self.assertEqual(calls, ['verify.yml'] + (['harden.yml'] if mode == 'harden' else []) + ['verify.yml'])
                messages = ' '.join(str(call.args) for call in output.call_args_list)
                self.assertIn('Post-convergence access verification failed', messages)
                self.assertIn('make verify-access on the current inventory route', messages)

    def test_default_ubuntu_socket_and_multiport_state_are_accepted(self):
        fake = self.inspection_fixture()
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'service')
        self.enable_socket()
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        fake.params.update(verify=False, ssh_ports=[22, 2222, 2200], current_port=22)
        self.socket_fixture_routes([22])
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        fake.params['current_port'] = 2222
        with self.assertRaisesRegex(ValueError, 'Current inventory SSH route'):
            self.inspect(fake)
        fake.params['current_port'] = 22
        self.socket_listen = '[::]:22 (Stream)'
        self.sockets = 'LISTEN 0 128 [::]:22 [::]:* users:(("systemd",pid=1,fd=3),("sshd",pid=10,fd=3))'
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')

    def test_socket_candidate_validates_generated_ports_before_live_switch(self):
        fake = self.inspection_fixture()
        self.enable_socket()
        fake.params.update(verify=False, socket_candidate=True)
        self.sockets = self.sockets.splitlines()[0]  # old listener survives daemon-reload
        self.socket_dropins = '/run/systemd/generator/ssh.socket.d/addresses.conf'
        path = self.fixture_path(self.socket_dropins)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[Socket]\nListenStream=\nListenStream=[::]:2222\nListenStream=[::]:2200\n')
        self.assertEqual(self.inspect(fake)['ssh_activation'], 'socket')
        generated = path.read_text()
        for invalid in ('[Socket]\nListenStream=\nListenStream=99999\n',
                        '[Socket]\nListenStream=\nAccept=yes\n',
                        '[Socket]\nListenStream=\nListenStream=[::]:2222\n'):
            path.write_text(invalid)
            with self.assertRaises(ValueError):
                self.inspect(fake)
        path.write_text(generated)
        self.socket_listen = '[::]:2222 (Stream)'
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_ambiguous_socket_configuration_stops_readonly(self):
        changes = [lambda: setattr(self, 'socket_enabled', 'disabled'),
                   lambda: setattr(self, 'socket_listen', '/run/ssh.sock (Stream)'),
                   lambda: setattr(self, 'socket_listen', '[::]:9999 (Stream)'),
                   lambda: setattr(self, 'socket_listen', '[::]:2222 (Datagram)'),
                   lambda: setattr(self, 'socket_relationship', 'Requires=\nAfter=\nKillMode=control-group\n'),
                   lambda: self.fixture_path(self.service_dropins).write_text('[Unit]\nRequires=ssh.socket\nAfter=ssh.socket\n[Service]\nExecStart=custom\n')]
        for change in changes:
            fake = self.inspection_fixture()
            self.enable_socket()
            change()
            before = {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()}
            with self.assertRaises(ValueError):
                self.inspect(fake)
            self.assertEqual(before, {p: p.read_bytes() for p in self.directory.rglob('*') if p.is_file()})
        fake = self.inspection_fixture()
        self.enable_socket()
        self.socket_dropins = '/etc/systemd/system/ssh.socket.d/custom.conf'
        path = self.fixture_path(self.socket_dropins)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('[Socket]\nListenStream=2222\n')
        with self.assertRaises(ValueError):
            self.inspect(fake)
        # The same override is rejected even with service-only activation.
        self.socket = 'inactive'
        self.socket_enabled = 'disabled'
        self.service_dropins = ''
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_socket_handler_order_and_firewall_before_listener_mutation(self):
        handlers = yaml.safe_load((ROOT / 'roles/host_hardening/handlers/main.yml').read_text())
        self.assertEqual(handlers[1]['when'], "hardening_before.ssh_activation == 'service'")
        self.assertTrue(handlers[2]['ansible.builtin.systemd_service']['daemon_reload'])
        self.assertTrue(handlers[3]['portfolio_hardening_info']['socket_candidate'])
        self.assertEqual(handlers[4]['ansible.builtin.command']['argv'], ['systemctl', 'restart', 'ssh.socket', 'ssh.service'])
        for handler in handlers[2:]:
            self.assertEqual(handler['when'], "hardening_before.ssh_activation == 'socket'")
            self.assertEqual(handler['listen'], handlers[0]['listen'])
        allow = next(i for i, task in enumerate(self.tasks) if task.get('loop') == '{{ ssh_listen_ports }}')
        config = next(i for i, task in enumerate(self.tasks) if 'ansible.builtin.blockinfile' in task)
        self.assertLess(allow, config)
        self.assertEqual(self.tasks[-1]['ansible.builtin.meta'], 'flush_handlers')

    def test_port_assertions_and_absent_ufw_preflight(self):
        task = self.tasks[0]
        variables = {'ansible_port': 2222, 'ssh_listen_ports': [2222, 2200], 'firewall_allowed_tcp_ports': []}
        result = self.local_ansible([task], variables)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for ports in ([2200], [2222, 2222], [2222, '2200'], [2222, True], [2222, 65536]):
            result = self.local_ansible([task], variables | {'ssh_listen_ports': ports})
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('changed=0', result.stdout)
        fake = self.inspection_fixture(managed=False, active=False)
        fake.get_bin_path.return_value = None
        import shutil
        shutil.rmtree(self.fixture_path('/etc/ufw'))
        self.fixture_path('/etc/default/ufw').unlink()
        result = self.inspect(fake)
        self.assertEqual(result['ssh_adoption'], [])
        result.pop('ssh_adoption')
        result.pop('ssh_sources')
        self.assertEqual(result, {'ufw_installed': False, 'ssh_activation': 'service',
                                             'socket_reload_required': False})
        self.fixture_path('/etc/default/ufw').write_text('orphan')
        with self.assertRaises(ValueError):
            self.inspect(fake)

    def test_legacy_port_adoption_preflight_is_exact_and_readonly(self):
        for included in (False, True):
            for socket_mode in (False, True):
                fake = self.inspection_fixture(managed=False, active=False)
                source = '/etc/ssh/sshd_config.d/50-provider.conf' if included else '/etc/ssh/sshd_config'
                path = self.fixture_path(source)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# provider comment\n  Port 2222 # keep comment\nPasswordAuthentication yes\n')
                self.effective = 'port 2222\npubkeyauthentication yes\n'
                self.sockets = self.sockets.replace(':2200', ':2222')
                if socket_mode:
                    self.enable_socket()
                    self.socket_listen = '0.0.0.0:2222 (Stream) [::]:2222 (Stream)'
                before = path.read_bytes()
                with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                        patch.object(info.glob, 'glob', return_value=[source] if included else []):
                    result = info.inspect(fake)
                self.assertEqual(result['ssh_adoption'], [{'path': source, 'line': 2, 'port': 2222}])
                self.assertEqual(path.read_bytes(), before)
                fake.params['verify'] = True
                with self.assertRaises(ValueError):
                    self.inspect(fake)

    def test_unsupported_legacy_port_types_fail_readonly(self):
        for content, diagnostic in (
                ('Port 2201\n', 'outside desired'),
                ('ListenAddress 0.0.0.0\n', 'ListenAddress'),
                ('Match User other\nPort 2222\n', 'legacy Port'),
                ('Port=2222\n', 'legacy Port'),
                ('Include /custom/*.conf\n', 'Include'),
                ('Include /etc/ssh/sshd_config.d/*.conf\nInclude /etc/ssh/sshd_config.d/*.conf\n', 'Include')):
            fake = self.inspection_fixture(managed=False, active=False)
            path = self.fixture_path('/etc/ssh/sshd_config')
            path.write_text(content)
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, diagnostic):
                self.inspect(fake)
            self.assertEqual(path.read_text(), content)
        for state in ('effective', 'live', 'current', 'custom-unit'):
            fake = self.inspection_fixture(managed=False, active=False)
            self.fixture_path('/etc/ssh/sshd_config').write_text('Port 2222\n')
            self.effective = 'port 2222\npubkeyauthentication yes\n'
            if state == 'effective':
                self.effective += 'port 2201\n'
            elif state == 'live':
                self.sockets = self.sockets.replace(':2200', ':2201')
            elif state == 'current':
                self.sockets = self.sockets.replace(':2222', ':2200')
            else:
                self.service_dropins = '/etc/systemd/system/ssh.service.d/custom.conf'
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.inspect(fake)

    def test_adoption_candidate_transaction_preserves_files_and_converges(self):
        for included in (False, True):
            fake = self.inspection_fixture(managed=False, active=False)
            source = '/etc/ssh/sshd_config.d/50-provider.conf' if included else '/etc/ssh/sshd_config'
            source_path = self.fixture_path(source)
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text('# provider\nPort 2222 # keep\nPasswordAuthentication yes\n')
            main = self.fixture_path('/etc/ssh/sshd_config')
            self.effective = 'port 2222\npubkeyauthentication yes\n'
            snippets = [source] if included else []
            with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                    patch.object(info.glob, 'glob', return_value=snippets):
                plan = info.inspect(fake)
            original = {p['path']: self.fixture_path(p['path']).read_bytes() for p in plan['ssh_sources']}
            module = Mock(params={'ssh_ports': [2222, 2200], 'sources': plan['ssh_sources'],
                                  'adoption': plan['ssh_adoption']}, tmpdir=str(self.directory), check_mode=False)
            module.run_command.return_value = (1, '', '')
            module.atomic_move.side_effect = lambda src, dest: os.replace(src, self.fixture_path(dest))
            with patch.object(adoption, 'Path', side_effect=self.fixture_path), \
                    patch.object(adoption.glob, 'glob', return_value=snippets):
                with self.assertRaisesRegex(ValueError, 'candidate failed'):
                    adoption.adopt(module)
                module.atomic_move.assert_not_called()
                for name, data in original.items():
                    self.assertEqual(self.fixture_path(name).read_bytes(), data)

                def validate(argv):
                    candidate = Path(argv[-1]).read_text()
                    self.assertTrue(candidate.startswith(adoption.BEGIN))
                    self.assertNotIn('Port 2222 # keep', candidate)
                    if included:
                        self.assertNotIn(adoption.INCLUDES, candidate)
                        staged = next(Path(argv[-1]).parent.glob('includes/*.conf')).read_text()
                        self.assertEqual(staged, '# provider\n# keep\nPasswordAuthentication yes\n')
                    return 0, 'port 2200\nport 2222\npubkeyauthentication yes\n', ''

                module.run_command.side_effect = [(0, '', ''), (0, 'port 2201\npubkeyauthentication yes\n', '')]
                with self.assertRaisesRegex(ValueError, 'effective ports'):
                    adoption.adopt(module)
                for name, data in original.items():
                    self.assertEqual(self.fixture_path(name).read_bytes(), data)
                module.run_command.side_effect = validate
                if included:
                    writes = []

                    def fail_main_once(src, dest):
                        writes.append(dest)
                        if dest == '/etc/ssh/sshd_config' and writes.count(dest) == 1:
                            raise SystemExit('synthetic atomic_move failure')
                        os.replace(src, self.fixture_path(dest))

                    module.atomic_move.side_effect = fail_main_once
                    with self.assertRaises(SystemExit):
                        adoption.adopt(module)
                    for name, data in original.items():
                        self.assertEqual(self.fixture_path(name).read_bytes(), data)
                    self.assertEqual(writes, [source, '/etc/ssh/sshd_config', '/etc/ssh/sshd_config', source])
                    module.atomic_move.side_effect = lambda src, dest: os.replace(src, self.fixture_path(dest))
                self.assertTrue(adoption.adopt(module))
                self.assertTrue(main.read_text().startswith(adoption.BEGIN))
                self.assertTrue(source_path.read_text().endswith('# provider\n# keep\nPasswordAuthentication yes\n'))
                module.atomic_move.reset_mock()
                module.params['adoption'] = []
                self.assertFalse(adoption.adopt(module))
                module.atomic_move.assert_not_called()
            self.assertEqual(info.unmanaged_ssh(main.read_text(), main=True), [])
            if included:
                self.assertEqual(info.unmanaged_ssh(source_path.read_text()), [])
            # A refreshed preflight produces an empty adoption plan on convergence.
            with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                    patch.object(info.glob, 'glob', return_value=snippets):
                self.assertEqual(info.inspect(fake)['ssh_adoption'], [])

    def test_multiple_exact_records_adopt_and_converge(self):
        for content, snippet_content in (
                (b'Port 2222\nPort 2200\n', None),
                (b'Port 2222 # first\r\nPort 2200 # second\n', None),
                (b'Port 2222 # first\nPort 2222 # second\n', None),
                (b'Port 2222 # first\n', b'Port 2200 # second\nPort 2222 # duplicate\n')):
            with self.subTest(content=content, snippet=snippet_content):
                fake = self.inspection_fixture(managed=False, active=False)
                main_name = '/etc/ssh/sshd_config'
                main = self.fixture_path(main_name)
                snippets = []
                main.write_bytes(b'# unrelated provider\n' + content +
                                 b'Include /etc/ssh/sshd_config.d/*.conf\r\nPasswordAuthentication yes\n')
                if snippet_content is not None:
                    name = '/etc/ssh/sshd_config.d/50-provider.conf'
                    path = self.fixture_path(name)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'# snippet\n' + snippet_content + b'PermitRootLogin yes\n')
                    snippets.append(name)
                self.effective = 'port 2222\nport 2200\npubkeyauthentication yes\n'
                with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                        patch.object(info.glob, 'glob', return_value=snippets):
                    plan = info.inspect(fake)
                self.assertEqual(len(plan['ssh_adoption']), 3 if snippets else 2)
                original = {s['path']: self.fixture_path(s['path']).read_bytes() for s in plan['ssh_sources']}
                module = Mock(params={'ssh_ports': [2222, 2200], 'sources': plan['ssh_sources'],
                                      'adoption': plan['ssh_adoption']}, tmpdir=str(self.directory), check_mode=False)
                def validate(argv):
                    staged = Path(argv[-1])
                    text = staged.read_text()
                    self.assertEqual(text.splitlines()[1:4], ['Port 2200', 'Port 2222', 'PubkeyAuthentication yes'])
                    self.assertNotIn('Port 2222 #', text)
                    self.assertNotIn(adoption.INCLUDES, text)
                    for path in staged.parent.glob('includes/*.conf'):
                        self.assertNotIn('Port ', path.read_text())
                    return 0, 'port 2200\nport 2222\npubkeyauthentication yes\n', ''
                module.run_command.side_effect = validate
                module.atomic_move.side_effect = lambda src, dest: os.replace(src, self.fixture_path(dest))
                with patch.object(adoption, 'Path', side_effect=self.fixture_path), \
                        patch.object(adoption.glob, 'glob', return_value=snippets):
                    records = module.params['adoption']
                    for malformed in (records + [records[0]], [records[0] | {'line': True}],
                                      [records[0] | {'port': 9999}], [records[0] | {'line': 100}],
                                      [records[0] | {'path': '/custom/sshd_config'}]):
                        module.params['adoption'] = malformed
                        with self.assertRaises(ValueError):
                            adoption.adopt(module)
                        module.atomic_move.assert_not_called()
                    module.params['adoption'] = records
                    # Drift introduced by validation must also abort immediately before writes.
                    def drift(argv):
                        result = validate(argv)
                        if '-T' in argv:
                            main.write_bytes(original[main_name] + b'# drift\n')
                        return result
                    module.run_command.side_effect = drift
                    with self.assertRaises(ValueError):
                        adoption.adopt(module)
                    module.atomic_move.assert_not_called()
                    main.write_bytes(original[main_name])
                    module.run_command.side_effect = validate
                    if snippets:
                        writes = []
                        def fail_main(src, dest):
                            writes.append(dest)
                            os.replace(src, self.fixture_path(dest))
                            if dest == main_name and writes.count(dest) == 1:
                                raise OSError('synthetic failure after replacement')
                        module.atomic_move.side_effect = fail_main
                        with self.assertRaises(OSError):
                            adoption.adopt(module)
                        self.assertEqual(original, {n: self.fixture_path(n).read_bytes() for n in original})
                        module.atomic_move.side_effect = lambda src, dest: os.replace(src, self.fixture_path(dest))
                    self.assertTrue(adoption.adopt(module))
                    for name, data in original.items():
                        expected = data
                        for record in records:
                            if record['path'] == name:
                                line = data.splitlines(keepends=True)[record['line'] - 1]
                                comment = line[line.index(b'#'):] if b'#' in line else b''
                                expected = expected.replace(line, comment, 1)
                        if name == main_name:
                            block = (adoption.BEGIN + '\nPort 2200\nPort 2222\nPubkeyAuthentication yes\n' +
                                     adoption.END + '\n').encode()
                            expected = block + expected
                        self.assertEqual(self.fixture_path(name).read_bytes(), expected)
                    with patch.object(info, 'Path', side_effect=self.fixture_path), patch.object(info, 'STATE', self.marker), \
                            patch.object(info.glob, 'glob', return_value=snippets):
                        refreshed = info.inspect(fake)
                    self.assertEqual(refreshed['ssh_adoption'], [])
                    module.params['adoption'] = refreshed['ssh_adoption']
                    module.atomic_move.reset_mock()
                    self.assertFalse(adoption.adopt(module))
                    module.atomic_move.assert_not_called()

    def test_adoption_with_real_local_ansible_then_changed_zero(self):
        main = self.directory / 'sshd_config'
        main.write_text('# provider\nPort 2222 # keep\nPort 2200 # other\nPort 2222 # duplicate\nPasswordAuthentication yes\n')
        main.chmod(0o644)
        snippets = self.directory / 'sshd_config.d'
        snippets.mkdir()
        validator = self.directory / 'sshd'
        validator.write_text(f'''#!{ROOT / '.venv/bin/python'}
import sys
from pathlib import Path
text = Path(sys.argv[-1]).read_text()
if Path({str(self.directory / 'invalid')!r}).exists():
    sys.exit(1)
assert text.startswith('# BEGIN ANSIBLE PORTFOLIO SSH PORTS')
assert 'Port 2222 # keep' not in text
assert 'PasswordAuthentication yes' in text
if '-T' in sys.argv:
    print('port 2200\\nport 2222\\npubkeyauthentication yes')
''')
        validator.chmod(0o700)
        library = self.directory / 'library'
        library.mkdir()
        code = (ROOT / 'library/portfolio_ssh_adopt.py').read_text()
        code = code.replace(repr(adoption.MAIN), repr(str(main)))
        code = code.replace(repr(adoption.INCLUDES), repr(str(snippets / '*.conf')))
        code = code.replace("'/usr/sbin/sshd'", repr(str(validator)))
        (library / 'fixture_adopt.py').write_text(code)
        task = copy.deepcopy(next(t for t in self.tasks if 'portfolio_ssh_adopt' in t))
        task['fixture_adopt'] = task.pop('portfolio_ssh_adopt')
        task.pop('become')
        task.pop('notify')
        block = copy.deepcopy(next(t for t in self.tasks if 'ansible.builtin.blockinfile' in t))
        block.pop('become')
        block.pop('notify')
        block['ansible.builtin.blockinfile'].update(path=str(main), owner=os.getuid(), group=os.getgid(),
                                                  validate=f'{validator} -t -f %s')
        variables = {'ssh_listen_ports': [2222, 2200], 'hardening_before': {
            'ssh_sources': [{'path': str(main), 'sha256': hashlib.sha256(main.read_bytes()).hexdigest()}],
            'ssh_adoption': [{'path': str(main), 'line': line, 'port': port}
                             for line, port in ((2, 2222), (3, 2200), (4, 2222))]}}
        original = main.read_bytes()
        invalid = self.directory / 'invalid'
        invalid.touch()
        failed = self.local_ansible([task, block], variables)
        self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
        self.assertIn('changed=0', failed.stdout)
        self.assertEqual(main.read_bytes(), original)
        invalid.unlink()
        first = self.local_ansible([task, block], variables)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('changed=1', first.stdout)
        self.assertTrue(main.read_text().endswith('# provider\n# keep\n# other\n# duplicate\nPasswordAuthentication yes\n'))
        variables['hardening_before']['ssh_adoption'] = []
        second = self.local_ansible([task, block], variables)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn('changed=0', second.stdout)

    def test_adoption_rejects_source_drift_before_writes(self):
        main = self.fixture_path('/etc/ssh/sshd_config')
        main.parent.mkdir(parents=True)
        data = b'Port 2222\n'
        main.write_bytes(data + b'# concurrent change\n')
        module = Mock(params={'ssh_ports': [2222],
                              'sources': [{'path': '/etc/ssh/sshd_config', 'sha256': hashlib.sha256(data).hexdigest()}],
                              'adoption': [{'path': '/etc/ssh/sshd_config', 'line': 1, 'port': 2222}]})
        with patch.object(adoption, 'Path', side_effect=self.fixture_path), \
                patch.object(adoption.glob, 'glob', return_value=[]), self.assertRaises(ValueError):
            adoption.adopt(module)
        module.run_command.assert_not_called()
        module.atomic_move.assert_not_called()

    def test_unmanaged_state_and_socket_activation_fail_before_mutation(self):
        fake = self.inspection_fixture(managed=False, active=False)
        self.assertTrue(self.inspect(fake)['ufw_installed'])
        for change in ('unknown-rule', 'raw-rule', 'base-config', 'active', 'ssh-ports', 'socket'):
            fake = self.inspection_fixture(managed=False, active=False)
            if change == 'unknown-rule':
                self.added = 'ufw allow 2222/tcp'
            elif change == 'raw-rule':
                self.fixture_path('/etc/ufw/user.rules').write_text('-A ufw-user-input -j ACCEPT\n')
            elif change == 'base-config':
                self.fixture_path('/etc/ufw/before.rules').write_text('custom base configuration')
            elif change == 'active':
                self.status = 'Status: active'
            elif change == 'socket':
                self.socket = 'active'
            else:
                self.fixture_path('/etc/ssh/sshd_config').write_text('Port 2201\n')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.inspect(fake)
        for text in ('Port=2222\n', 'ListenAddress 0.0.0.0:22\n', 'Include /other/config\n',
                     '# BEGIN ANSIBLE PORTFOLIO SSH PORTS\nPermitRootLogin no\n# END ANSIBLE PORTFOLIO SSH PORTS\n'):
            with self.assertRaises(ValueError):
                info.unmanaged_ssh(text, main=True)


if __name__ == '__main__':
    unittest.main()
