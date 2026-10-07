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
        self.assertEqual(sum('notify' in task for task in self.tasks), 1)
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
        return self.directory / str(name).lstrip('/') if str(name).startswith('/etc/') else Path(name)

    def inspection_fixture(self, managed=True, active=True):
        files = {'/etc/os-release': 'ID=ubuntu\n', '/etc/ssh/sshd_config': 'Include /etc/ssh/sshd_config.d/*.conf\n',
                 '/etc/default/ufw': 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n',
                 '/etc/ufw/ufw.conf': 'ENABLED=yes\n'}
        for name in info.PROTECTED + info.RULE_FILES:
            files.setdefault(name, '# stock fixture\n')
        for name, content in files.items():
            path = self.fixture_path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        fake = Mock(params={'ssh_ports': [2222, 2200], 'tcp_ports': [80, 443], 'verify': managed,
                            'refresh_rules': False})
        fake.get_bin_path.return_value = '/usr/sbin/ufw'
        self.status = ('Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n' +
                       '\n'.join(f'{p}/tcp{family} ALLOW IN Anywhere{family} # portfolio-host-hardening'
                                 for p in [2222, 2200, 80, 443] for family in ['', ' (v6)'])) if active else 'Status: inactive'
        self.added = '\n'.join(f"ufw allow {p}/tcp comment 'portfolio-host-hardening'" for p in [2222, 2200, 80, 443]) if managed else ''
        self.socket = 'disabled'
        self.service = 'active'
        self.effective = 'port 2222\nport 2200\npubkeyauthentication yes\n'
        self.sockets = '\n'.join(f'LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:* users:(("sshd",pid=10,fd=3))' for p in [2222, 2200])

        package_conffiles = '\n'.join(f' {name} {hashlib.md5(self.fixture_path(name).read_bytes()).hexdigest()}'
                                      for name in info.PROTECTED)

        def command(argv, **kwargs):
            if argv == ['/usr/bin/lsb_release', '-is']:
                return 0, 'Ubuntu', ''
            if argv[:2] == ['systemctl', 'show']:
                return 0, 'FragmentPath=/usr/lib/systemd/system/ssh.service\nDropInPaths=\n', ''
            if argv[0] == 'systemctl' and argv[2] == 'ssh.socket':
                return (0 if self.socket == 'active' else 1), self.socket, ''
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
        mutations = [lambda: setattr(self, 'socket', 'active'), lambda: setattr(self, 'service', 'inactive'),
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
        self.assertEqual(self.inspect(fake), {'ufw_installed': False})
        self.fixture_path('/etc/default/ufw').write_text('orphan')
        with self.assertRaises(ValueError):
            self.inspect(fake)

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
                self.fixture_path('/etc/ssh/sshd_config').write_text('Port 2222\n')
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.inspect(fake)
        for text in ('Port=2222\n', 'ListenAddress 0.0.0.0:22\n', 'Include /other/config\n',
                     '# BEGIN ANSIBLE PORTFOLIO SSH PORTS\nPermitRootLogin no\n# END ANSIBLE PORTFOLIO SSH PORTS\n'):
            with self.assertRaises(ValueError):
                info.unmanaged_ssh(text, main=True)


if __name__ == '__main__':
    unittest.main()
