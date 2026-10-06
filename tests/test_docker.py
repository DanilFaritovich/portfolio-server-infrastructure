"""Docker-stage regressions: synthetic inventory, opaque keys and local Ansible only."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('docker_access', ROOT / 'scripts/access.py')
access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(access)


class DockerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.inventory = self.directory / 'fixture.yml'
        self.inventory.write_text(yaml.safe_dump({'all': {'children': {'bootstrap': {'hosts': {
            'fixture': {'ansible_host': 'fixture.example.test', 'ansible_port': 2222, 'ansible_user': 'root'},
        }}}}}))
        self.key = self.directory / 'opaque-key'
        self.key.touch(mode=0o600)
        Path(str(self.key) + '.pub').touch(mode=0o600)
        self.tasks = yaml.safe_load((ROOT / 'roles/docker_host/tasks/main.yml').read_text())

    def test_managed_transport_overlay_and_controller_isolation(self):
        for mode in ('docker-host', 'verify-docker'):
            with self.subTest(mode=mode), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host') as trust, \
                    patch.object(access, 'prepare_key') as prepare, \
                    patch.object(access.subprocess, 'run') as run:
                overlays = []

                def capture(command, **kwargs):
                    overlay = Path(command[-1])
                    self.assertEqual(overlay.stat().st_mode & 0o777, 0o600)
                    overlays.append(json.loads(overlay.read_text()))
                    self.assertNotIn('--ask-pass', command)
                    self.assertNotIn('--ask-become-pass', command)
                    self.assertEqual(json.loads(command[command.index('-e') + 1]), {})
                    self.assertNotIn('input', kwargs)
                    self.assertNotIn('shell', kwargs)
                    self.assertFalse(any('password' in k.lower() for k in kwargs['env']))

                run.side_effect = capture
                with patch.dict(os.environ, {'FIXTURE': 'safe'}, clear=True), patch('builtins.print'):
                    access.live(mode, self.inventory, self.key)
                prepare.assert_not_called()
                trust.assert_called_once_with('fixture.example.test', 2222, allow_trust=False)
                self.assertEqual([Path(c.args[0][3]).name for c in run.call_args_list], ['verify.yml', mode + '.yml'])
                for overlay in overlays:
                    host = overlay['all']['hosts']['fixture']
                    self.assertEqual(host['ansible_user'], 'ansible')
                    self.assertEqual(host['ansible_connection'], 'ssh')
                    self.assertEqual(host['ansible_private_key_file'], str(self.key))
                    self.assertTrue(host['ansible_host_key_checking'])
                    for option in ('StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                                   'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'IdentityAgent=none'):
                        self.assertIn(option, host['ansible_ssh_args'])
                    self.assertFalse(any('paramiko' in k or 'password' in k for k in host))
                    local = overlay['all']['hosts']['localhost']
                    self.assertEqual(local['ansible_connection'], 'local')
                    self.assertEqual(local['ansible_python_interpreter'], access.sys.executable)
                    self.assertFalse(local['ansible_become'])
                stage = overlays[1]['all']['hosts']['fixture']
                self.assertNotIn('ansible_become', stage)  # Preserve per-task privilege decisions.
                self.assertEqual(stage['ansible_become_flags'], '-n')
                self.assertTrue(all(not Path(c.args[0][-1]).exists() for c in run.call_args_list))

    def test_preflight_failure_never_reaches_docker_playbook(self):
        for mode in ('docker-host', 'verify-docker'):
            with self.subTest(mode=mode), patch.object(access, 'prerequisites'), \
                    patch.object(access, 'known_host'), patch.object(access, 'run_playbook') as run, \
                    patch('builtins.print'):
                run.side_effect = subprocess.CalledProcessError(1, 'synthetic access verification')
                with self.assertRaises(subprocess.CalledProcessError):
                    access.live(mode, self.inventory, self.key)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[3], 'verify.yml')
                run.reset_mock()
                with self.assertRaises(ValueError):
                    access.live(mode, ROOT / 'inventories/production.example.yml', self.key)
                run.assert_not_called()
        self.key.unlink()
        with patch.object(access, 'prerequisites'), patch.object(access, 'run_playbook') as run:
            with self.assertRaisesRegex(ValueError, 'make bootstrap-user'):
                access.live('docker-host', self.inventory, self.key)
            run.assert_not_called()

    def local_ansible(self, tasks, variables):
        """Execute selected assertions/copy on temporary local fixtures; deny network."""
        guard = self.directory / 'sitecustomize.py'
        guard.write_text('import socket\n'
                         'def deny(*args, **kwargs):\n'
                         '    raise RuntimeError("Offline Docker test forbids network")\n'
                         'socket.socket.connect = deny\n'
                         'socket.socket.connect_ex = deny\n'
                         'socket.create_connection = deny\n')
        playbook = self.directory / 'local.yml'
        playbook.write_text(yaml.safe_dump([{'name': 'Local Docker fixture', 'hosts': 'localhost',
                                           'gather_facts': False, 'vars': variables, 'tasks': tasks}]))
        return subprocess.run([str(ROOT / '.venv/bin/ansible-playbook'), '-i', 'localhost,', '-c', 'local',
                               '-e', json.dumps({'ansible_python_interpreter': str(ROOT / '.venv/bin/python')}),
                               str(playbook)], cwd=ROOT, capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, PYTHONPATH=str(self.directory), ANSIBLE_NOCOLOR='1',
                                       ANSIBLE_HOME=str(self.directory / 'ansible'),
                                       ANSIBLE_LOCAL_TEMP=str(self.directory / 'tmp'),
                                       ANSIBLE_REMOTE_TEMP=str(self.directory / 'remote')))

    def test_safety_assertions_reject_conflicts_before_any_mutation(self):
        defaults = yaml.safe_load((ROOT / 'roles/docker_host/defaults/main.yml').read_text())
        assertions = [t for t in self.tasks if 'ansible.builtin.assert' in t][:2]
        variables = defaults | {'ansible_facts': {'distribution': 'Ubuntu', 'distribution_release': 'noble',
                                                'architecture': 'x86_64', 'service_mgr': 'systemd', 'packages': {}}}
        result = self.local_ansible(assertions, variables)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('changed=0', result.stdout)
        for change in ({'packages': {'containerd': [{}]}}, {'distribution': 'Debian'}, {'architecture': 'unknown'}):
            with self.subTest(change=change):
                result = self.local_ansible(assertions, variables | {'ansible_facts': variables['ansible_facts'] | change})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('changed=0', result.stdout)
        first_mutation = next(i for i, t in enumerate(self.tasks) if 'ansible.builtin.apt' in t)
        self.assertTrue(all(i < first_mutation for i, t in enumerate(self.tasks) if 'ansible.builtin.assert' in t))
        self.assertFalse(any('ansible.builtin.command' in t or 'ansible.builtin.shell' in t for t in self.tasks))
        self.assertFalse(any(t.get('ansible.builtin.apt', {}).get('state') == 'absent' for t in self.tasks))

    def test_existing_configuration_is_preserved_or_rejected_before_installation(self):
        defaults = yaml.safe_load((ROOT / 'roles/docker_host/defaults/main.yml').read_text())
        names = ('Compare existing daemon configuration privately', 'Refuse an unmanaged daemon configuration')
        tasks = [t for t in self.tasks if t['name'] in names]
        variables = defaults | {'docker_host_existing': {'results': [{'stat': {'exists': True}}]}}
        for content, accepted in ((json.dumps(defaults['docker_host_daemon_config']), True),
                                  ('{"log-driver": "json-file", "unrelated": "private fixture"}', False),
                                  ('invalid private fixture', False)):
            with self.subTest(accepted=accepted, content=content):
                data = variables | {'docker_host_existing_daemon': {
                    'content': base64.b64encode(content.encode()).decode()}}
                result = self.local_ansible(tasks, data)
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                self.assertIn('changed=0', result.stdout)
                self.assertNotIn('private fixture', result.stdout + result.stderr)
                if not accepted:
                    self.assertIn('manually', result.stdout)

    def test_repository_rendering_passes_rerun_preflight_and_rejects_competitors(self):
        defaults = yaml.safe_load((ROOT / 'roles/docker_host/defaults/main.yml').read_text())
        template = ROOT / 'roles/docker_host/templates/docker.sources.j2'
        destination = self.directory / 'docker.sources'
        variables = defaults | {'ansible_facts': {'distribution_release': 'noble', 'architecture': 'x86_64'}}
        result = self.local_ansible([{'name': 'Render fixture repository', 'ansible.builtin.template': {
            'src': str(template), 'dest': str(destination), 'mode': '0600',
        }}], variables)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = ('Compare repository contents privately',
                 'Refuse competing Docker repositories or an unmanaged target source')
        tasks = [t for t in self.tasks if t['name'] in names]
        tasks = yaml.safe_load(yaml.safe_dump(tasks).replace("'docker.sources.j2'", "'" + str(template) + "'"))
        source = {'item': '/etc/apt/sources.list.d/docker.sources',
                  'content': base64.b64encode(destination.read_bytes()).decode()}
        competing = {'item': '/etc/apt/sources.list.d/legacy.list',
                     'content': base64.b64encode(b'deb https://download.docker.com/linux/ubuntu noble stable').decode()}
        for sources, accepted in (([source], True), ([source, competing], False),
                                  ([source | {'content': base64.b64encode(b'unmanaged').decode()}], False)):
            with self.subTest(accepted=accepted):
                result = self.local_ansible(tasks, variables | {'docker_host_source_contents': {'results': sources}})
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                self.assertIn('changed=0', result.stdout)

    def test_daemon_configuration_converges_and_only_changed_copy_notifies(self):
        config = yaml.safe_load((ROOT / 'roles/docker_host/defaults/main.yml').read_text())['docker_host_daemon_config']
        original = next(t for t in self.tasks if 'ansible.builtin.copy' in t)
        self.assertEqual(original['ansible.builtin.copy']['validate'], '/usr/bin/dockerd --validate --config-file %s')
        self.assertEqual(original['notify'], 'Restart Docker after validated configuration changes')
        self.assertEqual(sum('notify' in t for t in self.tasks), 1)
        dest = self.directory / 'daemon.json'
        # Real local copy module, no elevated privileges or daemon/service operations.
        task = {'name': 'Install fixture daemon policy', 'ansible.builtin.copy': {
            'content': original['ansible.builtin.copy']['content'], 'dest': str(dest), 'mode': '0600',
        }}
        first = self.local_ansible([task], {'docker_host_daemon_config': config})
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('changed=1', first.stdout)
        second = self.local_ansible([task], {'docker_host_daemon_config': config})
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn('changed=0', second.stdout)
        self.assertEqual(json.loads(dest.read_text()), config)
        self.assertEqual(config['log-driver'], 'local')
        self.assertEqual(config['log-opts'], {'max-size': '20m', 'max-file': '5'})

    def test_make_and_ci_keep_live_stages_outside_offline_checks(self):
        makefile = (ROOT / 'Makefile').read_text()
        self.assertNotIn('\nbootstrap:', makefile)
        self.assertNotIn('\nverify:', makefile)
        for filename in ('README.md', 'README.ru.md', 'AGENTS.md', 'Makefile', 'scripts/access.py'):
            self.assertNotRegex((ROOT / filename).read_text(), r'make (bootstrap|verify)(?=\s|`|$)')
        for target in ('bootstrap-user', 'verify-access', 'docker-host', 'verify-docker'):
            result = subprocess.run(['make', '-n', target], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'scripts/access.py {target} ', result.stdout)
        for target in ('check', 'ci'):
            result = subprocess.run(['make', '-n', target], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('scripts/access.py', result.stdout)
            self.assertNotIn('inventories/production.yml', result.stdout)
            for playbook in ('bootstrap.yml', 'verify.yml', 'docker-host.yml', 'verify-docker.yml'):
                self.assertIn(f'--syntax-check -i inventories/production.example.yml playbooks/{playbook}', result.stdout)
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertNotIn('scripts/access.py', workflow)
        self.assertIn('make ci', workflow)

    def test_verification_reports_probes_unchanged_and_guarantees_cleanup(self):
        tasks = yaml.safe_load((ROOT / 'playbooks/verify-docker.yml').read_text())[0]['tasks']
        for task in tasks:
            if 'ansible.builtin.command' in task:
                self.assertIs(task['changed_when'], False)
                self.assertTrue(task['become'])
        smoke = tasks[-1]
        self.assertEqual(smoke['always'][0]['ansible.builtin.command']['argv'][:3], ['docker', 'rm', '--force'])
        self.assertIn('verify_docker_container.rc | default(1) == 0', smoke['always'][0]['when'])
        self.assertEqual(smoke['block'][0]['ansible.builtin.command']['argv'][2:4], ['--network', 'none'])


if __name__ == '__main__':
    unittest.main()
