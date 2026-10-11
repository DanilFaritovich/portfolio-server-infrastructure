"""Offline boot race, bounded agent transport and output-free probe contracts."""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from portfolio_cli import e2e, e2e_readiness as readiness

IDENTITY = 'd52aa4d9-889d-448f-847c-762868428aa6'


class ReadinessTests(unittest.TestCase):
    def wait(self, query, *, clock=None, running=None):
        with patch.object(readiness.time, 'sleep') as sleep, \
                patch.object(readiness.time, 'monotonic', side_effect=clock, return_value=0):
            readiness.wait_ready(IDENTITY, query=query, running=running or (lambda: True))
        return sleep

    def test_agent_boot_then_guest_pending_then_ready_no_parallel_probes(self):
        query = Mock(side_effect=[None, {'pid': 4}, {'exited': False},
                                  {'exited': True, 'exitcode': 10}, {'pid': 5},
                                  {'exited': True, 'exitcode': 0}])
        sleep = self.wait(query)
        self.assertEqual(sleep.call_count, 5)
        requests = [call.args[0] for call in query.call_args_list]
        self.assertEqual([r['execute'] for r in requests],
                         ['guest-exec', 'guest-exec', 'guest-exec-status', 'guest-exec-status',
                          'guest-exec', 'guest-exec-status'])
        for request in requests:
            if request['execute'] == 'guest-exec':
                self.assertFalse(request['arguments']['capture-output'])
                self.assertEqual(request['arguments']['arg'][-1], IDENTITY)
        self.assertEqual(requests[2]['arguments'], {'pid': 4})
        self.assertEqual(requests[3]['arguments'], {'pid': 4})

    def test_readiness_timeout_before_agent_connects(self):
        query = Mock(return_value=None)
        with self.assertRaisesRegex(ValueError, 'readiness timed out'):
            self.wait(query, clock=[0, 1, 301])
        self.assertEqual(query.call_count, 1)

    def test_transport_loss_bad_protocol_guest_error_and_identity_mismatch_stop(self):
        for result in (None, {}, {'exited': 'yes'}, {'exited': True, 'signal': 9},
                       {'exited': True, 'exitcode': 20}, {'exited': True, 'exitcode': 30},
                       {'exited': True, 'exitcode': True}):
            with self.subTest(result=result):
                query = Mock(side_effect=[{'pid': 4}, result])
                with self.assertRaises(ValueError):
                    self.wait(query)
                self.assertEqual(query.call_count, 2)

    def test_stopped_guest_and_invalid_pid_stop(self):
        query = Mock()
        with self.assertRaisesRegex(ValueError, 'not running'):
            self.wait(query, running=lambda: False)
        query.assert_not_called()
        for pid in (-1, True, '4', None):
            with self.subTest(pid=pid), self.assertRaisesRegex(ValueError, 'PID'):
                self.wait(Mock(return_value={'pid': pid}))

    def test_probe_exit_codes_use_real_readonly_guest_checks(self):
        # Execute the exact payload against synthetic files and mocked tools.
        for boot_done, marker, status, logind, ssh, button, sshd, expected in (
                (False, IDENTITY, 0, 0, 0, True, 0, 10),
                (True, 'other', 0, 0, 0, True, 0, 30),
                (True, IDENTITY, 2, 0, 0, True, 0, 20),
                (True, IDENTITY, 0, 1, 0, True, 0, 10),
                (True, IDENTITY, 0, 0, 1, True, 0, 10),
                (True, IDENTITY, 0, 0, 0, False, 0, 10),
                (True, IDENTITY, 0, 0, 0, True, 1, 20),
                (True, IDENTITY, 0, 0, 0, True, 0, 0)):
            def read(path, **kwargs):
                return marker if str(path) == '/etc/portfolio-e2e-id' else 'Power Button' if button else ''
            def run(args, **kwargs):
                self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
                self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
                codes = {'cloud-init': status, '/usr/sbin/sshd': sshd,
                         'systemd-logind': logind, 'ssh.service': ssh}
                return SimpleNamespace(returncode=codes.get(args[-1], codes.get(args[0])))
            with patch.object(Path, 'read_text', read), patch.object(Path, 'is_file', return_value=boot_done), \
                    patch.object(sys, 'argv', ['probe', IDENTITY]), patch.object(subprocess, 'run', side_effect=run):
                try:
                    exec(compile(readiness.PROBE, '<readiness probe>', 'exec'), {})
                except SystemExit as error:
                    code = error.code
                else:
                    code = 0
            self.assertEqual(code, expected)

    def test_transport_retries_only_exact_agent_disconnected_condition(self):
        argv = ['virsh', '--connect', e2e.URI, 'qemu-agent-command', IDENTITY, '{}', '--timeout', '5']
        for stderr, retry in (
                ('error: Guest agent is not responding: QEMU guest agent is not connected\n', True),
                ('error: Агент гостя не отвечает: Агент гостевой системы QEMU не подключён\n', True),
                ('error: Агент гостя не отвечает: Агент гостевой системы QEMU не подключён\nextra', False),
                ('error: Агент гостя не отвечает: тайм-аут', False),
                ('error: Агент гостевой системы QEMU не настроен', False),
                ('error: failed to connect to the hypervisor', False),
                ('error: domain is not running', False),
                ('error: permission denied', False)):
            with patch.object(e2e.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr=stderr)):
                if retry:
                    self.assertIsNone(e2e.command(argv, agent_boot=True))
                else:
                    with self.assertRaises(ValueError):
                        e2e.command(argv, agent_boot=True)

    def test_transport_rejects_other_operations_before_execution(self):
        with patch.object(e2e.subprocess, 'run') as run, self.assertRaises(ValueError):
            e2e.command(['virsh', '--connect', e2e.URI, 'shutdown', IDENTITY], agent_boot=True)
        run.assert_not_called()

    def test_transport_failures_have_static_diagnoses_without_private_text(self):
        argv = ['virsh', '--connect', e2e.URI, 'qemu-agent-command', IDENTITY,
                '--timeout', '5', '{"private":"request"}']
        for stderr, diagnosis in (
                ('error: argument unsupported: QEMU guest agent is not configured', 'channel unavailable'),
                ('error: Command guest-exec has been disabled', 'command unavailable'),
                ('error: CommandNotFound', 'command unavailable'),
                ('error: Guest agent is not responding: timed out', 'query failed or timed out'),
                ('error: permission denied', 'authorization failed'),
                ('error: unexpected failure', 'unrecognized guest-agent transport failure'),
                ('error: Guest agent is not responding: QEMU guest agent is not connected\nextra',
                 'query failed or timed out')):
            private = '\nprivate-guest-output password=secret\x1b[31m'
            with self.subTest(stderr=stderr), patch.object(e2e.subprocess, 'run', return_value=
                    SimpleNamespace(returncode=1, stdout='private stdout', stderr=stderr + private)):
                with self.assertRaises(ValueError) as caught:
                    e2e.command(argv, agent_boot=True)
                message = str(caught.exception)
                self.assertIn('guest readiness agent query, exit 1', message)
                self.assertIn(diagnosis, message)
                for withheld in (IDENTITY, 'password=secret', 'private', '\x1b', stderr):
                    self.assertNotIn(withheld, message)

    def test_guest_ready_checks_channel_and_validates_protocol(self):
        stand = e2e.Stand(root=Path('/synthetic/fixture'))
        stand.state = {'uuid': IDENTITY}
        xml = ('<domain><features><acpi/></features><devices><channel type="unix">'
               '<target type="virtio" name="org.qemu.guest_agent.0"/>'
               '</channel></devices></domain>')
        def waiting(identity, *, query, running):
            self.assertEqual(identity, IDENTITY)
            query({'execute': 'guest-exec-status', 'arguments': {'pid': 4}})
        def transport(argv, **kwargs):
            self.assertEqual(argv[:5], ['virsh', '--connect', e2e.URI, 'qemu-agent-command', IDENTITY])
            self.assertEqual(argv[-2:], ['--timeout', '5'])
            self.assertTrue(kwargs['agent_boot'])
            return answer
        for answer in ('not-json', '[]', '{"error":{"class":"CommandNotFound"}}', '{"return":null}'):
            with patch.object(stand, 'resources'), patch.object(e2e, 'virsh', return_value=xml), \
                    patch.object(e2e, 'command', side_effect=transport), \
                    patch.object(readiness, 'wait_ready', side_effect=waiting), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                stand.guest_ready()
        for invalid in (xml.replace('<acpi/>', ''), xml.replace('org.qemu.guest_agent.0', 'other')):
            with patch.object(stand, 'resources'), patch.object(e2e, 'virsh', return_value=invalid), \
                    patch.object(e2e, 'command') as command, self.assertRaises(ValueError):
                stand.guest_ready()
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
