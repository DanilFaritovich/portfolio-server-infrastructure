"""Offline interactive convergence regression tests using a local terminal only."""

import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import termios
import time
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def terminal_session():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class ConvergenceTerminalTests(unittest.TestCase):
    def start(self, child, env=None):
        master, slave = pty.openpty()
        child = 'import sys\nsys.path.insert(0, "scripts")\n' + child
        runner = (
            'import os, sys\n'
            'sys.path.insert(0, "scripts")\n'
            'from portfolio_cli.e2e import convergence_command\n'
            'try:\n'
            '    convergence_command([sys.executable, "-c", ' + repr(child) + '], dict(os.environ))\n'
            'except (ValueError, OSError) as error:\n'
            '    print("STOP:", error, flush=True)\n'
            '    sys.exit(23)\n'
        )
        process = subprocess.Popen([sys.executable, '-c', runner], cwd=ROOT,
                                   stdin=slave, stdout=slave, stderr=slave,
                                   preexec_fn=terminal_session, env=env)
        os.close(slave)
        self.master, self.process, self.pending = master, process, b''
        self.addCleanup(self.cleanup_terminal, process, master)

    def cleanup_terminal(self, process, master):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        os.close(master)

    def expect(self, marker, timeout=5):
        marker = marker.encode()
        deadline = time.monotonic() + timeout
        while marker not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.master], [], [], max(0, remaining))[0]:
                self.fail('Terminal marker was not displayed before input: ' + repr(marker))
            try:
                data = os.read(self.master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    self.fail('Terminal closed before marker: ' + repr(marker))
                raise
            self.assertTrue(data, 'Terminal ended before marker')
            self.pending = (self.pending + data)[-32768:]
        self.pending = self.pending.split(marker, 1)[1]

    def answer(self, value):
        os.write(self.master, value)

    def test_prompt_visible_before_each_answer(self):
        self.start('import sys\n'
                   'print("TTY", sys.stdin.isatty(), sys.stdout.isatty(), sys.stderr.isatty(), flush=True)\n'
                   'for index in range(2):\n'
                   '    answer = input("Confirm %d? [y/N] " % index)\n'
                   '    print("ANSWER", index, repr(answer), flush=True)\n'
                   'sys.exit(7)\n')
        self.expect('TTY True False True')
        for index in range(2):
            self.expect('Confirm %d? [y/N] ' % index)
            self.assertIsNone(self.process.poll())
            self.answer(b'y\n')
            self.expect("ANSWER %d 'y'" % index)
        self.expect('Repeat initialization failed')
        self.assertEqual(self.process.wait(timeout=5), 23)

    def recaps(self, *, drift=0, smoke=3, omit=False):
        names = [yaml.safe_load((ROOT / 'playbooks' / name).read_text())[0]['name']
                 for name in ('setup-swap.yml', 'docker-host.yml', 'harden.yml', 'secure-ssh.yml',
                              'setup-operations.yml', 'setup-deployment-prerequisites.yml', 'verify-docker.yml')]
        return ''.join('PLAY [' + name + '] ***\nPLAY RECAP ***\n'
                       'e2e : ok=10 changed=%d unreachable=0 failed=0\n' % (smoke if index == len(names) - 1 else drift)
                       for index, name in enumerate(names) if not (omit and index == 0))

    def test_yes_and_normal_completion_with_split_unicode_and_recaps(self):
        self.start('import os, sys\n'
                   'print("BUFFERED START")\n'
                   'assert os.read(0, 1) == b"\\n"\n'
                   'assert sys.stdin.isatty()\n'
                   'assert input("Authorize? [y/N] ") == "y"\n'
                   'for byte in ' + repr(('Готово\n' + self.recaps()).encode()) + ':\n'
                   '    os.write(1, bytes([byte]))\n')
        self.expect('BUFFERED START')
        self.answer(b'\n')
        self.expect('Authorize? [y/N] ')
        self.answer(b'y\n')
        self.expect('Готово')
        self.expect('failed=0')
        self.expect('changed=3 unreachable=0 failed=0')
        self.assertEqual(self.process.wait(timeout=5), 0)

    def test_no_and_eof_are_not_confirmations(self):
        for response in (b'n\n', b'\x04'):
            with self.subTest(response=response):
                self.start('import sys\n'
                           'from portfolio_cli.initialization import init_input\n'
                           'try:\n'
                           '    answer = init_input("Authorize? [y/N] ")\n'
                           'except ValueError:\n'
                           '    print("EOF CANCELLED", file=sys.stderr, flush=True)\n'
                           '    sys.exit(4)\n'
                           'if answer != "y":\n'
                           '    print("DECLINED", file=sys.stderr, flush=True)\n'
                           '    sys.exit(5)\n'
                           'raise RuntimeError("Unexpected automatic approval")\n')
                self.expect('Authorize? [y/N] ')
                self.answer(response)
                self.expect('DECLINED' if response == b'n\n' else 'EOF CANCELLED')
                self.expect('Repeat initialization failed')
                self.assertEqual(self.process.wait(timeout=5), 23)
                self.doCleanups()

    def test_recap_drift_missing_and_smoke_counts(self):
        for options in ({'drift': 1}, {'omit': True}, {'smoke': 0}, {'smoke': 2}, {'smoke': 4}):
            with self.subTest(options=options):
                self.start('import sys\nsys.stdout.write(' + repr(self.recaps(**options)) + ')\n')
                self.expect('did not prove provisioning changed=0')
                self.assertEqual(self.process.wait(timeout=5), 23)
                self.doCleanups()

    def test_mixed_large_stdout_stderr_and_unterminated_recap(self):
        self.start('import os, sys\n'
                   'for index in range(128):\n'
                   '    os.write(1, b"x" * 4096)\n'
                   '    os.write(2, b"stderr diagnostic\\n" * 256)\n'
                   'os.write(1, b"\\n")\n'
                   'print("DIAGNOSTIC END", file=sys.stderr, flush=True)\n'
                   'sys.stdout.write(' + repr(self.recaps().rstrip('\n')) + ')\n')
        self.expect('DIAGNOSTIC END', timeout=10)
        self.expect('changed=3 unreachable=0 failed=0')
        self.assertEqual(self.process.wait(timeout=5), 0)

    def test_child_exception_stderr_and_nonzero_exit(self):
        self.start('raise RuntimeError("synthetic child failure")\n')
        self.expect('RuntimeError: synthetic child failure')
        self.expect('Repeat initialization failed')
        self.assertEqual(self.process.wait(timeout=5), 23)

    def test_unicode_under_python_utf8_mode_with_c_locale(self):
        self.start('print("Готово")\nprint(' + repr(self.recaps()) + ')\n',
                   env=dict(os.environ, LC_ALL='C', PYTHONUTF8='1'))
        self.expect('Готово')
        self.expect('changed=3 unreachable=0 failed=0')
        self.assertEqual(self.process.wait(timeout=5), 0)

    def test_ctrl_c_stops_waiting_for_confirmation(self):
        self.start('input("Authorize? [y/N] ")\n')
        self.expect('Authorize? [y/N] ')
        self.answer(b'\x03')
        self.expect('KeyboardInterrupt')
        self.assertNotEqual(self.process.wait(timeout=5), 0)

    def test_no_answer_is_supplied_by_orchestrator(self):
        self.start('answer = input("Authorize? [y/N] ")\n'
                   'print("ANSWER RECEIVED", flush=True)\n')
        self.expect('Authorize? [y/N] ')
        self.assertEqual(self.pending, b'')
        self.assertFalse(select.select([self.master], [], [], 0.2)[0])
        self.assertIsNone(self.process.poll())
        self.answer(b'n\n')
        self.expect('ANSWER RECEIVED')
        self.expect('did not prove provisioning changed=0')
        self.assertEqual(self.process.wait(timeout=5), 23)
