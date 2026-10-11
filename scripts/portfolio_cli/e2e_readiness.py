"""Bounded, output-free guest readiness probes over the owned libvirt channel."""

import time
import uuid

from .e2e_images import require


# Only exit codes cross the channel. Never collect guest command output or keys.
PROBE = '''import pathlib, subprocess, sys
try:
    if pathlib.Path('/etc/portfolio-e2e-id').read_text().strip() != sys.argv[1]:
        sys.exit(30)
    if not pathlib.Path('/var/lib/cloud/instance/boot-finished').is_file():
        sys.exit(10)
    def run(args):
        return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=5, check=False).returncode
    if run(['cloud-init', 'status']) != 0:
        sys.exit(20)
    if any(run(['systemctl', 'is-active', '--quiet', unit]) != 0
           for unit in ('systemd-logind', 'ssh.service')):
        sys.exit(10)
    if 'Power Button' not in pathlib.Path('/proc/bus/input/devices').read_text():
        sys.exit(10)
    if run(['/usr/sbin/sshd', '-t']) != 0:
        sys.exit(20)
except (OSError, subprocess.SubprocessError):
    sys.exit(20)
'''


def wait_ready(identity, *, query, running):
    """Poll one short read-only probe at a time; transport faults stop the wait."""
    require(str(uuid.UUID(identity)) == identity, 'Invalid readiness identity.')
    deadline, pid = time.monotonic() + 300, None
    while True:
        require(time.monotonic() < deadline,
                'Guest readiness timed out; inspect cloud-init/agent/SSH/logind at console. No shutdown or baseline attempted.')
        require(running(), 'Guest not running during readiness checks; STOP.')
        if pid is None:
            result = query({'execute': 'guest-exec', 'arguments': {
                'path': '/usr/bin/python3', 'arg': ['-c', PROBE, identity], 'capture-output': False}})
            if result is not None:
                require(type(result.get('pid')) is int and result['pid'] > 0, 'Invalid guest readiness PID; STOP.')
                pid = result['pid']
        else:
            result = query({'execute': 'guest-exec-status', 'arguments': {'pid': pid}})
            require(result is not None and type(result.get('exited')) is bool,
                    'Guest readiness probe lost or invalid; STOP.')
            if result['exited']:
                code = result.get('exitcode')
                require(type(code) is int, 'Guest readiness probe did not exit normally; STOP.')
                require(code != 30, 'Guest readiness identity mismatch; STOP.')
                require(code in (0, 10), 'Guest cloud-init/SSH readiness failed; inspect console. No shutdown or baseline attempted.')
                if code == 0:
                    return
                pid = None
        time.sleep(2)
