"""Explicit-frontier initialization using existing stage contracts.

A failed verifier cannot distinguish an absent stage from unknown state.
The operator selects the mutation frontier; earlier stages must verify.
Local event records never grant permission to skip a server verification.
"""

import json
import os
import sys
import tempfile
import time

from .common import require
from .human_access import human_access, human_inputs
from .inventory import managed_access
from .keys import check_key, human_key_path
from .operations import operations
from .provisioning import live


INIT_STAGES = (
    ('bootstrap', 'bootstrap-user', 'verify-access'),
    ('docker', 'docker-host', 'verify-docker'),
    ('hardening', 'harden', 'verify-hardening'),
    ('human', 'add-user', 'verify-user'),
    ('ssh', 'secure-ssh', 'verify-ssh-security'),
    ('operations', 'setup-operations', 'verify-operations'),
)


def init_stage(mode, inventory, key):
    """Call directly: the CLI owns the whole-run lock."""
    if mode in ('add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'):
        human_access(mode, inventory, key)
    elif mode in ('setup-operations', 'verify-operations'):
        operations(mode, inventory, key)
    else:
        live(mode, inventory, key)


def init_event(log, stage, status, started):
    """Persist fixed events, never output or exception text."""
    json.dump({'schema': 1, 'stage': stage, 'status': status,
               'elapsed_seconds': round(time.monotonic() - started, 3)}, log)
    log.write('\n')
    log.flush()
    os.fsync(log.fileno())


def init_server(inventory, key=None):
    """Verify dependencies, then converge explicitly selected remaining stages."""
    require(sys.stdin.isatty(), 'init-server requires an interactive terminal; confirmations cannot be bypassed.')
    choices = [stage[0] for stage in INIT_STAGES] + ['verify']
    frontier = os.environ.get('INIT_FROM', '')
    if not frontier:
        print('Choose the first stage authorized for mutation: ' + ', '.join(choices) +
              '. Earlier stages will only be verified. verify checks everything.')
        frontier = input('INIT_FROM (no default): ').strip()
    require(frontier in choices, 'Set INIT_FROM to bootstrap, docker, hardening, human, ssh, operations or verify.')
    managed_user, _ = managed_access(inventory, key)
    human = human_inputs(managed_user=managed_user)
    require(human['human_access_user_sudo'] == 'admin', 'init-server requires HUMAN_SUDO=admin and an independent human key.')
    check_key(human_key_path(os.environ.get('HUMAN_KEY'), human['human_access_user_name']))
    boundary = choices.index(frontier)
    print('LIVE: earlier stages must verify; mutation begins at ' + frontier +
          '. Keep provider console recovery available. No automatic retry or rollback.', flush=True)
    answer = input('Authorize this initialization plan? [y/N] ')
    require(answer.strip().lower() in ('y', 'yes'), 'Initialization declined; no host contact requested.')
    started = time.monotonic()
    completed = []
    current = 'run'
    # Exclusive random creation prevents symlink/clobber attacks. No caller log
    # path or sensitive data is accepted. Retain the safe report on failure.
    with tempfile.NamedTemporaryFile(mode='w', prefix='portfolio-init-', suffix='.jsonl', delete=False) as log:
        print('Safe initialization event log: ' + log.name, flush=True)
        try:
            init_event(log, current, 'started', started)
            for index, (stage, apply, verify) in enumerate(INIT_STAGES):
                current = stage
                checking = index < boundary
                print(f'[{index + 1}/{len(INIT_STAGES)}] {stage}: ' +
                      ('verify before skipping' if checking else 'apply and verify'), flush=True)
                init_event(log, stage, 'verifying' if checking else 'applying', started)
                if not checking:
                    if stage == 'hardening':
                        init_stage('inspect-hardening', inventory, key)
                    init_stage(apply, inventory, key)
                # Public-only add-user intentionally returns unverified.
                init_stage(verify, inventory, key)
                init_event(log, stage, 'verified_skip' if checking else 'completed', started)
                completed.append(stage)
            current = 'run'
            init_event(log, current, 'completed', started)
        except BaseException as error:
            try:
                init_event(log, current, 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', started)
            except OSError:
                print('Event log write failed; STOP. The last event may be incomplete.', file=sys.stderr)
            print(f'Initialization STOP at {current}; verified stages: ' +
                  (', '.join(completed) or 'none') +
                  '. Remote work may still be running. Diagnose through recovery before selecting a continuation.',
                  file=sys.stderr, flush=True)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise ValueError(f'Initialization failed at {current}; STOP. Use the existing stage inspectors and '
                             'recovery access for diagnosis; no later stages ran.') from None
    print('Initialization verified: ' + ', '.join(completed) + '. STOP. Applications remain separate.', flush=True)
