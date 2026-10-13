"""Explicit-frontier initialization using existing stage contracts.

A failed verifier cannot distinguish an absent stage from unknown state.
The operator selects the mutation frontier; earlier stages must verify.
Local event records never grant permission to skip a server verification.
"""

import errno
import json
import os
import sys
import subprocess
import tempfile
import time

from .common import require
from .human_access import human_access, human_inputs
from .inventory import managed_access, load_host, hardening_inputs
from .keys import check_key, human_key_path
from .operations import operations
from .provisioning import live
from .plans import plan_scope, plan_snapshot, validate_current_plan


INIT_STAGES = (
    ('bootstrap', 'bootstrap-user', 'verify-access'),
    ('docker', 'docker-host', 'verify-docker'),
    ('hardening', 'harden', 'verify-hardening'),
    ('human', 'add-user', 'verify-user'),
    ('ssh', 'secure-ssh', 'verify-ssh-security'),
    ('operations', 'setup-operations', 'verify-operations'),
)

# Exact fixed controller diagnostics only. Validation errors can also originate
# in remote JSON, so stripping controls or redacting keywords is insufficient.
INIT_SAFE_REASONS = frozenset({
    'Initialization cancelled (end of input); no mutation authorized.',
    'Managed access is not ready. Run make bootstrap-user first; check the dedicated key pair.',
    'Managed key-only SSH access failed.',
    'Managed SSH access failed; remaining host checks cannot run safely.',
    'Cannot safely complete host inspection; check managed sudo and Python.',
    'Managed sudo or read-only inspection failed; review manually.',
    'Resolve all FAIL findings before make harden. WARN findings can converge safely.',
    'Resolve FAIL findings manually before proceeding.',
    'Invalid user management response; stop and inspect through recovery.',
    'User management SSH/sudo failed; stop and inspect through recovery.',
    'Public key input cancelled; no VPS changes requested.',
    'Registration declined; no VPS changes requested.',
    'Final hardening declined; no SSH policy was changed.',
    'Operations setup declined; no changes requested.',
    'Host trust declined; bootstrap stopped.',
    'Use separate human and automation SSH keys.',
    'Use separate human and automation SSH key identities.',
    'HUMAN_KEY must correspond to HUMAN_PUBLIC_KEY for independent verification.',
    'A complete regular private/public key pair is required.',
    'Private key permissions must be 0600 or stricter.',
    'Public key is invalid.',
    'SSH policy application failed; it may already be installed. Stop and use the retained '
    'administrator session/provider console; do not retry blindly.',
})


def init_error_reason(error):
    """Return safe cause information without echoing arbitrary exception data."""
    if isinstance(error, ValueError) and error.args and type(error.args[0]) is str:
        if error.args[0] in INIT_SAFE_REASONS:
            return error.args[0]
    if isinstance(error, subprocess.TimeoutExpired):
        return 'SSH/Ansible command timed out; remote completion is unconfirmed.'
    if isinstance(error, subprocess.CalledProcessError):
        code = error.returncode
        return ('SSH/Ansible command failed with exit status ' + str(code) + '.'
                if type(code) is int else 'SSH/Ansible command failed.')
    if isinstance(error, OSError):
        code = errno.errorcode.get(error.errno) if type(error.errno) is int else None
        return 'Local I/O or process operation failed' + (f' ({code}).' if code else '.')
    if isinstance(error, EOFError):
        return 'Interactive input ended.'
    return 'Stage validation or execution failed; review the stage diagnostics through recovery.'


def init_input(prompt):
    """End-of-input is a default-deny cancellation before host contact."""
    try:
        return input(prompt)
    except EOFError:
        raise ValueError('Initialization cancelled (end of input); no mutation authorized.') from None


def init_stage(mode, inventory, key):
    """Call directly: the CLI owns the whole-run lock."""
    validate_current_plan()
    if mode in ('add-user', 'verify-user', 'secure-ssh', 'verify-ssh-security'):
        return human_access(mode, inventory, key)
    elif mode in ('setup-operations', 'verify-operations'):
        return operations(mode, inventory, key)
    else:
        return live(mode, inventory, key)


def init_event(log, stage, status, started):
    """Persist fixed events with stage elapsed time (whole-run time for run)."""
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
        frontier = init_input('INIT_FROM (no default): ').strip()
    require(frontier in choices, 'Set INIT_FROM to bootstrap, docker, hardening, human, ssh, operations or verify.')
    managed_user, _ = managed_access(inventory, key)
    human = human_inputs(managed_user=managed_user)
    require(human['human_access_user_sudo'] == 'admin', 'init-server requires HUMAN_SUDO=admin and an independent human key.')
    check_key(human_key_path(os.environ.get('HUMAN_KEY'), human['human_access_user_name']))
    boundary = choices.index(frontier)
    print('LIVE: earlier stages must verify; mutation begins at ' + frontier +
          '. Keep provider console recovery available. No automatic retry or rollback.', flush=True)
    modes = [apply for index, (_, apply, _) in enumerate(INIT_STAGES) if index >= boundary]
    alias, host, port, _, _ = load_host(inventory)
    print(f'Target: {host}:{port}; managed account: {managed_user}.')
    print('SSH/firewall inputs: ' + json.dumps(hardening_inputs(inventory, alias, port), sort_keys=True))
    print('Selected human policy: ' + json.dumps(human, sort_keys=True))
    with plan_scope(modes, lambda: plan_snapshot(inventory, key), reader=init_input, lazy=True):
        return init_execute(inventory, key, boundary)


def init_execute(inventory, key, boundary):
    """Execute under the caller's lock and bounded consent scope."""
    started = time.monotonic()
    completed = []
    current = 'run'
    event_started = started
    action = 'event log'
    # Exclusive random creation prevents symlink/clobber attacks. No caller log
    # path or sensitive data is accepted. Retain the safe report on failure.
    with tempfile.NamedTemporaryFile(mode='w', prefix='portfolio-init-', suffix='.jsonl', delete=False) as log:
        print('Safe initialization event log: ' + log.name, flush=True)
        try:
            init_event(log, current, 'started', started)
            for index, (stage, apply, verify) in enumerate(INIT_STAGES):
                current = stage
                event_started = time.monotonic()
                checking = index < boundary
                print(f'[{index + 1}/{len(INIT_STAGES)}] {stage}: ' +
                      ('verify before skipping' if checking else 'apply and verify'), flush=True)
                action = verify if checking else apply
                init_event(log, stage, 'verifying' if checking else 'applying', event_started)
                verified = None
                if not checking:
                    if stage == 'hardening':
                        action = 'inspect-hardening'
                        init_stage('inspect-hardening', inventory, key)
                    action = apply
                    verified = init_stage(apply, inventory, key)
                # Only a successful wrapper's exact verifier result covers this
                # boundary. No-op/public-only paths return no proof. Earlier
                # stages and separate invocations always verify afresh.
                if checking or verified != verify:
                    action = verify
                    if not checking:
                        init_event(log, stage, 'verifying', event_started)
                    init_stage(verify, inventory, key)
                init_event(log, stage, 'verified_skip' if checking else 'completed', event_started)
                completed.append(stage)
            current = 'run'
            event_started = started
            action = 'event log'
            init_event(log, current, 'completed', started)
        except BaseException as error:
            try:
                init_event(log, current, 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', event_started)
            except OSError:
                print('Event log write failed; STOP. The last event may be incomplete.', file=sys.stderr)
            print(f'Initialization STOP at {current}; verified stages: ' +
                  (', '.join(completed) or 'none') +
                  '. Remote work may still be running. Diagnose through recovery before selecting a continuation.',
                  file=sys.stderr, flush=True)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise ValueError(f'Initialization failed at {current} ({action}): {init_error_reason(error)} '
                             'STOP. Use the existing stage inspectors and recovery access for diagnosis; '
                             'no later stages ran.') from None
    print('Initialization verified: ' + ', '.join(completed) + '. STOP. Applications remain separate.', flush=True)
