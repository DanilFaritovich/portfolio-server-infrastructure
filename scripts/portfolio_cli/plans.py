"""Bounded, in-process consent; never environment flags or persistent authority."""

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import os
from pathlib import Path
import sys

from .common import ROOT, require

PLAN_ACTIONS = {
    'setup-swap': 'Manage only owned /swapfile using inventory swap_size_mb (remote sudo): allocate/activate, stage a safe resize, or disable without deletion; maintain fstab and verify independently. Conflicts or insufficient RAM/disk stop; retain recovery access.',
    'generate-user-key': 'Generate the selected missing human Ed25519 key pair locally without overwrite (directory 0700, private 0600); native passphrase input. Load only the new identity into the existing SSH agent when selected; no agent is started.',
    'bootstrap-user': 'Create/reuse the dedicated local automation key; create the managed account, authorized key and unrestricted NOPASSWD sudo (remote root; native login/sudo authentication).',
    'docker-host': 'Install official docker-ce, docker-ce-cli, containerd.io, docker-buildx-plugin and docker-compose-plugin APT packages; configure bounded local container logs and enable/start Docker (remote sudo); validate/restart only changed configuration; run a disposable smoke container, possibly caching its image.',
    'harden': 'Configure the selected SSH listeners and additive UFW rules; enable UFW, validate/reload SSH or restart its stock socket/service (remote sudo); preserve human recovery login.',
    'add-user': 'Create the selected human account if absent, register its exact public key and selected groups/sudo policy (remote sudo); existing accounts use additive key registration only.',
    'secure-ssh': 'Disable root, password and keyboard-interactive SSH login after independent administrator proof; validate and activate the final SSH policy (remote sudo). Your approval attests provider console recovery is tested and available; retain an administrator session.',
    'setup-operations': 'Install unattended-upgrades/logrotate; configure Ubuntu security-only unattended updates, journald retention (256M system, 64M runtime, 512M keep-free, 14 days) and stock maintenance timers (remote sudo); restart journald only after changed configuration; no automatic reboot.',
    'reboot-host': 'Reboot the selected host using remote sudo; wait for bounded recovery and verify access, Docker (disposable smoke container/image cache) and hardening; keep provider console available.',
    'add-user-key': 'Register only the selected public key in the managed account ledger (remote sudo).',
    'revoke-user-key': 'Revoke only the selected managed fingerprint after fresh recovery proof (remote sudo).',
    'remove-user': 'Remove the selected managed account after fresh recovery proof; retain home files (remote sudo).',
    'apply-apt-policy': 'Add only the missing Remove-New-Unused-Dependencies false line to the guarded existing root:root 0644 APT policy file (remote sudo), then verify operations.',
}
PLAN_SCOPE = ContextVar('portfolio_plan_scope', default=None)
E2E_EXECUTION = ContextVar('portfolio_e2e_execution', default=None)
PLAN_NOOP_MESSAGES = {
    'harden': 'Hardening already matches; no changes required.',
    'secure-ssh': 'Final SSH policy already matches; no changes required.',
    'setup-operations': 'Managed configuration already matches; no changes required.',
}


def plan_code_snapshot():
    """Bind execution contracts/templates without exposing their contents."""
    digest = hashlib.sha256()
    sources = [*(ROOT / 'roles').rglob('*.yml'), *(ROOT / 'roles').rglob('*.j2'),
               *(ROOT / 'playbooks').glob('*.yml'), *(ROOT / 'library').glob('portfolio_*.py'),
               *(ROOT / 'scripts/portfolio_cli').glob('*.py'), ROOT / 'scripts/user_management.py',
               ROOT / 'Makefile']
    for path in sorted(sources):
        require(not path.is_symlink(), 'Plan implementation source changed; STOP.')
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def plan_snapshot(inventory, key=None):
    """Bind consent to inventory bytes, policy inputs and PUBLIC identity only."""
    environment = tuple(sorted((name, value) for name, value in os.environ.items()
                               if name.startswith('HUMAN_') or name in ('AUTOMATION_KEY', 'RECOVERY_USER',
                                                                       'RECOVERY_KEY', 'KEY_FINGERPRINT', 'KEY_NAME',
                                                                       'SSH_AUTH_SOCK', 'AGENT_LOAD', 'INIT_FROM')))
    path = Path(inventory)
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    public = os.environ.get('HUMAN_PUBLIC_KEY')
    if not public and os.environ.get('HUMAN_USER'):
        public = os.environ.get('HUMAN_KEY') or str(Path.home() / '.ssh/portfolio-infra' / (os.environ['HUMAN_USER'] + '_ed25519'))
        public += '.pub'
    identity = hashlib.sha256(Path(public).expanduser().read_bytes()).hexdigest() if public and Path(public).expanduser().exists() else None
    e2e_state = Path(os.environ['PORTFOLIO_E2E_ROOT']) / 'state.json' if os.environ.get('PORTFOLIO_E2E_ROOT') else None
    fixture = hashlib.sha256(e2e_state.read_bytes()).hexdigest() if e2e_state and e2e_state.exists() else None
    public_paths = [Path(os.environ['RECOVERY_KEY'] + '.pub')] if os.environ.get('RECOVERY_KEY') else []
    if e2e_state is not None:
        public_paths.append(e2e_state.parent / 'home/.ssh/controller/ansible_ed25519.pub')
    public_inputs = tuple(hashlib.sha256(public_path.read_bytes()).hexdigest() if public_path.exists() else None
                          for public_path in public_paths)
    return str(path.absolute()), str(key), digest, environment, identity, plan_code_snapshot(), fixture, public_inputs


def plan_confirm(actions, *, validate=lambda: None, reader=None, prompt='Apply this plan? [y/N] '):
    """No prompt for an empty plan; validation always precedes dispatch."""
    if not actions:
        validate()
        return
    print('Plan:', flush=True)
    for action in actions:
        print('  - ' + action, flush=True)
    require(sys.stdin.isatty(), 'Applying a plan requires an interactive terminal.')
    try:
        answer = (reader or input)(prompt)
    except (EOFError, KeyboardInterrupt):
        answer = ''
    require(answer.strip().lower() in ('y', 'yes'), 'Plan declined; no changes requested.')
    validate()


@contextmanager
def plan_scope(modes, snapshot, *, reader=None, lazy=False, actions=None, prompt='Apply this plan? [y/N] '):
    """Reuse only exact named stage contracts in this call stack; reset on errors."""
    before = snapshot()
    def validate():
        require(snapshot() == before, 'Plan inputs changed; STOP and review a new plan.')
    inherited = PLAN_SCOPE.get()
    if inherited is not None:
        allowed, parent_validate, parent_authorize = inherited
        parent_validate()
        require(set(modes) <= allowed, 'Operation is outside the approved plan; STOP.')
        def nested_validate():
            parent_validate()
            validate()
        def nested_authorize():
            nested_validate()
            parent_authorize()
            nested_validate()
        nested_validate()
        token = PLAN_SCOPE.set((frozenset(modes), nested_validate, nested_authorize))
        try:
            yield
        finally:
            PLAN_SCOPE.reset(token)
        return
    actions = actions if actions is not None else [PLAN_ACTIONS[mode] for mode in modes]
    approved = False
    def authorize():
        nonlocal approved
        validate()
        if not approved:
            plan_confirm(actions, validate=validate, reader=reader, prompt=prompt)
            approved = True
    if lazy:
        print('Workflow plan (read-only preflight first; confirmation only if a mutation is needed):')
        for action in actions:
            print('  - ' + action)
    else:
        authorize()
    token = PLAN_SCOPE.set((frozenset(modes), validate, authorize))
    try:
        yield
    finally:
        PLAN_SCOPE.reset(token)


def planned_action(mode):
    scope = PLAN_SCOPE.get()
    if scope is None:
        return False
    allowed, validate, authorize = scope
    require(mode in allowed, 'Operation is outside the approved plan; STOP.')
    authorize()
    return True


def validate_current_plan():
    """Recheck inherited inputs without granting or requesting mutation consent."""
    scope = PLAN_SCOPE.get()
    if scope is not None:
        scope[1]()


def stage_consent(mode, inventory, key=None, public=None):
    def selected_identity():
        paths = ([Path(str(key) + '.pub')] if key else []) + ([Path(public)] if public else [])
        return tuple(hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None for path in paths)
    identities = selected_identity()
    def validate_identity():
        require(selected_identity() == identities, 'Selected public identity changed; STOP before mutation.')
    # Preserve explicit public-file automation; this task changes interactive UX.
    if mode == 'add-user' and not sys.stdin.isatty():
        require(os.environ.get('HUMAN_PUBLIC_KEY'), 'Noninteractive registration requires an explicit public file.')
        print('Plan: ' + PLAN_ACTIONS[mode])
        validate_identity()
        return
    if planned_action(mode):
        validate_identity()
        return
    before = plan_snapshot(inventory, key)
    def validate():
        require(plan_snapshot(inventory, key) == before, 'Plan inputs changed; STOP and review a new plan.')
        validate_identity()
    plan_confirm([PLAN_ACTIONS[mode]], validate=validate)


@contextmanager
def e2e_child_plan(inventory, mode):
    """Receive one bounded parent plan through an inherited anonymous descriptor.

    This is confined to guarded E2E children, never a general CLI yes switch.
    The descriptor is consumed/closed, and no receipt is saved for later runs.
    """
    import json
    descriptor = os.environ.pop('PORTFOLIO_E2E_PLAN_FD', None)
    if descriptor is None:
        yield
        return
    require(os.environ.get('PORTFOLIO_E2E_ROOT'), 'Plan transfer is restricted to guarded E2E children.')
    with os.fdopen(int(descriptor)) as stream:
        payload = json.loads(stream.read(32769))
    require(payload['mode'] == mode and payload['frontier'] == os.environ.get('INIT_FROM') and
            payload.get('kind', '') == os.environ.pop('PORTFOLIO_E2E_PLAN_KIND', ''),
            'E2E child operation changed; STOP.')
    before = json.dumps(plan_snapshot(inventory), sort_keys=True)
    require(payload['snapshot'] == before, 'E2E child plan inputs changed; STOP.')
    allowed = frozenset(payload['modes'])
    require(allowed <= PLAN_ACTIONS.keys(), 'Invalid E2E stage plan; STOP.')
    def validate():
        require(json.dumps(plan_snapshot(inventory), sort_keys=True) == before,
                'E2E child plan inputs changed; STOP.')
    token = PLAN_SCOPE.set((allowed, validate, validate))
    try:
        yield
    finally:
        PLAN_SCOPE.reset(token)


@contextmanager
def e2e_plan_pipe(inventory, env, mode):
    """Create a single child invocation grant from the active in-process scope."""
    import json
    scope = PLAN_SCOPE.get()
    if scope is None:
        yield env, ()
        return
    allowed, validate, authorize = scope
    execution = E2E_EXECUTION.get()
    generated = None
    if execution is not None:
        operations, identities = execution
        validate()
        if mode not in PLAN_ACTIONS:
            require(mode in ('list-users', 'show-user', 'list-user-keys', 'verify-user', 'verify-swap'),
                    'Additional E2E operation; STOP.')
            yield env, ()
            validate()
            return
        require(operations, 'Additional E2E operation; STOP.')
        expected_mode, expected_inventory, expected_env = operations[0]
        expected_env = dict(expected_env)
        fingerprint = expected_env.get('KEY_FINGERPRINT')
        if callable(fingerprint):
            expected_env['KEY_FINGERPRINT'] = fingerprint()
        require((mode, str(inventory), env) == (expected_mode, str(expected_inventory), expected_env),
                'E2E execution plan operation/inputs changed; STOP.')
        operations.pop(0)
        allowed = frozenset([mode])
        if mode == 'generate-user-key':
            generated = Path(env['HUMAN_KEY'] + '.pub')
            require(all(not path.exists() and not path.is_symlink() for path in
                        (generated, Path(env['HUMAN_KEY']))), 'E2E key plan changed; STOP.')
    authorize()
    original = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update(env)
        snapshot = json.dumps(plan_snapshot(inventory), sort_keys=True)
    finally:
        os.environ.clear()
        os.environ.update(original)
    data = json.dumps({'mode': mode, 'frontier': env.get('INIT_FROM'),
                       'modes': sorted(allowed), 'snapshot': snapshot,
                       'kind': 'execution' if execution is not None else ''}).encode()
    require(len(data) < 4096, 'E2E plan transfer too large; STOP.')
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, data)
        os.close(write_fd)
        write_fd = None
        child_env = dict(env, PORTFOLIO_E2E_PLAN_FD=str(read_fd))
        if execution is not None:
            child_env['PORTFOLIO_E2E_PLAN_KIND'] = 'execution'
        yield child_env, (read_fd,)
        if generated is not None:
            require(generated.exists() and not generated.is_symlink(), 'Planned public key output missing; STOP.')
            identities[generated] = generated.read_bytes()
        if execution is not None:
            validate()
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


@contextmanager
def e2e_execution_plan(operations, actions, snapshot):
    """One invocation, ordered exact mutation contracts and generated public outputs."""
    require(PLAN_SCOPE.get() is None and E2E_EXECUTION.get() is None, 'E2E execution plans cannot inherit broader consent; STOP.')
    identities = {}
    def bound_snapshot():
        require(all(not path.is_symlink() and path.read_bytes() == value
                    for path, value in identities.items()), 'E2E generated identity changed; STOP.')
        return snapshot()
    with plan_scope(sorted({operation[0] for operation in operations}), bound_snapshot,
                    actions=actions, prompt='Authorize this E2E execution plan? [y/N] '):
        token = E2E_EXECUTION.set((list(operations), identities))
        try:
            yield
            validate_current_plan()
        finally:
            E2E_EXECUTION.reset(token)
