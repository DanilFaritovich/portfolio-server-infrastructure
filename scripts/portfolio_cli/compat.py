"""Isolated legacy helper imports for file-based access.py consumers.

The CLI runs the package directly. Legacy importers historically patched a flat
module namespace, sometimes loading several independent copies without adding
them to sys.modules. Rebind the same function code to each caller's namespace
instead of propagating patches into shared package modules. No source is executed
or duplicated, and package execution never uses this adapter.
"""

from contextlib import contextmanager
from importlib import import_module
from types import FunctionType


MODULES = (
    'common', 'plans', 'inventory', 'keys', 'clipboard', 'host_trust', 'ansible',
    'inspection', 'verification', 'provisioning', 'human_access',
    'user_management', 'operations', 'initialization', 'local_keys', 'ssh', 'cli',
)


def install(namespace):
    """Expose the old helpers with per-import globals and mock isolation."""
    exports = {}
    for name in MODULES:
        module = import_module(f'{__package__}.{name}')
        exports.update((key, value) for key, value in vars(module).items()
                       if not key.startswith('_'))
    namespace.update(exports)
    namespace['PLAN_SCOPE'] = namespace['ContextVar']('legacy_plan_scope', default=None)
    namespace['E2E_EXECUTION'] = namespace['ContextVar']('legacy_e2e_execution', default=None)
    # These values were evaluated separately on each legacy module import.
    namespace['DEFAULT_KEY'] = namespace['Path'].home() / '.ssh/portfolio-server-infrastructure/ansible_ed25519'
    for name in ('HARDENING_FIELDS', 'HOST_FIELDS'):
        namespace[name] = set(namespace[name])
    for name, value in exports.items():
        if not isinstance(value, FunctionType) or not value.__module__.startswith(__package__ + '.'):
            continue
        decorated = name in ('public_key_snapshot', 'add_user_public_key', 'pipeline_lock', 'plan_scope', 'e2e_child_plan', 'e2e_plan_pipe', 'e2e_execution_plan')
        original = value.__wrapped__ if decorated else value
        bound = FunctionType(original.__code__, namespace, original.__name__,
                             original.__defaults__, original.__closure__)
        bound.__kwdefaults__ = original.__kwdefaults__
        bound.__annotations__ = original.__annotations__.copy()
        bound.__doc__ = original.__doc__
        bound.__module__ = namespace['__name__']
        bound.__qualname__ = original.__qualname__
        namespace[name] = contextmanager(bound) if decorated else bound
