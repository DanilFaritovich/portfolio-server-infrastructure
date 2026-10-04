"""Configure the pinned builtin Paramiko transport through its plugin API."""

from ansible.plugins.connection.paramiko_ssh import Connection as ParamikoConnection
from ansible.plugins.connection.paramiko_ssh import DOCUMENTATION as PARAMIKO_DOCUMENTATION

# Reuse the pinned plugin's option definitions; no SSH/authentication code is copied.
DOCUMENTATION = PARAMIKO_DOCUMENTATION.replace('connection: paramiko', 'connection: portfolio_password', 1)


class Connection(ParamikoConnection):
    def set_options(self, task_keys=None, var_options=None, direct=None):
        # Core 2.18.6 has no variable bindings for these options. Its env/INI
        # bindings also configure deprecated globals, so use direct plugin options.
        options = dict(direct or {}, look_for_keys=False, host_key_auto_add=False, record_host_keys=False)
        super().set_options(task_keys=task_keys, var_options=var_options, direct=options)
