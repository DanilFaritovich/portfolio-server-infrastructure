"""Controller prerequisites and pinned Ansible execution with temporary overlays."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

from .common import ROOT, require


def prerequisites(mode):
    for tool in ('ssh', 'ssh-keygen', 'sftp', 'scp', *(['ssh-keyscan'] if mode == 'bootstrap-user' else [])):
        require(shutil.which(tool), f'Missing {tool}. Install the documented controller prerequisite.')
    if mode == 'bootstrap-user':
        require(importlib.util.find_spec('paramiko') is not None, 'Missing local Paramiko. Run make setup or make deps.')
    require((ROOT / '.venv/bin/ansible-playbook').is_file(), 'Run make setup or make deps first.')
    require((ROOT / '.ansible/collections/ansible_collections/ansible/posix').is_dir(),
            'Missing ansible.posix collection. Run make deps.')


def run_playbook(path, alias, variables, playbook, ask_pass=False, ask_become=False, check=False, diff=False):
    # Connection extra-vars would override even delegated localhost. Scope runtime
    # settings to the managed host in an additional inventory source instead.
    connection = {name: value for name, value in variables.items() if name.startswith('ansible_')}
    inputs = {name: value for name, value in variables.items() if not name.startswith('ansible_')}
    overlay = {'all': {'hosts': {alias: connection, 'localhost': {
        'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable, 'ansible_become': False,
    }}}}
    command = [str(ROOT / '.venv/bin/ansible-playbook'), '-i', str(path),
               str(ROOT / 'playbooks' / playbook), '--limit', alias, '-e', json.dumps(inputs)]
    if ask_pass:
        command.append('--ask-pass')
    if ask_become:
        command.append('--ask-become-pass')
    if check:
        command.append('--check')
    if diff:
        command.append('--diff')
    environment = os.environ.copy()
    for name in ('ANSIBLE_PARAMIKO_LOOK_FOR_KEYS', 'ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD',
                 'ANSIBLE_PARAMIKO_RECORD_HOST_KEYS'):
        environment.pop(name, None)
    # Contains only connection settings and paths, never passwords/key contents.
    # NamedTemporaryFile uses 0600 and removes this overlay after the child exits.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', prefix='bootstrap-inventory-') as inventory:
        json.dump(overlay, inventory)
        inventory.flush()
        command.extend(['-i', inventory.name])
        subprocess.run(command, cwd=ROOT, check=True, env=environment)
