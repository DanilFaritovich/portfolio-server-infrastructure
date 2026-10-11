"""Independent Ansible access checks over the selected SSH ports."""

import subprocess

from .ansible import run_playbook
from .keys import check_key, public_key_file


def verify_hardening(inventory, alias, host, port, stage, inputs):
    # Each selected verification port gets a new independent connection. Reuse the
    # already trusted host identity via HostKeyAlias; never scan/accept keys.
    identity = host if port == 22 else f'[{host}]:{port}'
    print('LIVE / POST-CONVERGENCE VERIFY: all ssh_listen_ports are required on the server; '
          'fresh SSH access is required on every ssh_verify_ports entry.', flush=True)
    for target_port in inputs['ssh_verify_ports']:
        connection = stage | {'ansible_port': target_port,
                              'ansible_ssh_args': stage['ansible_ssh_args'] + f' -o HostKeyAlias={identity}'}
        try:
            run_playbook(inventory, alias, connection, 'verify.yml')
        except subprocess.CalledProcessError:
            print(f'Post-convergence access verification failed on configured SSH port {target_port}. '
                  'Stop and check make verify-access on the current inventory route and recovery access. '
                  'A future port may be unavailable until make harden succeeds.', flush=True)
            raise
        run_playbook(inventory, alias, connection | inputs, 'verify-hardening.yml')


def verify_human(inventory, alias, host, port, managed, inputs, human, key):
    check_key(key)
    public_key_file(str(key) + '.pub')
    identity = host if port == 22 else f'[{host}]:{port}'
    for target in inputs['ssh_verify_ports']:
        connection = managed | {'ansible_user': human['human_access_user_name'],
                                'ansible_private_key_file': str(key), 'ansible_port': target,
                                # Human encrypted keys may use their existing agent; only this identity is eligible.
                                'ansible_ssh_args': managed['ansible_ssh_args']
                                + f' -o HostKeyAlias={identity}'}
        run_playbook(inventory, alias, connection | human | {'portfolio_automation_user': managed['ansible_user']}, 'verify-user.yml')
