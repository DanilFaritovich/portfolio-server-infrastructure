"""Bootstrap, Docker, hardening and confirmed reboot stage orchestration."""

import subprocess
import sys

from .ansible import prerequisites, run_playbook
from .common import PASSWORD_CONNECTION, SSH_BASE, require
from .host_trust import known_host
from .inspection import inspect_host, hardening_plan
from .inventory import hardening_inputs, load_host, managed_access
from .keys import check_key, prepare_key
from .plans import PLAN_NOOP_MESSAGES, stage_consent
from .verification import verify_hardening


def live(mode, inventory, key=None):
    managed_user, key = managed_access(inventory, key)
    prerequisites(mode)
    if mode in ('docker-host', 'verify-docker', 'harden', 'verify-hardening', 'inspect-hardening', 'reboot-host'):
        try:
            check_key(key)
        except (ValueError, OSError):
            raise ValueError('Managed access is not ready. Run make bootstrap-user first; check the dedicated key pair.') from None
    alias, host, port, user, interpreter = load_host(inventory, validate_hardening=mode != 'inspect-hardening')
    inputs = hardening_inputs(inventory, alias, port, validate=mode != 'inspect-hardening') if mode in ('harden', 'verify-hardening', 'inspect-hardening', 'reboot-host') else {}
    if mode in ('bootstrap-user', 'docker-host', 'harden', 'reboot-host'):
        print(f'Target: {host}:{port}; managed account: {managed_user}; key path: {key}.')
        if inputs:
            print('SSH listeners: ' + str(inputs['ssh_listen_ports']) + '; allowed TCP: ' + str(inputs['firewall_allowed_tcp_ports']))
    if mode == 'reboot-host':
        require(sys.stdin.isatty(), 'Reboot requires an interactive terminal; no reboot was requested.')
    if mode == 'bootstrap-user':
        require(user != managed_user, 'Bootstrap login and managed user must be separate accounts.')
    known_host(host, port, allow_trust=mode == 'bootstrap-user')
    if mode == 'inspect-hardening':
        inspect_host(host, port, interpreter, key, inputs, managed_user)
        return
    if mode == 'bootstrap-user':
        require(sys.stdin.isatty(), 'Bootstrap requires an interactive terminal for the Ansible password prompt.')
        print(f'LIVE / MUTATING: configures {managed_user} and approves unrestricted NOPASSWD sudo.', flush=True)
        stage_consent(mode, inventory, key)
        prepare_key(key)
    else:
        check_key(key)
    variables = {
        'ansible_connection': 'ssh', 'ansible_host_key_checking': True,
        'ansible_ssh_args': SSH_BASE, 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
    }
    if mode == 'bootstrap-user':
        run_playbook(inventory, alias, variables | {
            'ansible_user': user,
            'ansible_connection': PASSWORD_CONNECTION,
            'ansible_paramiko_host_key_checking': True,
            'ansible_paramiko_private_key_file': '', 'ansible_paramiko_proxy_command': '',
            'ansible_paramiko_timeout': 15,
            'bootstrap_user_name': managed_user, 'bootstrap_user_public_key_path': str(key) + '.pub',
            'bootstrap_user_allow_passwordless_sudo': True,
        }, 'bootstrap.yml', ask_pass=True, ask_become=user != 'root')
    print(f'LIVE / VERIFY: checking key-only {managed_user} access, ping and sudo -n.', flush=True)
    managed = variables | {
        'ansible_user': managed_user, 'ansible_private_key_file': str(key), 'ansible_become': False,
        'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                            ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                            ' -o KbdInteractiveAuthentication=no',
    }
    try:
        run_playbook(inventory, alias, managed, 'verify.yml')
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if mode == 'reboot-host':
            raise ValueError('Pre-reboot key-only SSH/sudo verification failed; no reboot was requested. '
                             'Stop and check make verify-access and recovery access.') from None
        raise
    if mode == 'reboot-host':
        print(f'LIVE / MUTATING: reboot {host}:{port}. Keep provider console/recovery access. '
              'Docker verification afterward may change the image cache.', flush=True)
        stage_consent(mode, inventory, key)
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        stage['ansible_become_flags'] = '-n'
        phase = 'reboot and bounded SSH recovery'
        try:
            run_playbook(inventory, alias, stage | {'reboot_host_confirmed': True}, 'reboot-host.yml')
            phase = 'verify-access after reboot'
            run_playbook(inventory, alias, managed, 'verify.yml')
            phase = 'verify-docker after reboot'
            run_playbook(inventory, alias, stage, 'verify-docker.yml')
            phase = 'verify-hardening after reboot'
            verify_hardening(inventory, alias, host, port, stage, inputs)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError(f'{phase} failed; the host may already have rebooted. Stop and use provider '
                             'console/recovery access; do not repeat reboot blindly. No later checks ran.') from None
        print('Reboot and access/Docker/hardening verification completed. STOP.')
        return
    if mode in ('docker-host', 'verify-docker'):
        print('LIVE / MUTATING: Docker host provisioning.' if mode == 'docker-host' else
              'LIVE / VERIFY: Docker checks and disposable runtime smoke test (image cache may change).', flush=True)
        # Host-level ansible_become=False would override task-level become=True.
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        if mode == 'docker-host':
            stage_consent(mode, inventory, key)
        run_playbook(inventory, alias, stage | {'ansible_become_flags': '-n'}, mode + '.yml')
        if mode == 'docker-host':
            run_playbook(inventory, alias, stage | {'ansible_become_flags': '-n'}, 'verify-docker.yml')
    if mode in ('harden', 'verify-hardening'):
        stage = {name: value for name, value in managed.items() if name != 'ansible_become'}
        stage['ansible_become_flags'] = '-n'
        if mode == 'harden':
            print('LIVE / MUTATING: UFW and SSH listening ports. Keep provider recovery console access.', flush=True)
            before = hardening_plan(host, port, interpreter, key, inputs, managed_user)
            if before['changes_required']:
                stage_consent(mode, inventory, key)
                require(hardening_plan(host, port, interpreter, key, inputs, managed_user) == before,
                        'Hardening plan changed; STOP before mutation.')
                run_playbook(inventory, alias, stage | inputs, 'harden.yml')
            else:
                print(PLAN_NOOP_MESSAGES[mode])
        verify_hardening(inventory, alias, host, port, stage, inputs)
    print('Requested stage completed. STOP.')
    # Returned only after the independent postflight has succeeded.
    return {'bootstrap-user': 'verify-access', 'docker-host': 'verify-docker',
            'harden': 'verify-hardening'}.get(mode)
