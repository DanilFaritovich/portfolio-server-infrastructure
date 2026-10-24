"""Stage 08 using existing consent, managed transport and independent probes."""

import os

from .ansible import prerequisites, run_playbook
from .common import SSH_BASE, require
from .deployment_artifact import prepared_gh
from .host_trust import known_host
from .inventory import load_host, managed_access
from .keys import check_key
from .plans import plan_snapshot, stage_consent, validate_current_plan
from .verification import deployment_probe

DEPLOYMENT_MODES = ('setup-deployment-prerequisites', 'verify-deployment-prerequisites')


def deployment_prerequisites(mode, inventory, key=None):
    require(not os.environ.get('CI'), 'Deployment prerequisites LIVE commands are disabled in offline CI.')
    require(mode in DEPLOYMENT_MODES, 'Invalid deployment prerequisites operation.')
    user, key = managed_access(inventory, key)
    prerequisites(mode)
    check_key(key)
    alias, host, port, _, interpreter = load_host(inventory)
    known_host(host, port)
    verify = mode == 'verify-deployment-prerequisites'
    present = deployment_probe(host, port, interpreter, key, user, verify)
    if verify:
        return
    if not present:
        # Consent precedes local download AND every remote write. init-server
        # supplies its bounded, snapshot-bound plan through the same function.
        before = plan_snapshot(inventory, key)
        stage_consent(mode, inventory, key)
        with prepared_gh() as source:
            validate_current_plan()
            require(plan_snapshot(inventory, key) == before, 'Deployment plan inputs changed; STOP.')
            require(not deployment_probe(host, port, interpreter, key, user),
                    'Deployment prerequisites changed after planning; STOP.')
            run_playbook(inventory, alias, {
                'ansible_user': user, 'ansible_connection': 'ssh',
                'ansible_private_key_file': str(key), 'ansible_host_key_checking': True,
                'ansible_become_flags': '-n', 'ansible_ssh_common_args': '', 'ansible_ssh_extra_args': '',
                'ansible_ssh_args': SSH_BASE + ' -o BatchMode=yes -o IdentitiesOnly=yes'
                                    ' -o PreferredAuthentications=publickey -o PasswordAuthentication=no'
                                    ' -o KbdInteractiveAuthentication=no',
                'deployment_prerequisites_confirmed': True, 'deployment_prerequisites_source': str(source),
            }, 'setup-deployment-prerequisites.yml')
    else:
        print('Pinned gh already matches; no changes required.')
    deployment_probe(host, port, interpreter, key, user, verify=True)
    return 'verify-deployment-prerequisites'
