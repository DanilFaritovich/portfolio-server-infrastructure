"""Strict SSH stdin transports for hardening, operations and user-state payloads."""

import json
import shlex
import subprocess

from .common import ROOT, SSH_BASE, require


def inspect_host(host, port, interpreter, key, inputs, user):
    """Read-only SSH transport avoids Ansible's remote payload/tempfile writes."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), user + '@' + host,
    ]
    login = subprocess.run(ssh + ['id -un'], capture_output=True, text=True, check=False, timeout=30)
    if login.returncode or login.stdout.strip() != user:
        print('Hardening preflight\nFAIL  managed SSH access\n'
              'FAIL  host inspection unavailable without managed key-only access\n\nResult: NOT READY')
        raise ValueError('Managed SSH access failed; remaining host checks cannot run safely.')
    params = {'current_port': port, 'ssh_ports': inputs['ssh_listen_ports'],
              'tcp_ports': inputs['firewall_allowed_tcp_ports'], 'verify': False,
              'refresh_rules': False, 'socket_candidate': False, 'report_only': True}
    # Python receives code through stdin. -I isolates imports; -B prevents bytecode-cache writes;
    # imports are standard-library only. No copy, temp files, modules or handlers.
    payload = '__name__ = "portfolio_inspection"\n' + (ROOT / 'library/portfolio_hardening_info.py').read_text()
    payload += '\ninspect_stream(json.loads(' + repr(json.dumps(params)) + '))\n'
    process = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                             input=payload, capture_output=True, text=True, check=False, timeout=300)
    try:
        require(process.returncode == 0, 'Managed sudo or host inspection failed.')
        result = json.loads(process.stdout)
        require(type(result['ready']) is bool and isinstance(result['report'], str), 'Invalid inspection result.')
    except (ValueError, KeyError, TypeError):
        # Never dump SSH stderr, sudo errors, parser input or captured stdout.
        print('Hardening preflight\nPASS  managed SSH login\n'
              'FAIL  managed sudo or read-only inspection unavailable\n\nResult: NOT READY')
        raise ValueError('Cannot safely complete host inspection; check managed sudo and Python.') from None
    print(result['report'].replace('Hardening preflight', 'Hardening preflight\nPASS  managed SSH access', 1))
    require(result['ready'], 'Resolve all FAIL findings before make harden. WARN findings can converge safely.')


def user_probe(host, port, interpreter, key, controller, params):
    """Stream a bounded engine with no remote payload files or private-key reads."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), controller + '@' + host,
    ]
    source = (ROOT / 'library/portfolio_human_info.py').read_text()
    source = source.split('def main():')[0].replace('from ansible.module_utils.basic import AnsibleModule', '')
    payload = source + '\n' + (ROOT / 'scripts/user_management.py').read_text()
    payload += '\nmanage_stream(json.loads(' + repr(json.dumps(params | {'controller': controller})) + '))\n'
    result = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                            input=payload, capture_output=True, text=True, check=False, timeout=180)
    try:
        response = json.loads(result.stdout)
        require(result.returncode == 0 and response.get('ready') is True and isinstance(response['result'], dict),
                response.get('error', 'User management SSH/sudo failed; stop and inspect through recovery.'))
        return response['result']
    except (KeyError, TypeError, json.JSONDecodeError):
        raise ValueError('Invalid user management response; stop and inspect through recovery.') from None


def operations_probe(host, port, interpreter, key, module, params, user):
    """Strict key-only stream transport; no Ansible remote files or cache writes."""
    ssh = ['ssh'] + shlex.split(SSH_BASE) + [
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-i', str(key), '-p', str(port), user + '@' + host,
    ]
    login = subprocess.run(ssh + ['id -un'], capture_output=True, text=True, check=False, timeout=30)
    require(login.returncode == 0 and login.stdout.strip() == user, 'Managed key-only SSH access failed.')
    payload = '__name__ = "portfolio_inspection"\n' + (ROOT / 'library' / module).read_text()
    payload += '\ninspect_stream(json.loads(' + repr(json.dumps(params)) + '))\n'
    process = subprocess.run(ssh + ['sudo -n ' + shlex.quote(interpreter) + ' -I -B -'],
                             input=payload, capture_output=True, text=True, check=False, timeout=300)
    try:
        result = json.loads(process.stdout)
        require(process.returncode == 0 and type(result['ready']) is bool and
                isinstance(result['report'], str), 'Invalid read-only inspection result.')
    except (ValueError, KeyError, TypeError):
        raise ValueError('Managed sudo or read-only inspection failed; review manually.') from None
    print(result['report'])
    require(result['ready'], 'Resolve FAIL findings manually before proceeding.')
