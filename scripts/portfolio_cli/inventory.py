"""Static inventory validation and initial versus managed access selection."""

import os
import re

import yaml

from .common import DEFAULT_KEY, ROOT, require
from .keys import key_path


HARDENING_FIELDS = {'ssh_listen_ports', 'ssh_verify_ports', 'firewall_allowed_tcp_ports'}


HOST_FIELDS = {'ansible_host', 'ansible_port', 'ansible_user', 'bootstrap_login_user', 'ansible_private_key_file', 'ansible_python_interpreter'} | HARDENING_FIELDS | {'swap_size_mb'}


def setup_inventory(path):
    """Exclusive creation: never read or overwrite an existing production inventory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as target:
            target.write((ROOT / 'inventories/production.example.yml').read_text())
    except FileExistsError:
        print('Inventory already exists; preserved without reading it.')
    else:
        print('Inventory created. Edit ansible_host and ansible_port before bootstrap.')


def load_host(path, validate_hardening=True):
    require(path.is_file() and path.resolve() != ROOT / 'inventories/production.example.yml',
            'Real local inventory required. Run make setup, then edit host and port.')
    try:
        data = yaml.safe_load(path.read_text())
        require(set(data) == {'all'}, 'Use the static example inventory structure.')
        require(set(data['all']) == {'children'}, 'Use the static example inventory structure.')
        children = data['all']['children']
        require(set(children) == {'bootstrap'}, 'Exactly one bootstrap group is supported.')
        group = children['bootstrap']
        require(set(group) == {'hosts'}, 'Keep credentials and runtime variables out of inventory.')
        hosts = group['hosts']
        require(len(hosts) == 1, 'Exactly one bootstrap host is supported.')
        alias, values = next(iter(hosts.items()))
        require(isinstance(alias, str) and re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]*', alias),
                'Use a simple host alias such as portfolio.')
        require(alias != 'localhost', 'Reserve localhost for the controller; use a separate VPS alias.')
        require(isinstance(values, dict) and set(values) <= HOST_FIELDS,
                'Only host, port, access users/key path, Python interpreter, swap size and hardening port lists belong in inventory.')
        if 'swap_size_mb' in values:
            require(type(values['swap_size_mb']) is int and 0 <= values['swap_size_mb'] <= 1048576,
                    'swap_size_mb must be an integer from 0 to 1048576.')
        for name in HARDENING_FIELDS & values.keys() if validate_hardening else ():
            validate_ports(values[name], allow_empty=name == 'firewall_allowed_tcp_ports')
        host = values.get('ansible_host')
        port = values.get('ansible_port')
        user = values.get('bootstrap_login_user', values.get('ansible_user', 'root'))
        validate_access_values(values)
        interpreter = values.get('ansible_python_interpreter', '/usr/bin/python3')
        require(isinstance(host, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]*', host)
                and not host.endswith('.invalid') and '{{' not in host,
                'Set ansible_host to your verified VPS hostname or address.')
        require(type(port) is int and 1 <= port <= 65535, 'Set ansible_port to an integer from 1 to 65535.')
        require(isinstance(user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', user), 'Initial login must be root or another existing administrator.')
        require(isinstance(interpreter, str) and re.fullmatch(r'/[a-zA-Z0-9_./-]+', interpreter),
                'Use an absolute Python interpreter path.')
    except (yaml.YAMLError, TypeError, KeyError, AttributeError):
        # Parser exceptions can include inventory contents: do not expose them.
        raise ValueError('Invalid inventory. Use the static example structure without credentials.') from None
    return alias, host, port, user, interpreter


def validate_access_values(values):
    """Explicit access contract; legacy initial-login inventories remain supported."""
    explicit = 'bootstrap_login_user' in values or 'ansible_private_key_file' in values
    if explicit:
        require({'bootstrap_login_user', 'ansible_user', 'ansible_private_key_file'} <= values.keys(),
                'Set bootstrap_login_user, ansible_user and ansible_private_key_file together.')
        name = values['ansible_user']
        require(isinstance(name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}', name)
                and name != 'root', 'ansible_user must be a non-root managed Ubuntu username.')
        value = values['ansible_private_key_file']
        require(isinstance(value, str) and value and (value.startswith('/') or value.startswith('~/'))
                and '{{' not in value and '\n' not in value,
                'ansible_private_key_file must be an absolute or ~/ local key path.')
        key_path(value)
    else:
        require(values.get('ansible_user', 'root') != 'ansible',
                'Legacy inventory describes the initial login; use the explicit access fields for managed login.')


def managed_access(inventory, override=None):
    # Validate the entire static inventory before selecting any connection identity.
    alias, _, _, _, _ = load_host(inventory, validate_hardening=False)
    values = yaml.safe_load(inventory.read_text())['all']['children']['bootstrap']['hosts'][alias]
    if 'ansible_private_key_file' in values:
        key = key_path(values['ansible_private_key_file'])
        require(not override or key_path(override) == key,
                'Key override conflicts with ansible_private_key_file; update a candidate inventory explicitly.')
        return values['ansible_user'], key
    # Compatibility only: old inventory holds the initial login, with the established key.
    return 'ansible', key_path(override or DEFAULT_KEY)


def validate_ports(values, allow_empty=False):
    require(isinstance(values, list) and (allow_empty or values) and
            all(type(port) is int and 1 <= port <= 65535 for port in values) and
            len(values) == len(set(values)), 'Hardening ports must be unique integers from 1 to 65535.')


def hardening_inputs(path, alias, port, validate=True):
    # load_host has already validated the complete static inventory structure.
    host = yaml.safe_load(path.read_text())['all']['children']['bootstrap']['hosts'][alias]
    result = {'ssh_listen_ports': host.get('ssh_listen_ports', [port]),
              'firewall_allowed_tcp_ports': host.get('firewall_allowed_tcp_ports', [80, 443])}
    result['ssh_verify_ports'] = host.get('ssh_verify_ports', result['ssh_listen_ports'])
    if not validate:
        return result
    for name, values in result.items():
        validate_ports(values, allow_empty=name == 'firewall_allowed_tcp_ports')
    require(set(result['ssh_verify_ports']) <= set(result['ssh_listen_ports']),
            'ssh_verify_ports must be a non-empty subset of ssh_listen_ports.')
    require(port in result['ssh_listen_ports'],
            'Keep current ansible_port in ssh_listen_ports. Add new ports alongside the current route first.')
    require(port in result['ssh_verify_ports'], 'Keep current ansible_port in ssh_verify_ports.')
    return result


def swap_input(path, alias):
    values = yaml.safe_load(path.read_text())['all']['children']['bootstrap']['hosts'][alias]
    value = values.get('swap_size_mb')
    require(type(value) is int and 0 <= value <= 1048576,
            'Set swap_size_mb to an explicit integer from 0 to 1048576 before SWAP initialization.')
    return value
