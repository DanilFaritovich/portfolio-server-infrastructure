"""Local libvirt fixture management. Provisioning belongs to the existing CLI.

Only owned, static, single-disk BIOS guests on a dedicated NAT are supported.
A partial preparation is evidence to inspect/delete, never a resumable transaction.
"""

import contextlib
import errno
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

import yaml

from . import common, e2e_host, e2e_images
from .e2e_images import E2EError, require
from .common import ROOT

URI = 'qemu:///system'
NS = 'urn:portfolio:local-e2e:1'
MODES = ('prepare', 'status', 'test', 'reset', 'delete', 'list-distros')


def command_label(argv):
    """Only fixed operation names may enter diagnostics; argv may hold secrets."""
    labels = {'openssl': 'password hashing', 'cloud-localds': 'cloud-init seed creation',
              'virt-install': 'domain XML generation', 'sudo': 'confirmed host preparation',
              'ssh': 'SSH verification', 'make': 'scenario wrapper'}
    if argv and argv[0] in labels:
        return labels[argv[0]]
    if argv and argv[0] == 'qemu-img' and len(argv) > 1 and argv[1] in ('info', 'convert', 'resize'):
        return 'disk ' + argv[1]
    if argv and argv[0] == 'virsh' and len(argv) > 3 and argv[1:3] == ['--connect', URI]:
        labels = {'net-define': 'network definition', 'net-start': 'network activation',
                  'define': 'domain definition', 'start': 'domain startup',
                  'snapshot-create': 'baseline creation'}
        return labels.get(argv[3], 'libvirt operation')
    return 'local command'


def command(argv, *, capture=True, input=None, timeout=60, env=None):
    """Never echo arguments/output on failure (cloud-init and prompts are private)."""
    child_env = dict(env) if env is not None else dict(os.environ, LC_ALL='C')
    if argv and argv[0] in ('virt-install', 'cloud-localds', 'virsh', 'qemu-img'):
        # System tools may use /usr/bin/env python3 and require distro modules
        # (gi/libvirt). Make's pinned controller venv must not select their Python.
        controller_bins = {(ROOT / '.venv/bin').resolve()}
        if sys.prefix != sys.base_prefix:
            controller_bins.add((Path(sys.prefix) / 'bin').resolve())
        child_env['PATH'] = os.pathsep.join(entry for entry in child_env.get('PATH', os.defpath).split(os.pathsep)
                                           if Path(entry or '.').resolve() not in controller_bins)
        for name in ('PYTHONHOME', 'PYTHONPATH', 'VIRTUAL_ENV'):
            child_env.pop(name, None)
    result = subprocess.run(argv, input=input, text=True, capture_output=capture,
                            timeout=timeout, env=child_env, check=False)
    require(result.returncode == 0, 'E2E subprocess failed (' + command_label(argv)
            + f', exit {result.returncode}); STOP and diagnose before retrying. '
            'Command arguments and output are withheld to protect secrets.')
    return result.stdout if capture else ''


def virsh(*args):
    return command(['virsh', '--connect', URI, *args]).strip()


def convergence_command(argv, env):
    """Stream interactive output; retain only numeric recap counts, never a log."""
    smoke = yaml.safe_load((ROOT / 'playbooks/verify-docker.yml').read_text())[0]['name']
    required = {yaml.safe_load((ROOT / 'playbooks' / name).read_text())[0]['name'] for name in
                ('docker-host.yml', 'harden.yml', 'secure-ssh.yml', 'setup-operations.yml')}
    seen, failed, play = set(), False, None
    with subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, env=env) as process:
        for line in process.stdout:
            print(line, end='', flush=True)
            title = re.match(r'^PLAY \[(.+)\]', line)
            if title:
                play = title[1]
            match = re.match(r'^e2e\s*:\s+ok=\d+\s+changed=(\d+)\b', line)
            if match:
                seen.add(play)
                # The existing verifier deliberately creates/runs/removes one
                # smoke container: exactly three changes, not provisioning drift.
                failed |= int(match[1]) != (3 if play == smoke else 0)
        require(process.wait() == 0, 'Repeat initialization failed; state retained, no reset.')
    require(required <= seen and not failed, 'Repeat initialization did not prove provisioning changed=0; inspect recaps without automatic retry.')


def confirm(message):
    require(sys.stdin.isatty(), 'E2E requires a TTY for this operation.')
    try:
        answer = input(message + ' [y/N] ')
    except EOFError:
        answer = ''
    require(answer.strip().lower() in ('y', 'yes'), 'E2E operation declined.')


def disposable_password():
    """Retry local input only, before fixture state or VM creation."""
    while True:
        password = getpass.getpass('New disposable root password (at least 12 printable ASCII characters): ')
        if len(password) < 12:
            print('Password must contain at least 12 characters. Try again; Ctrl+C cancels preparation.')
            continue
        if not all(32 <= ord(c) < 127 for c in password):
            print('Password must use printable ASCII characters. Try again; Ctrl+C cancels preparation.')
            continue
        if password != getpass.getpass('Repeat disposable password: '):
            print('Passwords do not match. Try again; Ctrl+C cancels preparation.')
            continue
        return password


def safe_path(path, *, directory=False, private=True, group_write_gid=None):
    require(path.is_absolute() and path.resolve() == path and
            not any(p.is_symlink() for p in (path, *path.parents)), 'Unsafe E2E path.')
    info = path.lstat()
    group_write = (group_write_gid is not None and not directory and not private
                   and info.st_gid == group_write_gid and stat.S_IMODE(info.st_mode) == 0o660)
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.getuid() and (directory or info.st_nlink == 1)
            and info.st_mode & (0o077 if private else 0o002 if group_write else 0o022) == 0,
            'Unsafe E2E ownership/mode.')


def write_new(path, content, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'w') as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def xml_text(element):
    return ET.tostring(element, encoding='unicode')


def parse_xml(value):
    require('<!DOCTYPE' not in value and '<!ENTITY' not in value, 'Unsupported libvirt XML.')
    try:
        return ET.fromstring(value)
    except ET.ParseError:
        raise ValueError('Invalid libvirt XML; STOP.') from None


class Stand:
    def __init__(self, root=None):
        # Fixed per-user namespaces prevent caller path overrides from selecting production.
        self.root = root or Path.home() / '.local/share/portfolio-e2e'
        self.storage = Path('/var/lib/libvirt/images') / f'portfolio-e2e-{os.getuid()}'
        self.name = f'portfolio-e2e-{os.getuid()}'
        self.state = None

    @property
    def distro(self):
        # Schema 1 was exclusively Noble; keep old fixtures readable without rewriting state.
        return self.state['distro'] if self.state.get('schema') == 2 else e2e_images.registry(legacy=True)[0]

    @property
    def disk(self):
        return self.storage / 'guest.qcow2'

    @property
    def seed(self):
        return self.storage / 'seed.iso'

    @property
    def inventory(self):
        return self.root / 'inventory.yml'

    def load(self):
        safe_path(self.root, directory=True)
        path = self.root / 'state.json'
        safe_path(path)
        try:
            self.state = json.loads(path.read_text())
            fields = {'schema', 'uuid', 'network_uuid', 'phase', 'subnet', 'mac', 'cpus', 'memory', 'size'}
            require(set(self.state) == (fields if self.state.get('schema') == 1 else fields | {'distro'}),
                    'Unknown E2E state schema.')
            require(type(self.state['schema']) is int and self.state['schema'] in (1, 2) and self.state['phase'] in ('preparing', 'ready'), 'Invalid E2E phase.')
            for field in ('uuid', 'network_uuid'):
                require(str(uuid.UUID(self.state[field])) == self.state[field], 'Invalid E2E UUID.')
            require(re.fullmatch(r'52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}', self.state['mac']), 'Invalid E2E MAC.')
            self.validate_config(self.state)
            require(isinstance(self.distro, str) and self.distro, 'Invalid recorded E2E distro.')
            e2e_images.select(self.distro)
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError('Invalid E2E state; STOP without adopting resources.') from None
        return self.state

    def validate_config(self, config):
        subnet = ipaddress.ip_network(config['subnet'])
        require(subnet.version == 4 and subnet.prefixlen == 24 and subnet.is_private
                and subnet.subnet_of(ipaddress.ip_network('192.168.0.0/16')), 'Use a private 192.168.x.0/24 E2E subnet.')
        for field, lower, upper in (('cpus', 2, 16), ('memory', 4096, 32768), ('size', 25, 256)):
            require(type(config[field]) is int and lower <= config[field] <= upper, 'Invalid E2E CPU/RAM/disk setting.')

    @property
    def ip(self):
        return str(ipaddress.ip_network(self.state['subnet']).network_address + 10)

    def metadata(self):
        return ET.Element('{' + NS + '}owner', {'uuid': self.state['uuid'], 'root': str(self.root),
                                               'storage': str(self.storage)})

    def check_metadata(self, tree):
        owners = tree.findall('metadata/{' + NS + '}owner')
        require(len(owners) == 1 and owners[0].attrib == self.metadata().attrib, 'E2E metadata mismatch; resource is not owned.')

    def disk_file(self):
        """Only the owned qcow2 may grant its protected storage group write access."""
        safe_path(self.storage, directory=True, private=False)
        safe_path(self.disk, private=False, group_write_gid=self.storage.stat().st_gid)

    def domain_xml(self, tree, *, require_dac=False):
        require(tree is not None and tree.tag == 'domain' and tree.get('type') == 'kvm' and tree.findtext('uuid') == self.state['uuid']
                and tree.findtext('name') == self.name, 'E2E domain UUID/name/type mismatch.')
        self.check_metadata(tree)
        require(tree.find('os/loader') is None and tree.find('os/nvram') is None, 'E2E requires BIOS without NVRAM.')
        devices = tree.find('devices')
        require(devices is not None and not any(devices.findall(tag) for tag in
                ('filesystem', 'hostdev', 'shmem', 'redirdev')), 'Unsupported E2E device resources.')
        disks = devices.findall('disk')
        require(len(disks) == 2, 'E2E requires exactly the owned disk and seed.')
        found = {}
        for disk in disks:
            source, target = disk.find('source'), disk.find('target')
            require(disk.get('type') == 'file' and source is not None and target is not None
                    and 'file' in source.attrib and set(source.attrib) <= {'file', 'index'}
                    and disk.find('.//backingStore/source') is None
                    and not any(disk.find(tag) is not None for tag in ('dataStore', 'mirror', 'shareable', 'encryption')),
                    'Unsupported disk/backing chain; no files may be removed.')
            path = Path(source.get('file', ''))
            require(path in (self.disk, self.seed), 'Foreign E2E disk path.')
            require(path not in found, 'Duplicate E2E disk.')
            labels = source.findall('seclabel')
            require((not labels and not require_dac) or
                    (len(labels) == 1 and labels[0].attrib == {'model': 'dac', 'relabel': 'no'}
                     and not list(labels[0]) and not (labels[0].text or '').strip()),
                    'Unsupported E2E disk security label.')
            if path == self.disk:
                self.disk_file()
            else:
                safe_path(path, private=False)
            if path == self.disk:
                require(disk.get('device') == 'disk' and disk.find('driver').get('type') == 'qcow2'
                        and target.get('dev') == 'vda', 'Unsupported E2E snapshot backend.')
            else:
                require(disk.get('device') == 'cdrom' and disk.find('readonly') is not None, 'Unsafe E2E seed device.')
            found[path] = target.get('dev')
        interfaces = devices.findall('interface')
        require(len(interfaces) == 1 and interfaces[0].get('type') == 'network'
                and interfaces[0].find('source').get('network') == self.name
                and interfaces[0].find('mac').get('address') == self.state['mac'], 'Foreign E2E network attachment.')
        return found

    def network_xml(self, tree):
        require(tree.tag == 'network' and tree.findtext('uuid') == self.state['network_uuid']
                and tree.findtext('name') == self.name, 'E2E network UUID/name mismatch.')
        self.check_metadata(tree)
        require(tree.find('forward') is not None and tree.find('forward').attrib == {'mode': 'nat'}, 'E2E requires dedicated NAT.')
        ips = tree.findall('ip')
        gateway = str(ipaddress.ip_network(self.state['subnet']).network_address + 1)
        require(len(ips) == 1 and ips[0].get('address') == gateway and ips[0].get('netmask') == '255.255.255.0', 'Foreign E2E subnet.')
        hosts = ips[0].findall('dhcp/host')
        require(len(hosts) == 1 and hosts[0].get('mac') == self.state['mac'] and hosts[0].get('ip') == self.ip,
                'E2E DHCP reservation mismatch.')

    def resources(self):
        """A query failure is never interpreted as absence."""
        domains = virsh('list', '--all', '--uuid').split()
        networks = virsh('net-list', '--all', '--uuid').split()
        # Name collision must fail even if our UUID is absent.
        for identity in domains:
            tree = parse_xml(virsh('dumpxml', identity, '--inactive'))
            if identity == self.state['uuid'] or tree.findtext('name') == self.name:
                self.domain_xml(tree)
                # Runtime XML may differ from the persistent definition.
                self.domain_xml(parse_xml(virsh('dumpxml', identity)))
        for identity in networks:
            tree = parse_xml(virsh('net-dumpxml', identity))
            if identity == self.state['network_uuid'] or tree.findtext('name') == self.name:
                self.network_xml(tree)
                self.network_xml(parse_xml(virsh('net-dumpxml', identity, '--inactive')))
        return self.state['uuid'] in domains, self.state['network_uuid'] in networks

    def snapshots(self):
        names = virsh('snapshot-list', self.state['uuid'], '--name').splitlines()
        for name in names:
            require(name == 'baseline' or re.fullmatch(r'diagnostic-[a-z0-9-]+', name), 'Unknown E2E snapshot; inspect manually.')
            tree = parse_xml(virsh('snapshot-dumpxml', self.state['uuid'], name))
            memory = tree.find('memory')
            require(tree.findtext('name') == name and tree.findtext('state') == 'shutoff'
                    and memory is not None and memory.get('snapshot') == 'no', 'Only stopped internal snapshots are supported.')
            targets = self.domain_xml(tree.find('domain'))
            disks = tree.findall('disks/disk')
            expected = {targets[self.disk]: 'internal', targets[self.seed]: 'no'}
            require(len(disks) == 2 and {d.get('name'): d.get('snapshot') for d in disks} == expected
                    and all(d.find('source') is None for d in disks), 'External/unknown snapshot backend; STOP.')
        return names

    def ready(self, running=False):
        self.load()
        safe_path(self.storage, directory=True, private=False)
        require(self.state['phase'] == 'ready', 'Partial E2E preparation; inspect console/state, then explicitly delete. No automatic resume.')
        require(all(self.resources()), 'E2E resource missing; STOP without recreation.')
        require('baseline' in self.snapshots(), 'E2E baseline missing; STOP.')
        if running:
            require(virsh('domstate', self.state['uuid']) == 'running', 'Start the owned VM in virt-manager or virsh before testing.')
            require(self.state['network_uuid'] in virsh('net-list', '--uuid').split(), 'Owned E2E NAT is inactive.')
            network = parse_xml(virsh('net-dumpxml', self.state['network_uuid']))
            bridge = network.find('bridge')
            require(bridge is not None and bridge.get('name'), 'Owned NAT bridge is unavailable.')
            routes = json.loads(command(['ip', '-j', 'route', 'get', self.ip]))
            require(len(routes) == 1 and routes[0].get('dev') == bridge.get('name')
                    and not routes[0].get('gateway'), 'E2E IP route does not use the owned bridge; no SSH permitted.')
            lease = virsh('net-dhcp-leases', self.state['network_uuid'], '--mac', self.state['mac'])
            require(re.search(r'\b' + re.escape(self.ip) + r'/24\b', lease), 'No matching owned VM DHCP lease; no SSH attempted.')

    def expected_inventory(self):
        return {'all': {'children': {'bootstrap': {'hosts': {'e2e': {
            'ansible_host': self.ip, 'ansible_port': 22, 'bootstrap_login_user': 'root',
            'ansible_user': 'ansible', 'ansible_private_key_file': str(self.root / 'home/.ssh/controller/ansible_ed25519'),
            'ansible_python_interpreter': '/usr/bin/python3', 'ssh_listen_ports': [22],
            'ssh_verify_ports': [22], 'firewall_allowed_tcp_ports': [80, 443],
        }}}}}}

    def check_inventory(self, path):
        require(path == self.inventory, 'Production/foreign inventory is forbidden for E2E.')
        safe_path(path)
        try:
            require(yaml.safe_load(path.read_text()) == self.expected_inventory(), 'E2E inventory drift; no host contact permitted.')
        except yaml.YAMLError:
            raise ValueError('Invalid E2E inventory; no host contact permitted.') from None

    def status(self):
        if not self.root.exists():
            # Confirm the namespace is unused, rather than treating libvirt failure as absence.
            for mode, dump in (('list', 'dumpxml'), ('net-list', 'net-dumpxml')):
                for identity in virsh(mode, '--all', '--uuid').split():
                    require(parse_xml(virsh(dump, identity)).findtext('name') != self.name,
                            'E2E resource exists without local ownership state; STOP.')
            print('E2E not prepared. Fixture ready=False. Run make e2e-prepare after reviewing prerequisites.')
            return
        self.load()
        domain, network = self.resources()
        phase = self.state['phase']
        state = virsh('domstate', self.state['uuid']) if domain else 'absent'
        snapshots = self.snapshots() if domain else []
        lease = virsh('net-dhcp-leases', self.state['network_uuid'], '--mac', self.state['mac']) if network else ''
        leased = bool(re.search(r'\b' + re.escape(self.ip) + r'/24\b', lease))
        print(f'VM={self.name} UUID={self.state["uuid"]} state={state} phase={phase}\n'
              f'Distro={self.distro} ({e2e_images.select(self.distro)["name"]})\n'
              f'IP={self.ip} DHCP={leased} network={network} baseline={"baseline" in snapshots}\n'
              f'Fixture ready={phase == "ready" and domain and network and "baseline" in snapshots}\n'
              f'CPU={self.state["cpus"]} RAM MiB={self.state["memory"]} Disk GiB={self.state["size"]}\n'
              f'Local SSH trust={(self.root / "home/.ssh/known_hosts").is_file()}\n'
              f'Console: virsh -c {URI} console {self.state["uuid"]}')

    def no_overlap(self):
        subnet = ipaddress.ip_network(self.state['subnet'])
        routes = json.loads(command(['ip', '-j', 'route', 'show', 'table', 'all']))
        for route in routes:
            dest = route.get('dst', 'default')
            if dest != 'default':
                require(not subnet.overlaps(ipaddress.ip_network(dest, strict=False)), 'E2E subnet overlaps host routes.')
        for identity in virsh('net-list', '--all', '--uuid').split():
            tree = parse_xml(virsh('net-dumpxml', identity))
            require(tree.findtext('name') != self.name, 'E2E network name already exists without ownership.')
            for item in tree.findall('ip'):
                address = item.get('address')
                if address:
                    candidate = ipaddress.ip_network(address + '/' + (item.get('prefix') or item.get('netmask') or '32'), strict=False)
                    require(candidate.version != 4 or not subnet.overlaps(candidate), 'E2E subnet overlaps libvirt network.')
        for identity in virsh('list', '--all', '--uuid').split():
            require(parse_xml(virsh('dumpxml', identity, '--inactive')).findtext('name') != self.name,
                    'E2E VM name already exists without ownership.')

    def download(self):
        # TLS authenticates the official checksum list; an optional pinned digest
        # also allows reproducible selection and detects a release changing mid-download.
        profile = e2e_images.select(self.distro)
        image_url, checksum_url = profile['image_url'], profile['checksum_url']
        image_name = image_url.rsplit('/', 1)[1]
        with e2e_images.open_official(checksum_url) as response:
            require(response.url == checksum_url, 'Image checksum redirect refused.')
            checksums = response.read(65536).decode('ascii')
        matches = re.findall(r'^([0-9a-f]{64})\s+\*?' + re.escape(image_name) + r'$', checksums, re.M)
        require(len(matches) == 1, 'Official image checksum missing/ambiguous.')
        pinned = os.environ.get('E2E_IMAGE_SHA256', '')
        require(not pinned or re.fullmatch(r'[0-9a-f]{64}', pinned), 'Invalid pinned image SHA-256.')
        require(not pinned or pinned == matches[0], 'Pinned image checksum differs from official release.')
        target = self.root / 'image.img'
        digest = hashlib.sha256()
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output, e2e_images.open_official(image_url) as response:
            require(response.url == image_url, 'Image redirect refused.')
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(digest.hexdigest() == matches[0], 'Cloud image integrity failed; do not use this disk.')
        write_new(self.root / 'image.sha256', matches[0] + '\n')
        return target

    def prepare(self):
        if (self.root / 'state.json').exists():
            self.ready()
            requested = os.environ.get('E2E_DISTRO', '')
            require(not requested or e2e_images.select(requested)['id'] == self.distro,
                    'Existing VM distro differs; no replacement. Explicitly inspect/delete before choosing another distro.')
            self.status()
            return
        require(not self.root.exists() and not self.root.is_symlink(), 'Existing E2E directory without state; inspect manually.')
        profile = e2e_images.select(os.environ.get('E2E_DISTRO'))
        result = e2e_host.prepare(self.storage, command=command, confirm=confirm, safe_path=safe_path)
        if result is e2e_host.PreparationResult.REBOOT_REQUIRED:
            return result
        require(not list(self.storage.iterdir()), 'E2E storage must be empty; no disk will be overwritten.')
        config = {'subnet': os.environ.get('E2E_SUBNET') or '192.168.231.0/24',
                  'cpus': int(os.environ.get('E2E_CPUS') or '2'), 'memory': int(os.environ.get('E2E_MEMORY') or '4096'),
                  'size': int(os.environ.get('E2E_DISK_GB') or '25')}
        self.validate_config(config)
        self.state = dict(config, schema=2, distro=profile['id'], phase='preparing', uuid=str(uuid.uuid4()), network_uuid=str(uuid.uuid4()),
                          mac='52:54:00:' + ':'.join(f'{b:02x}' for b in os.urandom(3)))
        self.no_overlap()
        confirm(f'Create the local E2E VM/NAT and download {profile["name"]} official cloud image?')
        password = disposable_password()
        hashed = command(['openssl', 'passwd', '-6', '-stdin'], input=password + '\n').strip()
        require(re.fullmatch(r'\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}', hashed), 'Invalid password hash; preparation stopped.')
        del password
        self.root.mkdir(mode=0o700, parents=True)
        write_new(self.root / 'state.json', json.dumps(self.state))
        image = self.download()
        info = json.loads(command(['qemu-img', 'info', '--output=json', str(image)]))
        require(info.get('format') == 'qcow2' and not info.get('backing-filename'), 'Unsupported cloud image.')
        require(not self.disk.exists() and not self.disk.is_symlink(), 'Disk appeared during preparation; no overwrite.')
        command(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'qcow2', str(image), str(self.disk)], timeout=300)
        command(['qemu-img', 'resize', str(self.disk), str(config['size']) + 'G'])
        self.disk.chmod(0o660)
        # Storage has the operator-selected QEMU group and setgid bit; no chown/sudo here.
        cloud = {'hostname': 'portfolio-e2e', 'disable_root': False, 'ssh_pwauth': True,
                 'users': [{'name': 'root', 'lock_passwd': False, 'hashed_passwd': hashed}],
                 'write_files': [
                     {'path': '/etc/portfolio-e2e-id', 'permissions': '0644', 'content': self.state['uuid'] + '\n'},
                     {'path': '/etc/ssh/sshd_config.d/00-e2e-bootstrap.conf', 'permissions': '0644',
                      'content': 'PermitRootLogin yes\nPasswordAuthentication yes\n'}],
                 'runcmd': [['/usr/sbin/sshd', '-t'], ['systemctl', 'restart', 'ssh.service']]}
        write_new(self.root / 'user-data', '#cloud-config\n' + yaml.safe_dump(cloud))
        del hashed
        write_new(self.root / 'meta-data', yaml.safe_dump({'instance-id': self.state['uuid'], 'local-hostname': 'portfolio-e2e'}))
        require(not self.seed.exists() and not self.seed.is_symlink(), 'Seed appeared during preparation; no overwrite.')
        command(['cloud-localds', str(self.seed), str(self.root / 'user-data'), str(self.root / 'meta-data')])
        self.seed.chmod(0o640)
        network = ET.Element('network')
        ET.SubElement(network, 'name').text = self.name
        ET.SubElement(network, 'uuid').text = self.state['network_uuid']
        ET.SubElement(network, 'metadata').append(self.metadata())
        ET.SubElement(network, 'forward', mode='nat')
        ip = ET.SubElement(network, 'ip', address=str(ipaddress.ip_network(config['subnet']).network_address + 1), netmask='255.255.255.0')
        dhcp = ET.SubElement(ip, 'dhcp')
        ET.SubElement(dhcp, 'host', mac=self.state['mac'], name='portfolio-e2e', ip=self.ip)
        write_new(self.root / 'network.xml', xml_text(network))
        virsh('net-define', str(self.root / 'network.xml'))
        virsh('net-start', self.state['network_uuid'])
        tree = parse_xml(command(['virt-install', '--connect', URI, '--name', self.name, '--uuid', self.state['uuid'],
                                 '--memory', str(config['memory']), '--vcpus', str(config['cpus']), '--virt-type', 'kvm',
                                 '--osinfo', profile['osinfo'], '--import', '--boot', 'hd', '--graphics', 'none',
                                 '--console', 'pty,target_type=serial', '--disk', f'path={self.disk},format=qcow2,bus=virtio',
                                 '--disk', f'path={self.seed},device=cdrom,readonly=on', '--network',
                                 f'network={self.name},mac={self.state["mac"]},model=virtio', '--print-xml', '--dry-run']))
        metadata = tree.find('metadata')
        if metadata is None:
            metadata = ET.SubElement(tree, 'metadata')
        metadata.append(self.metadata())
        # QEMU already has group access through the dedicated setgid storage.
        # Keep controller ownership, including read-only seeds which libvirt
        # may otherwise leave QEMU-owned after shutdown. Preserve AppArmor.
        for source in tree.findall('devices/disk/source'):
            require(not source.findall('seclabel'), 'Unexpected generated disk security label.')
            ET.SubElement(source, 'seclabel', model='dac', relabel='no')
        self.domain_xml(tree, require_dac=True)
        write_new(self.root / 'domain.xml', xml_text(tree))
        virsh('define', str(self.root / 'domain.xml'))
        virsh('start', self.state['uuid'])
        print(f'Open another terminal: virsh -c {URI} console {self.state["uuid"]}\n'
              'Log in as root. Run cloud-init status --wait (must finish successfully), '
              'systemctl is-active ssh.socket, ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub.\n'
              'Retain the fingerprint for first-use trust. Test console recovery, then run poweroff. '
              'Leave console with Ctrl+]. No SSH trust is accepted automatically.', flush=True)
        confirm('Have cloud-init/SSH and console recovery been verified and the guest powered off?')
        self.wait_stopped('Guest must be shut off before baseline creation; shutdown wait timed out.')
        self.resources()
        snapshot = ET.Element('domainsnapshot')
        ET.SubElement(snapshot, 'name').text = 'baseline'
        ET.SubElement(snapshot, 'memory', snapshot='no')
        disks = ET.SubElement(snapshot, 'disks')
        for path, target in self.domain_xml(tree).items():
            ET.SubElement(disks, 'disk', name=target, snapshot='internal' if path == self.disk else 'no')
        write_new(self.root / 'snapshot.xml', xml_text(snapshot))
        virsh('snapshot-create', self.state['uuid'], str(self.root / 'snapshot.xml'))
        require('baseline' in self.snapshots(), 'Baseline verification failed.')
        (self.root / 'home/.ssh').mkdir(mode=0o700, parents=True)
        (self.root / 'home').chmod(0o700)
        (self.root / 'tmp').mkdir(mode=0o700)
        write_new(self.inventory, yaml.safe_dump(self.expected_inventory()))
        # Safe atomic completion; interrupted preparations stay explicitly incomplete.
        self.state['phase'] = 'ready'
        write_new(self.root / 'state.next', json.dumps(self.state))
        os.replace(self.root / 'state.next', self.root / 'state.json')
        virsh('start', self.state['uuid'])
        self.status()

    def wait_stopped(self, message):
        """Observe operator/graceful shutdown only; never force guest termination."""
        deadline = time.monotonic() + 120
        while True:
            state = virsh('domstate', self.state['uuid'])
            if state == 'shut off':
                return
            require(state in ('running', 'in shutdown'), 'Unexpected guest state while waiting for shutdown; STOP.')
            require(time.monotonic() < deadline, message)
            time.sleep(2)

    def stop(self):
        state = virsh('domstate', self.state['uuid'])
        if state == 'running':
            virsh('shutdown', self.state['uuid'])
            self.wait_stopped('VM not stopped; use console to shut down. No forced stop/revert.')
        require(virsh('domstate', self.state['uuid']) == 'shut off', 'VM not stopped; use console to shut down. No forced stop/revert.')

    def reset(self):
        self.ready()
        confirm('Restore owned E2E baseline? All changes in the guest will be lost.')
        self.ready()
        self.stop()
        self.ready()
        self.stopped_disk()
        virsh('snapshot-revert', self.state['uuid'], 'baseline')
        require(virsh('domstate', self.state['uuid']) == 'shut off', 'Unexpected snapshot activation; STOP.')
        self.ready()
        virsh('start', self.state['uuid'])
        print('Baseline restored. Local identities/trust are retained; bootstrap uses the original console password.')

    def delete(self):
        self.load()
        safe_path(self.storage, directory=True, private=False)
        info = self.storage.stat()
        storage_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
        sudo_rmdir = not os.access(self.storage.parent, os.W_OK)
        if sudo_rmdir:
            e2e_host.storage_parents(self.storage)
            require(e2e_host.shutil.which('sudo'), 'sudo unavailable; no deletion attempted.')
        domain, network = self.resources()
        snapshots = self.snapshots() if domain else []
        self.deletion_paths()  # All path checks precede the first mutation.
        self.no_foreign_users()
        confirm('Delete only the owned E2E VM, snapshots, NAT, disks and local fixture files?')
        if sudo_rmdir:
            confirm('Use sudo only to remove the empty dedicated E2E disk directory after deleting owned resources?')
        require((domain, network) == self.resources(), 'Resources changed during confirmation; STOP.')
        self.no_foreign_users()
        if domain:
            self.stop()
            self.resources()
            self.stopped_disk()
            require(snapshots == self.snapshots(), 'Snapshots changed; STOP.')
            for name in reversed(snapshots):
                virsh('snapshot-delete', self.state['uuid'], name)
            virsh('undefine', self.state['uuid'])
        if network:
            active = virsh('net-list', '--uuid').split()
            if self.state['network_uuid'] in active:
                virsh('net-destroy', self.state['network_uuid'])
            virsh('net-undefine', self.state['network_uuid'])
        self.no_foreign_users()
        files, directories = self.deletion_paths()
        # Persistent sibling lock is intentionally retained, like the CLI lock.
        # Retain controller state/ownership evidence until protected storage is
        # removed. The root-owned parent requires sudo even for an owned child.
        for path in files:
            if path.is_relative_to(self.storage):
                path.unlink()
        for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            if path != self.storage and path.is_relative_to(self.storage):
                path.rmdir()
        safe_path(self.storage, directory=True, private=False)
        info = self.storage.stat()
        require(storage_identity == (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
                and not list(self.storage.iterdir()), 'Storage changed during deletion; STOP.')
        self.no_foreign_users()
        if sudo_rmdir:
            e2e_host.storage_parents(self.storage)
            e2e_host.privileged(['rmdir', '--', str(self.storage)], command)
        else:
            self.storage.rmdir()
        require(not self.storage.exists() and not self.storage.is_symlink(), 'Storage removal incomplete; STOP.')
        for path in files:
            if not path.is_relative_to(self.storage) and path != self.root / 'state.json':
                path.unlink()
        for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
            if not path.is_relative_to(self.storage) and path != self.root:
                path.rmdir()
        (self.root / 'state.json').unlink()
        self.root.rmdir()
        print('Owned E2E fixture deleted. No shared libvirt pool or network was removed.')

    def stopped_disk(self):
        """Reject hidden qcow2 backing/data-file dependencies before destructive work."""
        require(virsh('domstate', self.state['uuid']) == 'shut off', 'Disk inspection requires a stopped guest.')
        self.disk_file()
        info = json.loads(command(['qemu-img', 'info', '--output=json', str(self.disk)]))
        require(info.get('format') == 'qcow2' and not info.get('backing-filename')
                and not info.get('full-backing-filename')
                and not info.get('format-specific', {}).get('data', {}).get('data-file'),
                'Unsupported qcow2 backing/data file; no destructive action permitted.')

    def no_foreign_users(self):
        networks = virsh('net-list', '--all', '--uuid').split()
        bridge = None
        if self.state['network_uuid'] in networks:
            tree = parse_xml(virsh('net-dumpxml', self.state['network_uuid']))
            self.network_xml(tree)
            element = tree.find('bridge')
            bridge = element.get('name') if element is not None else None
        for identity in virsh('list', '--all', '--uuid').split():
            if identity == self.state['uuid']:
                continue
            trees = []
            for flags in ((), ('--inactive',)):
                trees.append(parse_xml(virsh('dumpxml', identity, *flags)))
            for name in virsh('snapshot-list', identity, '--name').splitlines():
                trees.append(parse_xml(virsh('snapshot-dumpxml', identity, name)))
            for tree in trees:
                for source in tree.findall('.//source'):
                    for value in source.attrib.values():
                        if value.startswith('/'):
                            require(not Path(value).resolve().is_relative_to(self.storage), 'Another VM uses E2E storage; STOP.')
                    require(source.get('network') != self.name and
                            (not bridge or source.get('bridge') != bridge), 'Another VM uses E2E NAT; STOP.')

    def deletion_paths(self):
        files, directories = [], []
        for root in (self.root, self.storage):
            safe_path(root, directory=True, private=root == self.root)
            directories.append(root)
            for parent, children, names in os.walk(root, followlinks=False):
                for name in children:
                    path = Path(parent) / name
                    safe_path(path, directory=True, private=root == self.root)
                    directories.append(path)
                for name in names:
                    path = Path(parent) / name
                    if root == self.storage and path == self.disk:
                        self.disk_file()
                    else:
                        safe_path(path, private=root == self.root)
                    if root == self.storage:
                        require(path in (self.disk, self.seed), 'Unrecognized storage file; no deletion allowed.')
                    files.append(path)
        return files, directories

    def child_env(self):
        # Do not inherit arbitrary Ansible configuration, inventory, identities or sudo policy.
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'TERM', 'LANG', 'LC_ALL', 'SSH_AUTH_SOCK')}
        env.update(HOME=str(self.root / 'home'), TMPDIR=str(self.root / 'tmp'),
                   PORTFOLIO_E2E_ROOT=str(self.root), INVENTORY=str(self.inventory), AUTOMATION_KEY='',
                   ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_HOME=str(self.root / 'home/.ansible'),
                   HUMAN_USER='e2e_admin', HUMAN_SUDO='admin', HUMAN_GROUPS='', HUMAN_GROUPS_APPROVED='',
                   HUMAN_KEY=str(self.root / 'home/.ssh/human/admin_ed25519'),
                   HUMAN_PUBLIC_KEY=str(self.root / 'home/.ssh/human/admin_ed25519.pub'))
        return env

    def cli(self, mode, frontier=None, unchanged=False):
        self.load()
        self.check_inventory(self.inventory)
        self.ready(running=True)
        env = self.child_env()
        if frontier:
            env['INIT_FROM'] = frontier
        argv = ['make', '--no-print-directory', mode]
        if unchanged:
            convergence_command(argv, env)
        else:
            command(argv, capture=False, timeout=None, env=env)

    def independent(self):
        self.ready(running=True)
        self.check_inventory(self.inventory)
        from .ssh import interactive_ssh_command
        # Use the same strict transport constructor with explicit fixture HOME/trust.
        previous = os.environ.get('HOME')
        os.environ['HOME'] = str(self.root / 'home')
        try:
            key = Path(self.expected_inventory()['all']['children']['bootstrap']['hosts']['e2e']['ansible_private_key_file'])
            argv = interactive_ssh_command(self.ip, 22, 'ansible', key)
        finally:
            if previous is None:
                os.environ.pop('HOME', None)
            else:
                os.environ['HOME'] = previous
        probe = ('test "$(cat /etc/portfolio-e2e-id)" = ' + shlex.quote(self.state['uuid']) +
                 ' && test "$(id -un)" = ansible && sudo -n true'
                 ' && sudo -n systemctl is-active --quiet docker'
                 ' && sudo -n systemctl is-enabled --quiet docker'
                 ' && sudo -n docker info >/dev/null'
                 ' && sudo -n ufw status | head -1 | grep -Fx "Status: active"'
                 ' && sudo -n sshd -T | grep -Fx "passwordauthentication no"'
                 ' && sudo -n sshd -T | grep -Fx "permitrootlogin no"'
                 ' && (sudo -n systemctl is-active --quiet ssh.socket || sudo -n systemctl is-active --quiet ssh.service)'
                 ' && sudo -n systemctl is-active --quiet apt-daily.timer apt-daily-upgrade.timer'
                 ' && sudo -n systemctl is-enabled --quiet apt-daily.timer apt-daily-upgrade.timer'
                 ' && sudo -n systemctl is-active --quiet systemd-journald'
                 ' && cat /proc/sys/kernel/random/boot_id')
        # A remote PTY is unnecessary for noninteractive probes.
        argv.remove('-t')
        output = command(argv + [probe], timeout=90)
        boot = output.strip().splitlines()[-1] if output.strip() else ''
        require(re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot), 'Independent boot ID proof unavailable.')
        print('Independent SSH/sudo/Docker/UFW/systemd/final-policy probe passed.')
        return boot

    def test(self):
        self.load()
        self.check_inventory(self.inventory)
        self.ready(running=True)
        require(sys.stdin.isatty(), 'E2E test is interactive; no automatic confirmations.')
        # Generate the human identity using the existing local-only key workflow.
        env = self.child_env()
        env['AGENT_LOAD'] = 'ask'
        command(['make', '--no-print-directory', 'generate-user-key'], capture=False, timeout=None, env=env)
        frontier = os.environ.get('E2E_FROM', '')
        require(frontier in ('', 'bootstrap', 'docker', 'hardening', 'human', 'ssh', 'operations', 'verify'), 'Invalid E2E_FROM.')
        self.cli('init-server', frontier or None)
        self.cli('init-server', 'verify')
        self.independent()
        confirm('Run convergence again from docker, retaining all existing stage confirmations?')
        self.cli('init-server', 'docker', unchanged=True)
        self.cli('init-server', 'verify')
        before = self.independent()
        self.cli('reboot-host')  # Existing recovery and explicit reboot confirmation remain.
        self.cli('init-server', 'verify')
        after = self.independent()
        require(before != after, 'Reboot did not produce a new independently observed boot ID; STOP.')
        print('E2E passed: installation/verification/repeat changed=0/reboot.')


def configure_child():
    """Called before importing CLI modules; no alternate provisioning implementation."""
    root = Path(os.environ['PORTFOLIO_E2E_ROOT'])
    import pwd
    # HOME belongs to the isolated child, not the operator.
    original_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    expected = original_home / '.local/share/portfolio-e2e'
    require(root == expected, 'Foreign E2E root forbidden.')
    stand = Stand(root)
    stand.ready(running=True)
    require(os.environ.get('HOME') == str(root / 'home'), 'E2E requires isolated HOME.')
    safe_path(root / 'home', directory=True)
    safe_path(root / 'home/.ssh', directory=True)
    safe_path(root / 'tmp', directory=True)
    stand.check_inventory(Path(os.environ.get('INVENTORY', '')))
    # access.py accepts exactly the inventory owned by the stand. Explicit argv
    # checks prevent --inventory/--key overrides before argparse dispatch.
    local = sys.argv[1:] == ['generate-user-key']
    require(local or (len(sys.argv) == 6 and sys.argv[2:4] == ['--inventory', str(stand.inventory)]
            and sys.argv[4:] == ['--key', ''] and sys.argv[1] in ('init-server', 'reboot-host')),
            'Foreign E2E CLI arguments forbidden.')
    env = stand.child_env()
    for name in ('HUMAN_KEY', 'HUMAN_PUBLIC_KEY', 'HUMAN_USER', 'HUMAN_SUDO', 'ANSIBLE_CONFIG', 'TMPDIR'):
        require(os.environ.get(name) == env[name], 'Foreign E2E identity/configuration forbidden.')
    for name in ('INIT_FROM', 'AGENT_LOAD'):
        if name in os.environ:
            env[name] = os.environ[name]
    # Native Ansible and local-key children must not inherit arbitrary injected
    # transport/plugin settings even when this guard is invoked directly.
    os.environ.clear()
    os.environ.update(env)
    trust = root / 'home/.ssh/known_hosts'
    if trust.exists() or trust.is_symlink():
        safe_path(trust)
    common.validate_cli_path(trust)
    option = 'UserKnownHostsFile="' + str(trust).replace('\\', '\\\\').replace('"', '\\"') + '"'
    common.SSH_BASE += ' -o GlobalKnownHostsFile=/dev/null -o ' + shlex.quote(option)


@contextlib.contextmanager
def stand_lock(root):
    # The sibling inode survives delete and serializes the entire test, including children.
    root.parent.mkdir(parents=True, exist_ok=True)
    safe_path(root.parent, directory=True, private=False)
    path = root.parent / '.portfolio-e2e.lock'
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+') as lock:
        safe_path(path)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another E2E operation is running; STOP.') from None
        yield


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=MODES)
    args = parser.parse_args()
    os.umask(0o077)
    stand = Stand()
    phase = 'local prerequisites'
    try:
        require(os.getuid() != 0, 'Run E2E as the controller user, never with sudo.')
        require(not os.environ.get('E2E_INVENTORY'), 'E2E inventory overrides are forbidden.')
        if args.mode == 'list-distros':
            e2e_images.list_distros()
            return 0
        phase = 'fixture lock'
        with stand_lock(stand.root):
            phase = args.mode
            result = getattr(stand, args.mode)()
        if result is e2e_host.PreparationResult.REBOOT_REQUIRED:
            e2e_host.offer_reboot()
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt, EOFError, AttributeError, TypeError) as error:
        reason = error_reason(error)
        print('E2E STOP (' + phase + '): ' + reason + ' '
              'State retained; inspect local VM console and fixture metadata. '
              'No automatic reset/retry. See docs/local-vm-e2e.md.', file=sys.stderr)
        return 1


def error_reason(error):
    """Expose only static reasons and OS categories, never exception payloads."""
    if isinstance(error, E2EError):
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return 'Command timed out; completion is unconfirmed.'
    if isinstance(error, OSError):
        code = errno.errorcode.get(error.errno) if type(error.errno) is int else None
        reasons = {errno.EROFS: 'Filesystem is read-only; check controller sandbox/mount restrictions.',
                   errno.EACCES: 'Permission denied; check controller access restrictions with the administrator.',
                   errno.EPERM: 'Operation not permitted; check controller sandbox/access restrictions.',
                   errno.ENOENT: 'Required local file or executable is missing.'}
        return reasons.get(error.errno, 'Local I/O or process operation failed.') + (f' ({code})' if code else '')
    if isinstance(error, (EOFError, KeyboardInterrupt)):
        return 'Interactive operation cancelled; completion is unconfirmed.'
    return 'Prerequisite or execution failed.'
