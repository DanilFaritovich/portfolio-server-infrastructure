"""Capability-based Linux controller preparation; never VM creation."""

from enum import Enum
import grp
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

from .e2e_images import require

TOOLS = {'virsh': 'libvirt-clients', 'virt-install': 'virtinst', 'qemu-img': 'qemu-utils',
         'cloud-localds': 'cloud-image-utils', 'openssl': 'openssl', 'ssh-keygen': 'openssh-client',
         'ssh': 'openssh-client', 'ip': 'iproute2', 'qemu-system-x86_64': 'qemu-system-x86'}
PACKAGES = tuple(sorted(set(TOOLS.values()) | {'libvirt-daemon-system'}))


class PreparationResult(Enum):
    READY = 'ready'
    REBOOT_REQUIRED = 'reboot-required'


def offer_reboot():
    """Offer a normal local system restart after verified group configuration."""
    print('✓ Host permissions configured successfully.\n'
          'A system restart is required to activate new permissions.')
    later = 'Restart the system manually when ready. After rebooting, run: make e2e-prepare'
    if not sys.stdin.isatty():
        print(later)
        return
    print('\n[1] Reboot now (recommended)\n[2] Reboot later\n')
    try:
        while True:
            choice = input('Choose [1/2]: ').strip()
            if choice in ('', '2'):
                print(later)
                return
            if choice == '1':
                break
            print('Choose 1 or 2; press Enter to reboot later.')
        print('After rebooting, run: make e2e-prepare')
        print('Save your work first: rebooting may lose unsaved data.')
        if input('Reboot this system now? [y/N] ').strip().lower() not in ('y', 'yes'):
            print(later)
            return
    except (EOFError, KeyboardInterrupt):
        print('\n' + later)
        return
    executable = shutil.which('systemctl')
    if (not executable or os.getuid() == 0
            or any(os.environ.get(name) for name in ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY'))):
        print('Automatic reboot is unavailable for this session. ' + later)
        return
    try:
        # Captured output is non-interactive: explicitly respect inhibitors.
        # Keep system authorization; never use sudo, force, fallback or retry.
        result = subprocess.run([executable, '--check-inhibitors=yes', '--no-ask-password', 'reboot'],
                                capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            print('Automatic reboot is unavailable. ' + later)
        else:
            print('Reboot requested. If the system does not restart, ' + later)
    except (OSError, subprocess.SubprocessError, KeyboardInterrupt):
        print('Automatic reboot could not be confirmed; inspect system state before any manual retry. ' + later)


def supported_host():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'E2E requires a Linux x86_64 host with working KVM/libvirt; software emulation is unsupported.')


def package_manager():
    """Select a reviewed package mapping; OS release numbers are irrelevant."""
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return None
    # Do not infer package compatibility from ID_LIKE or an apt binary alone.
    if release.get('ID') in ('ubuntu', 'debian') and all(
            shutil.which(tool) for tool in ('apt-get', 'dpkg-query')):
        return 'apt'
    return None


def dependency_plan():
    """Prepared hosts need no supported installer; missing tools fail closed."""
    manager = package_manager()
    if manager == 'apt':
        return missing_packages()
    absent = [tool for tool in TOOLS if not shutil.which(tool)]
    if absent:
        print('Missing E2E host tools: ' + ', '.join(absent))
    require(not absent, 'Automatic dependency installation is unavailable for this package manager/environment. '
            'Install QEMU/KVM, system libvirt, virt-install, qemu-img, cloud-localds, OpenSSH, OpenSSL and iproute2 '
            'manually using your distribution packages, then rerun make e2e-prepare. No sudo/install attempted.')
    return []


def missing_packages():
    require(shutil.which('dpkg-query'), 'dpkg-query unavailable; prepare host dependencies manually.')
    missing = set()
    for package in PACKAGES:
        result = subprocess.run(['dpkg-query', '-W', '-f=${Status}', package], text=True,
                                capture_output=True, timeout=30, check=False)
        require(result.returncode in (0, 1), 'Package query failed; no installation attempted.')
        if result.returncode == 1 or result.stdout.strip() != 'install ok installed':
            missing.add(package)
    absent = [tool for tool in TOOLS if not shutil.which(tool)]
    if absent:
        print('Missing E2E host tools: ' + ', '.join(absent))
    require(all(TOOLS[tool] in missing for tool in absent),
            'Installed E2E package has a missing executable; repair PATH/package manually, no reinstall.')
    return sorted(missing)


def privileged(argv, command):
    require(shutil.which('sudo'), 'sudo unavailable; ask the host administrator to perform the displayed preparation.')
    # Native sudo prompt/output belongs to the terminal, never a hidden password pipe.
    command(['sudo', '--', *argv], capture=False, timeout=None)


def qemu_group():
    config = Path('/etc/libvirt/qemu.conf')
    require(config.is_file() and not config.is_symlink(), 'Inspect missing/unsafe libvirt qemu.conf manually.')
    info = config.stat()
    require(info.st_uid == 0 and info.st_mode & 0o022 == 0, 'Unsafe libvirt qemu.conf; inspect manually.')
    text = config.read_text()
    for field in ('user', 'group'):
        values = re.findall(r'^\s*' + field + r'\s*=\s*(.*?)\s*(?:#.*)?$', text, re.M)
        require(not values or values == ['"libvirt-qemu"'],
                'Custom QEMU user/group configuration; prepare disk access manually.')
    return grp.getgrnam('libvirt-qemu').gr_gid


def storage_parents(storage):
    require(storage == Path('/var/lib/libvirt/images') / f'portfolio-e2e-{os.getuid()}', 'Foreign E2E storage path.')
    for parent in storage.parents:
        require(not parent.is_symlink() and parent.is_dir(), 'Unsafe/missing E2E storage parent; inspect manually.')
        info = parent.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0
                and os.access(parent, os.X_OK), 'E2E storage parents require protected root ownership and traversal.')


def prepare(storage, *, command, confirm, safe_path):
    require(os.getuid() != 0, 'Run E2E as the controller user, never with sudo.')
    supported_host()
    require(re.search(r'\b(vmx|svm)\b', Path('/proc/cpuinfo').read_text()),
            'CPU virtualization flags unavailable; enable hardware virtualization before installing E2E dependencies.')
    missing = dependency_plan()
    if missing:
        print('Missing E2E host packages: ' + ', '.join(missing))
        print('Privileged plan: apt-get update; apt-get install --no-install-recommends --no-upgrade --no-remove ' + ' '.join(missing))
        confirm('Install only these missing E2E host dependencies using sudo/apt?')
        privileged(['apt-get', 'update'], command)
        privileged(['apt-get', 'install', '--no-install-recommends', '--no-upgrade', '--no-remove', *missing], command)
        require(not dependency_plan(), 'E2E packages/tools still unavailable after apt; STOP, no automatic retry.')
    kvm = Path('/dev/kvm')
    require(kvm.exists() and stat.S_ISCHR(kvm.stat().st_mode),
            'KVM unavailable; enable hardware virtualization/KVM manually. Software emulation is unsupported.')
    account = pwd.getpwuid(os.getuid())
    require(re.fullmatch(r'[a-z_][a-z0-9_-]*\$?', account.pw_name), 'Unsupported controller account name.')
    required_groups = {name: grp.getgrnam(name) for name in ('libvirt', 'kvm')}
    effective = set(os.getgroups()) | {os.getgid()}
    pending = [name for name, group in required_groups.items() if group.gr_gid not in effective]
    additions = [name for name in pending if account.pw_name not in required_groups[name].gr_mem
                 and required_groups[name].gr_gid != account.pw_gid]
    if additions:
        print('Privileged plan: add controller to groups ' + ', '.join(additions)
              + '. libvirt access is root-equivalent; only trusted administrators should receive it.')
        confirm('Grant these libvirt/KVM host permissions using sudo?')
        privileged(['usermod', '-aG', ','.join(additions), '--', account.pw_name], command)
    if pending:
        # Successful usermod alone is insufficient evidence of configured membership.
        configured = {name: grp.getgrnam(name) for name in pending}
        require(all(account.pw_name in group.gr_mem or group.gr_gid == account.pw_gid
                    for group in configured.values()),
                'Host group permissions were not configured; inspect manually, no automatic retry.')
        return PreparationResult.REBOOT_REQUIRED
    require(os.access(kvm, os.R_OK | os.W_OK), 'No read/write KVM access; inspect device ACLs/permissions manually.')
    # Failure is not absence and must not trigger service/polkit configuration changes.
    command(['virsh', '--connect', 'qemu:///system', 'list', '--all', '--uuid'])
    capabilities = ET.fromstring(command(['virsh', '--connect', 'qemu:///system', 'capabilities']))
    require(capabilities.find("guest/arch[@name='x86_64']/domain[@type='kvm']") is not None,
            'libvirt does not advertise x86_64 KVM; inspect host configuration manually.')
    gid = qemu_group()
    storage_parents(storage)
    if not storage.exists() and not storage.is_symlink():
        print(f'Privileged plan: create only {storage}, owner UID={os.getuid()}, QEMU GID={gid}, mode=2750.')
        confirm('Create the new dedicated E2E disk directory using sudo?')
        storage_parents(storage)
        # mkdir is exclusive: a concurrently appearing directory fails without changing it.
        privileged(['mkdir', '-m', '2750', '--', str(storage)], command)
        require(not storage.is_symlink() and storage.is_dir() and storage.stat().st_uid == 0,
                'Disk directory changed during creation; STOP.')
        privileged(['chown', '--no-dereference', f'{os.getuid()}:{gid}', '--', str(storage)], command)
        # chown may clear setgid; owner performs the final mode change after validation.
        safe_path(storage, directory=True, private=False)
        storage.chmod(0o2750)
    safe_path(storage, directory=True, private=False)
    info = storage.stat()
    require(info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o2750
            and os.access(storage, os.R_OK | os.W_OK | os.X_OK),
            'Existing disk directory has incompatible QEMU group/mode/access; inspect manually, no chmod/chown repair.')

    return PreparationResult.READY
