#!/usr/bin/python
"""Own exactly /swapfile; stage replacements and stop on partial activation."""

DOCUMENTATION = r'''
---
module: portfolio_swap
short_description: Safely manage or independently verify the owned swapfile
description:
  - Refuses unmanaged files, unsafe metadata, pending state and conflicting configuration.
  - Disabling preserves the file; resizing stages a fully allocated replacement.
options:
  size_mb:
    description: Desired size in MiB, zero disables without deleting the file.
    type: int
    required: true
  verify:
    description: Independently verify without configuration changes.
    type: bool
    default: false
author: Portfolio infrastructure maintainers
'''
EXAMPLES = r'''
- name: Manage owned swap
  portfolio_swap:
    size_mb: 2048
  become: true
'''
RETURN = r'''
changed:
  description: Whether managed state changed or would change in check mode.
  type: bool
  returned: always
'''

import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid

from ansible.module_utils.basic import AnsibleModule

SWAP = Path('/swapfile')
FSTAB = Path('/etc/fstab')
STATE = Path('/var/lib/portfolio-swap')
LINE = '/swapfile none swap sw 0 0 # portfolio-swap\n'
MIB = 1024 * 1024
RESERVE = 256 * MIB


def require(value, message):
    if not value:
        raise ValueError(message + '; STOP and diagnose before retrying.')


def metadata(path, mode):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe swap parent path')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1,
            'Unsafe swap file metadata')
    return info


def file_identity(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    require(result.returncode == 0, 'Swap command failed')
    return result.stdout.strip()


def active_swap():
    rows = Path('/proc/swaps').read_text().splitlines()
    require(rows and rows[0].split() == ['Filename', 'Type', 'Size', 'Used', 'Priority'],
            'Unsupported kernel swap table')
    result = None
    for row in rows[1:]:
        fields = row.split()
        require(len(fields) == 5, 'Invalid kernel swap entry')
        if fields[0] == str(SWAP):
            require(result is None and fields[1] == 'file', 'Conflicting active swap')
            result = [int(fields[2]) * 1024, int(fields[3]) * 1024]
        elif SWAP.exists():
            # Alias paths must never evade ownership/active-file checks.
            require(not Path(fields[0]).exists() or not os.path.samefile(fields[0], SWAP),
                    'Swapfile is active through an unmanaged alias')
    return result


def memory_available():
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    value = values.get('MemAvailable', '').split()
    require(len(value) == 2 and value[1] == 'kB', 'MemAvailable unavailable')
    return int(value[0]) * 1024


def trusted_state_parent():
    for parent in STATE.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe swap state parent')


def snapshot(size, *, activating=False):
    require(type(size) is int and 0 <= size <= 1048576, 'swap_size_mb must be an integer from 0 to 1048576')
    trusted_state_parent()
    require(not STATE.is_symlink(), 'Unsafe swap state directory')
    receipt = None
    if STATE.exists():
        info = STATE.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe swap state directory')
        require(set(p.name for p in STATE.iterdir()) <= {'receipt.json', 'pending'}, 'Unknown swap state files')
        require(activating or (not (STATE / 'pending').exists() and not (STATE / 'pending').is_symlink()),
                'Pending swap activation')
        if activating:
            metadata(STATE / 'pending', 0o600)
        path = STATE / 'receipt.json'
        if path.exists() or path.is_symlink():
            require(metadata(path, 0o600).st_size < 4096, 'Oversized swap receipt')
            receipt = json.loads(path.read_text())
            require(set(receipt) == {'schema', 'identity', 'uuid'} and receipt['schema'] == 1
                    and str(uuid.UUID(receipt['uuid'])) == receipt['uuid'], 'Invalid swap receipt')
    info = None
    if SWAP.exists() or SWAP.is_symlink():
        info = metadata(SWAP, 0o600)
        require(run(['findmnt', '-n', '-o', 'TARGET', '--target', str(SWAP)]) != str(SWAP), 'Swapfile is a mountpoint')
        require(receipt is not None and receipt['identity'] == file_identity(info), 'Unmanaged or changed /swapfile')
        require(run(['blkid', '-p', '-s', 'TYPE', '-o', 'value', str(SWAP)]) == 'swap'
                and run(['blkid', '-p', '-s', 'UUID', '-o', 'value', str(SWAP)]) == receipt['uuid'],
                'Swap signature differs from receipt')
        require(info.st_size >= MIB and info.st_blocks * 512 >= info.st_size, 'Sparse or invalid swapfile')
    else:
        require(receipt is None, 'Owned swapfile is missing')
    metadata(FSTAB, 0o644)
    require(run(['findmnt', '-n', '-o', 'TARGET', '--target', str(FSTAB)]) != str(FSTAB), 'fstab is a mountpoint')
    fstab = FSTAB.read_bytes().decode('utf-8')
    require(len(fstab) <= 1024 * 1024, 'Oversized fstab')
    own_lines = 0
    for line in fstab.splitlines(keepends=True):
        fields = line.split('#', 1)[0].split()
        if not fields:
            continue
        source = fields[0]
        alias = source.startswith('/') and Path(source).exists() and SWAP.exists() and os.path.samefile(source, SWAP)
        if source == str(SWAP) or alias or (receipt and receipt['uuid'] in source):
            require(receipt is not None and line == LINE, 'Unmanaged swapfile fstab entry')
            own_lines += 1
    require(own_lines <= 1, 'Duplicate swapfile fstab entry')
    unit = run(['systemctl', 'show', 'swapfile.swap', '--property=FragmentPath', '--value'])
    require(not unit or unit in ('/run/systemd/generator/swapfile.swap',
                                '/run/systemd/generator.early/swapfile.swap',
                                '/run/systemd/generator.late/swapfile.swap'), 'Custom swapfile unit')
    require(not run(['systemctl', 'show', 'swapfile.swap', '--property=DropInPaths', '--value']),
            'Custom swapfile unit overrides')
    active = active_swap()
    require(info is not None or active is None, 'Active swap has no owned file')
    if active:
        require(active[0] == info.st_size - os.sysconf('SC_PAGE_SIZE'), 'Active swap size differs')
    desired = ''.join(line for line in fstab.splitlines(keepends=True) if line != LINE)
    if size:
        desired += ('' if not desired or desired.endswith('\n') else '\n') + LINE
    # Preserve the exact existing fstab when it already contains the managed line.
    if bool(own_lines) == bool(size):
        desired = fstab
    resize = bool(size) and (info is None or info.st_size != size * MIB)
    change = resize or bool(active) != bool(size) or desired != fstab
    return dict(receipt=receipt, identity=file_identity(info) if info else None,
                active=active, fstab=fstab, fstab_identity=file_identity(FSTAB.lstat()),
                desired=desired, resize=resize, change=change)


def capacity(before, size, staged=False):
    if before['active'] and (not size or before['resize']):
        require(memory_available() >= before['active'][1] + RESERVE, 'Insufficient RAM to safely swapoff')
    for path in (SWAP.parent, FSTAB.parent, STATE.parent):
        storage = os.statvfs(path)
        require(not storage.f_flag & os.ST_RDONLY, 'Read-only swap/configuration filesystem')
        require(storage.f_bavail * storage.f_frsize >= len(before['desired'].encode()) + MIB,
                'Insufficient disk space for atomic swap configuration and evidence')
    if before['resize']:
        require(run(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(SWAP.parent)]) in ('ext4', 'xfs'),
                'Unsupported swap filesystem')
        free = os.statvfs(SWAP.parent)
        require(free.f_bavail * free.f_frsize >= (0 if staged else size * MIB) + RESERVE,
                'Insufficient disk space for a complete staged swapfile and reserve')


def atomic(path, content, mode):
    descriptor, name = tempfile.mkstemp(prefix='.portfolio-swap-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def apply_swap(size, verify=False, check=False):
    before = snapshot(size)
    if verify:
        require(not before['change'], 'Swap size, activity or fstab differs from inventory')
        return False
    if not before['change']:
        return False
    capacity(before, size)
    if check:
        return True
    if not STATE.exists():
        STATE.mkdir(mode=0o700)
        sync_directory(STATE.parent)
    # Lock the directory inode: verification never creates lock files. The CLI
    # additionally serializes all stages; raw root changes require manual exclusion.
    descriptor = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(snapshot(size) == before, 'Swap state changed during preflight')
        capacity(before, size)
        with (STATE / 'pending').open('x') as marker:
            os.fchmod(marker.fileno(), 0o600)
            marker.write('Swap activation incomplete; diagnose through recovery.\n')
            marker.flush()
            os.fsync(marker.fileno())
        sync_directory(STATE)
        staged = None
        if before['resize']:
            stage_descriptor, name = tempfile.mkstemp(prefix='.portfolio-swap-', dir=SWAP.parent)
            staged = Path(name)
            with os.fdopen(stage_descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                block = bytes(MIB)
                for _ in range(size):
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
            new_uuid = str(uuid.uuid4())
            run(['mkswap', '--uuid', new_uuid, str(staged)])
            require(run(['blkid', '-p', '-s', 'TYPE', '-o', 'value', str(staged)]) == 'swap'
                    and run(['blkid', '-p', '-s', 'UUID', '-o', 'value', str(staged)]) == new_uuid,
                    'Staged swap signature invalid')
            require(metadata(staged, 0o600).st_blocks * 512 >= size * MIB, 'Staged swapfile has holes')
            with staged.open('rb') as stream:
                os.fsync(stream.fileno())
        # Recheck immediately before stopping the old swap; swapoff itself may
        # refuse if memory changes. Never replace an active file on failure.
        require(active_swap() == before['active'] and FSTAB.read_bytes().decode('utf-8') == before['fstab']
                and file_identity(FSTAB.lstat()) == before['fstab_identity']
                and (file_identity(SWAP.lstat()) if SWAP.exists() else None) == before['identity'],
                'Concurrent swap or fstab change')
        require((json.loads((STATE / 'receipt.json').read_text()) if (STATE / 'receipt.json').exists() else None)
                == before['receipt'], 'Concurrent swap ownership change')
        capacity(before, size, staged=staged is not None)
        if before['active'] and (not size or before['resize']):
            run(['swapoff', str(SWAP)])
            require(active_swap() is None, 'Swapfile remains active')
        if staged:
            os.replace(staged, SWAP)
            sync_directory(SWAP.parent)
            receipt = dict(schema=1, identity=file_identity(SWAP.lstat()), uuid=new_uuid)
            atomic(STATE / 'receipt.json', json.dumps(receipt) + '\n', 0o600)
        if before['desired'] != before['fstab']:
            require(FSTAB.read_bytes().decode('utf-8') == before['fstab'] and file_identity(FSTAB.lstat()) == before['fstab_identity'],
                    'Concurrent fstab change')
            atomic(FSTAB, before['desired'], 0o644)
            run(['systemctl', 'daemon-reload'])
        if size and active_swap() is None:
            run(['swapon', str(SWAP)])
        require(bool(active_swap()) == bool(size), 'Swap activation differs')
        # Pending evidence is cleared only after independent complete inspection.
        # The dedicated activation check retains the marker throughout.
        pending = STATE / 'pending'
        verify_final(size)
        pending.unlink()
        sync_directory(STATE)
        return True
    finally:
        os.close(descriptor)


def verify_final(size):
    """Reuse the complete inspector while retaining pending evidence under lock."""
    require(not snapshot(size, activating=True)['change'], 'Final swap state mismatch')


def main():
    module = AnsibleModule(argument_spec=dict(size_mb=dict(type='int', required=True),
                                             verify=dict(type='bool', default=False)), supports_check_mode=True)
    try:
        changed = apply_swap(module.params['size_mb'], module.params['verify'], module.check_mode)
        module.exit_json(changed=changed)
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
        module.fail_json(msg='SWAP safety/verification failed; STOP. Inspect RAM, disk, ownership, fstab, units and pending state through recovery; no blind retry.')


if __name__ == '__main__':
    main()
