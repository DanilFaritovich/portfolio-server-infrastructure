#!/usr/bin/python
"""Fixed gh file contract and exclusive, no-replace publication. No remote download."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import stat

GH_SHA256 = '7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b'
GH_SIZE = 42086560
TARGET = Path('/usr/bin/gh')
STAGED = Path('/usr/bin/.portfolio-gh-2.102.0.pending')
UPLOAD = Path('/usr/bin/.portfolio-gh-2.102.0.upload')
OS_RELEASE = Path('/etc/os-release')


def require(condition, message='Deployment prerequisites safety check failed; STOP and diagnose.'):
    if not condition:
        raise ValueError(message)


def host_check():
    release = dict(line.split('=', 1) for line in OS_RELEASE.read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu'
            and release.get('VERSION_ID', '').strip('"') == '24.04'
            and platform.machine() == 'x86_64', 'Requires Ubuntu 24.04 AMD64.')


def ancestry(path):
    for parent in reversed(path.parents):
        meta = parent.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0
                and meta.st_mode & 0o022 == 0)
        require('system.posix_acl_access' not in os.listxattr(parent, follow_symlinks=False))


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def binary_check(path):
    """O_NOFOLLOW plus descriptor/path snapshots reject swaps and partial reads."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o755 and before.st_nlink == 1
                and before.st_size == GH_SIZE)
        require(not os.listxattr(path, follow_symlinks=False))
        digest = hashlib.sha256()
        remaining = GH_SIZE
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            require(block)
            digest.update(block)
            remaining -= len(block)
        require(not stream.read(1) and digest.hexdigest() == GH_SHA256)
        require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()))
        return identity(before)


def inspect(verify=False, uploading=False):
    host_check()
    ancestry(TARGET)
    require(not os.path.lexists(STAGED), 'Incomplete gh installation; STOP and diagnose pending state.')
    require(uploading or not os.path.lexists(UPLOAD), 'Incomplete gh upload; STOP and diagnose.')
    if not os.path.lexists(TARGET):
        require(not verify, 'Pinned gh is absent; installation requires a confirmed plan.')
        return False
    binary_check(TARGET)
    return True


def install(source=None, verify=False, check=False):
    """Directory flock serializes this narrow installer without creating lock files.

    The stage inode is created exclusively and retained on every failure. link()
    publishes complete validated bytes only if the destination remains absent.
    Unrelated root writers/raw Ansible must still be manually serialized.
    """
    if inspect(verify, uploading=source is not None):
        return False
    if check or verify:
        return True
    if source is None:
        UPLOAD.mkdir(mode=0o700)
        return True
    require(Path(source) == UPLOAD / 'gh')
    meta = UPLOAD.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == meta.st_gid == 0
            and stat.S_IMODE(meta.st_mode) == 0o700 and sorted(p.name for p in UPLOAD.iterdir()) == ['gh'])
    # Ansible's copy stages the controller-verified file privately. Verify again
    # before opening the dedicated pending inode in the protected destination.
    ancestry(Path(source))
    binary_check(Path(source))
    directory = os.open(TARGET.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not inspect(uploading=True))
        descriptor = os.open(STAGED, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            with open(source, 'rb') as incoming:
                remaining = GH_SIZE
                while remaining:
                    block = incoming.read(min(1024 * 1024, remaining))
                    require(block)
                    output.write(block)
                    remaining -= len(block)
                require(not incoming.read(1))
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        binary_check(STAGED)
        ancestry(TARGET)
        require(not os.path.lexists(TARGET))
        os.link(STAGED, TARGET, follow_symlinks=False)
        os.fsync(directory)
        # Both names intentionally share the completed inode only during publish.
        require(STAGED.lstat().st_ino == TARGET.lstat().st_ino and TARGET.lstat().st_nlink == 2)
        STAGED.unlink()
        os.fsync(directory)
        inspect(verify=True, uploading=True)
        Path(source).unlink()
        UPLOAD.rmdir()
        os.fsync(directory)
        inspect(verify=True)
        return True
    finally:
        os.close(directory)


def inspect_stream(params):
    try:
        present = inspect(params.get('verify', False))
        result = dict(ready=True, present=present,
                      report='PASS  deployment prerequisites: pinned gh verified' if present else
                             'PASS  deployment prerequisites: safe absent destination; installation requires consent')
    except (ValueError, OSError):
        result = dict(ready=False, report='FAIL  deployment prerequisites: OS, file contract or pending state; STOP and diagnose')
    print(json.dumps(result))


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec=dict(source=dict(type='path'), verify=dict(type='bool', default=False),
                                             prepare=dict(type='bool', default=False), confirmed=dict(type='bool', default=False)),
                           supports_check_mode=True)
    try:
        if module.params['prepare'] or module.params['source']:
            require(module.params['confirmed'], 'An explicit installation plan is required.')
            changed = install(module.params['source'], check=module.check_mode)
            module.exit_json(changed=changed)
        present = inspect(module.params['verify'])
        module.exit_json(changed=False, present=present)
    except (ValueError, OSError):
        module.fail_json(msg='Deployment prerequisites failed; STOP. Inspect gh metadata, checksum and pending inode through recovery. No automatic replacement or rollback.')


if __name__ == '__main__':
    main()
