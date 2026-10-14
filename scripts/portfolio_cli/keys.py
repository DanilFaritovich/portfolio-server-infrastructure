"""Local key paths, metadata, public identities and locked key preparation."""

from pathlib import Path
import base64
import contextlib
import fcntl
import os
import re
import stat
import subprocess
import sys
import tempfile

from .common import ROOT, require, validate_cli_path


def key_path(value):
    path = Path(value).expanduser().absolute()
    validate_cli_path(path)
    require(not path.resolve().is_relative_to(ROOT), 'Keep automation keys outside the repository.')
    require(not any(part.is_symlink() for part in [path, *path.parents]), 'Key paths must not use symlinks.')
    return path


def check_key(path):
    info = path.parent.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            'Key directory must be owned by you with permissions 0700 or stricter.')
    for item in (path, Path(str(path) + '.pub')):
        require(item.exists() and not item.is_symlink(), 'A complete regular private/public key pair is required.')
        info = item.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and os.access(item, os.R_OK),
                'Key files must be readable regular files owned by the current controller user.')
    require(path.stat().st_mode & 0o077 == 0, 'Private key permissions must be 0600 or stricter.')


def prepare_key(path, label='automation', interactive_passphrase=False):
    """Only inspect private-key metadata; ssh-keygen creates new material locally."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            'Key directory must be owned by you with permissions 0700 or stricter.')
    # Serialize concurrent wrapper runs before checking/creating the pair.
    descriptor = os.open(path.parent / '.bootstrap-key.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        public = Path(str(path) + '.pub')
        require(not path.is_symlink() and not public.is_symlink(), 'Key files must not be symlinks.')
        created = not path.exists() and not public.exists()
        if created:
            if interactive_passphrase:
                require(sys.stdin.isatty(), 'New user key generation requires a terminal for the passphrase prompt.')
            command = ['ssh-keygen', '-q', '-t', 'ed25519', '-C',
                       'portfolio-server-infrastructure ' + label, '-f', str(path)]
            if not interactive_passphrase:
                command.extend(['-N', ''])
            subprocess.run(command, check=True)
            print(f'Dedicated {label} key created locally' +
                  ('.' if interactive_passphrase else ' (without passphrase).'))
        else:
            print(f'Existing {label} key preserved.')
        check_key(path)
        return created


def human_key_path(value, name, key_name=None, public_only=False):
    if key_name:
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}', key_name) and not key_name.endswith('.pub'),
                'KEY_NAME must be a simple private-key filename, without directories or a .pub suffix.')
    path = Path(value or Path.home() / '.ssh/portfolio-infra' / (key_name or name + '_ed25519')).expanduser().absolute()
    validate_cli_path(path)
    inspected = Path(str(path) + '.pub') if public_only else path
    require(not any(p.is_symlink() for p in [inspected, *inspected.parents]), 'Human key paths must not use symlinks.')
    require(not inspected.resolve().is_relative_to(ROOT) or
            inspected.resolve().is_relative_to(ROOT / 'secrets/portfolio-infra'),
            'Repository human keys are allowed only under secrets/portfolio-infra/.')
    return path


def public_key_file(value):
    path = Path(value).expanduser().absolute()
    require(path.suffix == '.pub' and not any(p.is_symlink() for p in [path, *path.parents]),
            'Import a regular .pub file without symlinks.')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= 16384,
            'Public key must be a small regular file owned by you.')
    require(info.st_mode & 0o022 == 0, 'Public key must not be writable by group or others.')
    content = read_public_key(path)
    validate_public_key_text(content)
    result = subprocess.run(['ssh-keygen', '-l', '-f', str(path)], capture_output=True, check=False)
    require(result.returncode == 0, 'Public key is invalid.')
    return path


def validate_public_key_text(content):
    require(len(content.encode('utf-8')) <= 16384, 'Public key must be small plain text.')
    content = content.strip()
    require(len(content.splitlines()) == 1 and re.fullmatch(
        r'(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,3}( [^\r\n]*)?', content),
        'Import exactly one plain OpenSSH public key without authorized_keys options.')


def read_public_key(path):
    try:
        with path.open(encoding='utf-8', newline='') as source:
            return source.read()
    except UnicodeError:
        raise ValueError('Public key must be UTF-8 plain text.') from None


def public_key_identity(public):
    """Validate public material only; comments and file paths do not identify a key."""
    kind, encoded = read_public_key(public_key_file(public)).split()[:2]
    return kind, base64.b64decode(encoded, validate=True)


def require_independent_key(public, controller_key, message):
    require(public_key_identity(public) != public_key_identity(str(controller_key) + '.pub'), message)


def public_fingerprint(public):
    result = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(public)],
                            capture_output=True, text=True, check=True)
    fields = result.stdout.split()
    require(len(fields) >= 2 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', fields[1]),
            'Cannot determine the public-key SHA256 fingerprint.')
    return fields[1]


def prepare_human_key(key, name, interactive_passphrase=False):
    if key.is_relative_to(ROOT):
        for directory in (ROOT / 'secrets', ROOT / 'secrets/portfolio-infra'):
            directory.mkdir(mode=0o700, exist_ok=True)
            require(directory.stat().st_uid == os.getuid() and directory.stat().st_mode & 0o077 == 0,
                    'Local secrets directories must be owned by you with permissions 0700.')
    if interactive_passphrase:
        return prepare_key(key, label='human ' + name, interactive_passphrase=True)
    else:
        return prepare_key(key, label='human ' + name)


@contextlib.contextmanager
def public_key_snapshot(content):
    validate_public_key_text(content)
    with tempfile.TemporaryDirectory(prefix='portfolio-public-') as directory:
        public = Path(directory) / 'key.pub'
        with open(public, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
            output.write(content)
        yield public_key_file(str(public))
