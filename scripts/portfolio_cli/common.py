"""Repository paths, transport policy constants and shared validation guards."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


DEFAULT_KEY = Path.home() / '.ssh/portfolio-server-infrastructure/ansible_ed25519'


PASSWORD_CONNECTION = 'portfolio_password'


SSH_BASE = ('-F /dev/null -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none'
            ' -o ConnectTimeout=15 -o ForwardAgent=no -o ClearAllForwardings=yes'
            ' -o PermitLocalCommand=no -o UpdateHostKeys=no')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_cli_path(path):
    # OpenSSH expands tokens in identity/trust paths even when argv bypasses a shell.
    value = str(path)
    require(all(ord(char) >= 32 and ord(char) != 127 for char in value) and
            '%' not in value and '${' not in value,
            'SSH paths must not contain control characters or OpenSSH expansion tokens.')
