"""Public-material clipboard selection and explicitly confirmed tool installation."""

import os
import platform
import shutil
import subprocess
import sys

from .common import require
from .keys import public_fingerprint, public_key_snapshot, read_public_key


def clipboard_command(fallback='show-public-key'):
    """Select a desktop backend; install only after explicit terminal consent."""
    candidates = []
    if sys.platform == 'darwin':
        candidates.append(('pbcopy', ['pbcopy']))
    elif sys.platform.startswith('linux'):
        if os.environ.get('WAYLAND_DISPLAY'):
            candidates.append(('wl-copy', ['wl-copy']))
        if os.environ.get('DISPLAY'):
            candidates.extend([('xclip', ['xclip', '-selection', 'clipboard']),
                               ('xsel', ['xsel', '--clipboard', '--input'])])
    else:
        raise ValueError(f'Clipboard is unsupported on this OS; use make {fallback}.')
    require(candidates, f'No graphical clipboard session (headless environment); use make {fallback}.')
    command = next((argv for tool, argv in candidates if shutil.which(tool)), None)
    if command:
        return command
    require(sys.platform != 'darwin', f'Built-in pbcopy not found; use make {fallback}.')
    package = 'wl-clipboard' if candidates[0][0] == 'wl-copy' else 'xclip'
    require(sys.stdin.isatty(), 'Clipboard utility not found. Required package: ' + package +
            f'. Non-interactive mode: install it manually or use make {fallback}.')
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        release = {}
    distributions = {release.get('ID', ''), *release.get('ID_LIKE', '').split()}
    require(distributions & {'ubuntu', 'debian'} and shutil.which('apt-get'),
            'Automatic clipboard installation requires Ubuntu/Debian with APT; '
            'install ' + package + f' manually or use make {fallback}.')
    installer = ['apt-get', 'install', '-y', package]
    if os.geteuid() != 0:
        require(shutil.which('sudo'), 'Clipboard installation requires sudo; '
                'install ' + package + f' manually or use make {fallback}.')
        installer.insert(0, 'sudo')
    print('Clipboard utility not found.\nRequired package: ' + package + '\n')
    try:
        answer = input('Install now? [Y/n]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise ValueError('Clipboard installation cancelled; data was not copied.') from None
    require(answer in ('', 'y', 'yes'), 'Clipboard installation declined; data was not copied.')
    try:
        result = subprocess.run(installer, check=False, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Clipboard installation failed; data was not copied. '
                         'Install ' + package + f' manually or use make {fallback}.') from None
    require(result.returncode == 0, 'Clipboard installation failed; data was not copied. '
            'Install ' + package + f' manually or use make {fallback}.')
    command = next((argv for tool, argv in candidates if shutil.which(tool)), None)
    require(command, 'Clipboard utility is still unavailable after installation; data was not copied. '
            f'Use make {fallback}.')
    return command


def copy_clipboard(content, fallback='show-public-key'):
    command = clipboard_command(fallback)
    try:
        # Clipboard owners may outlive their launcher; do not leave output pipes
        # open in a background owner while communicate waits for EOF.
        result = subprocess.run(command, input=content.encode('utf-8'), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Clipboard copy failed; check the desktop session and clipboard utility.') from None
    require(result.returncode == 0, 'Clipboard copy failed; check the desktop session and clipboard utility.')


def copy_public_key(public):
    content = read_public_key(public)
    with public_key_snapshot(content) as snapshot:
        selected = public_fingerprint(snapshot)
    copy_clipboard(content)
    print('Public SSH key copied to clipboard.\nSHA256 fingerprint: ' + selected)
