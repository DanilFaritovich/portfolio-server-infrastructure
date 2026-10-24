"""Controller-only preparation of one pinned official GitHub CLI release."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import platform
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

from .common import require

GH_VERSION = '2.102.0'
GH_URL = 'https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_linux_amd64.tar.gz'
GH_ARCHIVE_SHA256 = 'bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386'
GH_BINARY_SHA256 = '7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b'
GH_MEMBER = 'gh_2.102.0_linux_amd64/bin/gh'
GH_BINARY_SIZE = 42086560
GH_LIMIT = 64 * 1024 * 1024


class GhRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == 'https' and parsed.hostname == 'release-assets.githubusercontent.com'
                and parsed.port in (None, 443) and not parsed.username and not parsed.password
                and not parsed.fragment, 'Untrusted gh release redirect; STOP.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def gh_download(destination):
    # Unlike cloud images, GitHub assets require a signed CDN redirect. The
    # existing cloud-image downloader deliberately refuses every redirect.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), GhRedirect())
    with opener.open(GH_URL, timeout=60) as response, destination.open('xb') as output:
        total = 0
        while block := response.read(1024 * 1024):
            total += len(block)
            require(total <= GH_LIMIT, 'Oversized gh archive; STOP.')
            output.write(block)
        require(total > 0, 'Empty gh archive; STOP.')


def gh_extract(archive, destination):
    require(archive.stat().st_size <= GH_LIMIT and
            hashlib.sha256(archive.read_bytes()).hexdigest() == GH_ARCHIVE_SHA256,
            'gh archive SHA256 mismatch; STOP.')
    # No extract/extractall: only the exact regular member is ever read, with a
    # decompressed size bound. No archive pathname becomes a filesystem path.
    with tarfile.open(archive, 'r:gz') as bundle:
        selected = None
        for index, member in enumerate(bundle):
            require(index < 4096, 'Oversized gh archive index; STOP.')
            if member.name == GH_MEMBER:
                require(selected is None and member.isfile() and not member.issparse()
                        and member.size == GH_BINARY_SIZE, 'Unsafe gh archive member; STOP.')
                selected = member
        require(selected is not None, 'Missing gh executable; STOP.')
        with bundle.extractfile(selected) as incoming, destination.open('xb') as output:
            digest = hashlib.sha256()
            remaining = GH_BINARY_SIZE
            header = incoming.read(20)
            require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00',
                    'gh executable must be ELF64 AMD64; STOP.')
            output.write(header)
            digest.update(header)
            remaining -= len(header)
            while remaining:
                block = incoming.read(min(1024 * 1024, remaining))
                require(block, 'Truncated gh executable; STOP.')
                output.write(block)
                digest.update(block)
                remaining -= len(block)
            require(not incoming.read(1) and digest.hexdigest() == GH_BINARY_SHA256,
                    'gh binary SHA256 mismatch; STOP.')
            output.flush()
            os.fchmod(output.fileno(), 0o500)
            os.fsync(output.fileno())


@contextmanager
def prepared_gh():
    """Ephemeral, exclusive artifacts: no persistent cache to adopt or repair."""
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'Local gh preparation requires a Linux AMD64 controller.')
    with tempfile.TemporaryDirectory(prefix='portfolio-gh-') as temporary:
        directory = Path(temporary)
        archive, binary = directory / 'release.tar.gz', directory / 'gh'
        gh_download(archive)
        gh_extract(archive, binary)
        version = subprocess.run([str(binary), '--version'], capture_output=True, text=True,
                                 timeout=15, check=True,
                                 env={'PATH': '/usr/bin:/bin', 'HOME': temporary, 'GH_CONFIG_DIR': temporary})
        require(version.stdout.splitlines()[0].startswith('gh version ' + GH_VERSION + ' '),
                'Unexpected gh version; STOP.')
        meta = binary.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                and stat.S_IMODE(meta.st_mode) == 0o500 and meta.st_nlink == 1
                and hashlib.sha256(binary.read_bytes()).hexdigest() == GH_BINARY_SHA256,
                'Prepared gh changed; STOP.')
        yield binary
