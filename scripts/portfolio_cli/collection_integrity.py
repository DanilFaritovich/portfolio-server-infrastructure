"""Read-only verification of pinned collection contents, including restored caches."""

import hashlib
import json
import os
from pathlib import Path
import stat

import yaml


def collection_require(condition):
    if not condition:
        raise ValueError('Pinned collection integrity failed; inspect the local dependency tree before retrying.')


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_collection_path(path, directory=False, parent=False):
    meta = path.lstat()
    collection_require((stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode))
                       and meta.st_uid == os.getuid() and meta.st_mode & (0o002 if parent else 0o022) == 0
                       and (directory or meta.st_nlink == 1) and (directory or meta.st_size <= 2 * 1024 * 1024))


def check_collections(root):
    """Anchor both metadata and all installed file bytes in the committed lock.

    Cache hits never grant readiness. No cache repair, imports from cached code,
    network requests, private inputs or managed-host contact occur here.
    """
    root = Path(root)
    requirements = yaml.safe_load((root / 'collections.yml').read_text())['collections']
    lock = json.loads((root / 'collections.lock.json').read_text())
    collection_require(lock['schema'] == 1 and len(requirements) == len(lock['collections']))
    for requirement in requirements:
        name = requirement['name']
        expected = lock['collections'][name]
        collection_require(requirement['version'] == expected['version'] and requirement['type'] == 'git'
                           and requirement['source'] == expected['source'])
        parts = name.split('.')
        collection_require(len(parts) == 2 and all(part.isidentifier() for part in parts))
        path = root
        for part in ('.ansible', 'collections', 'ansible_collections', *parts):
            path /= part
            safe_collection_path(path, directory=True, parent=part != parts[-1])
        files, links, total, visited = {}, {}, 0, 0
        for entry in path.rglob('*'):
            visited += 1
            collection_require(visited <= 1024)
            meta = entry.lstat()
            directory = stat.S_ISDIR(meta.st_mode)
            relative = entry.relative_to(path).as_posix()
            if stat.S_ISLNK(meta.st_mode):
                # The official release contains ten test-runner links. Only
                # those exact locked relative targets may be dereferenced.
                target = os.readlink(entry)
                collection_require(expected.get('symlinks', {}).get(relative) == target
                                   and meta.st_uid == os.getuid() and meta.st_nlink == 1)
                resolved = entry.resolve(strict=True)
                collection_require(resolved.is_relative_to(path))
                safe_collection_path(resolved)
                links[relative] = target
            else:
                safe_collection_path(entry, directory=directory)
            if directory:
                continue
            total += entry.stat().st_size
            collection_require(total <= 16 * 1024 * 1024)
            if relative not in ('MANIFEST.json', 'FILES.json'):
                files[relative] = hashlib.sha256(entry.read_bytes()).hexdigest()
        collection_require(links == expected.get('symlinks', {}))
        collection_require(canonical_hash(sorted(files.items())) == expected['tree_sha256'])
        manifest = json.loads((path / 'MANIFEST.json').read_text())
        collection_require(canonical_hash(manifest['collection_info']) == expected['metadata_sha256'])
        file_manifest = (path / 'FILES.json').read_bytes()
        collection_require(manifest['format'] == 1 and manifest['file_manifest_file'] == {
            'name': 'FILES.json', 'ftype': 'file', 'format': 1, 'chksum_type': 'sha256',
            'chksum_sha256': hashlib.sha256(file_manifest).hexdigest(),
        })
        records = json.loads(file_manifest)['files']
        collection_require(all(record['ftype'] in ('file', 'dir') for record in records)
                           and len({record['name'] for record in records}) == len(records))
        collection_require({record['name']: record['chksum_sha256'] for record in records
                            if record['ftype'] == 'file'} == files)
