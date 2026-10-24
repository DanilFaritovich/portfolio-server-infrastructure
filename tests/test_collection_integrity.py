"""Offline dependency-lock/cache integrity checks; no registry or Git access."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_cli_package import load_access
from portfolio_cli.collection_integrity import canonical_hash, check_collections

ROOT = Path(__file__).resolve().parents[1]


class CollectionIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.collection = self.root / '.ansible/collections/ansible_collections/ansible/posix'
        self.collection.mkdir(parents=True)
        self.collection.chmod(0o755)
        self.module = self.collection / 'module.py'
        self.module.write_text('# synthetic collection module\n')
        self.module.chmod(0o644)
        self.files = {'module.py': hashlib.sha256(self.module.read_bytes()).hexdigest()}
        self.info = {'name': 'posix', 'namespace': 'ansible', 'version': '2.0.0', 'dependencies': {}}
        files = {'files': [{'name': '.', 'ftype': 'dir'},
                           {'name': 'module.py', 'ftype': 'file', 'chksum_sha256': self.files['module.py']}]}
        self.file_manifest = self.collection / 'FILES.json'
        self.file_manifest.write_text(json.dumps(files))
        manifest = {'format': 1, 'collection_info': self.info, 'file_manifest_file': {
            'name': 'FILES.json', 'ftype': 'file', 'format': 1, 'chksum_type': 'sha256',
            'chksum_sha256': hashlib.sha256(self.file_manifest.read_bytes()).hexdigest()}}
        self.manifest = self.collection / 'MANIFEST.json'
        self.manifest.write_text(json.dumps(manifest))
        self.file_manifest.chmod(0o644)
        self.manifest.chmod(0o644)
        self.source = 'git+https://github.com/ansible-collections/ansible.posix.git,' + 'a' * 40
        (self.root / 'collections.yml').write_text('collections:\n  - name: ansible.posix\n    version: "2.0.0"\n'
                                                   '    type: git\n    source: ' + self.source + '\n')
        lock = {'schema': 1, 'collections': {'ansible.posix': {
            'version': '2.0.0', 'source': self.source, 'tree_sha256': canonical_hash(sorted(self.files.items())),
            'metadata_sha256': canonical_hash(self.info)}}}
        (self.root / 'collections.lock.json').write_text(json.dumps(lock))

    def check(self):
        check_collections(self.root)

    def test_exact_cached_tree_is_verified_without_mutation(self):
        before = {p: p.lstat().st_mtime_ns for p in self.root.rglob('*')}
        self.check()
        self.check()
        self.assertEqual(before, {p: p.lstat().st_mtime_ns for p in self.root.rglob('*')})

    def test_changed_file_is_rejected_even_with_consistent_forged_manifests(self):
        self.module.write_text('# changed code\n')
        files = json.loads(self.file_manifest.read_text())
        files['files'][1]['chksum_sha256'] = hashlib.sha256(self.module.read_bytes()).hexdigest()
        self.file_manifest.write_text(json.dumps(files))
        manifest = json.loads(self.manifest.read_text())
        manifest['file_manifest_file']['chksum_sha256'] = hashlib.sha256(self.file_manifest.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_extra_and_generated_bytecode_files_are_rejected(self):
        self.module.unlink()
        with self.assertRaises(ValueError):
            self.check()
        self.module.write_text('# synthetic collection module\n')
        self.module.chmod(0o644)
        for name in ('foreign.py', '__pycache__/module.cpython-312.pyc'):
            with self.subTest(name=name):
                extra = self.collection / name
                extra.parent.mkdir(exist_ok=True)
                extra.write_bytes(b'foreign')
                with self.assertRaises(ValueError):
                    self.check()
                extra.unlink()

    def test_symbolic_and_hard_links_are_rejected(self):
        external = self.root / 'external.py'
        self.module.rename(external)
        self.module.symlink_to(external)
        with self.assertRaises(ValueError):
            self.check()
        self.module.unlink()
        os.link(external, self.module)
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_metadata_permissions_or_owner_fail(self):
        self.module.chmod(0o666)
        with self.assertRaises(ValueError):
            self.check()
        self.module.chmod(0o644)
        with patch('portfolio_cli.collection_integrity.os.getuid', return_value=-1):
            with self.assertRaises(ValueError):
                self.check()
        info = dict(self.info, version='unexpected')
        manifest = json.loads(self.manifest.read_text())
        manifest['collection_info'] = info
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.check()

    def test_collection_parent_symlink_is_rejected(self):
        collection = self.root / '.ansible/collections'
        moved = self.root / 'moved'
        collection.rename(moved)
        collection.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.check()

    def test_manifest_tampering_and_source_drift_are_rejected(self):
        original = self.file_manifest.read_bytes()
        self.file_manifest.write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.check()
        self.file_manifest.write_bytes(original)
        requirements = self.root / 'collections.yml'
        requirements.write_text(requirements.read_text().replace('a' * 40, 'b' * 40))
        with self.assertRaises(ValueError):
            self.check()

    def test_repository_lock_pins_official_source_and_complete_tree(self):
        import yaml
        spec = yaml.safe_load((ROOT / 'collections.yml').read_text())['collections'][0]
        locked = json.loads((ROOT / 'collections.lock.json').read_text())['collections']['ansible.posix']
        self.assertEqual(spec['name'], 'ansible.posix')
        self.assertEqual(spec['version'], '2.0.0')
        self.assertEqual(spec['type'], 'git')
        self.assertEqual(spec['source'], locked['source'])
        self.assertRegex(spec['source'], r'^git\+https://github\.com/ansible-collections/ansible\.posix\.git,[a-f0-9]{40}$')
        self.assertRegex(locked['tree_sha256'], r'^[a-f0-9]{64}$')
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        steps = workflow['jobs']['offline-validation']['steps']
        cache = next(step for step in steps if step.get('uses', '').startswith('actions/cache@'))
        self.assertIn('collections.lock.json', cache['with']['key'])
        self.assertNotIn('restore-keys', cache['with'])
        self.assertNotIn('.venv', cache['with']['path'])
        setup = (ROOT / 'scripts/setup.sh').read_text()
        self.assertIn('--offline --no-deps', setup)
        self.assertLess(setup.index('scripts/check-collections.py\n'), setup.index('sh scripts/install-actionlint.sh\n'))


if __name__ == '__main__':
    unittest.main()
