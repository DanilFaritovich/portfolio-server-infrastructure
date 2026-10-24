"""Offline fixed-artifact, remote-file and operator boundary regressions."""

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from test_cli_package import load_access
from portfolio_cli import cli, deployment_artifact as artifact, deployment_prerequisites as stage
from portfolio_cli import initialization, plans

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployment_guard', ROOT / 'library/portfolio_deployment_prerequisites.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


REAL_ANCESTRY = guard.ancestry
REAL_HOST_CHECK = guard.host_check


class FileContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, filename in [('TARGET', 'gh'), ('STAGED', 'pending'), ('UPLOAD', 'upload')]:
            self.stack.enter_context(patch.object(guard, name, self.root / filename))
        self.bytes = b'synthetic pinned executable'
        self.stack.enter_context(patch.object(guard, 'GH_SIZE', len(self.bytes)))
        self.stack.enter_context(patch.object(guard, 'GH_SHA256', hashlib.sha256(self.bytes).hexdigest()))
        self.stack.enter_context(patch.object(guard, 'host_check'))
        self.stack.enter_context(patch.object(guard, 'ancestry'))
        self.stack.enter_context(patch.object(guard.os, 'listxattr', return_value=[]))
        # Model remote root metadata without privilege or real system paths.
        self.owner = 0
        original_lstat, original_fstat = Path.lstat, os.fstat
        def root_meta(meta):
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            values = {name: getattr(meta, name) for name in fields}
            values.update(st_uid=self.owner, st_gid=self.owner)
            return SimpleNamespace(**values)
        self.stack.enter_context(patch.object(Path, 'lstat', lambda path: root_meta(original_lstat(path))))
        self.stack.enter_context(patch.object(guard.os, 'fstat', lambda fd: root_meta(original_fstat(fd))))

    def write(self, path=None, data=None, mode=0o755):
        path = path or guard.TARGET
        path.write_bytes(self.bytes if data is None else data)
        path.chmod(mode)
        return path

    def prepare(self):
        self.assertTrue(guard.install())
        return self.write(guard.UPLOAD / 'gh')

    def test_install_absent_verify_and_noop_preserve_inode_and_timestamps(self):
        source = self.prepare()
        self.assertTrue(guard.install(source))
        self.assertFalse(guard.UPLOAD.exists())
        self.assertFalse(guard.STAGED.exists())
        before = guard.identity(guard.TARGET.lstat())
        self.assertFalse(guard.install())
        self.assertTrue(guard.inspect(verify=True))
        self.assertEqual(guard.identity(guard.TARGET.lstat()), before)

    def test_wrong_digest_size_mode_owner_links_and_symlink_fail_closed(self):
        for kind in ('digest', 'size', 'mode', 'owner', 'hardlink', 'symlink'):
            with self.subTest(kind=kind):
                self.owner = 0
                if os.path.lexists(guard.TARGET):
                    guard.TARGET.unlink()
                self.write()
                if kind == 'digest':
                    self.write(data=b'x' * len(self.bytes))
                elif kind == 'size':
                    self.write(data=b'partial')
                elif kind == 'mode':
                    guard.TARGET.chmod(0o775)
                elif kind == 'owner':
                    self.owner = 1000
                elif kind == 'hardlink':
                    os.link(guard.TARGET, self.root / 'other')
                else:
                    guard.TARGET.unlink()
                    guard.TARGET.symlink_to(self.write(self.root / 'elsewhere'))
                with self.assertRaises((ValueError, OSError)):
                    guard.install()

    def test_absence_is_not_verify_success_and_check_never_writes(self):
        with self.assertRaises(ValueError):
            guard.inspect(verify=True)
        self.assertTrue(guard.install(check=True))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_interrupted_upload_or_publish_blocks_every_normal_operation(self):
        source = self.prepare()
        with self.assertRaises(ValueError):
            guard.inspect()
        with patch.object(guard.os, 'link', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                guard.install(source)
        self.assertTrue(guard.STAGED.exists())
        self.assertFalse(guard.TARGET.exists())
        for verify in (True, False):
            with self.assertRaises(ValueError):
                guard.inspect(verify)
        with self.assertRaises(ValueError):
            guard.install(source)

    def test_interruption_after_publication_preserves_both_links_and_blocks_acceptance(self):
        source = self.prepare()
        real_fsync = os.fsync
        calls = []
        def interrupted(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                raise OSError('power loss after publication')
            real_fsync(descriptor)
        with patch.object(guard.os, 'fsync', side_effect=interrupted):
            with self.assertRaises(OSError):
                guard.install(source)
        self.assertEqual(guard.TARGET.read_bytes(), self.bytes)
        self.assertEqual(guard.TARGET.lstat().st_nlink, 2)
        self.assertTrue(guard.UPLOAD.exists())
        self.assertTrue(guard.STAGED.exists())
        with self.assertRaises(ValueError):
            guard.inspect(verify=True)

    def test_publication_never_replaces_a_concurrent_destination(self):
        source = self.prepare()
        link = os.link
        def conflict(*args, **kwargs):
            guard.TARGET.write_bytes(b'foreign')
            return link(*args, **kwargs)
        with patch.object(guard.os, 'link', side_effect=conflict):
            with self.assertRaises(FileExistsError):
                guard.install(source)
        self.assertEqual(guard.TARGET.read_bytes(), b'foreign')
        self.assertTrue(guard.STAGED.exists())

    def test_changed_upload_digest_and_failed_postflight_retain_evidence(self):
        source = self.prepare()
        source.write_bytes(b'x' * len(self.bytes))
        with self.assertRaises(ValueError):
            guard.install(source)
        self.assertTrue(guard.UPLOAD.exists())
        self.assertFalse(guard.TARGET.exists())

    def test_ancestry_rejects_links_writable_and_nonroot(self):
        # Exercise the actual ancestry predicate on synthetic metadata only.
        actual = self.stack.pop_all()
        try:
            for mode, uid, gid in ((stat.S_IFLNK | 0o777, 0, 0), (stat.S_IFDIR | 0o775, 0, 0),
                                   (stat.S_IFDIR | 0o755, 1000, 0), (stat.S_IFDIR | 0o755, 0, 1000)):
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)):
                    with self.assertRaises(ValueError):
                        REAL_ANCESTRY(Path('/synthetic/bin/gh'))
        finally:
            actual.close()

    def test_supported_os_only(self):
        actual = self.stack.pop_all()
        try:
            release = self.root / 'os-release'
            with patch.object(guard, 'OS_RELEASE', release), patch.object(guard.platform, 'machine', return_value='x86_64'):
                release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
                REAL_HOST_CHECK()
                for value in ('ID=ubuntu\nVERSION_ID="22.04"\n', 'ID=debian\nVERSION_ID="24.04"\n'):
                    release.write_text(value)
                    with self.assertRaises(ValueError):
                        REAL_HOST_CHECK()
        finally:
            actual.close()


class ArtifactTests(unittest.TestCase):
    def test_official_fixed_contract_matches_remote_verifier(self):
        self.assertEqual(artifact.GH_BINARY_SHA256, guard.GH_SHA256)
        self.assertEqual(artifact.GH_BINARY_SIZE, guard.GH_SIZE)
        self.assertEqual(artifact.GH_VERSION, '2.102.0')
        self.assertIn('/cli/cli/releases/download/v2.102.0/', artifact.GH_URL)

    def test_archive_digest_rejects_before_tar_open(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'bad.tar.gz'
            archive.write_bytes(b'untrusted')
            with patch.object(artifact.tarfile, 'open') as extract:
                with self.assertRaisesRegex(ValueError, 'SHA256'):
                    artifact.gh_extract(archive, Path(directory) / 'gh')
                extract.assert_not_called()

    def test_only_exact_regular_member_is_read_and_binary_digest_and_elf_are_checked(self):
        for kind in ('valid', 'symlink', 'duplicate', 'wrong-digest', 'wrong-elf'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = b'\x7fELF\x02\x01\x01' + b'\0' * 11 + b'\x3e\x00' + b'synthetic'
                if kind == 'wrong-elf':
                    binary = b'bad!' + binary[4:]
                archive = root / 'release.tar.gz'
                with tarfile.open(archive, 'w:gz') as bundle:
                    foreign = tarfile.TarInfo('../../must-not-extract')
                    foreign.size = 1
                    bundle.addfile(foreign, io.BytesIO(b'x'))
                    for _ in range(2 if kind == 'duplicate' else 1):
                        member = tarfile.TarInfo(artifact.GH_MEMBER)
                        member.size = len(binary)
                        if kind == 'symlink':
                            member.type = tarfile.SYMTYPE
                            member.linkname = '/etc/passwd'
                        bundle.addfile(member, io.BytesIO(binary))
                with patch.object(artifact, 'GH_ARCHIVE_SHA256', hashlib.sha256(archive.read_bytes()).hexdigest()), \
                        patch.object(artifact, 'GH_BINARY_SIZE', len(binary)), \
                        patch.object(artifact, 'GH_BINARY_SHA256', 'wrong' if kind == 'wrong-digest' else hashlib.sha256(binary).hexdigest()):
                    if kind == 'valid':
                        artifact.gh_extract(archive, root / 'gh')
                        self.assertEqual((root / 'gh').read_bytes(), binary)
                        self.assertEqual(set(p.name for p in root.iterdir()), {'release.tar.gz', 'gh'})
                        with self.assertRaises(FileExistsError):
                            artifact.gh_extract(archive, root / 'gh')
                    else:
                        with self.assertRaises(ValueError):
                            artifact.gh_extract(archive, root / 'gh')

    def test_preparation_failure_cleans_private_artifacts_without_execution(self):
        created = []
        def download(path):
            created.append(path.parent)
            path.write_bytes(b'untrusted')
        with patch.object(artifact, 'gh_download', side_effect=download), \
                patch.object(artifact.platform, 'system', return_value='Linux'), \
                patch.object(artifact.platform, 'machine', return_value='x86_64'), \
                patch.object(artifact.subprocess, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'SHA256'):
                with artifact.prepared_gh():
                    self.fail('unverified artifact accepted')
            execute.assert_not_called()
        self.assertTrue(created)
        self.assertFalse(created[0].exists())

    def test_downloader_bounds_size_without_network(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.side_effect = [b'123456', b'789012', b'']
        opener = Mock()
        opener.open.return_value = response
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(artifact.urllib.request, 'build_opener', return_value=opener), \
                patch.object(artifact, 'GH_LIMIT', 10):
            with self.assertRaisesRegex(ValueError, 'Oversized'):
                artifact.gh_download(Path(directory) / 'release.tar.gz')

    def test_redirect_restrictions(self):
        redirect = artifact.GhRedirect()
        for url in ('http://release-assets.githubusercontent.com/file', 'https://evil.test/file',
                    'https://user:password@release-assets.githubusercontent.com/file',
                    'https://release-assets.githubusercontent.com:444/file'):
            with self.assertRaises(ValueError):
                redirect.redirect_request(None, None, 302, '', {}, url)


class StageTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.dict(os.environ, CI=''))
        for name, value in [('managed_access', ('automation', Path('/synthetic-key'))),
                            ('load_host', ('fixture', 'example.test', 22, 'root', '/usr/bin/python3'))]:
            self.stack.enter_context(patch.object(stage, name, return_value=value))
        self.prerequisites = self.stack.enter_context(patch.object(stage, 'prerequisites'))
        self.check = self.stack.enter_context(patch.object(stage, 'check_key'))
        self.trust = self.stack.enter_context(patch.object(stage, 'known_host'))
        self.probe = self.stack.enter_context(patch.object(stage, 'deployment_probe', side_effect=[False, False, True]))
        self.stack.enter_context(patch.object(stage, 'plan_snapshot', return_value=('fixed',)))
        self.consent = self.stack.enter_context(patch.object(stage, 'stage_consent'))
        self.playbook = self.stack.enter_context(patch.object(stage, 'run_playbook'))
        @contextlib.contextmanager
        def prepared():
            yield Path('/synthetic-verified-gh')
        self.prepare = self.stack.enter_context(patch.object(stage, 'prepared_gh', side_effect=prepared))

    def run_stage(self, mode='setup-deployment-prerequisites'):
        return stage.deployment_prerequisites(mode, Path('/synthetic-inventory'))

    def test_install_confirmation_preflight_and_independent_postflight(self):
        self.assertEqual(self.run_stage(), 'verify-deployment-prerequisites')
        self.consent.assert_called_once()
        self.prepare.assert_called_once()
        self.assertEqual(self.probe.call_args_list[-1].kwargs, {'verify': True})
        variables = self.playbook.call_args.args[2]
        self.assertTrue(variables['deployment_prerequisites_confirmed'])
        self.assertEqual(variables['ansible_become_flags'], '-n')
        self.assertIn('BatchMode=yes', variables['ansible_ssh_args'])
        self.assertIn('IdentitiesOnly=yes', variables['ansible_ssh_args'])
        self.assertEqual(self.playbook.call_args.args[3], 'setup-deployment-prerequisites.yml')

    def test_noop_still_has_independent_postflight_without_download_or_confirmation(self):
        self.probe.side_effect = [True, True]
        self.run_stage()
        self.assertEqual(self.probe.call_count, 2)
        self.playbook.assert_not_called()
        self.prepare.assert_not_called()
        self.consent.assert_not_called()

    def test_verify_never_downloads_or_mutates(self):
        self.probe.side_effect = [True]
        self.run_stage('verify-deployment-prerequisites')
        self.playbook.assert_not_called()
        self.prepare.assert_not_called()
        self.consent.assert_not_called()

    def test_decline_trust_key_ssh_sudo_and_postflight_failures_stop(self):
        for failing in (self.prerequisites, self.check, self.trust, self.probe, self.consent, self.prepare):
            with self.subTest(failing=failing):
                self.playbook.reset_mock()
                previous = failing.side_effect
                failing.side_effect = ValueError('blocked')
                self.probe.side_effect = ValueError('blocked') if failing is self.probe else [False, False, True]
                with self.assertRaises(ValueError):
                    self.run_stage()
                self.playbook.assert_not_called()
                failing.side_effect = previous
        self.probe.side_effect = [False, False, ValueError('postflight failed')]
        with self.assertRaisesRegex(ValueError, 'postflight'):
            self.run_stage()
        self.playbook.assert_called_once()

    def test_native_dispatch_lock_and_legacy_mock_isolation(self):
        legacy, other = load_access('deployment_legacy'), load_access('deployment_other')
        with patch.object(legacy, 'deployment_prerequisites') as handler:
            legacy.init_stage('setup-deployment-prerequisites', Path('/fixture'), None)
        handler.assert_called_once()
        self.assertIsNot(legacy.deployment_prerequisites.__globals__, other.deployment_prerequisites.__globals__)
        with patch.object(cli, 'pipeline_lock', side_effect=ValueError('locked')), \
                patch.object(cli, 'deployment_prerequisites') as handler, \
                patch.object(sys, 'argv', ['access.py', 'setup-deployment-prerequisites']):
            self.assertEqual(cli.main(), 1)
            handler.assert_not_called()

    def test_new_stage_dispatch_and_all_prior_verifier_failures_stop(self):
        self.assertEqual(len(initialization.INIT_STAGES), 8)
        self.assertEqual(initialization.INIT_STAGES[-1][0], 'deployment-prerequisites')
        for index in range(7):
            calls = []
            def execute(mode, *_):
                calls.append(mode)
                if mode == initialization.INIT_STAGES[index][2]:
                    raise ValueError('prior verification failed')
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(initialization, 'init_stage', side_effect=execute), \
                    patch.object(initialization.tempfile, 'tempdir', directory):
                with self.assertRaises(ValueError):
                    initialization.init_execute(Path('/fixture'), None, 7)
            self.assertEqual(calls, [row[2] for row in initialization.INIT_STAGES[:index + 1]])
            self.assertNotIn('setup-deployment-prerequisites', calls)

    def test_inventory_drift_during_local_preparation_stops_transfer(self):
        with patch.object(stage, 'plan_snapshot', side_effect=[('before',), ('changed',)]):
            with self.assertRaisesRegex(ValueError, 'inputs changed'):
                self.run_stage()
        self.playbook.assert_not_called()

    def test_stage_dispatch_cannot_bypass_ci_guard_through_initialization(self):
        with patch.dict(os.environ, CI='true'):
            with self.assertRaisesRegex(ValueError, 'disabled in offline CI'):
                initialization.init_stage('setup-deployment-prerequisites', Path('/fixture'), None)
        self.prerequisites.assert_not_called()
        self.probe.assert_not_called()

    def test_real_default_deny_and_offline_make_boundary(self):
        with patch.object(plans.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', return_value=''), \
                patch.object(plans, 'plan_snapshot', return_value=('fixed',)):
            with self.assertRaises(ValueError):
                plans.stage_consent('setup-deployment-prerequisites', Path('/fixture'))
        result = subprocess.run(['make', '-n', 'check'], cwd=ROOT, text=True, capture_output=True, check=True)
        self.assertNotIn('scripts/access.py', result.stdout)
        self.assertNotIn('scripts/e2e.py', result.stdout)
        self.assertIn('--syntax-check', result.stdout)
        for target in stage.DEPLOYMENT_MODES:
            env = dict(os.environ, CI='true', HOME=tempfile.gettempdir(), INVENTORY='/synthetic-nonexistent')
            # Dispatch directly: pipeline-lock metadata is a separate tested boundary.
            with patch.dict(os.environ, env), patch.object(cli, 'deployment_prerequisites') as live:
                with self.assertRaisesRegex(ValueError, 'disabled in offline CI'):
                    cli.dispatch(SimpleNamespace(mode=target, key=None), Path('/synthetic-nonexistent'))
                live.assert_not_called()
            with tempfile.TemporaryDirectory() as home:
                command_env = dict(os.environ, CI='true', HOME=home, INVENTORY='/synthetic-nonexistent', AUTOMATION_KEY='')
                command_env.pop('PORTFOLIO_E2E_ROOT', None)
                result = subprocess.run(['make', '--no-print-directory', target], cwd=ROOT,
                                        env=command_env, stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('disabled in offline CI', result.stderr)


if __name__ == '__main__':
    unittest.main()
