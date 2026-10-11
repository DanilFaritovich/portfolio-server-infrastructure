"""Host/image preparation tests: every privileged/network/hypervisor probe mocked."""

import contextlib
import io
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from portfolio_cli import e2e, e2e_host as host, e2e_images as images


class ImagesTests(unittest.TestCase):
    def test_registry_default_and_selection(self):
        self.assertEqual(images.select()['id'], 'ubuntu-24.04')
        self.assertEqual(images.select('ubuntu-22.04')['architecture'], 'amd64')
        with self.assertRaisesRegex(ValueError, 'Unsupported E2E_DISTRO'):
            images.select('debian-12')

    def test_registry_rejects_unsafe_or_unsupported_profiles(self):
        original = yaml.safe_load(Path(images.__file__).with_name('e2e_distros.yml').read_text())
        cases = [('image_url', 'https://evil.example/image'), ('checksum_url', 'http://cloud-images.ubuntu.com/SHA256SUMS'),
                 ('architecture', 'arm64'), ('boot', 'uefi'), ('version', '26.04'), ('ssh', 'custom'),
                 ('osinfo', '--evil'), ('name', 'name\x1b[0m'), ('image_url', original['distros'][0]['image_url'] + '?q=1')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'registry.yml'
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    data = json.loads(json.dumps(original))
                    data['distros'][0][field] = value
                    path.write_text(yaml.safe_dump(data))
                    with self.assertRaises(ValueError):
                        images.registry(path)
            for data in (dict(original, default='unknown'), dict(original, schema=True),
                         dict(original, distros=original['distros'] * 2), dict(original, extra='bad')):
                path.write_text(yaml.safe_dump(data))
                with self.assertRaises(ValueError):
                    images.registry(path)
            path.write_text('schema: 1\nschema: 2\n')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                images.registry(path)

    def test_redirect_refused_before_following(self):
        with self.assertRaisesRegex(ValueError, 'before following'):
            images.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')

    def test_selected_image_download_and_pinned_digest(self):
        payload = b'synthetic qcow2 bytes'
        digest = hashlib.sha256(payload).hexdigest()
        class Response(io.BytesIO):
            def __init__(self, url, content):
                super().__init__(content)
                self.url = url
        for distro in ('ubuntu-22.04', 'ubuntu-24.04'):
            with self.subTest(distro=distro), tempfile.TemporaryDirectory() as directory:
                stand = e2e.Stand(Path(directory))
                stand.state = {'schema': 2, 'distro': distro}
                profile = images.select(distro)
                def fetch(url):
                    self.assertIn(url, (profile['checksum_url'], profile['image_url']))
                    data = (digest + ' *' + profile['image_url'].rsplit('/', 1)[1] + '\n').encode() \
                        if url == profile['checksum_url'] else payload
                    return Response(url, data)
                with patch.object(images, 'open_official', side_effect=fetch) as opening, \
                        patch.dict(os.environ, E2E_IMAGE_SHA256=digest):
                    self.assertEqual(stand.download().read_bytes(), payload)
                    self.assertEqual((stand.root / 'image.sha256').read_text().strip(), digest)
                    self.assertEqual([call.args[0] for call in opening.call_args_list],
                                     [profile['checksum_url'], profile['image_url']])
        for pin in ('0' * 64, 'invalid'):
            with tempfile.TemporaryDirectory() as directory:
                stand = e2e.Stand(Path(directory))
                stand.state = {'schema': 2, 'distro': 'ubuntu-24.04'}
                profile = images.select()
                checksum = (digest + ' *' + profile['image_url'].rsplit('/', 1)[1] + '\n').encode()
                with patch.object(images, 'open_official', return_value=Response(profile['checksum_url'], checksum)) as opening, \
                        patch.dict(os.environ, E2E_IMAGE_SHA256=pin), self.assertRaises(ValueError):
                    stand.download()
                opening.assert_called_once()
                self.assertFalse((stand.root / 'image.img').exists())

    def test_make_list_is_local_and_exports_distro(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, HOME=directory)
            run = subprocess.run(['make', '--no-print-directory', 'e2e-list-distros'],
                                 cwd=e2e.ROOT, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('ubuntu-24.04', run.stdout)
            self.assertIn('ubuntu-22.04', run.stdout)
            self.assertFalse((Path(directory) / '.local').exists())
            run = subprocess.run(['make', '-n', 'e2e-prepare', 'E2E_DISTRO=ubuntu-22.04'],
                                 cwd=e2e.ROOT, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(run.returncode, 0)
            self.assertIn('scripts/e2e.py prepare', run.stdout)
            self.assertIn('export E2E_DISTRO', (e2e.ROOT / 'Makefile').read_text())
    def test_make_prepare_passes_selected_distro_to_mocked_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            venv = Path(directory) / 'venv'
            (venv / 'bin').mkdir(parents=True)
            interpreter = venv / 'bin/python'
            interpreter.write_text("#!/bin/sh\nprintf '%s\\n' \"$E2E_DISTRO\" \"$*\"\n")
            interpreter.chmod(0o700)
            run = subprocess.run(['make', '--no-print-directory', 'e2e-prepare', 'E2E_DISTRO=ubuntu-22.04', f'VENV={venv}'],
                                 cwd=e2e.ROOT, env=dict(os.environ, HOME=directory), text=True, capture_output=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.splitlines(), ['ubuntu-22.04', 'scripts/e2e.py prepare'])



class HostTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.storage = Path(self.temp) / 'storage'
        self.storage.mkdir(mode=0o2750)
        self.storage.chmod(0o2750)
        self.run = Mock(return_value="<capabilities><guest><arch name='x86_64'><domain type='kvm'/></arch></guest></capabilities>")
        self.confirm = Mock()
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(host, 'supported_host'))
        self.stack.enter_context(patch.object(host, 'package_manager', return_value='apt'))
        self.missing = self.stack.enter_context(patch.object(host, 'missing_packages', return_value=[]))
        self.stack.enter_context(patch.object(host, 'storage_parents'))
        self.stack.enter_context(patch.object(host, 'qemu_group', return_value=os.getgid()))
        self.stack.enter_context(patch.object(host.shutil, 'which', return_value='/mock/bin'))
        self.stack.enter_context(patch.object(host.pwd, 'getpwuid', return_value=SimpleNamespace(pw_name='tester', pw_gid=os.getgid())))
        self.groups = {'kvm': SimpleNamespace(gr_gid=os.getgid(), gr_mem=['tester']),
                       'libvirt': SimpleNamespace(gr_gid=os.getgid(), gr_mem=['tester'])}
        self.stack.enter_context(patch.object(host.grp, 'getgrnam', side_effect=lambda name: self.groups[name]))
        original_stat = Path.stat
        self.stack.enter_context(patch.object(Path, 'stat', lambda path, **kw:
                                              SimpleNamespace(st_mode=stat.S_IFCHR) if path == Path('/dev/kvm')
                                              else original_stat(path, **kw)))
        self.stack.enter_context(patch.object(Path, 'read_text', return_value='flags : vmx'))
        self.stack.enter_context(patch.object(host.os, 'access', return_value=True))

    def prepare(self):
        host.prepare(self.storage, command=self.run, confirm=self.confirm, safe_path=e2e.safe_path)

    def test_ready_dependencies_do_not_use_sudo_or_confirm(self):
        self.prepare()
        self.confirm.assert_not_called()
        self.assertTrue(all(call.args[0][0] == 'virsh' for call in self.run.call_args_list))

    def test_non_apt_prepared_host_passes_without_install_or_confirmation(self):
        with patch.object(host, 'package_manager', return_value=None):
            self.prepare()
        self.missing.assert_not_called()
        self.confirm.assert_not_called()
        self.assertTrue(all(call.args[0][0] == 'virsh' for call in self.run.call_args_list))

    def test_non_apt_missing_dependency_blocks_before_sudo_or_hypervisor(self):
        with patch.object(host, 'package_manager', return_value=None), \
                patch.object(host.shutil, 'which', side_effect=lambda tool: None if tool == 'virt-install' else '/mock'):
            with self.assertRaisesRegex(ValueError, 'manually'):
                self.prepare()
        self.run.assert_not_called()
        self.confirm.assert_not_called()

    def test_declining_install_stops_before_sudo(self):
        self.missing.return_value = ['virtinst']
        self.confirm.side_effect = e2e.E2EError('declined')
        with self.assertRaisesRegex(ValueError, 'declined'):
            self.prepare()
        self.run.assert_not_called()

    def test_install_only_missing_then_reprobe(self):
        self.missing.side_effect = [['virtinst'], []]
        self.prepare()
        apt = [call.args[0] for call in self.run.call_args_list if call.args[0][0] == 'sudo']
        self.assertEqual(apt, [['sudo', '--', 'apt-get', 'update'],
                               ['sudo', '--', 'apt-get', 'install', '--no-install-recommends', '--no-upgrade', '--no-remove', 'virtinst']])
        self.confirm.assert_called_once()

    def test_sudo_and_apt_failures_stop_no_retry(self):
        for failure_at in (0, 1):
            self.missing.side_effect = None
            self.missing.return_value = ['virtinst']
            self.run.reset_mock()
            self.run.side_effect = [''] * failure_at + [e2e.E2EError('subprocess failed')]
            with self.assertRaisesRegex(ValueError, 'subprocess failed'):
                self.prepare()
            self.assertEqual(self.run.call_count, failure_at + 1)
        self.run.side_effect = None
        with patch.object(host.shutil, 'which', return_value=None), self.assertRaisesRegex(ValueError, 'sudo unavailable'):
            self.prepare()

    def test_install_postcheck_failure_stops(self):
        self.missing.return_value = ['virtinst']
        with self.assertRaisesRegex(ValueError, 'still unavailable'):
            self.prepare()
        self.assertEqual(self.run.call_count, 2)

    def test_group_grant_requires_separate_consent_and_relogin(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=[])
        with self.assertRaisesRegex(ValueError, 'Log out'):
            self.prepare()
        self.assertEqual(self.run.call_args.args[0], ['sudo', '--', 'usermod', '-aG', 'libvirt', '--', 'tester'])
        self.confirm.assert_called_once()

    def test_already_configured_group_requires_relogin_without_usermod(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=['tester'])
        with self.assertRaisesRegex(ValueError, 'Log out'):
            self.prepare()
        self.run.assert_not_called()
        self.confirm.assert_not_called()

    def test_group_decline_and_libvirt_error_no_disk_mutation(self):
        self.groups['kvm'] = SimpleNamespace(gr_gid=987654, gr_mem=[])
        self.confirm.side_effect = e2e.E2EError('declined')
        with self.assertRaisesRegex(ValueError, 'declined'):
            self.prepare()
        self.run.assert_not_called()
        self.groups['kvm'] = self.groups['libvirt']
        self.run.side_effect = e2e.E2EError('libvirt failed')
        with self.assertRaisesRegex(ValueError, 'libvirt failed'):
            self.prepare()
        self.assertEqual(self.storage.stat().st_mode & 0o7777, 0o2750)

    def test_missing_hardware_or_kvm_capability_blocks(self):
        with patch.object(Path, 'read_text', return_value='flags : none'), self.assertRaisesRegex(ValueError, 'virtualization'):
            self.prepare()
        self.missing.assert_not_called()
        self.run.return_value = '<capabilities/>'
        with self.assertRaisesRegex(ValueError, 'does not advertise'):
            self.prepare()
        self.confirm.assert_not_called()

    def test_existing_wrong_storage_mode_not_repaired(self):
        self.storage.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'incompatible QEMU'):
            self.prepare()
        self.confirm.assert_not_called()
        self.assertEqual(self.storage.stat().st_mode & 0o7777, 0o700)

    def test_new_disk_directory_decline_or_mkdir_failure(self):
        self.storage.rmdir()
        self.confirm.side_effect = e2e.E2EError('declined')
        with self.assertRaisesRegex(ValueError, 'declined'):
            self.prepare()
        self.assertTrue(all(call.args[0][0] == 'virsh' for call in self.run.call_args_list))
        self.confirm.side_effect = None
        self.run.reset_mock()
        self.run.side_effect = [self.run.return_value, self.run.return_value, e2e.E2EError('mkdir failed')]
        with self.assertRaisesRegex(ValueError, 'mkdir failed'):
            self.prepare()
        self.assertEqual(self.run.call_count, 3)
        self.assertFalse(self.storage.exists())

    def test_new_directory_created_exclusively_with_confirmed_owner(self):
        self.storage.rmdir()
        original_stat = Path.stat
        root_owned = False
        def probe(path, **kw):
            info = original_stat(path, **kw)
            if path == self.storage and root_owned:
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
            return info
        def execute(argv, **kwargs):
            nonlocal root_owned
            if argv[0] == 'virsh':
                return self.run.return_value
            if argv[2] == 'mkdir':
                self.storage.mkdir(mode=0o2750)
                root_owned = True
            elif argv[2] == 'chown':
                root_owned = False
            return ''
        self.run.side_effect = execute
        with patch.object(Path, 'stat', side_effect=probe, autospec=True):
            self.prepare()
        self.confirm.assert_called_once()
        sudo = [call.args[0] for call in self.run.call_args_list if call.args[0][0] == 'sudo']
        self.assertEqual(sudo[0], ['sudo', '--', 'mkdir', '-m', '2750', '--', str(self.storage)])
        self.assertEqual(sudo[1][2:4], ['chown', '--no-dereference'])
        self.assertEqual(self.storage.stat().st_mode & 0o7777, 0o2750)

    def test_privileged_mkdir_refuses_a_concurrently_appearing_directory(self):
        self.storage.rmdir()
        def execute(argv, **kwargs):
            if argv[0] == 'sudo':
                self.storage.mkdir(mode=0o700)
                raise e2e.E2EError('mkdir failed')
            return self.run.return_value
        self.run.side_effect = execute
        with self.assertRaisesRegex(ValueError, 'mkdir failed'):
            self.prepare()
        self.assertEqual(self.storage.stat().st_mode & 0o7777, 0o700)
        self.assertFalse(any('chown' in call.args[0] for call in self.run.call_args_list))



class PackageTests(unittest.TestCase):
    def test_missing_packages_query_and_broken_tools(self):
        with patch.object(host.shutil, 'which', return_value='/mock'), \
                patch.object(host.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='install ok installed')) as run:
            self.assertEqual(host.missing_packages(), [])
            self.assertEqual(run.call_count, len(host.PACKAGES))
            run.side_effect = lambda args, **kw: SimpleNamespace(returncode=int(args[-1] == 'virtinst'), stdout='install ok installed')
            self.assertEqual(host.missing_packages(), ['virtinst'])
            with patch.object(host.shutil, 'which', side_effect=lambda name: None if name == 'qemu-img' else '/mock'), \
                    self.assertRaisesRegex(ValueError, 'no reinstall'):
                host.missing_packages()
            run.side_effect = None
            run.return_value.returncode = 2
            with self.assertRaisesRegex(ValueError, 'query failed'):
                host.missing_packages()

    def test_storage_parents_reject_foreign_paths_and_symlinks(self):
        with self.assertRaisesRegex(ValueError, 'Foreign'):
            host.storage_parents(Path('/tmp/foreign'))
        storage = Path('/var/lib/libvirt/images') / f'portfolio-e2e-{os.getuid()}'
        with patch.object(Path, 'is_symlink', return_value=True), self.assertRaisesRegex(ValueError, 'Unsafe'):
            host.storage_parents(storage)

    def test_custom_qemu_identity_blocks_automatic_directory_setup(self):
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o644)), \
                patch.object(Path, 'read_text', return_value='user = "custom"\ngroup = "libvirt-qemu"'), \
                self.assertRaisesRegex(ValueError, 'Custom QEMU'):
            host.qemu_group()
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o644)), \
                patch.object(Path, 'read_text', return_value='user = "libvirt-qemu" # stock\ngroup = "libvirt-qemu"'), \
                patch.object(host.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=42)):
            self.assertEqual(host.qemu_group(), 42)

    def test_host_support_uses_platform_not_distro_or_release(self):
        with patch.object(host.platform, 'system', return_value='Linux'), \
                patch.object(host.platform, 'machine', return_value='x86_64'), \
                patch.object(host.platform, 'freedesktop_os_release') as release:
            host.supported_host()
            release.assert_not_called()
        for system, machine in (('Windows', 'x86_64'), ('Darwin', 'x86_64'), ('Linux', 'aarch64')):
            with patch.object(host.platform, 'system', return_value=system), \
                    patch.object(host.platform, 'machine', return_value=machine), self.assertRaises(ValueError):
                host.supported_host()

    def test_apt_detection_uses_family_and_tools_without_version_allowlist(self):
        with patch.object(host.shutil, 'which', return_value='/mock'), \
                patch.object(host.platform, 'freedesktop_os_release') as release:
            for distribution in ('ubuntu', 'debian'):
                for version in ('20.04', '24.04', '26.04', '99', None):
                    release.return_value = {'ID': distribution, 'VERSION_ID': version}
                    self.assertEqual(host.package_manager(), 'apt')
            for metadata in ({'ID': 'fedora'}, {'ID': 'unknown', 'ID_LIKE': 'ubuntu debian'}, {}):
                release.return_value = metadata
                self.assertIsNone(host.package_manager())
            release.side_effect = OSError('missing os-release')
            self.assertIsNone(host.package_manager())
        for missing in ('apt-get', 'dpkg-query'):
            with patch.object(host.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu'}), \
                    patch.object(host.shutil, 'which', side_effect=lambda tool: None if tool == missing else '/mock'):
                self.assertIsNone(host.package_manager())

    def test_unsupported_installer_accepts_preinstalled_tools_without_package_queries(self):
        with patch.object(host, 'package_manager', return_value=None), \
                patch.object(host.shutil, 'which', return_value='/mock'), \
                patch.object(host.subprocess, 'run') as run:
            self.assertEqual(host.dependency_plan(), [])
            run.assert_not_called()

    def test_unsupported_installer_missing_tools_stops_with_manual_instructions(self):
        with patch.object(host, 'package_manager', return_value=None), \
                patch.object(host.shutil, 'which', side_effect=lambda tool: None if tool == 'cloud-localds' else '/mock'), \
                patch.object(host.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(ValueError, 'manually'):
                host.dependency_plan()
            self.assertIn('cloud-localds', output.getvalue())
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
