"""Host/image preparation tests: every privileged/network/hypervisor probe mocked."""

import contextlib
import errno
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
        return host.prepare(self.storage, command=self.run, confirm=self.confirm, safe_path=e2e.safe_path)

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

    def test_group_grant_requires_separate_consent_and_reboot(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=[])
        self.run.side_effect = lambda *args, **kwargs: self.groups['libvirt'].gr_mem.append('tester')
        self.assertIs(self.prepare(), host.PreparationResult.REBOOT_REQUIRED)
        self.assertEqual(self.run.call_args.args[0], ['sudo', '--', 'usermod', '-aG', 'libvirt', '--', 'tester'])
        self.confirm.assert_called_once()

    def test_already_configured_group_requires_reboot_without_usermod(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=['tester'])
        self.assertIs(self.prepare(), host.PreparationResult.REBOOT_REQUIRED)
        self.run.assert_not_called()
        self.confirm.assert_not_called()

    def test_group_grant_without_confirmed_membership_fails_closed(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=[])
        with self.assertRaisesRegex(ValueError, 'not configured'):
            self.prepare()
        self.assertEqual(self.run.call_count, 1)

    def test_after_reboot_rechecks_access_without_grant(self):
        self.groups['libvirt'] = SimpleNamespace(gr_gid=987654, gr_mem=['tester'])
        with patch.object(host.os, 'getgroups', return_value=[987654]):
            self.assertIs(self.prepare(), host.PreparationResult.READY)
        self.confirm.assert_not_called()
        self.assertTrue(all(call.args[0][0] == 'virsh' for call in self.run.call_args_list))

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
                # Model chown clearing setgid and an owner outside QEMU's group.
                self.storage.chmod(0o750)
            elif argv[2] == 'chmod':
                self.storage.chmod(int(argv[3], 8))
            return ''
        self.run.side_effect = execute
        with patch.object(Path, 'stat', side_effect=probe, autospec=True):
            self.prepare()
        self.confirm.assert_called_once()
        sudo = [call.args[0] for call in self.run.call_args_list if call.args[0][0] == 'sudo']
        self.assertEqual(sudo[0], ['sudo', '--', 'mkdir', '-m', '2750', '--', str(self.storage)])
        self.assertEqual(sudo[1][2:4], ['chown', '--no-dereference'])
        self.assertEqual(sudo[2], ['sudo', '--', 'chmod', '2750', '--', str(self.storage)])
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

    def test_empty_missing_setgid_directory_can_finish_only_after_confirmation(self):
        self.storage.chmod(0o750)
        def execute(argv, **kwargs):
            if argv[0] == 'sudo':
                self.assertEqual(argv, ['sudo', '--', 'chmod', '2750', '--', str(self.storage)])
                self.storage.chmod(0o2750)
            return self.run.return_value
        self.run.side_effect = execute
        self.assertEqual(self.prepare(), host.PreparationResult.READY)
        self.confirm.assert_called_once()
        self.assertEqual(stat.S_IMODE(self.storage.stat().st_mode), 0o2750)

    def test_missing_setgid_recovery_decline_drift_data_and_acl_block(self):
        for case in ('decline', 'drift', 'data', 'acl'):
            with self.subTest(case=case):
                self.storage.chmod(0o750)
                self.run.reset_mock()
                self.confirm.reset_mock()
                self.confirm.side_effect = None
                if case == 'decline':
                    self.confirm.side_effect = images.E2EError('declined')
                elif case == 'drift':
                    self.confirm.side_effect = lambda message: self.storage.chmod(0o700)
                elif case == 'data':
                    (self.storage / 'disk').write_text('synthetic')
                with patch.object(host.os, 'listxattr', return_value=['system.posix_acl_access'] if case == 'acl' else []):
                    with self.assertRaises(ValueError):
                        self.prepare()
                self.assertFalse(any(call.args[0][0] == 'sudo' for call in self.run.call_args_list))
                if case == 'data':
                    (self.storage / 'disk').unlink()
                if case in ('data', 'acl'):
                    self.confirm.assert_not_called()



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

    def test_unreadable_qemu_configuration_blocks_without_exposing_exception(self):
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0, st_mode=0o600)), \
                patch.object(Path, 'read_text', side_effect=PermissionError('SECRET\x1b[31m')), \
                patch.object(host.grp, 'getgrnam') as group:
            with self.assertRaisesRegex(images.E2EError, 'QEMU configuration is not readable') as caught:
                host.qemu_group()
            self.assertNotIn('SECRET', str(caught.exception))
            group.assert_not_called()

    def test_unreadable_qemu_inspection_requires_consent_and_stops_on_failure(self):
        info = SimpleNamespace(st_uid=0, st_mode=0o600, st_dev=1, st_ino=2,
                               st_mtime_ns=3, st_ctime_ns=4, st_size=5)
        with patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'stat', return_value=info), \
                patch.object(Path, 'read_text', side_effect=PermissionError('SECRET')), \
                patch.object(host.shutil, 'which', return_value='/usr/bin/sudo'), \
                patch.object(host.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=42)) as group:
            events = []
            confirm = Mock(side_effect=lambda message: events.append('confirm'))
            command = Mock(side_effect=lambda *args, **kwargs: events.append('sudo'))
            self.assertEqual(host.qemu_group(command=command, confirm=confirm), 42)
            self.assertEqual(events, ['confirm', 'sudo'])
            argv = command.call_args.args[0]
            self.assertEqual(argv[:5], ['sudo', '--', '/usr/bin/python3', '-I', '-c'])
            self.assertEqual(argv[5], host.QEMU_INSPECT)
            self.assertEqual(argv[6:], ['1', '2', '3', '4', '5'])
            self.assertEqual(command.call_args.kwargs, {'capture': False, 'timeout': None})
            group.reset_mock()
            command.reset_mock()
            confirm.side_effect = images.E2EError('declined')
            with self.assertRaisesRegex(ValueError, 'declined'):
                host.qemu_group(command=command, confirm=confirm)
            command.assert_not_called()
            group.assert_not_called()
            confirm.side_effect = None
            command.side_effect = images.E2EError('sudo failed')
            with self.assertRaisesRegex(ValueError, 'sudo failed'):
                host.qemu_group(command=command, confirm=confirm)
            group.assert_not_called()

    def test_privileged_qemu_inspector_validates_identity_metadata_and_snapshot(self):
        # Execute the exact privileged payload offline with only synthetic files.
        for text, unsafe, changed, expected in (
                ('# user = "custom"\n', False, False, 0),
                ('user = "libvirt-qemu"\ngroup = "libvirt-qemu"', False, False, 0),
                ('user = "custom"', False, False, 1),
                ('group = "root"', False, False, 1),
                ('user = "libvirt-qemu"\nuser = "libvirt-qemu"', False, False, 1),
                ('', True, False, 1), ('', False, True, 1)):
            with self.subTest(text=text, unsafe=unsafe, changed=changed), tempfile.TemporaryFile(mode='w+') as stream:
                stream.write(text)
                stream.seek(0)
                info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | (0o666 if unsafe else 0o600),
                                       st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4, st_size=5)
                final = SimpleNamespace(**vars(info))
                if changed:
                    final.st_ino = 99
                duplicate = os.dup(stream.fileno())
                with patch.object(os, 'open', return_value=duplicate) as opening, \
                        patch.object(os, 'fstat', return_value=info), patch.object(os, 'stat', return_value=final), \
                        patch.object(sys, 'argv', ['-c', '1', '2', '3', '4', '5']), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    code = 0
                    try:
                        exec(host.QEMU_INSPECT, {})
                    except SystemExit as error:
                        code = error.code
                    self.assertEqual(code, expected)
                    if text.strip():
                        self.assertNotIn(text.strip(), output.getvalue())
                    opening.assert_called_once_with('/etc/libvirt/qemu.conf', os.O_RDONLY | os.O_NOFOLLOW)

    def test_cli_lock_failure_reports_safe_os_cause_and_never_prepares(self):
        for code, label in ((errno.EROFS, 'EROFS'), (errno.EACCES, 'EACCES'), (errno.EPERM, 'EPERM'),
                            (errno.ENOENT, 'ENOENT'), (errno.EIO, 'EIO')):
            with self.subTest(code=code), patch.object(e2e, 'Stand') as stand, \
                    patch.object(e2e, 'stand_lock', side_effect=OSError(code, 'SECRET\x1b[31m', '/private/path')), \
                    patch.object(sys, 'argv', ['e2e.py', 'prepare']), \
                    contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(e2e.main(), 1)
                self.assertIn('E2E STOP (fixture lock)', errors.getvalue())
                self.assertIn(label, errors.getvalue())
                self.assertNotIn('SECRET', errors.getvalue())
                self.assertNotIn('/private/path', errors.getvalue())
                stand.return_value.prepare.assert_not_called()

    def test_error_categories_hide_process_payloads(self):
        for error, expected in ((subprocess.TimeoutExpired(['SECRET'], 1, output='SECRET'), 'timed out'),
                                (ValueError('SECRET'), 'Prerequisite'), (EOFError('SECRET'), 'cancelled'),
                                (KeyboardInterrupt('SECRET'), 'cancelled')):
            with self.subTest(error=type(error).__name__):
                reason = e2e.error_reason(error)
                self.assertIn(expected, reason)
                self.assertNotIn('SECRET', reason)

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


class RebootTests(unittest.TestCase):
    GNOME = {'XDG_CURRENT_DESKTOP': 'ubuntu:GNOME', 'XDG_SESSION_TYPE': 'wayland',
             'WAYLAND_DISPLAY': 'wayland-0', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/mock/bus'}

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(host.sys.stdin, 'isatty', return_value=True))
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(patch.object(host.os, 'getuid', return_value=1000))
        self.stack.enter_context(patch.object(host.platform, 'system', return_value='Linux'))
        self.stack.enter_context(patch.object(Path, 'is_dir', return_value=True))
        self.which = self.stack.enter_context(patch.object(host.shutil, 'which', return_value='/mock/systemctl'))
        self.run = self.stack.enter_context(patch.object(host.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='')))

    def interact(self, answers):
        with patch('builtins.input', side_effect=answers):
            host.offer_reboot()
        self.assertIn('make e2e-prepare', self.output.getvalue())
        self.assertNotIn('E2E STOP', self.output.getvalue())

    def test_later_and_default_do_not_reboot(self):
        for answer in ('2', ''):
            self.interact([answer])
        self.run.assert_not_called()

    def test_invalid_selection_reprompts(self):
        self.interact(['bad', '2'])
        self.run.assert_not_called()

    def test_now_requires_final_default_deny_confirmation(self):
        for answer in ('', 'n', 'YES PLEASE'):
            self.interact(['1', answer])
        self.run.assert_not_called()
        self.assertIn('unsaved data', self.output.getvalue())

    def test_now_warns_before_consent_and_requests_native_reboot(self):
        def answer(prompt):
            if '[y/N]' in prompt:
                self.assertIn('unsaved data', self.output.getvalue())
                self.assertIn('After rebooting, run: make e2e-prepare', self.output.getvalue())
                self.run.assert_not_called()
                return 'y'
            return '1'
        with patch('builtins.input', side_effect=answer):
            host.offer_reboot()
        self.assertEqual(self.run.call_args.args[0], ['/mock/systemctl', '--check-inhibitors=yes', '--no-ask-password', 'reboot'])
        self.assertEqual(self.run.call_args.kwargs['timeout'], 30)
        self.run.assert_called_once()
        self.assertIn('Reboot requested', self.output.getvalue())
        self.assertIn('[1] Reboot now (recommended)', self.output.getvalue())

    def test_root_does_not_bypass_system_authorization(self):
        with patch.object(host.os, 'getuid', return_value=0):
            self.interact(['1', 'y'])
        self.run.assert_not_called()

    def test_local_gnome_reboots_via_session_manager_on_x11_and_wayland(self):
        for session, display in (('x11', 'DISPLAY'), ('wayland', 'WAYLAND_DISPLAY')):
            with self.subTest(session=session), patch.dict(os.environ, dict(self.GNOME, XDG_SESSION_TYPE=session,
                                                                           **{display: ':mock'})):
                self.run.reset_mock()
                self.which.reset_mock()
                self.which.side_effect = lambda name: '/mock/' + name
                self.interact(['1', 'y'])
                self.which.assert_called_once_with('gnome-session-quit')
                self.run.assert_called_once()
                self.assertEqual(self.run.call_args.args[0], ['/mock/gnome-session-quit', '--reboot'])
                self.assertEqual(self.run.call_args.kwargs['env']['DBUS_SESSION_BUS_ADDRESS'], self.GNOME['DBUS_SESSION_BUS_ADDRESS'])
                self.assertEqual(self.run.call_args.kwargs['env']['LC_ALL'], 'C')
        self.assertIn('complete any desktop confirmation', self.output.getvalue())

    def test_gnome_identity_is_exact_and_session_desktop_is_only_a_fallback(self):
        for desktop, session_desktop, expected in (('ubuntu:GNOME', '', 'gnome-session-quit'),
                                                  ('', 'gnome', 'gnome-session-quit'),
                                                  ('NOTGNOME', 'gnome', 'systemctl'),
                                                  ('KDE', 'gnome', 'systemctl')):
            with self.subTest(desktop=desktop), patch.dict(os.environ, dict(self.GNOME,
                    XDG_CURRENT_DESKTOP=desktop, XDG_SESSION_DESKTOP=session_desktop)):
                self.which.reset_mock()
                self.interact(['1', 'y'])
                self.which.assert_called_once_with(expected)

    def test_incomplete_gnome_never_falls_through_to_systemctl(self):
        for changes in ({'XDG_SESSION_TYPE': 'tty'}, {'XDG_SESSION_TYPE': 'unknown'},
                        {'WAYLAND_DISPLAY': ''}, {'DBUS_SESSION_BUS_ADDRESS': ''},
                        {'DBUS_SESSION_BUS_ADDRESS': 'tcp:host=remote,port=1234'},
                        {'XDG_SESSION_TYPE': 'x11', 'DISPLAY': ''}):
            with self.subTest(changes=changes), patch.dict(os.environ, dict(self.GNOME, **changes)):
                self.interact(['1', 'y'])
        with patch.dict(os.environ, self.GNOME):
            self.which.return_value = None
            self.interact(['1', 'y'])
        self.run.assert_not_called()
        self.assertIn('GNOME needs a local X11/Wayland display and session bus', self.output.getvalue())
        self.assertIn('gnome-session-quit is not installed', self.output.getvalue())

    def test_other_linux_systemd_sessions_preserve_inhibitors(self):
        for session in ('', 'tty', 'x11', 'wayland'):
            with self.subTest(session=session), patch.dict(os.environ, XDG_CURRENT_DESKTOP='KDE', XDG_SESSION_TYPE=session):
                self.run.reset_mock()
                self.interact(['1', 'y'])
                self.run.assert_called_once()
                self.assertEqual(self.run.call_args.args[0],
                                 ['/mock/systemctl', '--check-inhibitors=yes', '--no-ask-password', 'reboot'])

    def test_non_linux_or_non_systemd_or_unknown_session_is_manual(self):
        with patch.object(host.platform, 'system', return_value='Darwin'):
            self.interact(['1', 'y'])
        with patch.object(Path, 'is_dir', return_value=False):
            self.interact(['1', 'y'])
        with patch.dict(os.environ, XDG_SESSION_TYPE='unknown'):
            self.interact(['1', 'y'])
        with patch.object(host.platform, 'freedesktop_os_release') as release:
            host.reboot_command()
            release.assert_not_called()
        self.run.assert_not_called()

    def test_unsupported_or_remote_session_falls_back_manually(self):
        for env in ({'SSH_CONNECTION': 'mock'}, {'SSH_CLIENT': 'mock'}, {'SSH_TTY': '/mock'},
                    {'XDG_SESSION_REMOTE': '1'}, {'XDG_SESSION_REMOTE': 'yes'}, {'XDG_SESSION_REMOTE': 'unknown'}):
            with patch.dict(os.environ, dict(self.GNOME, **env)):
                self.interact(['1', 'yes'])
        self.which.return_value = None
        self.interact(['1', 'y'])
        self.run.assert_not_called()
        self.assertIn('Automatic reboot unavailable:', self.output.getvalue())

    def test_diagnostics_are_short_static_and_never_echo_sensitive_output(self):
        cases = [('Operation inhibited by GNOME shutdown/block', 'session/application inhibitor'),
                 ('Access denied', 'system authorization denied'),
                 ('Interactive authentication required', 'interactive authentication'),
                 ('Unknown option --check-inhibitors', 'does not support'),
                 ('Could not connect to the session manager', 'service unavailable'),
                 ('org.freedesktop.DBus.Error.ServiceUnknown', 'service unavailable'),
                 ('Something unexpected', 'unrecognized diagnostic'), ('', 'exited unsuccessfully')]
        for diagnostic, expected in cases:
            with self.subTest(diagnostic=diagnostic):
                self.run.reset_mock()
                self.output.seek(0)
                self.output.truncate()
                self.run.return_value = SimpleNamespace(returncode=1,
                    stderr=diagnostic + ('\n\x1b[31mSECRET-user/private/path\x07' if diagnostic else ''))
                self.interact(['1', 'y'])
                output = self.output.getvalue()
                self.assertIn(expected, output)
                self.assertNotIn('SECRET', output)
                self.assertNotIn('\x1b', output)
                self.assertNotIn('\x07', output)
                self.assertLess(len(output), 1000)
                self.run.assert_called_once()

    def test_gnome_zero_exit_with_error_is_unconfirmed_without_second_backend(self):
        self.run.return_value = SimpleNamespace(returncode=0, stderr='Could not connect to the session manager')
        with patch.dict(os.environ, self.GNOME):
            self.which.return_value = '/mock/gnome-session-quit'
            self.interact(['1', 'y'])
        self.run.assert_called_once()
        self.which.assert_called_once_with('gnome-session-quit')
        self.assertIn('unconfirmed (exit status 0)', self.output.getvalue())
        self.assertNotIn('Reboot requested', self.output.getvalue())

    def test_each_backend_error_has_no_retry_or_backend_switch(self):
        for desktop in ('GNOME', 'KDE'):
            for failure in (FileNotFoundError('SECRET'), PermissionError('SECRET'),
                            subprocess.TimeoutExpired('SECRET', 30, stderr='SECRET'), KeyboardInterrupt(),
                            UnicodeDecodeError('utf8', b'\xff', 0, 1, 'SECRET')):
                with self.subTest(desktop=desktop, failure=type(failure).__name__), \
                        patch.dict(os.environ, dict(self.GNOME, XDG_CURRENT_DESKTOP=desktop)):
                    self.run.reset_mock()
                    self.which.reset_mock()
                    self.run.side_effect = failure
                    self.interact(['1', 'y'])
                    self.run.assert_called_once()
                    self.which.assert_called_once()
                    self.assertNotIn('SECRET', self.output.getvalue())
        self.assertIn('request timed out', self.output.getvalue())
        self.assertIn('request interrupted', self.output.getvalue())
        self.assertIn('no longer available', self.output.getvalue())
        self.assertIn('permission to execute', self.output.getvalue())

    def test_reboot_errors_are_manual_without_retry(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired('mock', 30),
                      subprocess.CalledProcessError(1, 'mock'), KeyboardInterrupt()):
            self.run.side_effect = error
            self.interact(['1', 'y'])
        self.run.side_effect = None
        self.run.return_value.returncode = 1
        self.interact(['1', 'y'])
        self.assertEqual(self.run.call_count, 5)
        self.assertIn('Restart the system manually', self.output.getvalue())

    def test_non_tty_and_interrupted_input_are_safe(self):
        with patch.object(host.sys.stdin, 'isatty', return_value=False), patch('builtins.input') as read:
            host.offer_reboot()
            read.assert_not_called()
        for answers in ([EOFError()], [KeyboardInterrupt()], ['1', EOFError()], ['1', KeyboardInterrupt()]):
            self.interact(answers)
        self.run.assert_not_called()

    def test_prepare_returns_before_fixture_or_vm_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            stand = e2e.Stand(Path(directory) / 'fixture')
            with patch.object(host, 'prepare', return_value=host.PreparationResult.REBOOT_REQUIRED), \
                    patch.object(e2e, 'command') as command, patch.object(e2e, 'confirm') as confirm:
                self.assertIs(stand.prepare(), host.PreparationResult.REBOOT_REQUIRED)
            command.assert_not_called()
            confirm.assert_not_called()
            self.assertFalse(stand.root.exists())
            self.assertIsNone(stand.state)

    def test_cli_pending_is_success_and_releases_lock_before_menu(self):
        locked = False

        @contextlib.contextmanager
        def lock(*args):
            nonlocal locked
            locked = True
            yield
            locked = False

        def menu():
            self.assertFalse(locked)

        with patch.object(e2e, 'Stand') as stand, patch.object(e2e, 'stand_lock', side_effect=lock), \
                patch.object(host, 'offer_reboot', side_effect=menu) as offer_reboot, \
                patch.object(sys, 'argv', ['e2e.py', 'prepare']), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            stand.return_value.prepare.return_value = host.PreparationResult.REBOOT_REQUIRED
            self.assertEqual(e2e.main(), 0)
        offer_reboot.assert_called_once()
        self.assertEqual(errors.getvalue(), '')

    def test_cli_ready_or_failed_preparation_never_offers_reboot(self):
        for failure in (False, True):
            with self.subTest(failure=failure), patch.object(e2e, 'Stand') as stand, \
                    patch.object(e2e, 'stand_lock', return_value=contextlib.nullcontext()), \
                    patch.object(host, 'offer_reboot') as offer, \
                    patch.object(sys, 'argv', ['e2e.py', 'prepare']), \
                    contextlib.redirect_stderr(io.StringIO()):
                stand.return_value.prepare.return_value = host.PreparationResult.READY
                if failure:
                    stand.return_value.prepare.side_effect = e2e.E2EError('Group configuration failed')
                self.assertEqual(e2e.main(), int(failure))
                offer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
