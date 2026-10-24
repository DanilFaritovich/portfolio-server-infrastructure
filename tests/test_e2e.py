"""Offline libvirt ownership and lifecycle contracts; no real VM/SSH probes."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import xml.etree.ElementTree as ET

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from portfolio_cli import e2e, plans

CONFIRM = e2e.confirm


class StandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stand = e2e.Stand(self.base / '.local/share/portfolio-e2e')
        self.stand.storage = self.base / 'storage'
        self.stand.root.mkdir(mode=0o700, parents=True)
        self.stand.storage.mkdir(mode=0o700)
        self.state = dict(schema=1, uuid='d52aa4d9-889d-448f-847c-762868428aa6',
                          network_uuid='aa62ef32-d95b-4bc7-b35f-9e72984b2ec8',
                          phase='ready', subnet='192.168.231.0/24', mac='52:54:00:11:22:33',
                          cpus=2, memory=4096, size=25)
        e2e.write_new(self.stand.root / 'state.json', json.dumps(self.state))
        self.stand.load()
        e2e.write_new(self.stand.disk, 'synthetic disk')
        e2e.write_new(self.stand.seed, 'synthetic seed')
        self.domain = ET.Element('domain', type='kvm')
        ET.SubElement(self.domain, 'uuid').text = self.state['uuid']
        ET.SubElement(self.domain, 'name').text = self.stand.name
        ET.SubElement(self.domain, 'metadata').append(self.stand.metadata())
        devices = ET.SubElement(self.domain, 'devices')
        for path, target, device, fmt in ((self.stand.disk, 'vda', 'disk', 'qcow2'), (self.stand.seed, 'sda', 'cdrom', 'raw')):
            disk = ET.SubElement(devices, 'disk', type='file', device=device)
            ET.SubElement(disk, 'source', file=str(path))
            ET.SubElement(disk, 'target', dev=target)
            ET.SubElement(disk, 'driver', type=fmt)
            if device == 'cdrom':
                ET.SubElement(disk, 'readonly')
        interface = ET.SubElement(devices, 'interface', type='network')
        ET.SubElement(interface, 'source', network=self.stand.name)
        ET.SubElement(interface, 'mac', address=self.state['mac'])
        self.network = ET.Element('network')
        ET.SubElement(self.network, 'uuid').text = self.state['network_uuid']
        ET.SubElement(self.network, 'name').text = self.stand.name
        ET.SubElement(self.network, 'metadata').append(self.stand.metadata())
        ET.SubElement(self.network, 'forward', mode='nat')
        ET.SubElement(self.network, 'bridge', name='virbr-e2e')
        ip = ET.SubElement(self.network, 'ip', address='192.168.231.1', netmask='255.255.255.0')
        ET.SubElement(ET.SubElement(ip, 'dhcp'), 'host', mac=self.state['mac'], ip=self.stand.ip)
        self.snapshot = ET.Element('domainsnapshot')
        ET.SubElement(self.snapshot, 'name').text = 'baseline'
        ET.SubElement(self.snapshot, 'state').text = 'shutoff'
        ET.SubElement(self.snapshot, 'memory', snapshot='no')
        disks = ET.SubElement(self.snapshot, 'disks')
        ET.SubElement(disks, 'disk', name='vda', snapshot='internal')
        ET.SubElement(disks, 'disk', name='sda', snapshot='no')
        self.snapshot.append(ET.fromstring(e2e.xml_text(self.domain)))
        self.calls = []
        self.vm_state = 'running'
        self.domains = [self.state['uuid']]
        self.networks = [self.state['network_uuid']]
        self.snapshots = ['baseline']
        self.mock = patch.object(e2e, 'virsh', side_effect=self.virsh)
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.commands = patch.object(e2e, 'command', side_effect=self.command)
        self.commands.start()
        self.addCleanup(self.commands.stop)
        self.plan_input = patch('builtins.input', return_value='y')
        self.plan_input.start()
        self.addCleanup(self.plan_input.stop)
        self.plan_tty = patch.object(sys.stdin, 'isatty', return_value=True)
        self.plan_tty.start()
        self.addCleanup(self.plan_tty.stop)
        self.confirm = patch.object(e2e, 'confirm')
        self.confirm.start()
        self.addCleanup(self.confirm.stop)

    def command(self, args, **kwargs):
        if args[:2] == ['qemu-img', 'info']:
            return '{"format":"qcow2"}'
        return '[{"dev":"virbr-e2e"}]'

    def virsh(self, *args):
        self.calls.append(args)
        mode = args[0]
        if mode == 'list':
            return '\n'.join(self.domains)
        if mode == 'net-list':
            return '\n'.join(self.networks)
        if mode == 'dumpxml':
            return e2e.xml_text(self.domain)
        if mode == 'net-dumpxml':
            return e2e.xml_text(self.network)
        if mode == 'domstate':
            return self.vm_state
        if mode == 'snapshot-list':
            return '\n'.join(self.snapshots)
        if mode == 'snapshot-dumpxml':
            return e2e.xml_text(self.snapshot)
        if mode == 'net-dhcp-leases':
            return '52:54:00:11:22:33 ipv4 192.168.231.10/24'
        if mode == 'shutdown':
            self.vm_state = 'shut off'
        if mode == 'start':
            self.vm_state = 'running'
        if mode == 'snapshot-delete':
            self.snapshots.remove(args[2])
        if mode == 'undefine':
            self.domains = []
        if mode == 'net-undefine':
            self.networks = []
        return ''

    def mutations(self):
        readonly = {'list', 'net-list', 'dumpxml', 'net-dumpxml', 'domstate', 'snapshot-list', 'snapshot-dumpxml', 'net-dhcp-leases'}
        return [args for args in self.calls if args[0] not in readonly]

    def test_existing_prepare_is_readonly_preserves_disks(self):
        before = self.stand.disk.stat().st_mtime_ns
        with contextlib.redirect_stdout(io.StringIO()), patch.object(e2e, 'command') as run:
            self.stand.prepare()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(before, self.stand.disk.stat().st_mtime_ns)
        run.assert_not_called()

    def test_existing_distro_change_blocks_without_host_preparation(self):
        with patch.dict(os.environ, E2E_DISTRO='ubuntu-22.04'), patch.object(e2e.e2e_host, 'prepare') as host:
            with self.assertRaisesRegex(ValueError, 'distro differs'):
                self.stand.prepare()
            host.assert_not_called()
        self.assertFalse(self.mutations())

    def test_schema2_keeps_recorded_distro_when_selection_omitted(self):
        self.state.update(schema=2, distro='ubuntu-22.04')
        (self.stand.root / 'state.json').write_text(json.dumps(self.state))
        with patch.dict(os.environ, E2E_DISTRO=''), patch.object(e2e.e2e_host, 'prepare') as host, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.stand.prepare()
            host.assert_not_called()
        self.assertIn('ubuntu-22.04', output.getvalue())
        self.assertFalse(self.mutations())

    def test_invalid_recorded_distro_blocks(self):
        for distro in ('unknown', '', None):
            self.state.update(schema=2, distro=distro)
            (self.stand.root / 'state.json').write_text(json.dumps(self.state))
            with self.assertRaises(ValueError):
                self.stand.load()

    def test_partial_prepare_stops_without_recreation(self):
        self.state['phase'] = 'preparing'
        (self.stand.root / 'state.json').write_text(json.dumps(self.state))
        with self.assertRaisesRegex(ValueError, 'Partial'), patch.object(e2e, 'command') as run:
            self.stand.prepare()
        run.assert_not_called()
        self.assertFalse(self.mutations())

    def test_unjournaled_directory_and_existing_storage_never_overwritten(self):
        (self.stand.root / 'state.json').unlink()
        with self.assertRaisesRegex(ValueError, 'without state'):
            self.stand.prepare()
        self.assertFalse(self.calls)
        self.assertEqual(self.stand.disk.read_text(), 'synthetic disk')

    def test_missing_resource_not_recreated(self):
        self.domains = []
        with self.assertRaisesRegex(ValueError, 'missing'):
            self.stand.prepare()
        self.assertFalse(self.mutations())

    def test_uuid_metadata_path_and_network_conflicts_stop_mutations(self):
        cases = [('uuid', self.domain.find('uuid'), None, 'wrong'),
                 ('metadata', self.domain.find('metadata/{' + e2e.NS + '}owner'), 'uuid', 'wrong'),
                 ('path', self.domain.find('devices/disk/source'), 'file', '/production/foreign.qcow2'),
                 ('network', self.network.find('uuid'), None, 'wrong')]
        for name, node, attribute, value in cases:
            with self.subTest(name=name):
                old = node.get(attribute) if attribute else node.text
                if attribute:
                    node.set(attribute, value)
                else:
                    node.text = value
                with self.assertRaises(ValueError):
                    self.stand.delete()
                self.assertFalse(self.mutations())
                if attribute:
                    node.set(attribute, old)
                else:
                    node.text = old

    def test_libvirt_query_failure_is_not_absence(self):
        with patch.object(e2e, 'virsh', side_effect=e2e.E2EError('query failed')):
            with self.assertRaisesRegex(ValueError, 'query failed'):
                self.stand.delete()
        self.assertTrue(self.stand.disk.exists())

    def test_reset_orders_shutdown_revert_start(self):
        self.stand.reset()
        self.assertEqual([x[0] for x in self.mutations()], ['shutdown', 'snapshot-revert', 'start'])

    def test_reset_decline_and_failed_shutdown_do_not_revert(self):
        with patch.object(e2e, 'confirm', side_effect=e2e.E2EError('declined')):
            with self.assertRaises(ValueError):
                self.stand.reset()
        self.assertFalse(self.mutations())
        self.vm_state = 'paused'
        with self.assertRaisesRegex(ValueError, 'not stopped'):
            self.stand.reset()
        self.assertFalse(self.mutations())

    def test_unsupported_snapshot_backend_blocks_reset_delete(self):
        self.snapshot.find('disks/disk').set('snapshot', 'external')
        for method in (self.stand.reset, self.stand.delete):
            with self.assertRaisesRegex(ValueError, 'External'):
                method()
        self.assertFalse(self.mutations())

    def test_delete_owned_resources_only(self):
        foreign = self.base / 'unrelated.qcow2'
        foreign.write_text('preserve')
        self.stand.delete()
        self.assertEqual([x[0] for x in self.mutations()], ['shutdown', 'snapshot-delete', 'undefine', 'net-destroy', 'net-undefine'])
        self.assertFalse(self.stand.root.exists())
        self.assertFalse(self.stand.storage.exists())
        self.assertEqual(foreign.read_text(), 'preserve')

    def test_delete_partial_without_domain_removes_only_fixture(self):
        self.domains = []
        self.stand.delete()
        self.assertNotIn('undefine', [x[0] for x in self.mutations()])

    def fixture_key(self, relative, mode):
        path = self.stand.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.stand.root:
                break
            parent.chmod(0o700)
        path.write_text('synthetic key material, never diagnostic output')
        path.chmod(mode)
        return path

    def test_delete_accepts_standard_public_keys_in_test_key_directories(self):
        for directory in ('controller', 'human', 'portfolio-infra'):
            self.fixture_key(f'home/.ssh/{directory}/test_ed25519', 0o600)
            self.fixture_key(f'home/.ssh/{directory}/test_ed25519.pub', 0o644)
        self.stand.delete()
        self.assertFalse(self.stand.root.exists())
        self.assertFalse(self.stand.storage.exists())

    def test_delete_public_key_exception_is_narrow_and_precedes_mutation(self):
        cases = [('home/.ssh/human/key.pub', mode) for mode in (0o622, 0o664, 0o666, 0o755, 0o4644)]
        cases += [(name, 0o644) for name in (
            'home/.ssh/human/private_key', 'home/.ssh/known_hosts', 'state-copy.json',
            'home/.ssh/unknown/key.pub', 'home/.ssh/key.pub', 'home/key.pub',
            'home/.ssh/human/nested/key.pub')]
        for relative, mode in cases:
            with self.subTest(path=relative, mode=oct(mode)):
                path = self.fixture_key(relative, mode)
                with self.assertRaisesRegex(e2e.E2EPathError, 'ownership/mode') as raised:
                    self.stand.delete()
                self.assertEqual(raised.exception.path, str(path))
                self.assertIn(json.dumps(str(path)), e2e.error_reason(raised.exception))
                self.assertNotIn('synthetic key material', e2e.error_reason(raised.exception))
                self.assertFalse(self.mutations())
                e2e.confirm.assert_not_called()
                path.unlink()

    def test_public_key_exception_preserves_owner_link_and_private_checks(self):
        path = self.fixture_key('home/.ssh/human/test.pub', 0o644)
        info = path.lstat()
        foreign = SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1,
                                  st_gid=info.st_gid, st_nlink=1)
        with patch.object(Path, 'lstat', return_value=foreign), \
                self.assertRaisesRegex(e2e.E2EPathError, 'ownership/mode'):
            e2e.safe_path(path, public_key=True)
        # The generic validator remains private by default, including .pub files.
        with self.assertRaises(e2e.E2EPathError):
            e2e.safe_path(path)
        link = path.with_name('hardlink.pub')
        os.link(path, link)
        with self.assertRaises(e2e.E2EPathError):
            self.stand.delete()
        link.unlink()
        link.symlink_to(path)
        with self.assertRaisesRegex(e2e.E2EPathError, 'Unsafe E2E path'):
            self.stand.delete()
        link.unlink()
        directory_link = path.parent.with_name('portfolio-infra')
        directory_link.symlink_to(path.parent, target_is_directory=True)
        with self.assertRaisesRegex(e2e.E2EPathError, 'Unsafe E2E path'):
            self.stand.delete()
        self.assertFalse(self.mutations())
        e2e.confirm.assert_not_called()

    def test_path_diagnostics_escape_terminal_controls(self):
        path = self.fixture_key('home/.ssh/human/bad\n\x1b[31m.pub', 0o666)
        with self.assertRaises(e2e.E2EPathError) as raised:
            self.stand.deletion_paths()
        reason = e2e.error_reason(raised.exception)
        self.assertIn(json.dumps(str(path)), reason)
        self.assertNotIn('\n', reason)
        self.assertNotIn('\x1b', reason)

    def test_protected_storage_removal_uses_confirmed_sudo_with_state_retained(self):
        def remove(argv, **kwargs):
            self.assertEqual(argv, ['sudo', '--', 'rmdir', '--', str(self.stand.storage)])
            self.assertTrue((self.stand.root / 'state.json').exists())
            self.assertFalse(any(self.stand.storage.iterdir()))
            self.stand.storage.rmdir()
        with patch.object(e2e.os, 'access', return_value=False), \
                patch.object(e2e.e2e_host, 'storage_parents') as parents, \
                patch.object(e2e.e2e_host.shutil, 'which', return_value='/usr/bin/sudo'), \
                patch.object(e2e, 'confirm') as consent, patch.object(e2e, 'command', side_effect=remove) as run:
            self.domains = []
            self.stand.delete()
        self.assertEqual(consent.call_count, 1)
        self.assertEqual(parents.call_count, 2)
        run.assert_called_once()
        self.assertFalse(self.stand.root.exists())

    def test_protected_storage_sudo_decline_precedes_mutation(self):
        with patch.object(e2e.os, 'access', return_value=False), \
                patch.object(e2e.e2e_host, 'storage_parents'), \
                patch.object(e2e.e2e_host.shutil, 'which', return_value='/usr/bin/sudo'), \
                patch.object(e2e, 'confirm', side_effect=ValueError('declined')):
            with self.assertRaisesRegex(ValueError, 'declined'):
                self.stand.delete()
        self.assertFalse(self.mutations())
        self.assertTrue(self.stand.disk.exists())
        self.assertTrue((self.stand.root / 'state.json').exists())

    def test_failed_storage_removal_preserves_controller_evidence(self):
        original = Path.rmdir
        def fail(path):
            if path == self.stand.storage:
                raise PermissionError('synthetic protected parent')
            original(path)
        with patch.object(Path, 'rmdir', fail), self.assertRaises(PermissionError):
            self.stand.delete()
        self.assertTrue((self.stand.root / 'state.json').exists())
        self.assertTrue(self.stand.storage.exists())
        self.assertFalse(any(self.stand.storage.iterdir()))

    def test_delete_symlink_hardlink_unknown_storage_stops_before_shutdown(self):
        outside = self.base / 'outside'
        outside.write_text('preserve')
        for kind in ('symlink', 'hardlink', 'unknown'):
            with self.subTest(kind=kind):
                path = self.stand.storage / 'unknown'
                if kind == 'symlink':
                    path.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, path)
                else:
                    path.write_text('unknown')
                with self.assertRaises(ValueError):
                    self.stand.delete()
                path.unlink()
                self.assertFalse(self.mutations())
        self.assertEqual(outside.read_text(), 'preserve')

    def test_production_inventory_and_drift_block_before_cli(self):
        production = self.base / 'production.yml'
        production.write_text('never read')
        with self.assertRaisesRegex(ValueError, 'Production'):
            self.stand.check_inventory(production)
        inventory = self.stand.expected_inventory()
        inventory['all']['children']['bootstrap']['hosts']['e2e']['ansible_host'] = '203.0.113.9'
        e2e.write_new(self.stand.inventory, yaml.safe_dump(inventory))
        with patch.object(e2e, 'command') as run:
            with self.assertRaisesRegex(ValueError, 'drift'):
                self.stand.cli('init-server')
        run.assert_not_called()

    def test_child_uses_only_isolated_inputs(self):
        with patch.dict(os.environ, {'INVENTORY': '/production', 'ANSIBLE_CONFIG': '/foreign', 'HUMAN_KEY': '/production/key'}):
            env = self.stand.child_env()
        self.assertEqual(env['INVENTORY'], str(self.stand.inventory))
        self.assertNotIn('/production', json.dumps(env))
        self.assertEqual(env['HOME'], str(self.stand.root / 'home'))

    def test_standalone_readiness_requires_configured_vm_and_both_admins(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        with patch.object(e2e.sys.stdin, 'isatty', return_value=True), \
                patch.object(self.stand, 'independent') as independent, patch.object(self.stand, 'cli') as cli:
            self.stand.standalone_ready()
            independent.assert_called_once()
            self.assertEqual(cli.call_args.args, ('verify-user',))
            self.assertEqual(cli.call_args.kwargs['user_inputs']['HUMAN_USER'], 'e2e_admin')
            with patch.object(e2e.sys.stdin, 'isatty', return_value=False), self.assertRaises(ValueError):
                self.stand.standalone_ready()
            cli.reset_mock()
            self.domain.find('uuid').text = 'foreign'
            with self.assertRaises(ValueError):
                self.stand.standalone_ready()
            cli.assert_not_called()

    def test_standalone_swap_transitions_and_two_persistence_proofs(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        with patch.object(self.stand, 'standalone_ready') as readiness, \
                patch.object(self.stand, 'cli') as cli, \
                patch.object(self.stand, 'swap_file_retained') as retained, \
                patch.object(self.stand, 'independent', side_effect=['a', 'b', 'c', 'd']):
            self.stand.test_swap()
        self.assertEqual(readiness.call_count, 2)
        self.assertEqual(retained.call_count, 2)
        expected = []
        for index, size in enumerate((512, 1024, 0, 512)):
            expected.extend([(('setup-swap',), dict(swap_size=size)),
                             (('verify-swap',), dict(swap_size=size)),
                             (('setup-swap',), dict(unchanged=True, swap_size=size)),
                             (('verify-swap',), dict(swap_size=size))])
            if index in (2, 3):
                expected.extend([(('reboot-host',), dict(swap_size=size)),
                                 (('verify-swap',), dict(swap_size=size)),
                                 (('setup-swap',), dict(unchanged=True, swap_size=size)),
                                 (('verify-swap',), dict(swap_size=size))])
        self.assertEqual([(c.args, c.kwargs) for c in cli.call_args_list], expected)
        self.assertFalse(self.mutations())

    def test_standalone_swap_stops_at_every_failed_step_without_reset(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        for failure in range(24):
            calls = []

            def dispatch(*args, **kwargs):
                calls.append((args, kwargs))
                if len(calls) == failure + 1:
                    raise e2e.E2EError('synthetic failure')

            with self.subTest(step=failure), patch.object(self.stand, 'standalone_ready'), \
                    patch.object(self.stand, 'cli', side_effect=dispatch), \
                    patch.object(self.stand, 'swap_file_retained'), \
                    patch.object(self.stand, 'independent', side_effect=['a', 'b', 'c', 'd']):
                with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                    self.stand.test_swap()
            self.assertEqual(len(calls), failure + 1)
            self.assertFalse(self.mutations())

    def test_standalone_swap_unchanged_boot_id_stops_before_reenable(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        with patch.object(self.stand, 'standalone_ready'), patch.object(self.stand, 'cli') as cli, \
                patch.object(self.stand, 'swap_file_retained'), \
                patch.object(self.stand, 'independent', return_value='same'):
            with self.assertRaisesRegex(ValueError, 'boot ID unchanged'):
                self.stand.test_swap()
        self.assertEqual(cli.call_args.args, ('verify-swap',))
        self.assertEqual(cli.call_args.kwargs['swap_size'], 0)
        self.assertFalse(self.mutations())

    def user_scenario(self, *, failure=None, bad_inspection=False, ssh_failure=None,
                      list_drift=None, list_kind='token', bad_repeat=None, home_drift=False):
        calls, accounts, removed, repeated = [], {}, {}, {}
        protected = {'name': 'ansible', 'protected': True}
        admin = {'name': 'e2e_admin', 'sudo': 'admin', 'groups': [], 'token': 'stable'}
        names = ['e2e_t_' + str(index).zfill(12) for index in (1, 2, 3)]
        list_calls = []

        def fingerprint(path):
            return 'SHA256:' + hashlib.sha256(path.name.encode()).hexdigest()[:43]

        def dispatch(mode, **kwargs):
            inputs = kwargs['user_inputs']
            name = inputs.get('HUMAN_USER')
            calls.append((mode, inputs, kwargs.get('capture', False)))
            if failure is not None and len(calls) == failure + 1:
                raise e2e.E2EError('synthetic failure')
            if mode == 'list-users':
                list_calls.append(mode)
                users = [dict(protected), dict(admin)] + list(accounts.values())
                if list_drift == len(list_calls):
                    if list_kind == 'extra':
                        users.append(dict(name='foreign', sudo='none'))
                    elif list_kind == 'missing':
                        users.pop()
                    else:
                        users[1]['token'] = 'foreign edit'
                return json.dumps({'users': users, 'changed': False})
            if mode == 'add-user' and name not in accounts:
                policy = inputs['HUMAN_SUDO']
                accounts[name] = dict(name=name, sudo=policy, groups=[], token='stable', uid=1001,
                                      commands=['ALL'] if policy == 'admin' else ['/usr/bin/id'] if policy == 'restricted' else [],
                                      keys=[{'fingerprint': fingerprint(Path(inputs['HUMAN_PUBLIC_KEY'])), 'managed': True}])
            elif mode == 'add-user-key':
                digest = fingerprint(Path(inputs['HUMAN_PUBLIC_KEY']))
                if not any(entry['fingerprint'] == digest for entry in accounts[name]['keys']):
                    accounts[name]['keys'].append({'fingerprint': digest, 'managed': True})
            elif mode == 'revoke-user-key':
                accounts[name]['keys'] = [entry for entry in accounts[name]['keys'] if entry['fingerprint'] != inputs['KEY_FINGERPRINT']]
            elif mode == 'remove-user' and name in accounts:
                del accounts[name]
                removed[name] = dict(name=name, removed=True, files_preserved=True)
            elif mode in ('show-user', 'list-user-keys'):
                data = dict(accounts.get(name, removed.get(name, {})), changed=False)
                if bad_inspection:
                    data['groups'] = ['foreign']
                return json.dumps(data)
            if mode in ('add-user', 'add-user-key', 'revoke-user-key', 'remove-user'):
                identity = mode, name, inputs.get('HUMAN_PUBLIC_KEY')
                repeated[identity] = repeated.get(identity, 0) + 1
                if mode == bad_repeat and repeated[identity] == 2:
                    if name in accounts:
                        accounts[name]['token'] = 'repeat changed state'
                    else:
                        removed[name]['unexpected'] = True

        ssh_steps, home_steps = [], []

        def probe(user, key, script, **kwargs):
            ssh_steps.append((user, key, script, kwargs))
            if ssh_failure is not None and len(ssh_steps) == ssh_failure + 1:
                raise e2e.E2EError('synthetic SSH failure')
            if kwargs.get('denied'):
                self.assertFalse(user in accounts and any(entry['fingerprint'] == fingerprint(Path(str(key) + '.pub'))
                                                         for entry in accounts[user]['keys']))
            if 'files=$(sudo -n find' in script:
                name = next(name for name in names if '/home/' + name in script)
                home_steps.append(name)
                changed = home_drift and home_steps.count(name) == 2
                return (hashlib.sha256(name.encode()).hexdigest() + '  /home/' + name + '/.portfolio-e2e-retained\n' +
                        ('b' if changed else 'a') * 64 + '  /home/' + name + '/.profile\n')
            return ''

        if not self.stand.inventory.exists():
            e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        with patch.object(self.stand, 'standalone_ready') as readiness, \
                patch.object(e2e.uuid, 'uuid4', side_effect=[SimpleNamespace(hex=name[6:]) for name in names]), \
                patch('portfolio_cli.keys.public_fingerprint', side_effect=fingerprint), \
                patch.object(self.stand, 'fixture_ssh', side_effect=probe) as ssh, \
                patch.object(self.stand, 'cli', side_effect=dispatch):
            if failure is not None or bad_inspection or ssh_failure is not None or list_drift or bad_repeat or home_drift:
                with self.assertRaises(ValueError):
                    self.stand.test_users()
                self.assertEqual(readiness.call_count, 1)
            else:
                self.stand.test_users()
                self.assertEqual(readiness.call_count, 2)
        return calls, ssh

    def test_standalone_users_owned_lifecycle_recovery_and_negative_access(self):
        calls, ssh = self.user_scenario()
        modes = [row[0] for row in calls]
        self.assertEqual(modes[0], 'list-users')
        self.assertEqual(modes.count('list-users'), 7)
        self.assertEqual(modes.count('add-user'), 6)
        self.assertEqual(modes.count('add-user-key'), 4)
        self.assertEqual(modes.count('revoke-user-key'), 2)
        self.assertEqual(modes.count('verify-user'), 6)
        self.assertEqual(modes.count('remove-user'), 6)
        policies = set()
        for mode, inputs, capture in calls:
            if mode == 'list-users':
                self.assertEqual(inputs, {})
                continue
            policies.add(inputs['HUMAN_SUDO'])
            self.assertTrue(inputs['HUMAN_USER'].startswith('e2e_t_'))
            self.assertEqual(inputs['RECOVERY_USER'], 'e2e_admin')
            self.assertEqual(inputs['RECOVERY_KEY'], str(self.stand.root / 'home/.ssh/human/admin_ed25519'))
            self.assertEqual(inputs['HUMAN_SUDO_COMMANDS'], '/usr/bin/id' if inputs['HUMAN_SUDO'] == 'restricted' else '')
            if 'HUMAN_KEY' in inputs:
                self.assertTrue(Path(inputs['HUMAN_KEY']).is_relative_to(self.stand.root / 'home/.ssh/human'))
            self.assertEqual(capture, mode in ('show-user', 'list-user-keys'))
        self.assertEqual(policies, {'admin', 'none', 'restricted'})
        denials = [c for c in ssh.call_args_list if c.kwargs.get('denied')]
        # Five denials before registration, one revoked key and five removed keys.
        self.assertEqual(len(denials), 11)
        self.assertTrue(all(c.args[0].startswith('e2e_t_') for c in denials))
        getent = [c for c in ssh.call_args_list if c.args[2].startswith('getent passwd')]
        self.assertEqual(len(getent), 6)
        self.assertTrue(all('test $? = 2' in c.args[2] for c in getent))
        self.assertEqual(sum('files=$(sudo -n find' in c.args[2] for c in ssh.call_args_list), 6)
        self.assertFalse(self.mutations())

    def test_standalone_users_failures_do_not_continue_or_reset(self):
        calls, _ = self.user_scenario()
        for index in range(len(calls)):
            with self.subTest(step=index):
                stopped, _ = self.user_scenario(failure=index)
                self.assertEqual(len(stopped), index + 1)
        stopped, _ = self.user_scenario(bad_inspection=True)
        self.assertEqual(stopped[-1][0], 'show-user')
        self.assertFalse(self.mutations())

    def test_standalone_users_protect_baseline_repeats_and_home_files(self):
        for list_drift in (2, 3, 4, 5, 6, 7):
            with self.subTest(list_drift=list_drift):
                stopped, _ = self.user_scenario(list_drift=list_drift)
                self.assertEqual(stopped[-1][0], 'list-users')
        for mode in ('add-user', 'add-user-key', 'revoke-user-key', 'remove-user'):
            with self.subTest(mode=mode):
                stopped, _ = self.user_scenario(bad_repeat=mode)
                self.assertEqual(stopped[-1][0], 'show-user')
        for list_kind in ('extra', 'missing'):
            self.user_scenario(list_drift=2, list_kind=list_kind)
        self.user_scenario(home_drift=True)
        self.assertFalse(self.mutations())

    def test_listed_users_rejects_duplicate_missing_admin_and_malformed_lists(self):
        controller = dict(name='ansible', protected=True)
        admin = dict(name='e2e_admin', sudo='admin')
        for users, changed in (([controller, admin, admin], False), ([controller], False),
                               ([dict(controller, protected=False), admin], False),
                               ([controller, dict(admin, sudo='none')], False),
                               ([controller, admin], True), ([controller, 'invalid'], False), (None, False)):
            with self.subTest(users=users, changed=changed), \
                    patch.object(self.stand, 'cli', return_value=json.dumps(dict(users=users, changed=changed))):
                with self.assertRaises(ValueError):
                    self.stand.listed_users()

    def test_user_sudo_probes_execute_safe_commands_and_reject_unexpected_results(self):
        # Execute the actual probe shell with synthetic functions, never local/guest sudo.
        name = 'e2e_t_123456789abc'
        marker = self.base / 'retained-marker'
        stub = '''fake_id() {
            if [ "$1" = -un ]; then printf '%s\\n' "$CASE_USER";
            else printf '%s\\n' "$CASE_UID"; return "$CASE_ID_RC"; fi
        }
        fake_sudo() {
            if [ "$3" = fake_id ] && [ "$CASE_POLICY" != none ]; then
                printf '0\\n'; return "$CASE_ROOT_RC"
            elif [ "$CASE_POLICY" = admin ]; then return 0
            else printf '%s\\n' "$CASE_DENIAL" >&2; return "$CASE_DENIED_RC"; fi
        }
        '''
        defaults = dict(CASE_USER=name, CASE_UID='1001', CASE_ID_RC='0', CASE_ROOT_RC='0',
                        CASE_DENIED_RC='1', CASE_DENIAL='sudo: a password is required')
        for policy in ('admin', 'none', 'restricted'):
            with patch.object(self.stand, 'fixture_ssh') as ssh:
                self.stand.user_sudo_probe(name, self.base / 'key', policy)
            script = ssh.call_args.args[2]
            self.assertNotIn('denied', ssh.call_args.kwargs)
            self.assertIn('sudo -k -n', script)
            self.assertNotIn('/bin/sh', script)
            script = script.replace('/home/' + name + '/.portfolio-e2e-retained', str(marker))
            script = script.replace('/usr/bin/id', 'fake_id').replace('id -un', 'fake_id -un').replace('sudo -k', 'fake_sudo -k')
            cases = [({}, True), ({'CASE_UID': '0'}, False), ({'CASE_ID_RC': '1'}, False),
                     ({'CASE_UID': 'unexpected'}, False), ({'CASE_UID': ''}, False)]
            if policy != 'none':
                cases.append(({'CASE_ROOT_RC': '1'}, False))
            if policy != 'admin':
                operation = '/usr/bin/id -u' if policy == 'none' else '/usr/bin/true'
                # The path above is replaced by the test transport's synthetic function.
                operation = operation.replace('/usr/bin/id', 'fake_id')
                cases.extend([({'CASE_DENIED_RC': '0'}, False), ({'CASE_DENIED_RC': '2'}, False),
                              ({'CASE_DENIAL': 'sudo: plugin error'}, False),
                              ({'CASE_DENIAL': "Sorry, user " + name + " is not allowed to execute '" + operation + "' as root on guest."}, True),
                              ({'CASE_DENIAL': "Sorry, user " + name + " is not allowed to execute '/other' as root on guest."}, False)])
            for overrides, allowed in cases:
                with self.subTest(policy=policy, overrides=overrides):
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(['/bin/sh', '-c', stub + script],
                                            env=dict(os.environ, CASE_POLICY=policy, **(defaults | overrides)),
                                            capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
                    self.assertEqual(marker.exists(), allowed)
                    if allowed:
                        self.assertEqual(marker.read_text(), name)

    def test_home_snapshot_requires_complete_output_and_preserves_query_failures(self):
        name = 'e2e_t_123456789abc'
        valid = (hashlib.sha256(name.encode()).hexdigest() + '  /home/' + name + '/.portfolio-e2e-retained\n' +
                 'a' * 64 + '  /home/' + name + '/.profile\n')
        with patch.object(self.stand, 'fixture_ssh', return_value=valid) as ssh:
            self.assertEqual(self.stand.user_home_snapshot(name, self.base / 'controller'), valid)
        probe = ssh.call_args.args[2]
        self.assertIn('test ! -L /home/' + name, probe)
        self.assertIn('-type l) && test -z', probe)
        self.assertIn('! -path /home/' + name + '/.ssh/authorized_keys', probe)
        for output in ('', 'unexpected', 'a' * 64 + '  /home/foreign/.profile\n'):
            with self.subTest(output=output), patch.object(self.stand, 'fixture_ssh', return_value=output):
                with self.assertRaisesRegex(ValueError, 'snapshot unavailable'):
                    self.stand.user_home_snapshot(name, self.base / 'controller')
        with patch.object(self.stand, 'fixture_ssh', return_value='a' * 64 + '  /home/' + name + '/.profile\n'):
            with self.assertRaisesRegex(ValueError, 'marker changed or missing'):
                self.stand.user_home_snapshot(name, self.base / 'controller')
        with patch.object(self.stand, 'fixture_ssh', side_effect=ValueError('query failure')):
            with self.assertRaisesRegex(ValueError, 'query failure'):
                self.stand.user_home_snapshot(name, self.base / 'controller')

    def test_standalone_users_probe_failures_never_continue_or_report_success(self):
        _, ssh = self.user_scenario()
        for index in range(ssh.call_count):
            with self.subTest(step=index):
                _, stopped = self.user_scenario(ssh_failure=index)
                self.assertEqual(stopped.call_count, index + 1)
        self.assertFalse(self.mutations())

    def test_standalone_decline_never_dispatches_mutations(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        for method in (self.stand.test_users, self.stand.test_swap):
            with self.subTest(method=method.__name__), patch.object(self.stand, 'standalone_ready'), \
                    patch('builtins.input', return_value='n'), \
                    patch.object(self.stand, 'cli') as cli, patch.object(self.stand, 'fixture_ssh') as ssh:
                with self.assertRaisesRegex(ValueError, 'declined'):
                    method()
                cli.assert_not_called()
                ssh.assert_not_called()
        self.assertFalse(self.mutations())

    def test_fixture_authentication_denial_rejects_network_trust_and_protocol_errors(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        denied = 'alice@' + self.stand.ip + ': Permission denied (publickey).\n'
        cases = [(255, '', denied, True), (0, '', '', False), (255, '', 'Connection refused', False),
                 (255, '', 'Host key verification failed.', False), (255, '', denied + 'unexpected', False),
                 (255, 'unexpected', denied, False), (1, '', denied, False)]
        for code, stdout, stderr, allowed in cases:
            with self.subTest(code=code, stderr=stderr), \
                    patch('portfolio_cli.ssh.interactive_ssh_command', return_value=['ssh', '-t', 'synthetic']) as transport, \
                    patch.object(e2e.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)) as run:
                previous = os.environ.get('HOME')
                if allowed:
                    self.stand.fixture_ssh('alice', self.base / 'selected', 'true', denied=True)
                else:
                    with self.assertRaisesRegex(ValueError, 'authentication denial'):
                        self.stand.fixture_ssh('alice', self.base / 'selected', 'true', denied=True)
                self.assertEqual(os.environ.get('HOME'), previous)
                self.assertEqual(transport.call_args.args, (self.stand.ip, 22, 'alice', self.base / 'selected'))
                self.assertEqual(run.call_args.kwargs['env']['HOME'], str(self.stand.root / 'home'))
                self.assertEqual(run.call_args.kwargs['env']['LC_ALL'], 'C')

    def test_standalone_user_cli_uses_make_without_consent_grant_or_production_inputs(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        with patch.dict(os.environ, INVENTORY='/production', HUMAN_USER='foreign', PORTFOLIO_E2E_PLAN_FD='999'), \
                patch.object(e2e, 'command', side_effect=self.command) as run:
            self.stand.cli('add-user', user_inputs={'HUMAN_USER': 'e2e_t_new', 'HUMAN_SUDO': 'admin'})
        self.assertEqual(run.call_args.args[0], ['make', '--no-print-directory', 'add-user'])
        env = run.call_args.kwargs['env']
        self.assertEqual(env['INVENTORY'], str(self.stand.inventory))
        self.assertEqual(env['HUMAN_USER'], 'e2e_t_new')
        self.assertNotIn('PORTFOLIO_E2E_PLAN_FD', env)
        self.assertNotIn('/production', json.dumps(env))

    def test_standalone_entrypoints_hold_lock_and_report_stop(self):
        for mode in ('test-users', 'test-swap'):
            events = []

            @contextlib.contextmanager
            def lock(root):
                events.append('lock')
                yield
                events.append('unlock')

            with self.subTest(mode=mode), patch.object(e2e, 'Stand', return_value=self.stand), \
                    patch.object(e2e, 'stand_lock', side_effect=lock), patch.object(os, 'getuid', return_value=1000), \
                    patch.object(os, 'umask'), patch.dict(os.environ, E2E_INVENTORY=''), \
                    patch.object(sys, 'argv', ['e2e.py', mode]), \
                    patch.object(self.stand, mode.replace('-', '_'), side_effect=lambda: events.append(mode)) as scenario:
                self.assertEqual(e2e.main(), 0)
                self.assertEqual(events, ['lock', mode, 'unlock'])
                scenario.side_effect = e2e.E2EError('synthetic failure')
                with contextlib.redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(e2e.main(), 1)
                self.assertIn('E2E STOP (' + mode + ')', stderr.getvalue())
                self.assertIn('No automatic reset/retry', stderr.getvalue())
                self.assertFalse(self.mutations())

    def test_user_commands_forward_only_explicit_inputs_without_plan_grants(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        inputs = dict(HUMAN_USER='alice', HUMAN_SUDO='restricted', HUMAN_GROUPS='readers',
                      HUMAN_GROUPS_APPROVED='readers', HUMAN_SUDO_COMMANDS='/usr/bin/id',
                      HUMAN_KEY='keys/alice', HUMAN_PUBLIC_KEY='keys/alice.pub',
                      RECOVERY_USER='bob', RECOVERY_KEY='keys/bob', KEY_NAME='alice',
                      KEY_FINGERPRINT='SHA256:' + 'a' * 43, AGENT_LOAD='no')
        poison = dict(INVENTORY='/production', AUTOMATION_KEY='/production/key',
                      ANSIBLE_SSH_EXECUTABLE='/foreign', HUMAN_UNKNOWN='unsafe',
                      RECOVERY_UNKNOWN='unsafe', PORTFOLIO_E2E_PLAN_FD='123', INIT_FROM='verify')
        for mode in e2e.USER_MODES:
            with self.subTest(mode=mode), patch.dict(os.environ, dict(inputs, **poison), clear=True), \
                    patch.object(e2e, 'command', side_effect=self.command) as run:
                self.stand.user_command(mode)
                args = run.call_args.args[0]
                self.assertEqual(args[2:], [mode, '--inventory', str(self.stand.inventory), '--key', ''])
                env = run.call_args.kwargs['env']
                for name, value in inputs.items():
                    expected = str(Path(value).absolute()) if name in e2e.USER_KEY_INPUTS else value
                    self.assertEqual(env[name], expected)
                self.assertEqual(env['HOME'], str(self.stand.root / 'home'))
                self.assertEqual(env['INVENTORY'], str(self.stand.inventory))
                self.assertEqual(env['AUTOMATION_KEY'], '')
                self.assertEqual(env['INIT_FROM'], '')
                for name in ('ANSIBLE_SSH_EXECUTABLE', 'HUMAN_UNKNOWN', 'RECOVERY_UNKNOWN', 'PORTFOLIO_E2E_PLAN_FD'):
                    self.assertNotIn(name, env)
                self.assertFalse(run.call_args.kwargs['capture'])
                self.assertIsNone(run.call_args.kwargs['timeout'])

    def test_user_commands_stop_before_dispatch_on_fixture_drift(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        for failure in ('uuid', 'route', 'stopped', 'inventory'):
            with self.subTest(failure=failure), patch.object(e2e, 'command', side_effect=self.command) as run:
                if failure == 'uuid':
                    self.domain.find('uuid').text = 'foreign'
                elif failure == 'route':
                    run.side_effect = lambda *args, **kwargs: '[{"dev":"foreign"}]'
                elif failure == 'stopped':
                    self.vm_state = 'shut off'
                else:
                    self.stand.inventory.write_text('foreign: inventory\n')
                with self.assertRaises(ValueError):
                    self.stand.user_command('remove-user')
                self.assertFalse(any(call.args[0][0] == sys.executable for call in run.call_args_list))
                self.domain.find('uuid').text = self.state['uuid']
                self.vm_state = 'running'

    def test_swap_profiles_bind_exact_owned_inventory_and_block_drift(self):
        self.stand.prepare_swap_inventories()
        for size in (0, 512, 1024):
            path = self.stand.swap_inventory(size)
            self.stand.check_inventory(path)
            self.assertEqual(yaml.safe_load(path.read_text())['all']['children']['bootstrap']['hosts']['e2e']['swap_size_mb'], size)
        path = self.stand.swap_inventory(512)
        data = yaml.safe_load(path.read_text())
        data['all']['children']['bootstrap']['hosts']['e2e']['swap_size_mb'] = 1024
        path.write_text(yaml.safe_dump(data))
        with self.assertRaisesRegex(ValueError, 'drift'):
            self.stand.check_inventory(path)
        with self.assertRaises(ValueError):
            self.stand.prepare_swap_inventories()
        with self.assertRaises(ValueError):
            self.stand.swap_inventory(2048)

    def test_test_failure_stops_without_reset(self):
        public = self.stand.root / 'home/.ssh/human/admin_ed25519.pub'
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text('synthetic public identity')
        prompt = patch('builtins.input', return_value='y')
        prompt.start()
        self.addCleanup(prompt.stop)
        frontier = patch.dict(os.environ, E2E_FROM='bootstrap')
        frontier.start()
        self.addCleanup(frontier.stop)
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        def command(args, **kwargs):
            if args[:4] == ['ip', '-j', 'route', 'get']:
                return '[{"dev": "virbr-e2e"}]'
            return ''

        with patch.object(e2e.sys.stdin, 'isatty', return_value=True), \
                patch.object(e2e, 'command', side_effect=command), patch.object(self.stand, 'cli', side_effect=e2e.E2EError('failed')) as cli:
            with self.assertRaises(ValueError):
                self.stand.test()
        cli.assert_called_once()
        self.assertFalse(self.mutations())

    def test_default_deny_no_tty_eof_empty(self):
        with patch.object(e2e.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError):
                CONFIRM('reset')
        for answer in ('', 'no'):
            with patch.object(e2e.sys.stdin, 'isatty', return_value=True), patch('builtins.input', return_value=answer):
                with self.assertRaises(ValueError):
                    CONFIRM('delete')

    def test_route_to_foreign_network_blocks_all_ssh(self):
        with patch.object(e2e, 'command', return_value='[{"dev":"eth0","gateway":"192.168.231.1"}]'):
            with self.assertRaisesRegex(ValueError, 'owned bridge'):
                self.stand.ready(running=True)
        self.assertFalse(self.mutations())

    def test_other_vm_attached_to_stand_blocks_deletion(self):
        self.domains.append('foreign-vm')
        with self.assertRaisesRegex(ValueError, 'Another VM'):
            self.stand.delete()
        self.assertFalse(self.mutations())

    def test_resources_changed_during_confirmation_block_reset(self):
        def change(_):
            self.domain.find('uuid').text = 'wrong'
        with patch.object(e2e, 'confirm', side_effect=change):
            with self.assertRaises(ValueError):
                self.stand.reset()
        self.assertFalse(self.mutations())

    def test_full_stage08_scenario_refuses_jammy_before_any_child(self):
        with patch.object(self.stand, 'load'), \
                patch.object(e2e.e2e_images, 'select', return_value={'version': '22.04'}), \
                patch.object(self.stand, 'cli') as child, \
                patch.object(self.stand, 'ready') as ready:
            with self.assertRaisesRegex(ValueError, 'requires Ubuntu 24.04'):
                self.stand.test()
        child.assert_not_called()
        ready.assert_not_called()
        self.assertFalse(self.mutations())

    def test_test_sequence_uses_one_bound_plan(self):
        public = self.stand.root / 'home/.ssh/human/admin_ed25519.pub'
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text('synthetic public identity')
        prompt = patch('builtins.input', return_value='y')
        prompt.start()
        self.addCleanup(prompt.stop)
        frontier = patch.dict(os.environ, E2E_FROM='bootstrap')
        frontier.start()
        self.addCleanup(frontier.stop)
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        def run(args, **kwargs):
            return '[{"dev":"virbr-e2e"}]' if args[:4] == ['ip', '-j', 'route', 'get'] else ''
        with patch.object(e2e.sys.stdin, 'isatty', return_value=True), \
                patch.object(e2e, 'command', side_effect=run), \
                patch.object(self.stand, 'cli') as cli, \
                patch.object(self.stand, 'swap_file_retained') as retained, \
                patch.object(self.stand, 'independent', side_effect=['initial', 'before', 'after', 'resized', 'disabled-before', 'disabled-after', 'enabled']) as independent, \
                patch.dict(os.environ, E2E_FROM='bootstrap'):
            self.stand.test()
        self.assertEqual(retained.call_count, 2)
        self.assertEqual(independent.call_count, 7)
        self.assertEqual([(c.args, c.kwargs) for c in cli.call_args_list], [
            (('init-server', 'bootstrap'), {}), (('init-server', 'verify'), {}),
            (('init-server', 'swap'), {'unchanged': True}), (('init-server', 'verify'), {}),
            (('reboot-host',), {}), (('init-server', 'verify'), {}),
            (('setup-swap',), {'unchanged': True}), (('verify-swap',), {})] + [
                row for size in (1024, 0, 512) for row in [
                    (('setup-swap',), {'swap_size': size}),
                    (('verify-swap',), {'swap_size': size}),
                    (('setup-swap',), {'unchanged': True, 'swap_size': size}),
                    (('verify-swap',), {'swap_size': size})] + ([
                        (('reboot-host',), {'swap_size': size}),
                        (('verify-swap',), {'swap_size': size}),
                        (('setup-swap',), {'unchanged': True, 'swap_size': size}),
                        (('verify-swap',), {'swap_size': size})] if size == 0 else [])])
        self.assertFalse(self.mutations())

    def test_failed_revert_keeps_disk_does_not_start_or_reset_again(self):
        original = self.virsh
        def fail(*args):
            if args[0] == 'snapshot-revert':
                self.calls.append(args)
                raise e2e.E2EError('unsupported revert backend')
            return original(*args)
        with patch.object(e2e, 'virsh', side_effect=fail):
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                self.stand.reset()
        self.assertEqual([x[0] for x in self.mutations()], ['shutdown', 'snapshot-revert'])
        self.assertTrue(self.stand.disk.exists())

    def test_swap_transition_failure_stops_before_later_actions(self):
        public = self.stand.root / 'home/.ssh/human/admin_ed25519.pub'
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text('synthetic public identity')
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        for failed_mode, unchanged in (('setup-swap', False), ('verify-swap', False), ('setup-swap', True)):
            with self.subTest(mode=failed_mode, unchanged=unchanged):
                def fail(mode, *args, **kwargs):
                    if mode == failed_mode and kwargs.get('swap_size') == 1024 and kwargs.get('unchanged', False) == unchanged:
                        raise e2e.E2EError('synthetic transition failure')
                with patch.object(e2e.sys.stdin, 'isatty', return_value=True), \
                        patch('builtins.input', return_value='y'), \
                        patch.object(self.stand, 'ready'), \
                        patch.object(e2e, 'command'), \
                        patch.object(self.stand, 'cli', side_effect=fail) as cli, \
                        patch.object(self.stand, 'swap_file_retained') as retained, \
                        patch.object(self.stand, 'independent', side_effect=['initial', 'before', 'after']), \
                        patch.dict(os.environ, E2E_FROM='bootstrap'):
                    with self.assertRaisesRegex(ValueError, 'synthetic transition failure'):
                        self.stand.test()
                self.assertEqual(cli.call_args.args, (failed_mode,))
                self.assertEqual(cli.call_args.kwargs.get('unchanged', False), unchanged)
                retained.assert_not_called()
                self.assertEqual(sum(call.args == ('reboot-host',) for call in cli.call_args_list), 1)

    def test_fresh_prepare_uses_cloud_init_then_stopped_baseline(self):
        self.fresh_prepare('ubuntu-24.04')

    def test_jammy_prepare_uses_compatible_cloud_init_and_inventory(self):
        self.fresh_prepare('ubuntu-22.04')

    def test_prepare_shutdown_timeout_retains_partial_fixture_without_baseline(self):
        self.fresh_prepare('ubuntu-24.04', shutdown_timeout=True)

    def test_prepare_decline_keeps_running_guest_without_shutdown_or_baseline(self):
        self.fresh_prepare('ubuntu-24.04', decline=True)

    def test_prepare_readiness_failure_never_requests_shutdown_or_baseline(self):
        self.fresh_prepare('ubuntu-24.04', readiness_failure=True)

    def test_stop_observes_shutdown_in_progress_without_second_request(self):
        with patch.object(e2e, 'virsh', side_effect=['in shutdown', 'in shutdown', 'shut off', 'shut off']) as run, \
                patch.object(e2e.time, 'sleep') as sleep:
            self.stand.stop()
        sleep.assert_called_once_with(2)
        self.assertTrue(all(call.args[0] == 'domstate' for call in run.call_args_list))

    def test_wait_stopped_rejects_ambiguous_state_without_mutation(self):
        self.vm_state = 'paused'
        with self.assertRaisesRegex(ValueError, 'Unexpected guest state'), patch.object(e2e.time, 'sleep') as sleep:
            self.stand.wait_stopped('timeout')
        sleep.assert_not_called()
        self.assertFalse(self.mutations())

    def test_disk_labels_block_drift_preserve_legacy_and_controller_ownership(self):
        self.stand.domain_xml(self.domain)  # Legacy fixtures need no XML rewrite.
        for source in self.domain.findall('devices/disk/source'):
            ET.SubElement(source, 'seclabel', model='dac', relabel='no')
        self.stand.domain_xml(self.domain, require_dac=True)
        label = self.domain.find('devices/disk/source/seclabel')
        for attrs in ({'model': 'dac', 'relabel': 'yes'}, {'model': 'selinux', 'relabel': 'no'}):
            label.attrib = attrs
            with self.assertRaisesRegex(ValueError, 'security label'):
                self.stand.domain_xml(self.domain)
        label.attrib = {'model': 'dac', 'relabel': 'no'}
        real_lstat = Path.lstat
        def foreign_owner(path):
            info = real_lstat(path)
            if path == self.stand.seed:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=info.st_nlink)
            return info
        with patch.object(Path, 'lstat', foreign_owner), self.assertRaisesRegex(ValueError, 'ownership/mode'):
            self.stand.domain_xml(self.domain)

    def test_group_write_is_limited_to_owned_disk_and_storage_group(self):
        self.stand.disk.chmod(0o660)
        self.stand.domain_xml(self.domain)
        self.vm_state = 'shut off'
        self.stand.stopped_disk()
        self.stand.deletion_paths()
        with self.assertRaisesRegex(ValueError, 'ownership/mode'):
            e2e.safe_path(self.stand.disk, private=False)
        self.stand.seed.chmod(0o660)
        with self.assertRaisesRegex(ValueError, 'ownership/mode'):
            self.stand.domain_xml(self.domain)
        self.stand.seed.chmod(0o640)
        real_stat = Path.stat
        def wrong_group(path, **kwargs):
            info = real_stat(path, **kwargs)
            if path == self.stand.storage:
                fields = list(info)
                fields[5] += 1
                return os.stat_result(fields)
            return info
        with patch.object(Path, 'stat', wrong_group), self.assertRaisesRegex(ValueError, 'ownership/mode'):
            self.stand.disk_file()

    def fresh_prepare(self, distro, *, shutdown_timeout=False, decline=False, readiness_failure=False):
        # All host tools, download and hypervisor operations are synthetic.
        self.stand.delete()
        self.stand.storage.mkdir(mode=0o700)
        self.calls.clear()
        self.vm_state = 'shut off'
        self.snapshots = []
        real_exists = Path.exists
        def exists(path):
            return True if path == Path('/dev/kvm') else real_exists(path)
        def download():
            image = self.stand.root / 'image.img'
            e2e.write_new(image, 'synthetic image')
            return image
        def run(args, **kwargs):
            if args[:4] == ['ip', '-j', 'route', 'show']:
                return '[]'
            if args[:3] == ['openssl', 'passwd', '-6']:
                return '$6$salt$' + 'A' * 86
            if args[:2] == ['qemu-img', 'info']:
                return '{"format":"qcow2"}'
            if args[:2] == ['qemu-img', 'convert']:
                e2e.write_new(self.stand.disk, 'new synthetic disk')
            if args[0] == 'cloud-localds':
                e2e.write_new(self.stand.seed, 'new synthetic seed')
            if args[0] == 'virt-install':
                self.domain.find('uuid').text = self.stand.state['uuid']
                self.domain.find('devices/interface/mac').set('address', self.stand.state['mac'])
                self.domain.remove(self.domain.find('metadata'))
                ET.SubElement(ET.SubElement(self.domain, 'features'), 'acpi')
                channel = ET.SubElement(self.domain.find('devices'), 'channel', type='unix')
                ET.SubElement(channel, 'target', type='virtio', name='org.qemu.guest_agent.0')
                self.assertIn('unix,target.type=virtio,target.name=org.qemu.guest_agent.0', args)
                return e2e.xml_text(self.domain)
            return ''
        shutdown = []
        readiness = []
        def wait_ready(identity, **kwargs):
            self.assertEqual(identity, self.stand.state['uuid'])
            self.assertTrue(kwargs['running']())
            self.assertFalse(any(c[0] == 'shutdown' for c in self.mutations()))
            if readiness_failure:
                raise e2e.E2EError('Guest readiness timed out')
            readiness.append('ready')
        def hypervisor(*args):
            if args[0] == 'shutdown':
                self.assertEqual(readiness, ['ready'])
                self.assertEqual(self.vm_state, 'running')
                self.calls.append(args)
                shutdown.extend(['running', 'in shutdown', 'shut off'] if not shutdown_timeout else ['running'])
                return ''
            if args[0] == 'domstate' and shutdown:
                self.vm_state = shutdown.pop(0)
            if args[0] == 'define':
                self.domain = ET.parse(args[1]).getroot()
                self.domains = [self.stand.state['uuid']]
            if args[0] == 'net-define':
                self.network = ET.parse(args[1]).getroot()
                self.networks = [self.stand.state['network_uuid']]
            if args[0] == 'snapshot-create':
                self.assertEqual(self.vm_state, 'shut off')
                self.snapshot = ET.parse(args[2]).getroot()
                ET.SubElement(self.snapshot, 'state').text = 'shutoff'
                self.snapshot.append(ET.fromstring(e2e.xml_text(self.domain)))
                self.snapshots = ['baseline']
            return self.virsh(*args)
        def confirmation(message):
            if 'create the baseline?' in message:
                self.assertEqual(self.vm_state, 'running')
                self.assertNotIn('poweroff', message)
                if decline:
                    raise e2e.E2EError('E2E operation declined.')
        with patch.object(Path, 'exists', exists), patch.object(e2e.e2e_host, 'prepare'), \
                patch.object(e2e.getpass, 'getpass', return_value='disposable-test-password'), \
                patch.object(self.stand, 'download', side_effect=download), \
                patch.object(e2e, 'command', side_effect=run), patch.object(e2e, 'virsh', side_effect=hypervisor), \
                patch.object(e2e, 'confirm', side_effect=confirmation), \
                patch.object(e2e.e2e_readiness, 'wait_ready', side_effect=wait_ready) as ready, \
                patch.object(e2e.time, 'sleep') as sleep, \
                patch.object(e2e.time, 'monotonic', side_effect=[0, 121] if shutdown_timeout else [0, 1, 2]), \
                patch.dict(os.environ, E2E_DISTRO=distro, E2E_CPUS='', E2E_MEMORY='', E2E_DISK_GB='', E2E_SUBNET=''):
            if shutdown_timeout or decline or readiness_failure:
                reason = 'declined' if decline else 'Guest readiness timed out' if readiness_failure else 'shutdown wait timed out'
                with self.assertRaisesRegex(ValueError, reason):
                    self.stand.prepare()
                self.assertEqual(self.stand.load()['phase'], 'preparing')
                expected = ['net-define', 'net-start', 'define', 'start'] + ([] if decline or readiness_failure else ['shutdown'])
                self.assertEqual([c[0] for c in self.mutations()], expected)
                self.assertFalse(self.stand.inventory.exists())
                self.assertFalse(self.snapshots)
                sleep.assert_not_called()
                self.assertEqual(ready.call_count, 0 if decline else 1)
                return
            self.stand.prepare()
            self.assertEqual(sleep.call_count, 2)
        self.assertEqual(self.stand.state['phase'], 'ready')
        self.assertEqual(self.stand.state['schema'], 2)
        self.assertEqual(self.stand.state['distro'], distro)
        self.assertEqual(self.stand.load()['distro'], distro)
        self.stand.check_inventory(self.stand.inventory)
        self.assertEqual([c[0] for c in self.mutations()], ['net-define', 'net-start', 'define', 'start', 'shutdown', 'snapshot-create', 'start'])
        for source in self.domain.findall('devices/disk/source'):
            self.assertEqual(source.find('seclabel').attrib, {'model': 'dac', 'relabel': 'no'})
        self.assertIsNone(self.domain.find('seclabel'))
        self.assertEqual(self.stand.disk.stat().st_mode & 0o777, 0o660)
        self.assertEqual(self.stand.seed.stat().st_mode & 0o777, 0o640)
        cloud = (self.stand.root / 'user-data').read_text()
        self.assertNotIn('disposable-test-password', cloud)
        self.assertIn('hashed_passwd', cloud)
        config = yaml.safe_load(cloud)
        self.assertEqual(config['packages'], ['qemu-guest-agent'])
        self.assertIn(['systemctl', 'start', 'qemu-guest-agent'], config['runcmd'])

    def test_repeat_recaps_enforce_zero_provisioning_allow_exact_smoke(self):
        names = [yaml.safe_load((e2e.ROOT / 'playbooks' / n).read_text())[0]['name'] for n in
                 ('setup-swap.yml', 'docker-host.yml', 'harden.yml', 'secure-ssh.yml', 'setup-operations.yml', 'setup-deployment-prerequisites.yml', 'verify-docker.yml')]
        for drift in (False, True):
            text = ''.join('PLAY [' + name + '] ***\n' +
                           'e2e : ok=10 changed=' + str(3 if index == len(names) - 1 else int(drift)) + ' failed=0\n'
                           for index, name in enumerate(names))
            class Process:
                stdout = io.BufferedReader(io.BytesIO(text.encode()))
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
                def wait(self):
                    return 0
            with patch.object(e2e.subprocess, 'Popen', return_value=Process()), contextlib.redirect_stdout(io.StringIO()):
                if drift:
                    with self.assertRaisesRegex(ValueError, 'changed=0'):
                        e2e.convergence_command(['synthetic'], {})
                else:
                    e2e.convergence_command(['synthetic'], {})

    def test_repeat_accepts_exact_noops_and_rejects_missing_evidence(self):
        docker = yaml.safe_load((e2e.ROOT / 'playbooks/docker-host.yml').read_text())[0]['name']
        smoke = yaml.safe_load((e2e.ROOT / 'playbooks/verify-docker.yml').read_text())[0]['name']
        swap_play = yaml.safe_load((e2e.ROOT / 'playbooks/setup-swap.yml').read_text())[0]['name']
        recaps = f'PLAY [{swap_play}] ***\ne2e : ok=10 changed=0 failed=0\nPLAY [{docker}] ***\ne2e : ok=10 changed=0 failed=0\nPLAY [{smoke}] ***\ne2e : ok=10 changed=3 failed=0\n'
        for missing in (False, True):
            messages = list(e2e.PLAN_NOOP_MESSAGES.values())
            if missing:
                messages.pop()
            output = recaps + '\n'.join(messages) + '\n'
            class Process:
                stdout = io.BufferedReader(io.BytesIO(output.encode()))
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
                def wait(self):
                    return 0
            with patch.object(e2e.subprocess, 'Popen', return_value=Process()), contextlib.redirect_stdout(io.StringIO()):
                if missing:
                    with self.assertRaisesRegex(ValueError, 'changed=0'):
                        e2e.convergence_command(['synthetic'], {})
                else:
                    e2e.convergence_command(['synthetic'], {})

    def test_swap_repeat_requires_own_zero_change_recap_without_smoke_exception(self):
        swap = yaml.safe_load((e2e.ROOT / 'playbooks/setup-swap.yml').read_text())[0]['name']
        verify = yaml.safe_load((e2e.ROOT / 'playbooks/verify-swap.yml').read_text())[0]['name']
        smoke = yaml.safe_load((e2e.ROOT / 'playbooks/verify-docker.yml').read_text())[0]['name']
        for title, changed, extra, success in (
                (swap, 0, '', True), (swap, 1, '', False), (swap, 3, '', False),
                (verify, 0, '', False),
                (swap, 0, f'PLAY [{smoke}] ***\ne2e : ok=10 changed=3 failed=0\n', False)):
            with self.subTest(title=title, changed=changed, extra=extra):
                output = f'PLAY [{title}] ***\ne2e : ok=10 changed={changed} failed=0\n' + extra
                class Process:
                    stdout = io.BufferedReader(io.BytesIO(output.encode()))
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        pass
                    def wait(self):
                        return 0
                with patch.object(e2e.subprocess, 'Popen', return_value=Process()), contextlib.redirect_stdout(io.StringIO()):
                    if success:
                        e2e.convergence_command(['synthetic'], {}, swap_only=True)
                    else:
                        with self.assertRaisesRegex(ValueError, 'changed=0'):
                            e2e.convergence_command(['synthetic'], {}, swap_only=True)

    def test_swap_cli_repeat_uses_targeted_make_and_inventory(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        self.stand.prepare_swap_inventories()
        with patch.object(self.stand, 'ready'), patch.object(e2e, 'convergence_command') as convergence:
            self.stand.cli('setup-swap', unchanged=True, swap_size=1024)
        args, kwargs = convergence.call_args
        self.assertEqual(args[0], ['make', '--no-print-directory', 'setup-swap'])
        self.assertEqual(args[1]['INVENTORY'], str(self.stand.swap_inventory(1024)))
        self.assertTrue(kwargs['swap_only'])

    def test_child_guard_validates_args_environment_and_pins_trust(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        (self.stand.root / 'home/.ssh').mkdir(mode=0o700, parents=True)
        (self.stand.root / 'home').chmod(0o700)
        (self.stand.root / 'tmp').mkdir(mode=0o700)
        env = self.stand.child_env()
        env['ANSIBLE_SSH_EXECUTABLE'] = '/foreign'
        env['PORTFOLIO_E2E_PLAN_FD'] = '123'
        argv = ['access.py', 'init-server', '--inventory', str(self.stand.inventory), '--key', '']
        from portfolio_cli import inspection
        with patch.object(e2e, 'Stand', return_value=self.stand), \
                patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.base))), \
                patch.object(e2e.common, 'SSH_BASE', e2e.common.SSH_BASE), \
                patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv):
            e2e.configure_child()
            self.assertIn('UserKnownHostsFile="' + str(self.stand.root / 'home/.ssh/known_hosts'), e2e.common.SSH_BASE)
            self.assertIn('UserKnownHostsFile="' + str(self.stand.root / 'home/.ssh/known_hosts'),
                          ' '.join(inspection.shlex.split(inspection.common.SSH_BASE)))
            self.assertNotIn('ANSIBLE_SSH_EXECUTABLE', os.environ)
            self.assertEqual(os.environ['PORTFOLIO_E2E_PLAN_FD'], '123')
        argv[3] = '/production/never-read.yml'
        with patch.object(e2e, 'Stand', return_value=self.stand), \
                patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.base))), \
                patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv):
            with self.assertRaisesRegex(ValueError, 'arguments forbidden'):
                e2e.configure_child()

    def test_swap_child_guard_accepts_only_exact_owned_profiles(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        self.stand.prepare_swap_inventories()
        (self.stand.root / 'home/.ssh').mkdir(mode=0o700, parents=True)
        (self.stand.root / 'home').chmod(0o700)
        (self.stand.root / 'tmp').mkdir(mode=0o700)
        for mode in ('setup-swap', 'verify-swap'):
            for size in (0, 512, 1024):
                with self.subTest(mode=mode, size=size):
                    inventory = self.stand.swap_inventory(size)
                    env = dict(self.stand.child_env(), INVENTORY=str(inventory))
                    argv = ['access.py', mode, '--inventory', str(inventory), '--key', '']
                    with patch.object(e2e, 'Stand', return_value=self.stand), \
                            patch.object(self.stand, 'ready'), \
                            patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.base))), \
                            patch.object(e2e.common, 'SSH_BASE', e2e.common.SSH_BASE), \
                            patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv):
                        e2e.configure_child()
                        argv[3] = '/production/never-read.yml'
                        with self.assertRaisesRegex(ValueError, 'arguments forbidden'):
                            e2e.configure_child()

    def test_user_guard_accepts_allowlist_and_keeps_fixture_trust(self):
        e2e.write_new(self.stand.inventory, yaml.safe_dump(self.stand.expected_inventory()))
        (self.stand.root / 'home/.ssh').mkdir(mode=0o700, parents=True)
        (self.stand.root / 'home').chmod(0o700)
        (self.stand.root / 'tmp').mkdir(mode=0o700)
        inputs = dict(HUMAN_USER='alice', HUMAN_KEY=str(self.base / 'alice'),
                      HUMAN_PUBLIC_KEY=str(self.base / 'alice.pub'), RECOVERY_USER='bob',
                      RECOVERY_KEY=str(self.base / 'bob'), HUMAN_GROUPS_APPROVED='readers')
        for mode in (*e2e.USER_MODES, 'generate-user-key'):
            env = self.stand.child_env(inputs)
            env.update(ANSIBLE_SSH_EXECUTABLE='/foreign')
            if mode != 'generate-user-key':
                env['PORTFOLIO_E2E_PLAN_FD'] = '123'
            argv = ['access.py', mode, '--inventory', str(self.stand.inventory)]
            if mode != 'generate-user-key':
                argv += ['--key', '']
            with self.subTest(mode=mode), patch.object(e2e, 'Stand', return_value=self.stand), \
                    patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(self.base))), \
                    patch.object(e2e.common, 'SSH_BASE', e2e.common.SSH_BASE), \
                    patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv):
                e2e.configure_child()
                for name, value in inputs.items():
                    self.assertEqual(os.environ[name], value)
                self.assertNotIn('ANSIBLE_SSH_EXECUTABLE', os.environ)
                if mode != 'generate-user-key':
                    self.assertEqual(os.environ['PORTFOLIO_E2E_PLAN_FD'], '123')
                self.assertIn(str(self.stand.root / 'home/.ssh/known_hosts'), e2e.common.SSH_BASE)
                for name, value in (('HOME', '/production'), ('AUTOMATION_KEY', '/production/key'),
                                    ('HUMAN_UNKNOWN', 'unsafe'), ('RECOVERY_UNKNOWN', 'unsafe'),
                                    ('HUMAN_KEY', 'relative/key')):
                    with patch.dict(os.environ, {name: value}), self.assertRaises(ValueError):
                        e2e.configure_child()

    def test_user_entrypoints_hold_fixture_lock_and_stop_on_failure(self):
        for mode in e2e.USER_MODES:
            events = []

            @contextlib.contextmanager
            def lock(root):
                self.assertEqual(root, self.stand.root)
                events.append('lock')
                yield
                events.append('unlock')

            with self.subTest(mode=mode), patch.object(e2e, 'Stand', return_value=self.stand), \
                    patch.object(e2e, 'stand_lock', side_effect=lock), patch.object(os, 'getuid', return_value=1000), \
                    patch.object(os, 'umask'), patch.dict(os.environ, E2E_INVENTORY=''), \
                    patch.object(sys, 'argv', ['e2e.py', mode]), \
                    patch.object(self.stand, 'user_command', side_effect=lambda selected: events.append(selected)):
                self.assertEqual(e2e.main(), 0)
                self.assertEqual(events, ['lock', mode, 'unlock'])
                with patch.object(e2e, 'stand_lock', side_effect=e2e.E2EError('Lock busy.')), \
                        patch.object(self.stand, 'user_command') as dispatch, contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(e2e.main(), 1)
                    dispatch.assert_not_called()
                with patch.object(self.stand, 'user_command', side_effect=subprocess.CalledProcessError(1, ['private'])), \
                        contextlib.redirect_stderr(io.StringIO()) as output:
                    self.assertEqual(e2e.main(), 1)
                    self.assertNotIn('private', output.getvalue())

    def test_make_user_targets_forward_parameters_as_environment(self):
        # Exercise the public Make recipes with a recorder, never the live CLI.
        work = self.base / 'make-wrapper'
        binary = work / '.venv/bin/python'
        binary.parent.mkdir(parents=True)
        (work / 'Makefile').write_text((e2e.ROOT / 'Makefile').read_text())
        record = work / 'record.json'
        binary.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
                          'from pathlib import Path\n'
                          'Path(os.environ["RECORD"]).write_text(json.dumps([sys.argv[1:], dict(os.environ)]))\n')
        binary.chmod(0o700)
        for mode in (*e2e.USER_MODES, 'test-users', 'test-swap'):
            with self.subTest(mode=mode):
                result = subprocess.run(['make', '--no-print-directory', 'e2e-' + mode,
                                         'HUMAN_USER=alice; touch SHOULD_NOT_EXIST', 'HUMAN_GROUPS_APPROVED=readers',
                                         'HUMAN_KEY=/explicit/key with spaces', 'RECOVERY_USER=bob',
                                         'RECOVERY_KEY=/explicit/recovery', 'KEY_FINGERPRINT=SHA256:example'],
                                        cwd=work, env=dict(os.environ, RECORD=str(record)),
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                args, env = json.loads(record.read_text())
                self.assertEqual(args, ['scripts/e2e.py', mode])
                self.assertEqual(env['HUMAN_USER'], 'alice; touch SHOULD_NOT_EXIST')
                self.assertEqual(env['HUMAN_GROUPS_APPROVED'], 'readers')
                self.assertEqual(env['HUMAN_KEY'], '/explicit/key with spaces')
                self.assertEqual(env['RECOVERY_USER'], 'bob')
                self.assertEqual(env['RECOVERY_KEY'], '/explicit/recovery')
                self.assertEqual(env['KEY_FINGERPRINT'], 'SHA256:example')
                self.assertFalse((work / 'SHOULD_NOT_EXIST').exists())

    def test_access_guard_foreign_root_never_dispatches_cli(self):
        env = dict(os.environ, PORTFOLIO_E2E_ROOT='/foreign')
        result = subprocess.run([str(e2e.ROOT / '.venv/bin/python'), 'scripts/access.py', 'init-server'],
                                cwd=e2e.ROOT, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('guard failed', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_cloud_image_digest_failure_retains_artifact_without_disk_changes(self):
        payload = b'synthetic image'
        digest = hashlib.sha256(payload).hexdigest()
        class Response(io.BytesIO):
            def __init__(self, data, url):
                super().__init__(data)
                self.url = url
        def fetch(url, **kwargs):
            data = (digest + ' *' + e2e.e2e_images.select()['image_url'].rsplit('/', 1)[1] + '\n').encode() if url.endswith('SHA256SUMS') else payload + b'corruption'
            return Response(data, url)
        with patch.object(e2e.e2e_images, 'open_official', side_effect=fetch), patch.dict(os.environ, E2E_IMAGE_SHA256=''):
            with self.assertRaisesRegex(ValueError, 'integrity failed'):
                self.stand.download()
        self.assertTrue((self.stand.root / 'image.img').exists())
        self.assertEqual(self.stand.disk.read_text(), 'synthetic disk')
        self.assertFalse(self.mutations())

    def test_hidden_disk_backing_dependency_blocks_revert(self):
        with patch.object(e2e, 'command', return_value='{"format":"qcow2","backing-filename":"/foreign"}'):
            with self.assertRaisesRegex(ValueError, 'backing/data file'):
                self.stand.reset()
        self.assertEqual([x[0] for x in self.mutations()], ['shutdown'])

    def test_make_surface_no_live_tools_for_forbidden_override(self):
        home = self.base / 'fresh-home'
        home.mkdir(mode=0o700)
        env = dict(os.environ, E2E_INVENTORY='/production', HOME=str(home))
        result = subprocess.run(['make', '--no-print-directory', 'e2e-test'], cwd=e2e.ROOT,
                                env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('inventory overrides are forbidden', result.stderr)
        self.assertFalse((home / '.local/share/portfolio-e2e').exists())


if __name__ == '__main__':
    unittest.main()
