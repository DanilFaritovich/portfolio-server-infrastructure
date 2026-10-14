"""Offline swap safety and wrapper contracts; all kernel/command probes mocked."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from test_cli_package import load_access

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('swap_guard', ROOT / 'library/portfolio_swap.py')
swap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(swap)


class SwapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name, path in [('SWAP', self.root / 'swapfile'), ('FSTAB', self.root / 'fstab'),
                           ('STATE', self.root / 'state')]:
            self.stack.enter_context(patch.object(swap, name, path))
        swap.FSTAB.write_text('# preserve\n/dev/foreign none swap sw 0 0\n')
        swap.FSTAB.chmod(0o644)
        self.original = swap.FSTAB.read_text()
        self.stack.enter_context(patch.object(swap, 'LINE', str(swap.SWAP) + ' none swap sw 0 0 # portfolio-swap\n'))
        self.stack.enter_context(patch.object(swap, 'trusted_state_parent'))
        self.stack.enter_context(patch.object(swap, 'metadata', side_effect=self.metadata))
        original_lstat = Path.lstat
        def root_lstat(path):
            result = original_lstat(path)
            if path == swap.STATE:
                values = list(result)
                values[4:6] = [0, 0]
                return os.stat_result(values)
            return result
        self.stack.enter_context(patch.object(Path, 'lstat', root_lstat))
        self.active = None
        self.uuid = '57d52951-a728-442b-ad68-e7acb5311e39'
        self.commands = []
        self.stack.enter_context(patch.object(swap, 'active_swap', side_effect=lambda: self.active))
        self.run = self.stack.enter_context(patch.object(swap, 'run', side_effect=self.command))
        self.ram = self.stack.enter_context(patch.object(swap, 'memory_available', return_value=1024 * swap.MIB))

    def metadata(self, path, mode):
        info = path.lstat()
        swap.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1,
                     'Unsafe fixture metadata')
        return info

    def command(self, argv):
        self.commands.append(argv)
        if argv[0] == 'findmnt':
            return 'ext4' if argv[3] == 'FSTYPE' else '/'
        if argv[0] == 'blkid':
            return 'swap' if argv[3] == 'TYPE' else self.uuid
        if argv[0] == 'mkswap':
            self.uuid = argv[2]
        if argv[0] == 'swapon':
            self.active = [swap.SWAP.stat().st_size - os.sysconf('SC_PAGE_SIZE'), 0]
        if argv[0] == 'swapoff':
            self.active = None
        return ''

    def mutations(self):
        return [argv for argv in self.commands if argv[0] in ('mkswap', 'swapoff', 'swapon') or argv[1:] == ['daemon-reload']]

    def create(self):
        self.assertTrue(swap.apply_swap(1))
        self.assertFalse((swap.STATE / 'pending').exists())
        self.assertFalse(swap.apply_swap(1, verify=True))

    def test_creation_resize_disable_retention_reenable_and_idempotence(self):
        self.create()
        self.assertEqual(swap.SWAP.stat().st_size, swap.MIB)
        self.assertEqual(stat.S_IMODE(swap.SWAP.stat().st_mode), 0o600)
        self.assertEqual(swap.FSTAB.read_text(), self.original + swap.LINE)
        receipt = (swap.STATE / 'receipt.json').read_bytes()
        self.commands.clear()
        self.assertFalse(swap.apply_swap(1))
        self.assertEqual(receipt, (swap.STATE / 'receipt.json').read_bytes())
        self.assertFalse(self.mutations())
        self.assertTrue(swap.apply_swap(2))
        self.assertEqual(swap.SWAP.stat().st_size, 2 * swap.MIB)
        self.assertEqual([a[0] for a in self.mutations()], ['mkswap', 'swapoff', 'swapon'])
        self.commands.clear()
        inode = swap.SWAP.stat().st_ino
        self.assertTrue(swap.apply_swap(0))
        self.assertEqual(swap.SWAP.stat().st_ino, inode)
        self.assertEqual(swap.SWAP.stat().st_size, 2 * swap.MIB)
        self.assertEqual(swap.FSTAB.read_text(), self.original)
        self.assertFalse(swap.apply_swap(0, verify=True))
        self.commands.clear()
        self.assertFalse(swap.apply_swap(0))
        self.assertFalse(self.mutations())
        self.assertTrue(swap.apply_swap(2))
        self.assertEqual(swap.SWAP.stat().st_ino, inode)
        self.assertNotIn('mkswap', [a[0] for a in self.mutations()])

    def test_foreign_fstab_comment_containing_managed_line_is_preserved(self):
        comment = '# example: ' + swap.LINE
        swap.FSTAB.write_text(self.original + comment)
        swap.apply_swap(1)
        self.assertEqual(swap.FSTAB.read_text(), self.original + comment + swap.LINE)
        swap.apply_swap(0)
        self.assertEqual(swap.FSTAB.read_text(), self.original + comment)

    def test_zero_without_file_never_creates_file_or_state(self):
        self.assertFalse(swap.apply_swap(0))
        self.assertFalse(swap.apply_swap(0, verify=True))
        self.assertFalse(swap.SWAP.exists())
        self.assertFalse(swap.STATE.exists())
        self.assertFalse(self.mutations())

    def test_verification_detects_inactivity_size_and_fstab_without_changes(self):
        self.create()
        for defect in ('size', 'activity', 'fstab'):
            with self.subTest(defect=defect):
                self.active = [swap.MIB - os.sysconf('SC_PAGE_SIZE'), 0] if defect != 'activity' else None
                swap.FSTAB.write_text(self.original if defect == 'fstab' else self.original + swap.LINE)
                before = swap.FSTAB.read_bytes()
                self.commands.clear()
                with self.assertRaises(ValueError):
                    swap.apply_swap(2 if defect == 'size' else 1, verify=True)
                self.assertEqual(swap.FSTAB.read_bytes(), before)
                self.assertFalse(self.mutations())

    def test_insufficient_memory_stops_disable_and_resize_before_mutation(self):
        self.create()
        self.active[1] = swap.MIB
        self.ram.return_value = swap.RESERVE
        for size in (0, 2):
            self.commands.clear()
            with self.assertRaisesRegex(ValueError, 'RAM'):
                swap.apply_swap(size)
            self.assertFalse(self.mutations())
            self.assertFalse((swap.STATE / 'pending').exists())
        self.assertEqual(swap.SWAP.stat().st_size, swap.MIB)

    def test_low_disk_and_unsupported_filesystem_stop_before_mutation(self):
        for failure in ('disk', 'filesystem'):
            with self.subTest(failure=failure), patch.object(swap.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096, f_flag=0)):
                if failure == 'filesystem':
                    self.run.side_effect = lambda argv: 'btrfs' if argv[0] == 'findmnt' else ''
                with self.assertRaises(ValueError):
                    swap.apply_swap(1)
                self.assertFalse(swap.SWAP.exists())
                self.assertFalse(swap.STATE.exists())
                self.assertFalse(self.mutations())

    def test_unmanaged_file_symlink_hardlink_and_fstab_are_never_adopted(self):
        for defect in ('file', 'symlink', 'hardlink', 'fstab'):
            with self.subTest(defect=defect):
                if defect == 'symlink':
                    swap.SWAP.symlink_to(self.root / 'absent')
                elif defect == 'hardlink':
                    other = self.root / 'foreign'
                    other.write_text('foreign')
                    other.chmod(0o600)
                    os.link(other, swap.SWAP)
                elif defect == 'file':
                    swap.SWAP.write_text('foreign')
                    swap.SWAP.chmod(0o600)
                else:
                    swap.FSTAB.write_text(self.original + swap.LINE)
                with self.assertRaises(ValueError):
                    swap.apply_swap(0)
                self.assertFalse(self.mutations())
                if swap.SWAP.exists() or swap.SWAP.is_symlink():
                    swap.SWAP.unlink()

    def test_failed_swapoff_keeps_original_and_pending_blocks_every_retry(self):
        self.create()
        before = swap.SWAP.read_bytes()
        original = self.command
        def fail(argv):
            if argv[0] == 'swapoff':
                raise ValueError('swapoff failed')
            return original(argv)
        self.run.side_effect = fail
        with self.assertRaises(ValueError):
            swap.apply_swap(2)
        self.assertEqual(swap.SWAP.read_bytes(), before)
        self.assertTrue((swap.STATE / 'pending').exists())
        for verify in (True, False):
            with self.assertRaisesRegex(ValueError, 'Pending'):
                swap.apply_swap(1, verify=verify)

    def test_concurrent_fstab_change_after_staging_stops_before_swapoff(self):
        self.create()
        original = self.command
        def drift(argv):
            value = original(argv)
            if argv[0] == 'mkswap':
                swap.FSTAB.write_text(swap.FSTAB.read_text() + '# concurrent\n')
            return value
        self.run.side_effect = drift
        self.commands.clear()
        with self.assertRaisesRegex(ValueError, 'Concurrent'):
            swap.apply_swap(2)
        self.assertNotIn('swapoff', [a[0] for a in self.commands])
        self.assertEqual(swap.SWAP.stat().st_size, swap.MIB)
        self.assertTrue((swap.STATE / 'pending').exists())

    def test_activation_failure_preserves_pending_and_verifier_refuses(self):
        original = self.command
        def fail(argv):
            if argv[0] == 'swapon':
                raise ValueError('activation failed')
            return original(argv)
        self.run.side_effect = fail
        with self.assertRaises(ValueError):
            swap.apply_swap(1)
        self.assertTrue((swap.STATE / 'pending').exists())
        with self.assertRaisesRegex(ValueError, 'Pending'):
            swap.apply_swap(1, verify=True)

    def test_receipt_signature_duplicate_fstab_and_overrides_block_changes(self):
        self.create()
        receipt = (swap.STATE / 'receipt.json').read_text()
        signature = self.uuid
        for defect in ('receipt', 'signature', 'duplicate', 'override'):
            with self.subTest(defect=defect):
                (swap.STATE / 'receipt.json').write_text(receipt)
                self.uuid = signature
                swap.FSTAB.write_text(self.original + swap.LINE)
                original = self.command
                self.run.side_effect = original
                if defect == 'receipt':
                    data = json.loads(receipt)
                    data['identity'][1] += 1
                    (swap.STATE / 'receipt.json').write_text(json.dumps(data))
                elif defect == 'signature':
                    self.uuid = '00000000-0000-4000-8000-000000000000'
                elif defect == 'duplicate':
                    swap.FSTAB.write_text(self.original + swap.LINE + swap.LINE)
                else:
                    self.run.side_effect = lambda argv: '/etc/systemd/system/swapfile.swap.d/custom.conf' if 'DropInPaths' in ' '.join(argv) else original(argv)
                self.commands.clear()
                with self.assertRaises(ValueError):
                    swap.apply_swap(0)
                self.assertFalse(self.mutations())

    def test_reboot_state_requires_activation_from_persistent_fstab(self):
        self.create()
        self.active = None
        with self.assertRaises(ValueError):
            swap.apply_swap(1, verify=True)
        self.active = [swap.MIB - os.sysconf('SC_PAGE_SIZE'), 0]
        self.assertFalse(swap.apply_swap(1, verify=True))
        swap.apply_swap(0)
        self.active = None
        self.assertFalse(swap.apply_swap(0, verify=True))
        self.assertTrue(swap.SWAP.exists())

    def test_check_mode_plans_without_writes(self):
        self.assertTrue(swap.apply_swap(1, check=True))
        self.assertFalse(swap.STATE.exists())
        self.assertFalse(swap.SWAP.exists())
        self.assertFalse(self.mutations())

    def test_invalid_size_and_custom_units_fail_closed(self):
        for size in (-1, True, '2048', 1048577):
            with self.assertRaises(ValueError):
                swap.apply_swap(size)
        self.run.side_effect = lambda argv: '/etc/systemd/system/swapfile.swap'
        with self.assertRaisesRegex(ValueError, 'Custom'):
            swap.apply_swap(0)
        self.assertFalse(swap.STATE.exists())


class SwapWrapperTests(unittest.TestCase):
    def test_native_and_legacy_wrappers_use_managed_preflight_and_exact_postflight(self):
        from portfolio_cli import provisioning
        for module in (provisioning, load_access('swap_compat')):
            for mode in ('setup-swap', 'verify-swap'):
                with self.subTest(module=module.__name__, mode=mode), contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(module, 'managed_access', return_value=('automation', Path('/synthetic'))))
                    stack.enter_context(patch.object(module, 'swap_input', return_value=2048))
                    for name in ('prerequisites', 'check_key', 'known_host', 'stage_consent'):
                        stack.enter_context(patch.object(module, name))
                    stack.enter_context(patch.object(module, 'load_host', return_value=('fixture', 'example.test', 22, 'root', '/usr/bin/python3')))
                    run = stack.enter_context(patch.object(module, 'run_playbook'))
                    result = module.live(mode, Path('/synthetic-inventory'))
                    self.assertEqual([call.args[3] for call in run.call_args_list],
                                     ['verify.yml', 'setup-swap.yml', 'verify-swap.yml'] if mode == 'setup-swap' else ['verify.yml', 'verify-swap.yml'])
                    self.assertEqual(result, 'verify-swap' if mode == 'setup-swap' else None)
                    for call in run.call_args_list:
                        self.assertEqual(call.args[2]['ansible_user'], 'automation')
                        self.assertIn('BatchMode=yes', call.args[2]['ansible_ssh_args'])

    def test_preflight_failure_stops_before_swap(self):
        module = load_access('swap_fail_compat')
        with patch.object(module, 'managed_access', return_value=('automation', Path('/synthetic'))), \
                patch.object(module, 'swap_input', return_value=2048), \
                patch.object(module, 'prerequisites'), patch.object(module, 'check_key'), \
                patch.object(module, 'known_host'), patch.object(module, 'load_host', return_value=('fixture', 'example.test', 22, 'root', '/usr/bin/python3')), \
                patch.object(module, 'run_playbook', side_effect=ValueError('failed')) as run:
            with self.assertRaises(ValueError):
                module.live('setup-swap', Path('/synthetic'))
        self.assertEqual(len(run.call_args_list), 1)


if __name__ == '__main__':
    unittest.main()
