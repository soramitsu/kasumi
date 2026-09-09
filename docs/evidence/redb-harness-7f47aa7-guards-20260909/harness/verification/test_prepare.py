"""Guard tests only: never invoke Cargo, tool installers or container commands."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from prepare import inventory, source_inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_content_modes_and_empty_directories_are_inputs(self):
        script = self.root / 'script'
        script.write_bytes(b'initial')
        script.chmod(0o644)
        before = inventory(self.root)
        self.assertEqual(before['script']['sha256'], hashlib.sha256(b'initial').hexdigest())
        self.assertEqual(before['script']['size'], 7)
        script.write_bytes(b'changed')
        self.assertNotEqual(before, inventory(self.root))
        script.write_bytes(b'initial')
        self.assertEqual(before, inventory(self.root))
        script.chmod(0o755)
        self.assertNotEqual(before, inventory(self.root))
        script.chmod(0o644)
        (self.root / 'empty').mkdir()
        self.assertNotEqual(before, inventory(self.root))
        self.assertEqual(inventory(self.root)['empty']['kind'], 'directory')

    def test_removal_is_detected(self):
        nested = self.root / 'nested'
        nested.mkdir()
        file = nested / 'input'
        file.write_bytes(b'input')
        before = inventory(self.root)
        file.unlink()
        self.assertNotEqual(before, inventory(self.root))
        nested.rmdir()
        self.assertNotEqual(before, inventory(self.root))

    def test_symlinks_to_files_directories_and_absent_targets_are_rejected(self):
        (self.root / 'file').write_bytes(b'input')
        (self.root / 'directory').mkdir()
        link = self.root / 'link'
        for target in ('file', 'directory', 'absent'):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaisesRegex(RuntimeError, 'symlink'):
                    inventory(self.root)
                link.unlink()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX named pipes')
    def test_special_files_are_rejected_without_reading(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(RuntimeError, 'file type'):
            inventory(self.root)

    def test_missing_root_and_traversal_errors_fail(self):
        with self.assertRaises(FileNotFoundError):
            inventory(self.root / 'absent')
        with patch('prepare.os.scandir', side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):
                inventory(self.root)

    def test_root_must_be_a_real_directory(self):
        file = self.root / 'file'
        file.write_bytes(b'input')
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        for root in (file, link):
            with self.subTest(root=root):
                with self.assertRaisesRegex(RuntimeError, 'real directory'):
                    inventory(root)

    def test_source_requires_both_exact_locks_and_rejects_generated_state(self):
        (self.root / 'fuzz').mkdir()
        locks = {'Cargo.lock': hashlib.sha256(b'root').hexdigest(),
                 'fuzz/Cargo.lock': hashlib.sha256(b'fuzz').hexdigest()}
        (self.root / 'Cargo.lock').write_bytes(b'root')
        with self.assertRaisesRegex(RuntimeError, 'verification lock'):
            source_inventory(self.root, locks)
        fuzz_lock = self.root / 'fuzz/Cargo.lock'
        fuzz_lock.write_bytes(b'fuzz')
        self.assertEqual(source_inventory(self.root, locks), inventory(self.root))
        fuzz_lock.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'verification lock'):
            source_inventory(self.root, locks)
        fuzz_lock.write_bytes(b'fuzz')
        for name in ('.git', 'target', 'fuzz/target', 'fuzz/corpus', 'fuzz/artifacts'):
            with self.subTest(name=name):
                path = self.root / name
                path.mkdir()
                with self.assertRaisesRegex(RuntimeError, 'generated state'):
                    source_inventory(self.root, locks)
                path.rmdir()
        (self.root / '.git').write_text('gitdir: elsewhere\n')
        with self.assertRaisesRegex(RuntimeError, 'generated state'):
            source_inventory(self.root, locks)


if __name__ == '__main__':
    unittest.main()
