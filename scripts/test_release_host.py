"""Acceptance preflight must observe container limits before expensive linking."""
from pathlib import Path
import tempfile
import unittest

from release_host import MIN_MEMORY_BYTES, linux_effective_memory


class EffectiveMemoryTests(unittest.TestCase):
    def test_container_root_and_stricter_ancestor_bound_physical_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "memory.max").write_text(str(7 << 30))
            effective, limits = linux_effective_memory(64 << 30, "0::/\n", root)
            self.assertEqual(effective, 7 << 30)
            self.assertLess(effective, MIN_MEMORY_BYTES)
            self.assertEqual(len(limits), 1)
            (root / "jobs" / "one").mkdir(parents=True)
            (root / "jobs" / "memory.max").write_text(str(16 << 30))
            (root / "jobs" / "one" / "memory.max").write_text("max")
            effective, _ = linux_effective_memory(64 << 30, "0::/jobs/one\n", root)
            self.assertEqual(effective, 7 << 30)
            (root / "memory.max").write_text("max")
            effective, _ = linux_effective_memory(64 << 30, "0::/jobs/one\n", root)
            self.assertEqual(effective, 16 << 30)
            self.assertGreaterEqual(effective, MIN_MEMORY_BYTES)

    def test_v1_limits_and_invalid_kernel_values_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "memory" / "worker"
            path.mkdir(parents=True)
            (path / "memory.limit_in_bytes").write_text(str(4 << 30))
            effective, _ = linux_effective_memory(32 << 30, "2:cpu,memory:/worker", root)
            self.assertEqual(effective, 4 << 30)
            (path / "memory.limit_in_bytes").write_text("invalid")
            with self.assertRaises(ValueError):
                linux_effective_memory(32 << 30, "2:memory:/worker", root)
            with self.assertRaises(ValueError):
                linux_effective_memory(32 << 30, "0::/../../escape", root)


if __name__ == "__main__":
    unittest.main()
