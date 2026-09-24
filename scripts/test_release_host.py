"""Acceptance preflight must observe container limits before expensive linking."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import release_host
from release_host import MIN_MEMORY_BYTES, linux_effective_memory


class EffectiveMemoryTests(unittest.TestCase):
    def test_preflight_records_explicit_kernel_os_and_native_machine(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "host.json"
            with patch.object(release_host.platform, "system", return_value="Linux"), \
                    patch.object(release_host.platform, "machine", return_value="aarch64"), \
                    patch.object(release_host.platform, "platform", return_value="Linux-synthetic"), \
                    patch.object(release_host.shutil, "disk_usage", return_value=SimpleNamespace(free=128 << 30)), \
                    patch.object(release_host.shutil, "which", return_value=None), \
                    patch.object(release_host.os, "sysconf", return_value=16 << 30), \
                    patch.object(release_host, "linux_effective_memory", return_value=(16 << 30, {})), \
                    patch.object(Path, "read_text", return_value="0::/"), \
                    patch.object(release_host, "sha256", return_value="a" * 64), \
                    patch.object(release_host, "write_json") as write_json, \
                    patch.object(release_host.sys, "argv", ["release_host.py", "--output", str(output),
                                                           "--target", "aarch64-unknown-linux-gnu"]):
                release_host.main()
            record = write_json.call_args.args[1]
            self.assertEqual(record["schema"], 2)
            self.assertEqual((record["os"], record["machine"], record["requested_target"]),
                             ("Linux", "aarch64", "aarch64-unknown-linux-gnu"))
            self.assertEqual(record["errors"], [])

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
