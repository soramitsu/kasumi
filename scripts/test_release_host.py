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
                    patch.object(release_host, "linux_emulation", return_value=("aarch64", [])), \
                    patch.object(Path, "read_text", return_value="0::/"), \
                    patch.object(release_host, "sha256", return_value="a" * 64), \
                    patch.object(release_host, "write_json") as write_json, \
                    patch.object(release_host.sys, "argv", ["release_host.py", "--output", str(output),
                                                           "--target", "aarch64-unknown-linux-gnu"]):
                release_host.main()
            record = write_json.call_args.args[1]
            self.assertEqual(record["schema"], 3)
            self.assertIs(record["translated"], False)
            self.assertEqual(record["emulation"], {"kernel_architecture": "aarch64", "findings": []})
            self.assertEqual((record["os"], record["machine"], record["requested_target"]),
                             ("Linux", "aarch64", "aarch64-unknown-linux-gnu"))
            self.assertEqual(record["errors"], [])

    def proc(self, root, kernel=None, handlers=()):
        if kernel is not None:
            (root / "sys/kernel").mkdir(parents=True)
            (root / "sys/kernel/arch").write_text(kernel + "\n")
        directory = root / "sys/fs/binfmt_misc"
        directory.mkdir(parents=True)
        (directory / "status").write_text("enabled\n")
        (directory / "register").write_text("")
        for name, state, interpreter, machine in handlers:
            magic = bytearray(b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x02\x00" + bytes(2))
            magic[18:20] = machine.to_bytes(2, "little")
            mask = bytearray(b"\xff" * 5 + b"\xfe\xfe" + bytes(1) + b"\xff" * 8 + b"\xfe\xff\xff\xff")
            (directory / name).write_text(
                state + "\ninterpreter " + interpreter + "\nflags: POCF\noffset 0\nmagic "
                + magic.hex() + "\nmask " + mask.hex() + "\n")
        return root

    def test_linux_translation_is_found_from_kernel_facts_not_uname(self):
        cases = (
            # Native: the kernel agrees and only foreign formats are handled.
            ("native", "aarch64", "aarch64", [("qemu-x86_64", "enabled", "/usr/bin/qemu-x86_64-static", 62)], 0),
            ("native-old-kernel", None, "x86_64", [], 0),
            # qemu-user or Rosetta: uname reports the emulated architecture.
            ("foreign-kernel", "x86_64", "aarch64", [], 1),
            ("qemu-user", None, "aarch64", [("qemu-aarch64", "enabled", "/usr/bin/qemu-aarch64-static", 183)], 1),
            ("rosetta", "aarch64", "x86_64", [("rosetta", "enabled", "/run/rosetta/rosetta", 62)], 2),
            ("disabled-handler", "aarch64", "aarch64", [("qemu-aarch64", "disabled", "/usr/bin/qemu-aarch64-static", 183)], 0))
        for label, kernel, machine, handlers, expected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                observed, findings = release_host.linux_emulation(
                    machine, self.proc(Path(temporary), kernel, handlers))
                self.assertEqual((observed, len(findings)), (kernel, expected), findings)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.proc(Path(temporary), "aarch64")
            (root / "sys/fs/binfmt_misc/broken").write_text("enabled\nmagic zz\n")
            with self.assertRaisesRegex(ValueError, "unreadable binary-format handler"):
                release_host.linux_emulation("aarch64", root)

    def test_translated_linux_host_fails_the_preflight_and_is_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "host.json"
            finding = "binary-format handler qemu-aarch64 runs aarch64 executables through /usr/bin/qemu"
            with patch.object(release_host.platform, "system", return_value="Linux"), \
                    patch.object(release_host.platform, "machine", return_value="aarch64"), \
                    patch.object(release_host.platform, "platform", return_value="Linux-synthetic"), \
                    patch.object(release_host.shutil, "disk_usage", return_value=SimpleNamespace(free=128 << 30)), \
                    patch.object(release_host.shutil, "which", return_value=None), \
                    patch.object(release_host.os, "sysconf", return_value=16 << 30), \
                    patch.object(release_host, "linux_effective_memory", return_value=(16 << 30, {})), \
                    patch.object(release_host, "linux_emulation", return_value=("x86_64", [finding])), \
                    patch.object(Path, "read_text", return_value="0::/"), \
                    patch.object(release_host, "sha256", return_value="a" * 64), \
                    patch.object(release_host, "write_json") as write_json, \
                    patch.object(release_host.sys, "argv", ["release_host.py", "--output", str(output),
                                                           "--target", "aarch64-unknown-linux-gnu"]):
                with self.assertRaisesRegex(SystemExit, "translated execution"):
                    release_host.main()
            record = write_json.call_args.args[1]
            self.assertIs(record["translated"], True)
            self.assertEqual(record["emulation"]["findings"], [finding])
            self.assertIn("translated execution cannot satisfy the native host gate", record["errors"])

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
