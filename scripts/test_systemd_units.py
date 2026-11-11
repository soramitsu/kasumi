"""Every shipped systemd unit keeps the settings that protect key material.

docs/operations.md states that the unit disables core files and service swap,
drops capabilities and restricts filesystem writes. The release package ships
its own units beside the deployment template, so each one is checked here.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNITS = {
    "deploy/kasumi.service": "/var/lib/kasumi",
    "release/systemd/kasumid.service": "/var/lib/kasumi",
    "release/systemd/kasumi-authority.service": "/var/lib/kasumi-authority",
}
# The node opens its database files and listeners; the authority has no database.
NODE_UNITS = {"deploy/kasumi.service", "release/systemd/kasumid.service"}
ENABLED = {"yes", "true", "on", "1"}


def service_settings(path):
    """The [Service] section as {name: [values]}, in file order."""
    settings, section = {}, None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]":
            name, separator, value = line.partition("=")
            assert separator, f"{path}: malformed line {line!r}"
            settings.setdefault(name, []).append(value)
    return settings


class SystemdUnitTests(unittest.TestCase):
    def test_each_unit_denies_core_files_swap_capabilities_and_foreign_writes(self):
        for unit, state in UNITS.items():
            with self.subTest(unit=unit):
                settings = service_settings(ROOT / unit)
                self.assertEqual(settings.get("LimitCORE"), ["0"])
                self.assertEqual(settings.get("MemorySwapMax"), ["0"])
                self.assertEqual(settings.get("CapabilityBoundingSet"), [""])
                self.assertEqual(settings.get("UMask"), ["0077"])
                self.assertEqual(settings.get("ProtectSystem"), ["strict"])
                self.assertEqual(settings.get("ReadWritePaths"), [state])
                for switch in ("NoNewPrivileges", "ProtectHome", "PrivateTmp", "PrivateDevices"):
                    self.assertEqual(len(settings.get(switch, [])), 1, switch)
                    self.assertIn(settings[switch][0], ENABLED, switch)
                self.assertNotEqual(settings.get("User"), ["root"])
                self.assertEqual(len(settings.get("User", [])), 1)

    def test_each_unit_keeps_private_diagnostics_past_a_restart(self):
        # Failure detail is kept out of the journal and written to a private
        # file instead. PrivateTmp deletes the temporary directory when the
        # unit stops, so each unit needs a logs directory only it can read.
        for unit in UNITS:
            with self.subTest(unit=unit):
                settings = service_settings(ROOT / unit)
                self.assertEqual(len(settings.get("LogsDirectory", [])), 1)
                self.assertTrue(settings["LogsDirectory"][0])
                self.assertEqual(settings.get("LogsDirectoryMode"), ["0700"])

    def test_each_node_unit_raises_the_descriptor_limit(self):
        for unit in sorted(NODE_UNITS):
            with self.subTest(unit=unit):
                limit = service_settings(ROOT / unit).get("LimitNOFILE")
                self.assertEqual(len(limit or []), 1)
                # The generated configuration alone budgets 1,024 database
                # files and 256 directories, before any listener socket.
                self.assertGreaterEqual(int(limit[0]), 4096)

    def test_every_shipped_unit_is_checked(self):
        shipped = {str(path.relative_to(ROOT)) for directory in ("deploy", "release/systemd")
                   for path in (ROOT / directory).glob("*.service")}
        self.assertEqual(shipped, set(UNITS))

    def test_settings_ignore_comments_and_other_sections(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            unit = Path(directory) / "example.service"
            unit.write_text("[Unit]\nLimitCORE=infinity\n[Service]\n# LimitCORE=1\nLimitCORE=0\n"
                            "CapabilityBoundingSet=\n[Install]\nMemorySwapMax=1\n")
            self.assertEqual(service_settings(unit), {"LimitCORE": ["0"], "CapabilityBoundingSet": [""]})


if __name__ == "__main__":
    unittest.main()
