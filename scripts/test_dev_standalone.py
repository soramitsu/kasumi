"""Offline checks for the disposable standalone helper; no Kasumi processes."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import dev_standalone as dev


def profile(directory):
    return {
        "format": 2,
        "family_id": "9d347667-433e-4b7f-b49e-a9ba6db43eaa",
        "tenant": "default",
        "principal": "administrator",
        "resource": {"kind": "database", "incarnation": "3e3c3fe0-5f81-418e-9c2e-6e99a915a61b"},
        "native_endpoint": "https://localhost:19444",
        "administrative_members": {"1": {"endpoint": "https://localhost:19445",
                                         "certificate_pins": ["b" * 64, "a" * 64]}},
        "mcp_endpoint": "https://localhost:19443/mcp",
        "identity": {"certificate": str(directory / "client.pem"),
                     "private_key": str(directory / "client-key.pem")},
        "server_ca": str(directory / "ca.pem"),
        "native_certificate_pin": "c" * 64,
        "bearer_file": str(directory / "default.token"),
    }


class DevStandaloneTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_three_consecutive_loopback_listeners_from_one_base_port(self):
        self.assertEqual(dev.ports(19443), {"mcp": 19443, "native": 19444, "admin": 19445})
        self.assertEqual(dev.network(dev.ports(19443)), {
            "mcp_listen": "127.0.0.1:19443", "mcp_public_url": "https://localhost:19443/mcp",
            "native_listen": "127.0.0.1:19444", "admin_listen": "127.0.0.1:19445"})
        for base in (0, 1023, 65534, "19443"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                dev.ports(base)

    def test_admin_client_and_binding_name_files_without_reading_credentials(self):
        token = self.root / "default.token"
        token.write_text("secret-bearer-value")
        installed = profile(self.root)
        path = self.root / "default.json"
        path.write_text(json.dumps(installed))
        admin = dev.admin_client(installed)
        self.assertEqual(admin["token_file"], str(token))
        self.assertEqual(admin["server_certificate_pins"], ["a" * 64, "b" * 64])
        self.assertEqual(admin["endpoint"], "https://localhost:19445")
        description = dev.binding(path)
        self.assertEqual(description, {
            "profile_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "tenant": "default", "incarnation": installed["resource"]["incarnation"],
            "principal": "administrator", "family_id": installed["family_id"]})
        self.assertNotIn("secret-bearer-value", json.dumps([admin, description]))
        installed["resource"]["kind"] = "control"
        path.write_text(json.dumps(installed))
        with self.assertRaises(ValueError):
            dev.binding(path)

    def test_private_files_are_new_and_owner_only(self):
        path = self.root / "state.json"
        dev.private_write(path, {"a": 1})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            dev.private_write(path, {"a": 2})
        link = self.root / "link.json"
        link.symlink_to(self.root / "elsewhere.json")
        with self.assertRaises(OSError):
            dev.private_write(link, {})
        self.assertFalse((self.root / "elsewhere.json").exists())

    def arguments(self, **values):
        defaults = {"directory": str(self.root / "kasumi"), "base_port": 19443, "bin_dir": str(self.root),
                    "collection": [], "ready_timeout": 1}
        return type("Arguments", (), {**defaults, **values})()

    def test_start_refuses_relative_existing_or_unusable_inputs_before_creating_anything(self):
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text("#!/bin/sh\nexit 1\n")
            binary.chmod(0o700)
        (self.root / "existing").mkdir()
        with self.assertRaises(ValueError):
            dev.start(self.arguments(directory="relative/kasumi"))
        with self.assertRaises(FileExistsError):
            dev.start(self.arguments(directory=str(self.root / "existing")))
        with self.assertRaises(ValueError):
            dev.start(self.arguments(base_port=80))
        with self.assertRaises(ValueError):
            dev.start(self.arguments(bin_dir=str(self.root / "missing")))
        definition = self.root / "claims.collection.json"
        definition.write_text(json.dumps({"name": "claims"}))
        with self.assertRaises(ValueError):
            dev.start(self.arguments(collection=[str(definition), str(definition)]))
        self.assertFalse((self.root / "kasumi").exists())

    def test_failed_start_removes_everything_it_created(self):
        # The fake kasumid records the temporary directory it was given.
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text("#!/bin/sh\necho \"$TMPDIR\" > \"$TMPDIR/seen\"\n"
                              "cp \"$TMPDIR/seen\" " + str(self.root / "seen") + "\n"
                              "echo init-failed >&2\nexit 1\n")
            binary.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "init-failed"):
            dev.start(self.arguments())
        directory = self.root / "kasumi"
        self.assertFalse(directory.exists())
        self.assertEqual((self.root / "seen").read_text().strip(), str(directory / "tmp"))

    def test_a_failed_server_quotes_its_log_and_leaves_no_credentials(self):
        directory = self.root / "kasumi"
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text("#!/bin/sh\n"
                              "if [ \"$1\" = init ]; then mkdir -p \"$4/profiles\" && "
                              "echo secret > \"$4/profiles/default.token\" && "
                              "cp \"$4/profiles/default.token\" " + str(self.root / "created") + "; exit 0; fi\n"
                              "echo 'listener 127.0.0.1:19444: address in use' >&2\nexit 1\n")
            binary.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "(?s)serve exited.*address in use"):
            dev.start(self.arguments())
        self.assertTrue((self.root / "created").exists())
        self.assertFalse(directory.exists())

    def test_a_failure_after_serving_stops_both_children_and_removes_the_directory(self):
        (self.root / "profile.json").write_text(json.dumps(profile(self.root)))
        # Popen can return before the shell has finished writing its PID file.
        # Let each simulated response wait for that child's completed startup.
        for name in ("server.ready", "watcher.ready"):
            os.mkfifo(self.root / name, 0o600)
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text("#!/bin/sh\ncase \"$1\" in\n"
                              f"init) mkdir -p \"$4/profiles\" && cp {self.root}/profile.json \"$4/profiles/default.json\";;\n"
                              f"serve) echo $$ > {self.root}/server.pid; "
                              f"echo ready > {self.root}/server.ready; exec sleep 30;;\n"
                              f"credential) echo $$ > {self.root}/watcher.pid; "
                              f"echo ready > {self.root}/watcher.ready; exec sleep 30;;\n"
                              f"--profile) read ready < {self.root}/server.ready; "
                              "echo '{\"ok\":true,\"result\":{\"collections\":[]}}';;\n"
                              f"*) read ready < {self.root}/watcher.ready; "
                              "echo 'create refused' >&2; exit 1;;\nesac\n")
            binary.chmod(0o700)
        definition = self.root / "claims.collection.json"
        definition.write_text(json.dumps({"name": "claims"}))
        with self.assertRaisesRegex(ValueError, "create refused"):
            dev.start(self.arguments(collection=[str(definition)]))
        self.assertFalse((self.root / "kasumi").exists())
        for name in ("server.pid", "watcher.pid"):
            with self.subTest(process=name), self.assertRaises(ProcessLookupError):
                os.kill(int((self.root / name).read_text()), 0)

    def test_busy_ports_are_refused_before_anything_is_created(self):
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text("#!/bin/sh\nexit 1\n")
            binary.chmod(0o700)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            busy = listener.getsockname()[1]
            with self.assertRaisesRegex(ValueError, f"mcp port {busy} is not free"):
                dev.start(self.arguments(base_port=busy))
        self.assertFalse((self.root / "kasumi").exists())
        self.assertEqual(dev.children(self.root)["TMPDIR"], str(self.root / "tmp"))

    def test_stop_signals_only_processes_it_started(self):
        directory = self.root / "kasumi"
        directory.mkdir()
        state = {"directory": str(directory), "kasumid": "/opt/kasumi/kasumid",
                 "configuration": str(directory / "installation/kasumi.json"),
                 "profile": str(directory / "installation/profiles/default.json"),
                 "server": os.getpid()}
        dev.save(directory, state)
        arguments = type("Arguments", (), {"directory": str(directory), "remove": True})()
        with patch("dev_standalone.os.kill") as kill:
            with self.assertRaisesRegex(ValueError, "did not start"):
                dev.stop(arguments)
            self.assertTrue(all(call.args[1] == 0 for call in kill.call_args_list))
        self.assertTrue(directory.exists())
        listing = subprocess.CompletedProcess([], 0, f"{state['kasumid']} serve {state['configuration']}\n")
        with patch("dev_standalone.subprocess.run", return_value=listing):
            self.assertTrue(dev.owned(123, state["kasumid"], state["configuration"]))
            self.assertFalse(dev.owned(123, state["kasumid"], state["profile"]))
            self.assertFalse(dev.owned(123, "/other/kasumid", state["configuration"]))
        other = self.root / "other"
        other.mkdir()
        (other / dev.STATE).write_text(json.dumps({**state, "directory": str(directory)}))
        with self.assertRaisesRegex(ValueError, "another directory"):
            dev.stop(type("Arguments", (), {"directory": str(other), "remove": True})())
        self.assertTrue(other.exists())


if __name__ == "__main__":
    unittest.main()
