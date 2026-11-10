"""Offline checks for the disposable standalone helper; fake binaries stand in for Kasumi."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings

import dev_standalone as dev

# A fake long-running kasumid: it exits 0 on SIGINT or SIGTERM, like the
# watcher and the server, and keeps its command line (no exec).
RUN = "trap 'exit 0' INT TERM; while :; do sleep 0.1; done"


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


def free_base_port():
    """A base port whose three consecutive loopback ports are free now. They lie below the
    ephemeral ranges (macOS 49152, Linux 32768), where outgoing connections take ports."""
    for _ in range(200):
        base = random.randrange(20000, 32000)
        with contextlib.suppress(ValueError):
            dev.require_free(dev.ports(base))
            return base
    raise AssertionError("no three consecutive free loopback ports")


class DevStandaloneTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        # start and resume return while the supervisor they launched keeps running, as it
        # must outlive them. Called in this process, that looks like a leaked child.
        warnings.filterwarnings("ignore", r"subprocess \d+ is still running", ResourceWarning)

    def tearDown(self):
        # Never leave a supervisor or fake daemon behind a failed test.
        directory = self.root / "kasumi"
        if (directory / dev.STATE).exists():
            with contextlib.suppress(Exception):
                dev.stop(self.stopping(directory))
        self.temporary.cleanup()

    def stopping(self, directory, remove=False):
        return type("Arguments", (), {"directory": str(directory), "remove": remove})()

    def fakes(self, cases):
        """kasumid and kasumictl as one POSIX shell script dispatching on its first argument."""
        for name in ("kasumid", "kasumictl"):
            binary = self.root / name
            binary.write_text(f"#!/bin/sh\ncase \"$1\" in\n{cases}\nesac\n")
            binary.chmod(0o700)

    def instance(self, **values):
        """An existing instance directory whose state names the fake kasumid."""
        directory = self.root / "kasumi"
        (directory / "installation/profiles").mkdir(parents=True)
        state = {"directory": str(directory), "kasumid": str(self.root / "kasumid"),
                 "configuration": str(directory / "installation/kasumi.json"),
                 "profile": str(directory / "installation/profiles/default.json"),
                 "keep_awake": False, **values}
        dev.save(directory, state)
        return directory

    def eventually(self, condition, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            value = condition()
            if value:
                return value
            self.assertLess(time.monotonic(), deadline, "the condition did not hold in time")
            time.sleep(0.05)

    def events(self, directory):
        """The supervisor.log events' fields, in order."""
        lines = (directory / "supervisor.log").read_text().splitlines()
        return [json.loads(line)["fields"] for line in lines if line.startswith("{")]

    def event(self, directory, message, process, after=0):
        found = [entry for entry in self.events(directory)[after:]
                 if entry["message"] == message and entry.get("process") == process]
        return found[0] if found else None

    def state(self, directory):
        return dev.read_json(directory / dev.STATE)

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

    def test_state_updates_merge_and_survive_an_abandoned_pending_file(self):
        directory = self.root / "kasumi"
        directory.mkdir()
        dev.save(directory, {"directory": str(directory), "server": 1})
        (directory / (dev.STATE + ".pending")).write_text("{}")
        self.assertEqual(dev.update_state(directory, {"watcher": 2}),
                         {"directory": str(directory), "server": 1, "watcher": 2})
        self.assertEqual(self.state(directory), {"directory": str(directory), "server": 1, "watcher": 2})
        self.assertEqual(stat.S_IMODE((directory / dev.STATE).stat().st_mode), 0o600)

    def arguments(self, **values):
        defaults = {"directory": str(self.root / "kasumi"), "base_port": 19443, "bin_dir": str(self.root),
                    "collection": [], "ready_timeout": 1, "allow_sleep": True}
        return type("Arguments", (), {**defaults, **values})()

    def test_a_definition_is_compared_with_the_defaults_the_server_reads_back(self):
        index = {"name": "status", "fields": [{"path": "/status", "kind": "string"}]}
        text = {"name": "body", "fields": [{"path": "/body", "kind": "string"}],
                "unique": True, "text": {"analyzer": "unicode_v1"}}
        definition = {"name": "claims", "indexes": [index, text]}
        self.assertEqual(dev.with_definition_defaults(definition), {
            "name": "claims", "strict_read_audit": False,
            "indexes": [{**index, "unique": False, "text": None}, text]})
        self.assertEqual(dev.with_definition_defaults({"name": "claims", "strict_read_audit": True}),
                         {"name": "claims", "strict_read_audit": True, "indexes": []})
        # The caller's definition is not modified.
        self.assertEqual(definition, {"name": "claims", "indexes": [index, text]})

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
        # The supervisor would restart the server; start fails at its first exit, well before the deadline.
        with self.assertRaisesRegex(ValueError, "(?s)serve exited with exit status 1.*address in use"):
            dev.start(self.arguments(ready_timeout=60))
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
                              f"init) mkdir -p \"$4/profiles\" && cp {self.root}/profile.json \"$4/profiles/default.json\" "
                              f"&& cp {self.root}/profile.json \"$4/profiles/operator.json\";;\n"
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

    def test_connections_left_in_time_wait_do_not_make_a_port_busy(self):
        # A stopped kasumid closes its connections first, leaving TIME_WAIT on its own ports.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            client = socket.create_connection(("127.0.0.1", port))
            accepted, _ = listener.accept()
            accepted.close()
            client.recv(1)
            client.close()
        dev.require_free({"admin": port})
        # A live listener still makes it busy, even one that reuses addresses as kasumid's do.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen()
            with self.assertRaisesRegex(ValueError, f"admin port {port} is not free"):
                dev.require_free({"admin": port})

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
            self.assertFalse(dev.recorded(state, "supervisor", 123))
        script = subprocess.CompletedProcess([], 0, f"/bin/sh {state['kasumid']} serve {state['configuration']}\n")
        with patch("dev_standalone.subprocess.run", return_value=script):
            self.assertTrue(dev.owned(123, state["kasumid"], state["configuration"]))
        supervisor = subprocess.CompletedProcess([], 0, f"/usr/bin/python3 {dev.SCRIPT} supervise {directory}\n")
        with patch("dev_standalone.subprocess.run", return_value=supervisor):
            self.assertTrue(dev.recorded(state, "supervisor", 123))
            self.assertFalse(dev.recorded({**state, "directory": str(directory) + "2"}, "supervisor", 123))
        other = self.root / "other"
        other.mkdir()
        (other / dev.STATE).write_text(json.dumps({**state, "directory": str(directory)}))
        with self.assertRaisesRegex(ValueError, "another directory"):
            dev.stop(type("Arguments", (), {"directory": str(other), "remove": True})())
        self.assertTrue(other.exists())
        os.unlink(directory / dev.STATE)  # Nothing for tearDown to stop.

    def test_restart_delays_double_from_one_second_to_five_minutes(self):
        self.assertEqual([dev.restart_delay(failures) for failures in range(1, 12)],
                         [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300])
        self.assertEqual(dev.restart_delay(100000), 300)
        self.assertEqual(dev.exit_status(3), "exit status 3")
        self.assertEqual(dev.exit_status(-signal.SIGKILL), "signal SIGKILL")

    def test_the_supervisor_runs_caffeinate_on_itself_the_server_and_a_watcher_per_profile(self):
        directory = self.root / "kasumi"
        state = {"directory": str(directory), "kasumid": "/opt/kasumi/kasumid",
                 "configuration": "/i/kasumi.json", "profile": "/i/profiles/default.json",
                 "control_profile": "/i/profiles/control.json", "operator_profile": "/i/profiles/operator.json",
                 "mcp_profile": "/i/profiles/mcp.json", "keep_awake": True}
        watchers = ["watcher", "control_watcher", "operator_watcher", "mcp_watcher"]
        with patch("dev_standalone.keep_awake_available", return_value=True):
            entries = dev.supervised(state, directory, 4242)
            self.assertEqual([(entry.kind, entry.command, entry.log) for entry in entries], [
                ("keep_awake", ["/usr/bin/caffeinate", "-i", "-s", "-w", "4242"], None),
                ("server", ["/opt/kasumi/kasumid", "serve", "/i/kasumi.json"], directory / "server.log"),
                ("watcher", ["/opt/kasumi/kasumid", "credential", "watch", "/i/profiles/default.json"],
                 directory / "credential.log"),
                ("control_watcher", ["/opt/kasumi/kasumid", "credential", "watch", "/i/profiles/control.json"],
                 directory / "control-credential.log"),
                ("operator_watcher", ["/opt/kasumi/kasumid", "credential", "watch", "/i/profiles/operator.json"],
                 directory / "operator-credential.log"),
                # The Control administrator renews the MCP credential.
                ("mcp_watcher", ["/opt/kasumi/kasumid", "credential", "watch", "/i/profiles/mcp.json",
                                 "/i/profiles/control.json"], directory / "mcp-credential.log")])
            allowed = dev.supervised({**state, "keep_awake": False}, directory, 4242)
            self.assertEqual([entry.kind for entry in allowed], ["server", *watchers])
            # An installation from before the operator and MCP profiles watches what it has.
            older = {key: value for key, value in state.items() if key not in ("operator_profile", "mcp_profile")}
            self.assertEqual([entry.kind for entry in dev.supervised(older, directory, 4242)],
                             ["keep_awake", "server", "watcher", "control_watcher"])
            # Without a Control profile to renew it, the MCP credential gets no watcher.
            uncontrolled = {key: value for key, value in state.items() if key != "control_profile"}
            self.assertEqual([entry.kind for entry in dev.supervised(uncontrolled, directory, 4242)],
                             ["keep_awake", "server", "watcher", "operator_watcher"])
        with patch("dev_standalone.keep_awake_available", return_value=False):
            self.assertEqual([entry.kind for entry in dev.supervised(state, directory, 4242)], ["server", *watchers])
        for kind, name in (("operator_watcher", "operator.json"), ("mcp_watcher", "mcp.json")):
            self.assertEqual(dev.watched_profile({"profile": "/i/profiles/default.json"}, kind), f"/i/profiles/{name}")

    def test_the_supervisor_restarts_failed_processes_after_a_backoff_and_logs_each_restart(self):
        failed = self.root / "serve.failed"
        self.fakes(f"serve) if [ ! -e {failed} ]; then : > {failed}; echo control_plane_closed >&2; exit 3; fi\n"
                   f"  {RUN};;\ncredential) {RUN};;")
        directory = self.instance()
        supervisor = dev.launch_supervisor(directory)
        restarted = self.eventually(lambda: self.event(directory, "supervised process restarted", "server"))
        exited = self.event(directory, "supervised process exited; restarting", "server")
        self.assertEqual((exited["status"], exited["restart_in_seconds"], exited["consecutive_failures"]),
                         ("exit status 3", 1, 1))
        state = self.state(directory)
        self.assertEqual((state["supervisor"], state["server"]), (supervisor.pid, restarted["pid"]))
        self.assertEqual(state["last_exit"]["server"]["status"], "exit status 3")
        self.assertIn("control_plane_closed", (directory / "server.log").read_text())
        # A watcher killed by a signal is restarted too.
        watcher = self.eventually(lambda: self.state(directory).get("watcher"))
        os.kill(watcher, signal.SIGKILL)
        replaced = self.eventually(lambda: self.event(directory, "supervised process restarted", "watcher"))
        self.assertNotEqual(replaced["pid"], watcher)
        self.assertEqual(self.event(directory, "supervised process exited; restarting", "watcher")["status"],
                         "signal SIGKILL")
        self.eventually(lambda: self.state(directory)["watcher"] == replaced["pid"])
        server = self.state(directory)["server"]
        self.assertEqual(dev.stop(self.stopping(directory)), {
            "directory": str(directory), "supervisor": "stopped", "watcher": "stopped",
            "control_watcher": "absent", "operator_watcher": "absent", "mcp_watcher": "absent", "server": "stopped",
            "removed": False})
        supervisor.poll()
        for pid in (supervisor.pid, server, replaced["pid"]):
            self.assertFalse(dev.alive(pid))
        state = self.state(directory)
        self.assertEqual([state[kind] for kind in dev.RECORDED], [None] * len(dev.RECORDED))
        self.assertEqual(self.events(directory)[-1]["message"], "supervisor stopped")

    def test_a_clean_server_exit_ends_supervision(self):
        self.fakes(f"serve) sleep 0.5; exit 0;;\ncredential) {RUN};;")
        directory = self.instance()
        supervisor = dev.launch_supervisor(directory)
        self.assertEqual(supervisor.wait(timeout=60), 0)
        messages = [(entry["message"], entry.get("process")) for entry in self.events(directory)]
        self.assertIn(("supervised process exited cleanly; not restarting", "server"), messages)
        self.assertIn(("supervised process stopped", "watcher"), messages)
        self.assertNotIn(("supervised process restarted", "server"), messages)
        state = self.state(directory)
        self.assertEqual([state[kind] for kind in dev.RECORDED], [None] * len(dev.RECORDED))

    def test_a_second_supervisor_for_one_directory_refuses_to_run(self):
        self.fakes(f"serve|credential) {RUN};;")
        directory = self.instance()
        first = dev.launch_supervisor(directory)
        self.eventually(lambda: self.state(directory).get("server"))
        second = dev.launch_supervisor(directory)
        self.assertEqual(second.wait(timeout=60), 1)
        self.assertIn("another supervisor runs", (directory / "supervisor.log").read_text())
        self.assertEqual(self.state(directory)["supervisor"], first.pid)
        dev.stop(self.stopping(directory))
        first.poll()

    def test_start_returns_with_captured_output_while_its_supervisor_keeps_running(self):
        # kasumi_dev.py runs `start` with capture_output: the supervisor must not hold those pipes.
        (self.root / "profile.json").write_text(json.dumps(profile(self.root)))
        # The definition omits every optional field; the server reads them back as their defaults.
        index = {"name": "status", "fields": [{"path": "/status", "kind": "string"}]}
        installed = json.dumps({"ok": True, "result": {"collections": [
            {"name": "claims", "indexes": [{**index, "unique": False, "text": None}],
             "strict_read_audit": False}]}})
        self.fakes(f"init) mkdir -p \"$4/profiles\" && for name in default control operator mcp; do "
                   f"cp {self.root}/profile.json \"$4/profiles/$name.json\"; done;;\n"
                   f"serve|credential) {RUN};;\n--profile) echo '{installed}';;\n--config) exit 0;;")
        definition = self.root / "claims.collection.json"
        definition.write_text(json.dumps({"name": "claims", "indexes": [index]}))
        directory = self.root / "kasumi"
        completed = subprocess.run(
            [sys.executable, str(dev.SCRIPT), "start", str(directory), "--base-port", str(free_base_port()),
             "--bin-dir", str(self.root), "--collection", str(definition), "--allow-sleep"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        started = json.loads(completed.stdout)
        self.assertEqual(started["collections"], ["claims"])
        self.assertEqual(started["control_profile"], str(directory / "installation/profiles/control.json"))
        self.assertEqual(started["operator_profile"], str(directory / "installation/profiles/operator.json"))
        self.assertEqual(started["mcp_profile"], str(directory / "installation/profiles/mcp.json"))
        self.assertFalse(started["keep_awake"])
        self.assertEqual(started["logs"]["supervisor"], str(directory / "supervisor.log"))
        self.assertTrue(dev.recorded(started, "supervisor", started["supervisor"]))

        def every_process_recorded():
            current = self.state(directory)
            return current if all(current.get(kind) for kind in dev.RECORDED) else None

        current = self.eventually(every_process_recorded)
        for kind in dev.RECORDED:
            with self.subTest(process=kind):
                self.assertTrue(dev.alive(current[kind]) and dev.recorded(current, kind, current[kind]))
        self.assertEqual(dev.stop(self.stopping(directory, remove=True)), {
            "directory": str(directory), "supervisor": "stopped", "watcher": "stopped",
            "control_watcher": "stopped", "operator_watcher": "stopped", "mcp_watcher": "stopped", "server": "stopped",
            "removed": True})
        self.assertFalse(directory.exists())
        for kind in dev.RECORDED:
            self.assertFalse(dev.alive(current[kind]))

    def test_resume_supervises_a_stopped_instance_again(self):
        self.fakes(f"serve|credential) {RUN};;")
        base = free_base_port()
        # A state written before supervision: dead process IDs, and no Control or operator watcher yet.
        directory = self.instance(ports=dev.ports(base), server=2 ** 22 + 1, watcher=2 ** 22 + 2,
                                  logs={"server": "kept"})
        for name in ("control", "operator", "mcp"):
            (directory / f"installation/profiles/{name}.json").write_text("{}")

        def resuming(bin_dir=None):
            return type("Arguments", (), {"directory": str(directory), "allow_sleep": True, "bin_dir": bin_dir})()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", base))
            listener.listen()
            with self.assertRaisesRegex(ValueError, f"mcp port {base} is not free"):
                dev.resume(resuming())
        resumed = dev.resume(resuming())
        self.assertTrue(dev.alive(resumed["supervisor"]) and dev.alive(resumed["server"]))
        self.assertEqual(resumed["control_profile"], str(directory / "installation/profiles/control.json"))
        self.assertEqual(resumed["operator_profile"], str(directory / "installation/profiles/operator.json"))
        self.assertEqual(resumed["logs"]["server"], str(directory / "server.log"))
        self.eventually(lambda: all(self.state(directory).get(kind) for kind in dev.WATCHER_KINDS))
        with self.assertRaisesRegex(ValueError, "still running"):
            dev.resume(resuming())
        result = dev.stop(self.stopping(directory))
        self.assertEqual({kind: result[kind] for kind in dev.RECORDED}, dict.fromkeys(dev.RECORDED, "stopped"))
        # --bin-dir moves the instance to another kasumid build from then on.
        upgraded = self.root / "upgraded"
        upgraded.mkdir()
        with self.assertRaisesRegex(ValueError, "not executable"):
            dev.resume(resuming(str(upgraded)))
        os.link(self.root / "kasumid", upgraded / "kasumid")
        moved = dev.resume(resuming(str(upgraded)))
        self.assertEqual(moved["kasumid"], str(upgraded / "kasumid"))
        self.assertTrue(dev.recorded(moved, "server", moved["server"]))
        self.assertFalse(dev.owned(moved["server"], self.root / "kasumid", moved["configuration"]))

    def test_stop_stops_an_unsupervised_launch_including_a_recorded_control_watcher(self):
        # Instances launched before supervision record their processes, sometimes with a
        # hand-started Control watcher, and no supervisor.
        self.fakes(f"serve|credential) {RUN};;")
        directory = self.instance()
        state = self.state(directory)
        control = Path(state["profile"]).with_name("control.json")
        launched = {kind: subprocess.Popen([state["kasumid"], *command], stdin=subprocess.DEVNULL)
                    for kind, command in (("server", ["serve", state["configuration"]]),
                                          ("watcher", ["credential", "watch", state["profile"]]),
                                          ("control_watcher", ["credential", "watch", str(control)]))}
        dev.update_state(directory, {kind: process.pid for kind, process in launched.items()})
        self.eventually(lambda: all(dev.recorded(state, kind, process.pid) for kind, process in launched.items()))
        self.assertEqual(dev.stop(self.stopping(directory)), {
            "directory": str(directory), "supervisor": "absent", "watcher": "stopped",
            "control_watcher": "stopped", "operator_watcher": "absent", "mcp_watcher": "absent", "server": "stopped",
            "removed": False})
        for process in launched.values():
            process.poll()
            self.assertFalse(dev.alive(process.pid))

    @unittest.skipUnless(dev.keep_awake_available(), "caffeinate is macOS only")
    def test_the_supervisor_holds_a_keep_awake_assertion_until_it_stops(self):
        self.fakes(f"serve|credential) {RUN};;")
        directory = self.instance(keep_awake=True)
        supervisor = dev.launch_supervisor(directory)
        started = self.eventually(lambda: self.event(directory, "supervised process started", "keep_awake"))
        self.assertEqual(dev.command_line(started["pid"]), f"{dev.CAFFEINATE} -i -s -w {supervisor.pid}")
        assertions = subprocess.run(["pmset", "-g", "assertions"], capture_output=True, text=True).stdout
        held = {line.split(" named:")[0].split()[-1] for line in assertions.splitlines()
                if f"pid {started['pid']}(caffeinate)" in line}
        self.assertEqual(held, {"PreventUserIdleSystemSleep", "PreventSystemSleep"})
        self.assertEqual(self.events(directory)[0]["keep_awake"], "held")
        dev.stop(self.stopping(directory))
        supervisor.poll()
        self.eventually(lambda: not dev.alive(started["pid"]))


if __name__ == "__main__":
    unittest.main()
