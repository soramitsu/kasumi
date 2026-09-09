"""Pure mocked dispatch guards: no Docker, Git, VM, native process, or listener."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("vm_dispatch", "/tmp/kasumi-small-native-vm-dispatch.py")
dispatch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dispatch)


class DispatchGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / "output"
        self.output.mkdir()
        self.source = self.root / "source"
        self.source.mkdir()
        self.build = self.root / "build"
        (self.build / "target/release").mkdir(parents=True)
        self.runner = self.root / "small_native_smoke.py"
        self.runner.write_bytes(b"reviewed runner fixture")
        (self.build / "evidence.json").write_bytes(b"reviewed evidence fixture")
        for name in ("kasumid", "kasumictl", "kasumi-bench-capacity"):
            (self.build / "target/release" / name).write_bytes(b"nonexecutable fixture")
        for name, value in {"OUTPUT": self.output, "BUILD": self.build, "SOURCE": self.source,
                            "RUNNER": self.runner, "RUNNER_SHA": dispatch.sha(self.runner),
                            "BUILD_SHA": dispatch.sha(self.build / "evidence.json")}.items():
            replacement = patch.object(dispatch, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        for name in ("Popen",):
            forbidden = patch.object(dispatch.subprocess, name,
                                     side_effect=AssertionError("pure test attempted subprocess"))
            forbidden.start()
            self.addCleanup(forbidden.stop)
        self.subject = object.__new__(dispatch.Dispatch)
        self.subject.record = {"commands": []}
        self.subject.persist = Mock()
        self.subject.owner = "1" * 32
        self.subject.name = "kasumi-small-native-001-" + self.subject.owner
        self.subject.cid = None
        self.subject.ownership_verified = False
        self.subject.create_attempted = False
        self.subject.create_certain = False
        self.commands = []

    def result(self, name, data):
        path = self.root / (name + ".mock-output")
        path.write_bytes(data)
        return {"exit_code": 0}, path

    def preflight(self, active):
        preserved = ["1e568c64b3ea", "8439dd098eee", "94255cddb090"]
        def command(name, args):
            self.commands.append(args)
            data = {"source-head": dispatch.COMMIT.encode() + b"\n",
                    "source-tree": b"a" * 40 + b"\n",
                    "preflight-all-containers": ("\n".join(preserved) + "\n").encode(),
                    "preflight-active-containers": active}[name]
            return self.result(name, data)
        self.subject.command = command
        self.subject.inspect = Mock(return_value={"Id": dispatch.IMAGE, "Architecture": "arm64", "Os": "linux"})
        return preserved

    def test_preflight_preserves_exited_context_and_admits_no_active_container(self):
        preserved = self.preflight(b"")
        self.subject.preflight()
        self.assertEqual(self.subject.record["preserved_container_ids"], preserved)
        self.assertIn(["docker", "ps", "-aq"], self.commands)
        self.assertIn(["docker", "ps", "-q"], self.commands)
        self.assertFalse(self.subject.create_attempted)
        self.assertEqual(len(self.subject.record["input_binaries"]), 3)

    def test_preflight_rejects_active_without_touching_preserved_containers(self):
        preserved = self.preflight(b"a11111111111\n")
        with self.assertRaisesRegex(RuntimeError, "active containers"):
            self.subject.preflight()
        self.assertEqual(self.subject.record["preserved_container_ids"], preserved)
        self.assertFalse(self.subject.create_attempted)
        self.subject.inspect.assert_not_called()
        self.assertTrue(all(args[0] == "git" or args[1] == "ps" for args in self.commands))

    def creation(self):
        cid = "a" * 64
        mounts = [(self.output, "/results", True), (self.source, "/source", False),
                  (self.build, "/build", False), (self.runner, "/tools/small_native_smoke.py", False)]
        value = {"Id": cid, "Image": dispatch.IMAGE, "Name": "/" + self.subject.name,
                 "Config": {"Labels": {dispatch.LABEL: self.subject.owner},
                            "Env": [key + "=" + val for key, val in dispatch.CONTAINER_ENV.items()]},
                 "HostConfig": {"Init": True, "ReadonlyRootfs": True, "NetworkMode": "none",
                                "NanoCpus": 2_000_000_000, "Memory": 4 << 30, "MemorySwap": 4 << 30,
                                "PidsLimit": 512,
                                "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=268435456,mode=1777"}},
                 "Mounts": [{"Type": "bind", "Source": str(host), "Destination": guest, "RW": rw}
                            for host, guest, rw in mounts], "State": {"Status": "created"}}
        def command(name, args):
            self.commands.append(args)
            self.assertEqual(name, "container-create")
            (self.output / "container.cid").write_text(cid + "\n")
            return self.result(name, (cid + "\n").encode())
        self.subject.command = command
        self.subject.inspect = Mock(return_value=value)
        return value

    def test_create_installs_exact_git_and_python_environment_and_readonly_inputs(self):
        self.creation()
        self.subject.create()
        self.assertTrue(self.subject.create_certain)
        self.assertTrue(self.subject.ownership_verified)
        self.assertEqual(len(self.commands), 1)
        args = self.commands[0]
        supplied = [args[i + 1] for i, arg in enumerate(args) if arg == "--env"]
        self.assertEqual(supplied, [key + "=" + val for key, val in dispatch.CONTAINER_ENV.items()])
        self.assertIn("GIT_CONFIG_VALUE_0=/source", supplied)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", supplied)
        self.assertNotIn("start", args)
        self.assertNotIn("rm", args)

    def test_create_rejects_missing_changed_and_duplicate_required_environment(self):
        original = self.creation()
        for key in dispatch.CONTAINER_ENV:
            for variant in ("missing", "changed", "duplicate"):
                with self.subTest(key=key, variant=variant):
                    value = copy.deepcopy(original)
                    env = value["Config"]["Env"]
                    entry = key + "=" + dispatch.CONTAINER_ENV[key]
                    if variant == "missing":
                        env.remove(entry)
                    elif variant == "changed":
                        env[env.index(entry)] = key + "=wrong"
                    else:
                        env.append(entry)
                    self.subject.inspect.return_value = value
                    with self.assertRaisesRegex(RuntimeError, "environment differs"):
                        self.subject.create()
                    self.assertFalse(self.subject.create_certain)
        self.assertTrue(all(args[:2] == ["docker", "create"] for args in self.commands))

    def test_create_rejects_writable_source_before_start(self):
        value = self.creation()
        value["Mounts"][1]["RW"] = True
        with self.assertRaisesRegex(RuntimeError, "mounts differ"):
            self.subject.create()
        self.assertFalse(self.subject.create_certain)
        self.assertEqual(len(self.commands), 1)


if __name__ == "__main__":
    unittest.main()
