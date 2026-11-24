import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import run_correctness as runner


class CorrectnessTests(unittest.TestCase):
    def test_frozen_scenarios_cover_each_unique_source_test(self):
        source = Path(__file__).resolve().parents[1]
        cases = runner.load_cases(source / runner.CONFIG)
        for tests in cases.values():
            for crate, _target, name in tests:
                files = (source / "crates" / crate).rglob("*.rs")
                definitions = sum(path.read_text().count("fn " + name + "(") for path in files)
                self.assertEqual(definitions, 1, (crate, name))

    def test_frozen_target_requires_the_compiling_package_profile_and_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
            (root / "target/debug").mkdir(parents=True)
            binary = root / "target/debug/fixture"
            binary.write_bytes(b"correct executable")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            process = root / "process.json"
            original = Path("/transported build/source")
            process.write_text(json.dumps({"working_directory": str(original)}))
            crate = "kasumi-kv"
            item = {"test": True, "target": "body", "package_id": "path+" +
                    (original / "crates" / crate).as_uri() + "#0.1.0", "sha256": digest}
            source = {"gates": [{"name": "workspace", "process": process.name,
                                 "process_sha256": hashlib.sha256(process.read_bytes()).hexdigest(),
                                 "executables": {"debug/fixture": item}}]}
            cases = {"case": [[crate, "body", "specific_case"]]}
            self.assertEqual(runner.artifacts(root, source, cases),
                             {(crate, "body"): ("debug/fixture", digest)})
            for change in ({"package_id": "registry+https://example.invalid#kasumi-kv@0.1.0"},
                           {"package_id": item["package_id"].replace("kasumi-kv", "another")},
                           {"test": False}, {"target": "other"}, {"sha256": "0" * 64}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    changed = copy.deepcopy(source)
                    changed["gates"][0]["executables"]["debug/fixture"].update(change)
                    runner.artifacts(root, changed, cases)

    def test_wrong_zero_or_ignored_libtest_output_is_rejected(self):
        names = runner.test_list(b"left::target: test\nother: test\n")
        self.assertEqual(runner.resolve(names, "target"), "left::target")
        for listing in (b"", b"left::target: test\nleft::target: test\n", b"not a listing"):
            with self.assertRaises(ValueError):
                runner.test_list(listing)
        for listing in (b"a::target: test\nb::target: test\n", b"left::target: benchmark\n"):
            with self.assertRaises(ValueError):
                runner.resolve(runner.test_list(listing), "target")
        good = (b"running 1 test\ntest left::target ... ok\n"
                b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                b"1 filtered out; finished in 0.02s\n")
        runner.check_pass(good, "left::target", 2)
        for bad in (good.replace(b"1 test\n", b"0 tests\n"),
                    good.replace(b"left::target", b"right::target"),
                    good.replace(b" ... ok", b" ... ignored"),
                    good.replace(b"1 filtered", b"0 filtered"),
                    good + good, b""):
            with self.assertRaises(ValueError):
                runner.check_pass(bad, "left::target", 2)
