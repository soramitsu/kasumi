"""Transport synthetic native custody roots through the operator's own commands.

One journal holds real attempts: the functional launcher and the independent
build producer against stand-in toolchains, and domain attempts that each own
one real child process. Passed, failed, interrupted and pre-dispatch outcomes
are all present. None of it is release evidence.
"""
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

import attempt_index
import domain_run
import package_release
import release_gate
import repeatable_assembly as assembly
import test_release_gate as functional_fixture
import test_run_independent_build as independent_fixture
import transport_attempt_journal as custody
import verify_release_acceptance as acceptance

SCRIPTS = Path(custody.__file__).resolve(strict=True).parent
JOURNAL = independent_fixture.JOURNAL
CAP = 1 << 30
RECORD = independent_fixture.producer.RECORD
REFUSED = (OSError, ValueError, KeyError, TypeError, tarfile.TarError)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def command(*arguments):
    """Run one frozen script as the operator would; return its exit code and output."""
    done = subprocess.run([sys.executable, "-I", "-S", "-B", *map(str, arguments)],
                          capture_output=True, text=True, timeout=600)
    return done.returncode, done.stdout, done.stderr


def domain(root, name, kind, status, report=None):
    """One journaled domain attempt that owned a real child process."""
    output = root / name
    attempt_index.begin(root, name, kind, output, now())
    output.mkdir()
    python = str(Path(sys.executable).resolve(strict=True))
    item = assembly.run_owned(output, "probe", [python, "-I", "-S", "-B", "-c", "print('domain probe')"],
                              str(output), {"PATH": "/usr/bin:/bin"}, 60)
    (output / "report.json").write_text(json.dumps(report or {"attempt": name}) + "\n")
    (output / "raw/nested").mkdir(parents=True)
    (output / "raw/nested/unreferenced.log").write_text("kept with the whole domain output\n")
    (output / "empty").mkdir()

    def lifted(ref):
        return {**ref, "path": name + "/" + ref["path"]}

    attempt_index.finish_outcome(
        root, name, status, now(), products={"report": "report.json"}, dispatch_started=True,
        processes=[{"id": "probe", "receipt": lifted(item["receipt"]), "log": lifted(item["stdout"]),
                    "executable": lifted(item["executable"])}])


@unittest.skipUnless(independent_fixture.TARGET is not None and functional_fixture.NATIVE is not None
                     and sys.platform in ("darwin", "linux") and sys.version_info >= (3, 11),
                     "custody transport needs a release host platform")
class CustodyTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        functional = functional_fixture.JournaledFunctionalRunTests("test_development_run_stays_unjournaled")
        independent = independent_fixture.IndependentBuildTests("test_existing_output_is_never_admitted")
        for fixture in (functional, independent):
            fixture.setUp()
            cls.addClassCleanup(fixture.doCleanups)
        cls.independent = independent
        cls.base = independent.root
        cls.root = independent.native
        # Independent builds: compiled, failed with a partial product, refused before dispatch.
        cls.built = independent.build("independent-1")
        independent.mode(exit=101, binaries=["kasumid"])
        independent.build("independent-failed")
        independent.mode()
        stale = {**independent.reservation, "starts_at": "2026-01-01T00:00:00+00:00",
                 "ends_at": "2026-01-02T00:00:00+00:00"}
        independent.build("independent-rejected", reservation=stale)
        # The primary functional run joins the same journal as functional-1.
        functional.root = cls.root
        assert functional.launch() == 0
        domain(cls.root, "correctness-1", "correctness", "passed")
        domain(cls.root, "recovery-1", "recovery", "interrupted")
        cls.transfer = cls.base / "transfer"
        cls.transfer.mkdir()
        # An earlier complete transfer, then one more admission: the journal has moved on.
        cls.earlier = cls.produce("earlier")
        domain(cls.root, "observability-1", "observability", "failed")
        cls.current = cls.produce("current")
        code, out, error = command(SCRIPTS / "attempt_index.py", "head", "--root", cls.root)
        assert code == 0, error
        cls.head = json.loads(out)
        cls.heads = cls.anchors("native-journal-heads.json", cls.head, str(cls.root))

    @classmethod
    def produce(cls, name):
        archive, producer = cls.transfer / (name + ".tar"), cls.transfer / (name + ".producer.json")
        code, out, error = command(SCRIPTS / "transport_attempt_journal.py", "produce", "--root", cls.root,
                                   "--archive", archive, "--producer", producer, "--max-bytes", CAP)
        assert code == 0, error
        return {"archive": archive, "producer": producer, **json.loads(out)}

    @classmethod
    def anchors(cls, name, head, original_root):
        path = cls.base / "operator" / name
        path.write_text(json.dumps([{"head": head, "original_root": original_root}]))
        return path

    def bundle(self, name):
        destination = self.base / name / "native-attempts" / JOURNAL
        destination.parent.mkdir(parents=True)
        return destination, self.base / (name + "-record")

    def restored(self, name, transfer):
        output = self.base / name
        output.mkdir()
        custody.read_archive(transfer["archive"], transfer["transport"]["archive_sha256"],
                             transfer["transport"]["manifest_sha256"], CAP, output)
        return output

    def assert_nothing_admitted(self, destination, record):
        self.assertEqual(list(destination.parent.iterdir()), [])
        receipt = json.loads((record / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "rejected")
        self.assertTrue(receipt["error"])
        return receipt["error"]

    def test_operator_commands_admit_a_complete_root_the_frozen_verifier_replays(self):
        destination, record = self.bundle("bundle")
        code, out, error = command(
            SCRIPTS / "transport_attempt_journal.py", "admit", "--archive", self.current["archive"],
            "--producer-manifest", self.current["producer"],
            "--producer-sha256", self.current["producer_sha256"], "--journal-heads", self.heads,
            "--max-bytes", CAP, "--output", destination, "--record", record)
        self.assertEqual(code, 0, error)
        receipt = json.loads((record / "receipt.json").read_text())
        self.assertEqual((receipt["status"], receipt["head"], receipt["original_root"], json.loads(out)["status"]),
                         ("admitted", self.head, str(self.root), "admitted"))
        self.assertEqual({fact["id"]: (fact["kind"], fact["status"], fact["selectable"])
                          for fact in receipt["attempts"]}, {
            "functional-1": ("functional", "passed", True),
            "independent-1": ("independent-build", "passed", True),
            "independent-failed": ("independent-build", "failed", False),
            "independent-rejected": ("independent-build", "failed", False),
            "correctness-1": ("correctness", "passed", True),
            "recovery-1": ("recovery", "interrupted", False),
            "observability-1": ("observability", "failed", False)})
        self.assertEqual([entry.name for entry in destination.parent.iterdir()], [JOURNAL])

        # The frozen verifier replays the relocated root against the operator's head and original
        # root, selecting each passed attempt as a gate would.
        names = sorted(path.name for path in (destination / "attempts").iterdir() if path.is_dir())
        retained = [{"id": name, "receipt": attempt_index.file_ref(
                        destination, destination / "attempts" / name / "attempt.json")} for name in names]
        acceptance.verify_attempts(
            destination, retained, {"run/evidence.json": "functional", "independent-1/" + RECORD: "independent-build",
                                    "correctness-1/outcome.json": "correctness"},
            head=self.head, original_root=str(self.root))
        package_release.verify_evidence(destination / "run")
        actual = {name: release_gate.sha256(self.root / "independent-1/build/target/release" / name)
                  for name in acceptance.package.BINARIES}
        whole = destination.parent.parent
        acceptance.check_independent_build(
            whole, attempt_index.file_ref(whole, whole / self.built["bundle_record"]),
            {"build_id": JOURNAL + ":functional-1", "build_root": "/unit/functional",
             "environment_id": "functional-environment"},
            independent_fixture.TARGET, self.independent.identity, actual)

        # Original relative paths, bytes and modes; failures and whole domain outputs included.
        manifest = json.loads((record / "manifest.json").read_text())
        self.assertEqual(release_gate.sha256(record / "producer.json"), self.current["producer_sha256"])
        for relative, identity in manifest["files"].items():
            original, moved = self.root / relative, destination / relative
            self.assertEqual((release_gate.sha256(moved), stat.S_IMODE(moved.stat().st_mode)),
                             (identity["sha256"], stat.S_IMODE(original.stat().st_mode)), relative)
        self.assertEqual(stat.S_IMODE((destination / "independent-1/build/target/release/kasumid").stat().st_mode),
                         0o755)
        failed = json.loads((destination / "independent-failed/outcome.json").read_text())
        self.assertEqual((failed["status"], [item["id"] for item in failed["products"]]), ("failed", ["kasumid"]))
        self.assertTrue((destination / "independent-failed/build/target/release/kasumid").is_file())
        self.assertIn("exit code 101", failed["error"])
        # Every retained operator input and diagnostic of an unsuccessful build travels with it.
        for name in ("independent-failed", "independent-rejected"):
            original = {path.relative_to(self.root / name).as_posix() for path in (self.root / name).rglob("*")
                        if path.is_file() and "build/source" not in path.as_posix()}
            moved = {path.relative_to(destination / name).as_posix() for path in (destination / name).rglob("*")
                     if path.is_file()}
            self.assertEqual(moved, original)
            self.assertIn("host/reservation.json", moved)
        for name in ("correctness-1", "recovery-1", "observability-1"):
            self.assertEqual((destination / name / "raw/nested/unreferenced.log").read_text(),
                             "kept with the whole domain output\n")
            self.assertEqual(list((destination / name / "empty").iterdir()), [])

        # Only compiler work trees are thinned: the verifier-read files inside them travel,
        # the rest stays behind and is accounted for.
        self.assertEqual(manifest["work_trees"], [
            "independent-1/build/source", "independent-1/build/target", "independent-failed/build/source",
            "independent-failed/build/target", "run/source", "run/target"])
        self.assertTrue((self.root / "independent-1/build/source/Cargo.toml").is_file())
        self.assertFalse((destination / "independent-1/build/source").exists())
        left = {(item["path"], item["scope"]): item for item in manifest["omitted"]}
        self.assertEqual(sorted(left), [("independent-1/build/source", "tree"),
                                        ("independent-failed/build/source", "tree")])
        self.assertEqual({path.name for path in (destination / "run/runner").iterdir()},
                         {path.name for path in (self.root / "run/runner").iterdir()})
        self.assertEqual(manifest["census"], {
            "files": manifest["file_count"] + sum(item["files"] for item in manifest["omitted"]),
            "bytes": manifest["total_bytes"] + sum(item["bytes"] for item in manifest["omitted"])})
        self.assertGreater(sum(item["bytes"] for item in manifest["omitted"]), 0)

    def test_rejected_transfers_leave_a_record_and_no_custody_root(self):
        current = self.current
        arguments = (current["archive"], current["producer"], current["producer_sha256"], self.heads, CAP)

        # The journal moved on after the earlier transfer: that archive is only a prefix now.
        destination, record = self.bundle("stale")
        earlier = self.earlier
        with self.assertRaisesRegex(ValueError, "another head or original root"):
            custody.admit(earlier["archive"], earlier["producer"], earlier["producer_sha256"], self.heads,
                          CAP, destination, record)
        self.assert_nothing_admitted(destination, record)
        prefix = self.restored("stale-restored", earlier)
        with self.assertRaisesRegex(ValueError, "head differs from its anchor"):
            custody.judge(prefix, self.head, str(self.root))

        # The operator names another original root than the journal's outcomes carry.
        destination, record = self.bundle("moved")
        elsewhere = self.anchors("elsewhere.json", self.head, str(self.root) + "-elsewhere")
        with self.assertRaisesRegex(ValueError, "another head or original root"):
            custody.admit(*arguments[:3], elsewhere, CAP, destination, record)
        self.assert_nothing_admitted(destination, record)
        whole = self.restored("current-restored", current)
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            custody.judge(whole, self.head, str(self.root) + "-elsewhere")

        # Bytes lost or changed in transit never reach the journal namespace.
        with tarfile.open(current["archive"]) as source:
            offset = source.getmember("custody/attempts/index.jsonl").offset_data
        raw = current["archive"].read_bytes()
        for label, data, message in (
                ("changed", raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:], "differs from the producer digest"),
                ("truncated", raw[:-10240], "differs from its producer record")):
            with self.subTest(transit=label):
                delivered = self.base / label / current["archive"].name
                delivered.parent.mkdir()
                delivered.write_bytes(data)
                destination, record = self.bundle(label + "-bundle")
                with self.assertRaisesRegex(ValueError, message):
                    custody.admit(delivered, *arguments[1:], destination, record)
                self.assert_nothing_admitted(destination, record)
                # Even with a matching outer digest, the strict reader refuses the content.
                (self.base / (label + "-restored")).mkdir()
                with self.assertRaisesRegex(REFUSED, "differ from the manifest|omitted a file|end of|EOF|trailer"):
                    custody.read_archive(delivered, release_gate.sha256(delivered),
                                         current["transport"]["manifest_sha256"], CAP,
                                         self.base / (label + "-restored"))

        # A restored copy that lost one file is not the journal the producer judged.
        (whole / "independent-1/build/target/release/kasumid").unlink()
        with self.assertRaises(REFUSED):
            custody.judge(whole, self.head, str(self.root))
        selection_only = self.restored("selection-restored", current)
        (selection_only / "run/format.log").unlink()
        judged = custody.judge(selection_only, self.head, str(self.root))[0]
        self.assertEqual([fact["id"] for fact in judged if not fact["selectable"] and fact["status"] == "passed"],
                         ["functional-1"])
        with self.assertRaisesRegex(ValueError, "judged differently from its original: functional-1"):
            custody.require_same(current["attempts"], judged)

        # An interrupted admission is visible, blocks a retry and is never mistaken for custody.
        destination, record = self.bundle("residue")
        pending = destination.with_name("." + JOURNAL + ".pending")
        pending.mkdir()
        with self.assertRaisesRegex(ValueError, "interrupted transfer left"):
            custody.admit(*arguments, destination, record)
        self.assertEqual(list(destination.parent.iterdir()), [pending])
        self.assertEqual(json.loads((record / "receipt.json").read_text())["status"], "rejected")
        destination, record = self.bundle("crash")
        with patch.object(custody.os, "rename", side_effect=OSError("unit crash before placement")), \
                self.assertRaisesRegex(OSError, "unit crash"):
            custody.admit(*arguments, destination, record)
        self.assertIn("unit crash", self.assert_nothing_admitted(destination, record))
        # A record directory is used once, so an earlier refusal is never overwritten.
        with self.assertRaises(ValueError):
            custody.admit(*arguments, destination, record)
        self.assertEqual(list(destination.parent.iterdir()), [])

    def test_outcome_stays_truthful_once_the_verified_root_is_placed(self):
        current = self.current
        arguments = (current["archive"], current["producer"], current["producer_sha256"], self.heads, CAP)

        def confirm(destination, name):
            """An ordinary repeat confirms the placed root where it is and concludes the admission."""
            inode = destination.stat().st_ino
            again = custody.admit(*arguments, destination, self.base / name)
            self.assertEqual((again["status"], again["placement"], destination.stat().st_ino),
                             ("admitted", "confirmed", inode))
            self.assertEqual(json.loads((self.base / name / "receipt.json").read_text())["status"], "admitted")
            self.assertEqual([entry.name for entry in destination.parent.iterdir()], [JOURNAL])

        # The rename succeeded and the namespace sync after it failed: never a rejection.
        destination, record = self.bundle("unsynced")
        sync = custody.functional_transport.sync_directory

        def failing(path):
            if Path(path) == destination.parent and destination.exists():
                raise OSError("unit namespace sync failed")
            return sync(path)

        with patch.object(custody.functional_transport, "sync_directory", side_effect=failing), \
                self.assertRaisesRegex(custody.Unconfirmed, "in place at .*unit namespace sync failed"):
            custody.admit(*arguments, destination, record)
        receipt = json.loads((record / "receipt.json").read_text())
        self.assertEqual((receipt["status"], receipt["placement"]), ("unconfirmed", "placed"))
        self.assertIn("admit the same transfer again", receipt["error"])
        self.assertEqual(sorted(path.name for path in record.iterdir()),
                         ["manifest.json", "producer.json", "receipt.json"])
        self.assertEqual([entry.name for entry in destination.parent.iterdir()], [JOURNAL])
        custody.require_same(current["attempts"], custody.judge(destination, self.head, str(self.root))[0])
        confirm(destination, "unsynced-record-2")

        # The receipt itself cannot be written after the rename: the command says so with status 2.
        destination, record = self.bundle("unreceipted")
        errors = io.StringIO()
        with patch.object(custody.transport, "publish", side_effect=OSError("unit record volume is full")), \
                contextlib.redirect_stderr(errors):
            code = custody.main(["admit", "--archive", str(current["archive"]), "--producer-manifest",
                                 str(current["producer"]), "--producer-sha256", current["producer_sha256"],
                                 "--journal-heads", str(self.heads), "--max-bytes", str(CAP),
                                 "--output", str(destination), "--record", str(record)])
        self.assertEqual(code, 2)
        self.assertRegex(errors.getvalue(), "admission unconfirmed: the verified root is in place at .*volume is full")
        self.assertEqual(sorted(path.name for path in record.iterdir()), ["manifest.json", "producer.json"])
        confirm(destination, "unreceipted-record-2")

        # A root that is already there is confirmed only if it is exactly this transfer; it is never replaced.
        destination, record = self.bundle("foreign")
        destination.mkdir()
        custody.read_archive(self.earlier["archive"], self.earlier["transport"]["archive_sha256"],
                             self.earlier["transport"]["manifest_sha256"], CAP, destination)
        before = (destination.stat().st_ino, custody.restored_roster(destination))
        with self.assertRaisesRegex(ValueError, "is not this transfer; nothing was replaced"):
            custody.admit(*arguments, destination, record)
        self.assertEqual(json.loads((record / "receipt.json").read_text())["status"], "rejected")
        self.assertEqual((destination.stat().st_ino, custody.restored_roster(destination)), before)
        destination, record = self.bundle("altered")
        destination.mkdir()
        custody.read_archive(current["archive"], current["transport"]["archive_sha256"],
                             current["transport"]["manifest_sha256"], CAP, destination)
        log = destination / "correctness-1/raw/nested/unreferenced.log"
        log.write_text(log.read_text().replace("kept", "lost"))
        with self.assertRaisesRegex(ValueError, "is not this transfer; nothing was replaced"):
            custody.admit(*arguments, destination, record)
        self.assertIn("lost", log.read_text())

        # Another writer finishes first, after this transfer was verified. A rename would replace
        # even an empty directory; the placement refuses instead and withdraws its own copy.
        destination, record = self.bundle("raced")
        judge = custody.judge

        def overtaken(root, head, original_root=None):
            judged = judge(root, head, original_root)
            destination.mkdir()
            return judged

        with patch.object(custody, "judge", side_effect=overtaken), \
                self.assertRaisesRegex(ValueError, "first; nothing was replaced"):
            custody.admit(*arguments, destination, record)
        self.assertEqual(json.loads((record / "receipt.json").read_text())["status"], "rejected")
        self.assertEqual([(entry.name, list(entry.iterdir())) for entry in destination.parent.iterdir()],
                         [(JOURNAL, [])])

        # Placements into one namespace exclude each other across processes and leave no file behind.
        contender = [sys.executable, "-c", "import fcntl, os, sys\ntry:\n fcntl.flock(os.open(sys.argv[1], "
                     "os.O_RDONLY), fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n sys.exit(7)",
                     str(destination.parent)]
        with custody.placing(destination.parent):
            self.assertEqual(subprocess.run(contender, timeout=60).returncode, 7)
        self.assertEqual(subprocess.run(contender, timeout=60).returncode, 0)
        self.assertEqual([entry.name for entry in destination.parent.iterdir()], [JOURNAL])

    def test_transported_journals_of_every_target_replay_as_one_bundle(self):
        bundle = self.base / "three-targets"
        namespace = bundle / "native-attempts"
        namespace.mkdir(parents=True)
        anchors, transfers, journals, selected = [], [], [], {}
        for index, target in enumerate(sorted(attempt_index.TARGETS)):
            root = self.base / "hosts" / str(index) / "custody"
            root.mkdir(parents=True)
            journal, host = "journal-" + target, "host-" + str(index)
            attempt_index.create(root, journal, host, target)
            domain(root, "correctness-" + str(index), "correctness", "passed")
            domain(root, "recovery-" + str(index), "recovery", "failed")
            produced = custody.produce(root, root.parent / "custody.tar", root.parent / "producer.json", CAP)
            anchors.append({"head": produced["head"], "original_root": str(root)})
            transfers.append((journal, root.parent, produced["producer_sha256"]))
            selected[f"native-attempts/{journal}/correctness-{index}/outcome.json"] = ("correctness", target, host)
        heads = self.base / "operator" / "three-heads.json"
        heads.write_text(json.dumps(anchors))
        for journal, transfer, digest in transfers:
            admitted = custody.admit(transfer / "custody.tar", transfer / "producer.json", digest, heads, CAP,
                                     namespace / journal, self.base / ("three-record-" + journal))
            self.assertEqual((admitted["status"], admitted["placement"]), ("admitted", "placed"))
            journals.append({"id": journal, "journal": attempt_index.file_ref(
                bundle, namespace / journal / "attempts/index.jsonl")})
        # The bundle verifier's own multi-journal replay, with the operator's heads and original roots.
        acceptance.verify_native_journals(bundle, journals, selected, heads)
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            acceptance.verify_native_journals(bundle, journals, {
                **selected, "native-attempts/" + transfers[0][0] + "/recovery-0/outcome.json":
                ("recovery", sorted(attempt_index.TARGETS)[0], "host-0")}, heads)
        # An interrupted admission's residue fails that verifier until an operator removes it.
        residue = namespace / ("." + transfers[0][0] + ".pending")
        residue.mkdir()
        with self.assertRaisesRegex(ValueError, "namespace differs from anchored roster"):
            acceptance.verify_native_journals(bundle, journals, selected, heads)
        residue.rmdir()
        acceptance.verify_native_journals(bundle, journals, selected, heads)

    def test_incomplete_or_aliased_originals_are_not_transported(self):
        def refuse(root, message):
            archive, producer = root.parent / (root.name + ".tar"), root.parent / (root.name + ".json")
            with self.assertRaisesRegex(ValueError, message):
                custody.produce(root, archive, producer, CAP)
            self.assertFalse(archive.exists() or producer.exists())
            self.assertEqual([path.name for path in root.parent.iterdir() if path.name.startswith(".")], [])

        scratch = self.base / "originals"
        scratch.mkdir()
        for name in ("empty", "open", "aliased"):
            (scratch / name).mkdir()
            attempt_index.create(scratch / name, "journal-" + name, "unit-host", independent_fixture.TARGET)
        refuse(scratch / "empty", "has no admission")
        domain(scratch / "open", "correctness-done", "correctness", "passed")
        attempt_index.begin(scratch / "open", "correctness-open", "correctness",
                            scratch / "open/correctness-open", now())
        refuse(scratch / "open", "unfinished admission")
        domain(scratch / "aliased", "correctness-linked", "correctness", "passed")
        (scratch / "aliased/correctness-linked/raw/link").symlink_to("nested")
        refuse(scratch / "aliased", "symlink.*correctness-linked/raw/link")

        # A passed rehearsal travels, but it is never offered as a selection: its own gate refuses it.
        (scratch / "rehearsed").mkdir()
        attempt_index.create(scratch / "rehearsed", "journal-rehearsed", "unit-host", independent_fixture.TARGET)
        for name, qualification in (("installed-rehearsal", domain_run.REHEARSAL),
                                    ("installed-qualifying", domain_run.QUALIFYING)):
            domain(scratch / "rehearsed", name, "installed", "passed",
                   {"schema": domain_run.SCHEMA, "qualification": qualification})
        produced = custody.produce(scratch / "rehearsed", scratch / "rehearsed.tar", scratch / "rehearsed.json", CAP)
        self.assertEqual([(fact["id"], fact["status"], fact["selectable"], fact["refusal"])
                          for fact in produced["attempts"]],
                         [("installed-qualifying", "passed", True, None),
                          ("installed-rehearsal", "passed", False, "the domain run is a non-qualifying rehearsal")])

        # The operator may leave a named directory behind; the verifier still gets what it reads.
        (scratch / "named").mkdir()
        attempt_index.create(scratch / "named", "journal-named", "unit-host", independent_fixture.TARGET)
        domain(scratch / "named", "correctness-done", "correctness", "passed")
        for omit, message in (("attempts", "inside an admitted output"),
                              ("correctness-done", "inside an admitted output"),
                              ("correctness-done/missing", "not an original directory"),
                              ("../named/correctness-done/raw", "unsafe attempt index path")):
            with self.subTest(omit=omit), self.assertRaisesRegex(ValueError, message):
                custody.produce(scratch / "named", scratch / "refused.tar", scratch / "refused.json", CAP, [omit])
            self.assertFalse((scratch / "refused.tar").exists())
        produced = custody.produce(scratch / "named", scratch / "named.tar", scratch / "named.json", CAP,
                                   ["correctness-done/raw"])
        manifest, _ = custody.read_archive(scratch / "named.tar", produced["transport"]["archive_sha256"],
                                           produced["transport"]["manifest_sha256"], CAP)
        self.assertEqual(manifest["work_trees"], ["correctness-done/raw"])
        self.assertEqual(manifest["omitted"], [{"path": "correctness-done/raw", "scope": "tree", "files": 1,
                                                "bytes": len("kept with the whole domain output\n")}])
        self.assertNotIn("correctness-done/raw/nested/unreferenced.log", manifest["files"])
        self.assertIn("correctness-done/probe/process.json", manifest["files"])
        code, _, error = command(SCRIPTS / "transport_attempt_journal.py", "produce", "--root", scratch / "open",
                                 "--archive", scratch / "open.tar", "--producer", scratch / "open.json",
                                 "--max-bytes", CAP)
        self.assertEqual((code, (scratch / "open.tar").exists()), (1, False))
        self.assertIn("unfinished admission", error)


if __name__ == "__main__":
    unittest.main()
