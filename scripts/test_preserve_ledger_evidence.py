"""Synthetic ledger and target/ trees, never native release evidence."""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import preserve_ledger_evidence as preserve


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ReferenceTests(unittest.TestCase):
    def test_every_target_token_is_classified_as_code_or_prose(self):
        text = "\n".join([
            "Prose about target/signing services and target/run/prose.log, too.",
            "Logs are in `target/run/a.log` and ``target/run/b.log``, and tests",
            "expect repository-root `target/` paths.",
            "```",
            "git apply --check target/run/fix.patch",
            "```",
            "~~~~",
            "cat target/run/fenced.json",
            "~~~~",
            "Three runs (`target/run/focused-{1,2}.log`, `target/run/dir/`).",
            "`kasumi-target/x` and `../target/y` are other paths; `target/../escape` is unsafe.",
            "Again `target/run/a.log`, `./target/run/dot.log` and `/checkout/target/run/abs.log`.",
            "Both `target/run/both.log` and target/run/both.log; see [log](target/run/link.log).",
        ])
        cited, unsafe, named = preserve.references([("docs/ledger.md", text)], "/checkout")
        self.assertEqual(cited, {
            "target/signing": (["docs/ledger.md:1"], ["docs/ledger.md:1"]),
            "target/run/prose.log": (["docs/ledger.md:1"], ["docs/ledger.md:1"]),
            "target/run/a.log": (["docs/ledger.md:2", "docs/ledger.md:12"], []),
            "target/run/b.log": (["docs/ledger.md:2"], []),
            "target/run/fix.patch": (["docs/ledger.md:5"], []),
            "target/run/fenced.json": (["docs/ledger.md:8"], []),
            "target/run/focused-1.log": (["docs/ledger.md:10"], []),
            "target/run/focused-2.log": (["docs/ledger.md:10"], []),
            "target/run/dir": (["docs/ledger.md:10"], []),
            "target/run/dot.log": (["docs/ledger.md:12"], []),
            "target/run/abs.log": (["docs/ledger.md:12"], []),
            "target/run/both.log": (["docs/ledger.md:13"], []),
            "target/run/link.log": (["docs/ledger.md:13"], ["docs/ledger.md:13"]),
        })
        self.assertEqual(unsafe, {"target/../escape": ["docs/ledger.md:11"]})
        self.assertEqual(named, ["docs/ledger.md:3"])

    def test_code_span_across_a_line_break_reports_the_line_of_the_path(self):
        cited, unsafe, named = preserve.references(
            [("docs/ledger.md", "one\ntwo `x\ntarget/run/a.log` three\n")])
        self.assertEqual(cited, {"target/run/a.log": (["docs/ledger.md:3"], [])})
        self.assertEqual((unsafe, named), ({}, []))

    def test_indented_code_blocks_and_fences_nested_in_list_items_are_code(self):
        text = "\n".join([
            "Run:",
            "",
            "    cat target/run/indented.log",
            "        target/run/deeper.log",
            "",
            "- A list item",
            "",
            "    ```sh",
            "    cat target/run/nested.log",
            "",
            "    tail target/run/after-blank.log",
            "    ```",
            "",
            "    Its paragraph names target/local.",
            "",
            "1. Item",
            "   - Nested",
            "",
            "         cat target/run/item-code.log",
            "Paragraph",
            "    lazy target/scratch continuation",
            "```inline``` is a span, target/issuer is prose.",
            "Still prose: target/archive.",
        ])
        cited, _, _ = preserve.references([("docs/ledger.md", text)])
        code = {path for path, (cited_by, prose) in cited.items() if not prose}
        prose = {path for path, (cited_by, prose) in cited.items() if prose}
        self.assertEqual(code, {"target/run/indented.log", "target/run/deeper.log",
                                "target/run/nested.log", "target/run/after-blank.log",
                                "target/run/item-code.log"})
        self.assertEqual(prose, {"target/local", "target/scratch", "target/issuer",
                                 "target/archive"})
        self.assertEqual(cited["target/run/after-blank.log"], (["docs/ledger.md:11"], []))


class PreservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="preserve-ledger-evidence-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.repository = self.root / "repository"
        self.destination = self.root / "evidence"
        self.manifest_path = self.root / "manifest.json"
        self.ledger("docs/first-release-goals.md", "# Goals\n")
        (self.repository / preserve.EVIDENCE).mkdir()

    def write(self, relative, data, base=None):
        path = (base or self.repository) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def ledger(self, relative, text):
        self.write(relative, text.encode())

    def cite(self, *paths):
        self.ledger("docs/production-release.md",
                    "# Ledger\n\n" + "".join(f"- `{path}`\n" for path in paths))

    def lock(self, path, mode=0):
        if os.geteuid() == 0:
            self.skipTest("root ignores permissions")
        os.chmod(path, mode)
        self.addCleanup(os.chmod, path, 0o700)

    def run_tool(self, *extra):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = preserve.main(["--repository", str(self.repository),
                                    "--destination", str(self.destination),
                                    "--manifest", str(self.manifest_path), *extra])
        self.stderr = stderr.getvalue()
        return status

    def manifest(self):
        return json.loads(self.manifest_path.read_text())

    def entry(self, manifest, path):
        return next(item for item in manifest["references"] if item["path"] == path)

    def copied(self, relative):
        return self.destination / relative

    def partials(self):
        return [path for path in self.destination.rglob("*") if path.name.endswith(".partial")]

    def test_cited_files_are_copied_and_manifest_hashes_match_the_copied_bytes(self):
        log = self.write("target/run/test.log", b"passed 1/1\n")
        patch = self.write("target/run/fix.patch", b"--- a\n+++ b\n")
        receipt = self.write("target/run/nested/receipt.json", b'{"status":"passed"}\n')
        os.utime(log, ns=(1_700_000_000_000_000_000, 1_700_000_000_123_456_789))
        self.cite("target/run/test.log", "target/run/fix.patch")
        self.ledger("docs/evidence/run-20260925/README.md",
                    "# Run\n\nReceipt: `target/run/nested/receipt.json`.\n")

        self.assertEqual(self.run_tool(), 0, self.stderr)
        manifest = self.manifest()
        self.assertEqual(manifest["schema"], preserve.SCHEMA)
        self.assertEqual((manifest["missing"], manifest["refused"], manifest["not_citations"]),
                         ([], [], []))
        self.assertEqual(manifest["destination"], str(self.destination))
        for source in (log, patch, receipt):
            relative = source.relative_to(self.repository).as_posix()
            entry = self.entry(manifest, relative)
            copy = self.copied(relative).read_bytes()
            self.assertEqual(copy, source.read_bytes())
            self.assertEqual(entry["sha256"], digest(copy))
            self.assertEqual(entry["bytes"], len(copy))
            self.assertEqual((entry["kind"], entry["disposition"]), ("file", "copied"))
            self.assertNotIn("prose_cited_by", entry)
        self.assertEqual(self.entry(manifest, "target/run/test.log")["cited_by"],
                         ["docs/production-release.md:3"])
        self.assertEqual(self.entry(manifest, "target/run/nested/receipt.json")["cited_by"],
                         ["docs/evidence/run-20260925/README.md:3"])
        self.assertEqual(self.entry(manifest, "target/run/test.log")["mtime_ns"],
                         1_700_000_000_123_456_789)
        self.assertEqual(self.copied("target/run/test.log").stat().st_mtime_ns,
                         1_700_000_000_123_456_789)
        ledger = {item["path"]: item for item in manifest["ledger"]}
        self.assertEqual(set(ledger), {"docs/production-release.md", "docs/first-release-goals.md",
                                       "docs/evidence/run-20260925/README.md"})
        for path, item in ledger.items():
            self.assertEqual(item["sha256"], digest((self.repository / path).read_bytes()))
        stored = self.destination / "manifests" / (digest(self.manifest_path.read_bytes()) + ".json")
        self.assertEqual(stored.read_bytes(), self.manifest_path.read_bytes())
        self.assertEqual(self.partials(), [])

    def test_cited_directory_is_preserved_through_a_hash_bound_inventory(self):
        self.write("target/candidate/README.md", b"# Review\n")
        self.write("target/candidate/revision1/candidate.patch", b"+fix\n")
        self.write("target/candidate/build/CACHEDIR.TAG",
                   preserve.CACHEDIR_SIGNATURE + b"\n# cargo\n")
        self.write("target/candidate/build/debug/kasumid", b"\0elf" * 10)
        self.write("target/candidate/notes/CACHEDIR.TAG", b"not a cache tag\n")
        self.cite("target/candidate/")

        self.assertEqual(self.run_tool(), 0, self.stderr)
        entry = self.entry(self.manifest(), "target/candidate")
        self.assertEqual(entry["kind"], "directory")
        self.assertEqual(entry["pruned_cache_directories"], ["target/candidate/build"])
        self.assertFalse(self.copied("target/candidate/build").exists())
        inventory = self.destination / entry["inventory"]
        self.assertEqual(entry["inventory_sha256"], digest(inventory.read_bytes()))
        listed = json.loads(inventory.read_text())
        self.assertEqual(listed["schema"], preserve.INVENTORY_SCHEMA)
        self.assertEqual([item["path"] for item in listed["files"]],
                         ["target/candidate/README.md", "target/candidate/notes/CACHEDIR.TAG",
                          "target/candidate/revision1/candidate.patch"])
        for item in listed["files"]:
            copy = self.copied(item["path"]).read_bytes()
            self.assertEqual(item["sha256"], digest(copy))
            self.assertEqual(copy, (self.repository / item["path"]).read_bytes())
        self.assertEqual((entry["files"], entry["copied_files"], entry["hash_only_files"]), (3, 3, 0))

    def test_missing_reference_is_listed_and_exits_nonzero(self):
        self.write("target/run/present.log", b"ok\n")
        self.cite("target/run/present.log", "target/run/absent.log", "target/gone/receipt.json")

        self.assertEqual(self.run_tool(), 1)
        manifest = self.manifest()
        self.assertEqual(manifest["missing"], [
            {"path": "target/gone/receipt.json", "cited_by": ["docs/production-release.md:5"]},
            {"path": "target/run/absent.log", "cited_by": ["docs/production-release.md:4"]},
        ])
        self.assertEqual(manifest["summary"]["missing"], 2)
        self.assertIn("missing: target/run/absent.log", self.stderr)
        self.assertEqual(self.copied("target/run/present.log").read_bytes(), b"ok\n")

    def test_citation_outside_a_code_span_is_preserved_or_exits_nonzero(self):
        forms = {
            "prose": "The log target/run/{name} was kept.\n",
            "indented code block": "Run:\n\n    cat target/run/{name}\n",
            "fence nested in a list item": ("- Replay:\n\n    ```sh\n    cd kasumi\n\n"
                                            "    cat target/run/{name}\n    ```\n"),
        }
        for form, template in forms.items():
            for exists in (True, False):
                with self.subTest(form=form, exists=exists):
                    name = form.replace(" ", "-") + ("-present" if exists else "-absent") + ".log"
                    path = "target/run/" + name
                    if exists:
                        self.write(path, form.encode())
                    self.ledger("docs/production-release.md",
                                "# Ledger\n\n" + template.format(name=name))
                    status = self.run_tool()
                    manifest = self.manifest()
                    if exists:
                        self.assertEqual(status, 0, self.stderr)
                        self.assertEqual(self.copied(path).read_bytes(), form.encode())
                        self.assertEqual(self.entry(manifest, path)["disposition"], "copied")
                    else:
                        self.assertEqual(status, 1)
                        self.assertEqual([item["path"] for item in manifest["missing"]], [path])

    def test_prose_mentions_are_preserved_listed_refused_or_recorded(self):
        self.write("target/run/prose.log", b"prose\n")
        self.write("target/local/notes.txt", b"a prose phrase that exists\n")
        self.write("target/run/code.log", b"code\n")
        self.ledger("docs/production-release.md", "\n".join([
            "# Ledger",
            "The run kept target/run/prose.log, and `target/run/code.log` again.",
            "It lost target/run/absent.log.",
            "Fixture-owned target/signing services and target/local catalogs;",
            "a bare target/unknown word; the ignored target/ directory.",
            "Code again: `target/run/prose.log`.",
            "",
        ]))

        self.assertEqual(self.run_tool(), 1)
        manifest = self.manifest()
        prose = self.entry(manifest, "target/run/prose.log")
        self.assertEqual((prose["cited_by"], prose["prose_cited_by"]),
                         (["docs/production-release.md:2", "docs/production-release.md:6"],
                          ["docs/production-release.md:2"]))
        self.assertEqual(self.copied("target/run/prose.log").read_bytes(), b"prose\n")
        self.assertNotIn("prose_cited_by", self.entry(manifest, "target/run/code.log"))
        # An existing path is preserved even when it is a known prose phrase.
        self.assertEqual(self.entry(manifest, "target/local")["kind"], "directory")
        self.assertEqual(self.copied("target/local/notes.txt").read_bytes(),
                         b"a prose phrase that exists\n")
        self.assertEqual(manifest["missing"], [{"path": "target/run/absent.log",
                                                "cited_by": ["docs/production-release.md:3"],
                                                "prose_cited_by": ["docs/production-release.md:3"]}])
        self.assertEqual(manifest["refused"], [{
            "path": "target/unknown",
            "reason": "prose mention is neither an existing path nor a known prose phrase",
            "cited_by": ["docs/production-release.md:5"],
            "prose_cited_by": ["docs/production-release.md:5"]}])
        self.assertEqual(manifest["not_citations"], [
            {"token": "target/", "reason": "names the build directory itself",
             "cited_by": ["docs/production-release.md:5"]},
            {"token": "target/signing", "reason": "known prose phrase",
             "cited_by": ["docs/production-release.md:4"]},
        ])
        summary = manifest["summary"]
        self.assertEqual((summary["references"], summary["prose_references"], summary["missing"],
                          summary["refused"], summary["not_citations"]), (5, 2, 1, 1, 2))

    def test_known_prose_phrase_in_code_is_a_citation(self):
        self.ledger("docs/production-release.md",
                    "Fixture-owned target/signing services.\n\n    ls target/local\n")

        self.assertEqual(self.run_tool(), 1)
        manifest = self.manifest()
        self.assertEqual(manifest["missing"], [{"path": "target/local",
                                                "cited_by": ["docs/production-release.md:3"]}])
        self.assertEqual([item["token"] for item in manifest["not_citations"]], ["target/signing"])

    def test_differing_destination_is_refused_and_left_unchanged(self):
        self.write("target/run/test.log", b"passed 1/1\n")
        self.write("target/run/other.log", b"other\n")
        earlier = self.write("target/run/test.log", b"failed 0/1\n", base=self.destination)
        before = earlier.stat()
        self.cite("target/run/test.log", "target/run/other.log")

        self.assertEqual(self.run_tool(), 1)
        self.assertEqual(earlier.read_bytes(), b"failed 0/1\n")
        after = earlier.stat()
        self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))
        manifest = self.manifest()
        self.assertEqual(manifest["refused"], [{"path": "target/run/test.log",
                                                "reason": "destination differs",
                                                "cited_by": ["docs/production-release.md:3"]}])
        self.assertEqual(self.copied("target/run/other.log").read_bytes(), b"other\n")
        self.assertEqual(self.partials(), [])

    def test_destination_created_while_copying_is_never_replaced(self):
        self.write("target/run/test.log", b"passed\n")
        self.cite("target/run/test.log")
        concurrent = self.copied("target/run/test.log")
        real_pread = os.pread

        def create_destination(descriptor, length, offset):
            if offset == 0 and length == preserve.CHUNK and not concurrent.exists():
                concurrent.write_bytes(b"concurrent\n")
            return real_pread(descriptor, length, offset)

        with mock.patch.object(preserve.os, "pread", side_effect=create_destination):
            self.assertEqual(self.run_tool(), 1)
        self.assertEqual(concurrent.read_bytes(), b"concurrent\n")
        self.assertEqual(self.manifest()["refused"][0]["reason"], "destination differs")
        self.assertEqual(self.partials(), [])

    def test_symlinked_destination_is_refused_and_not_followed(self):
        self.write("target/run/test.log", b"passed\n")
        outside = self.write("outside.log", b"keep\n", base=self.root)
        self.copied("target/run").mkdir(parents=True)
        self.copied("target/run/test.log").symlink_to(outside)
        self.cite("target/run/test.log")

        self.assertEqual(self.run_tool(), 1)
        self.assertEqual(outside.read_bytes(), b"keep\n")
        self.assertEqual(self.manifest()["refused"][0]["reason"], "destination is not a regular file")

    def test_identical_rerun_is_idempotent(self):
        self.write("target/run/test.log", b"passed 1/1\n")
        self.write("target/run/large.bin", b"\0" * 64)
        self.write("target/candidate/review.md", b"# Review\n")
        self.cite("target/run/test.log", "target/run/large.bin", "target/candidate")

        self.assertEqual(self.run_tool("--binary-cap", "16"), 0, self.stderr)
        first = self.manifest_path.read_bytes()
        copies = {path: (path.stat().st_ino, path.stat().st_mtime_ns)
                  for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(self.run_tool("--binary-cap", "16"), 0, self.stderr)
        self.assertEqual(self.manifest_path.read_bytes(), first)
        self.assertEqual({path: (path.stat().st_ino, path.stat().st_mtime_ns)
                          for path in self.destination.rglob("*") if path.is_file()}, copies)
        self.assertEqual(len(list((self.destination / "manifests").iterdir())), 1)
        self.assertEqual(self.partials(), [])

    def test_symlinked_source_is_refused(self):
        real = self.write("target/run/real.log", b"real\n")
        (self.repository / "target/run/alias.log").symlink_to(real)
        (self.repository / "target/linked").symlink_to(self.repository / "target/run")
        outside = self.write("outside/secret.txt", b"secret\n", base=self.root)
        self.write("target/candidate/review.md", b"# Review\n")
        (self.repository / "target/candidate/escape").symlink_to(outside.parent)
        self.cite("target/run/alias.log", "target/linked/real.log", "target/candidate")

        self.assertEqual(self.run_tool(), 1)
        refused = {item["path"]: item["reason"] for item in self.manifest()["refused"]}
        self.assertEqual(refused, {"target/run/alias.log": "symlink",
                                   "target/linked/real.log": "symlink: target/linked",
                                   "target/candidate/escape": "symlink"})
        self.assertFalse(self.copied("target/run/alias.log").exists())
        self.assertFalse(self.copied("target/linked").exists())
        self.assertFalse(self.copied("target/candidate/escape").exists())
        self.assertEqual(self.copied("target/candidate/review.md").read_bytes(), b"# Review\n")

    def test_unreadable_source_is_refused_and_later_references_are_preserved(self):
        locked = self.write("target/run/locked/secret.log", b"secret\n").parent
        unsearchable = self.write("target/run/unsearchable/hidden.log", b"hidden\n").parent
        self.write("target/run/ok.log", b"ok\n")
        self.lock(locked)
        self.lock(unsearchable, 0o600)
        self.cite("target/run/locked/secret.log", "target/run/ok.log",
                  "target/run/unsearchable/hidden.log")

        self.assertEqual(self.run_tool(), 1)
        self.assertNotIn("preservation aborted", self.stderr)
        manifest = self.manifest()
        self.assertEqual(manifest["refused"], [
            {"path": "target/run/locked/secret.log",
             "reason": "unreadable: target/run/locked: Permission denied",
             "cited_by": ["docs/production-release.md:3"]},
            {"path": "target/run/unsearchable/hidden.log",
             "reason": "unreadable: Permission denied",
             "cited_by": ["docs/production-release.md:5"]},
        ])
        self.assertEqual(self.copied("target/run/ok.log").read_bytes(), b"ok\n")
        self.assertEqual([item["path"] for item in manifest["references"]], ["target/run/ok.log"])
        self.assertFalse(self.copied("target/run/locked").exists())

    def test_unreadable_or_symlinked_ledger_is_refused(self):
        self.write("target/run/ok.log", b"ok\n")
        self.cite("target/run/ok.log")
        hidden = self.write("docs/evidence/hidden-20260925/README.md", b"`target/run/x.log`\n")
        self.lock(hidden.parent)
        document = self.write("docs/evidence/locked-20260925/README.md", b"`target/run/y.log`\n")
        self.lock(document)
        elsewhere = self.write("elsewhere/README.md", b"`target/run/z.log`\n", base=self.root)
        (self.repository / "docs/evidence/linked-20260925").symlink_to(elsewhere.parent)

        self.assertEqual(self.run_tool(), 1)
        manifest = self.manifest()
        self.assertEqual(manifest["refused"], [
            {"path": "docs/evidence/hidden-20260925",
             "reason": "ledger directory unreadable: Permission denied"},
            {"path": "docs/evidence/linked-20260925", "reason": "ledger directory is a symlink"},
            {"path": "docs/evidence/locked-20260925/README.md",
             "reason": "ledger document: unreadable: Permission denied"},
        ])
        self.assertEqual([item["path"] for item in manifest["references"]], ["target/run/ok.log"])

    def test_oversized_binary_is_recorded_but_not_copied(self):
        binary = b"\x7fELF\0\0" + bytes(range(256)) * 4
        self.write("target/run/kasumid", binary)
        self.write("target/run/small.bin", b"\0\1\2")
        self.write("target/run/large.log", b"line\n" * 1000)
        self.cite("target/run/kasumid", "target/run/small.bin", "target/run/large.log")

        self.assertEqual(self.run_tool("--binary-cap", "512"), 0, self.stderr)
        manifest = self.manifest()
        entry = self.entry(manifest, "target/run/kasumid")
        self.assertEqual((entry["disposition"], entry["bytes"], entry["sha256"]),
                         ("hash-only", len(binary), digest(binary)))
        self.assertFalse(self.copied("target/run/kasumid").exists())
        self.assertEqual(self.entry(manifest, "target/run/small.bin")["disposition"], "copied")
        self.assertEqual(self.entry(manifest, "target/run/large.log")["disposition"], "copied")
        self.assertEqual(self.copied("target/run/large.log").read_bytes(), b"line\n" * 1000)
        self.assertEqual((manifest["summary"]["hash_only_files"], manifest["summary"]["hash_only_bytes"]),
                         (1, len(binary)))

    def test_source_changed_while_copying_is_refused_without_publishing(self):
        growing = self.write("target/run/growing.log", b"first\n")
        self.cite("target/run/growing.log")
        real_pread = os.pread

        def append_then_read(descriptor, length, offset):
            if offset == 0 and length == preserve.CHUNK:
                with growing.open("ab") as log:
                    log.write(b"second\n")
            return real_pread(descriptor, length, offset)

        with mock.patch.object(preserve.os, "pread", side_effect=append_then_read):
            self.assertEqual(self.run_tool(), 1)
        self.assertEqual(self.manifest()["refused"][0]["reason"], "changed while preserving")
        self.assertFalse(self.copied("target/run/growing.log").exists())
        self.assertEqual(self.partials(), [])
        self.assertEqual(self.run_tool(), 0, self.stderr)
        self.assertEqual(self.copied("target/run/growing.log").read_bytes(), b"first\nsecond\n")

    def test_destination_failure_aborts_without_manifest_and_rerun_completes(self):
        self.write("target/run/a.log", b"a\n")
        self.write("target/run/b.log", b"b\n")
        self.cite("target/run/a.log", "target/run/b.log")
        real_fsync = os.fsync
        calls = []

        def fail_second(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                raise OSError(5, "Input/output error")
            return real_fsync(descriptor)

        with mock.patch.object(preserve.os, "fsync", side_effect=fail_second):
            self.assertEqual(self.run_tool(), 1)
        self.assertIn("preservation aborted, no manifest written", self.stderr)
        self.assertFalse(self.manifest_path.exists())
        self.assertEqual(self.copied("target/run/a.log").read_bytes(), b"a\n")
        self.assertFalse(self.copied("target/run/b.log").exists())
        self.assertEqual(self.partials(), [])

        self.assertEqual(self.run_tool(), 0, self.stderr)
        manifest = self.manifest()
        self.assertEqual([item["path"] for item in manifest["references"]],
                         ["target/run/a.log", "target/run/b.log"])
        self.assertEqual(self.copied("target/run/b.log").read_bytes(), b"b\n")

    @unittest.skipIf(preserve.FULL_FSYNC is None, "F_FULLFSYNC exists only on macOS")
    def test_every_fsync_is_followed_by_a_drive_cache_flush(self):
        self.write("target/run/a.log", b"a\n")
        self.write("target/candidate/review.md", b"# Review\n")
        self.cite("target/run/a.log", "target/candidate")
        real_fsync, real_fcntl = os.fsync, preserve.fcntl.fcntl
        calls = []

        def fsync(descriptor):
            calls.append(("fsync", descriptor))
            return real_fsync(descriptor)

        def fcntl(descriptor, command, *arguments):
            calls.append(("fcntl", descriptor, command))
            return real_fcntl(descriptor, command, *arguments)

        with mock.patch.object(preserve.os, "fsync", side_effect=fsync), \
                mock.patch.object(preserve.fcntl, "fcntl", side_effect=fcntl):
            self.assertEqual(self.run_tool(), 0, self.stderr)
        self.assertEqual(calls[1::2], [("fcntl", descriptor, preserve.FULL_FSYNC)
                                       for _, descriptor in calls[0::2]])
        # Two copies, an inventory, the stored and the repository manifest, and directories.
        self.assertGreaterEqual(len(calls) // 2, 6)

    @unittest.skipIf(preserve.FULL_FSYNC is None, "F_FULLFSYNC exists only on macOS")
    def test_failed_drive_cache_flush_aborts_without_manifest(self):
        self.write("target/run/a.log", b"a\n")
        self.cite("target/run/a.log")

        with mock.patch.object(preserve.fcntl, "fcntl",
                               side_effect=OSError(errno.ENOTSUP, "Operation not supported")):
            self.assertEqual(self.run_tool(), 1)
        self.assertIn("preservation aborted, no manifest written", self.stderr)
        self.assertFalse(self.manifest_path.exists())
        self.assertFalse(self.copied("target/run/a.log").exists())
        self.assertEqual(self.partials(), [])

        self.assertEqual(self.run_tool(), 0, self.stderr)
        self.assertEqual(self.copied("target/run/a.log").read_bytes(), b"a\n")

    def test_unsafe_reference_is_refused_and_nothing_escapes(self):
        self.write("escape.log", b"outside\n", base=self.root)
        self.cite("target/../../escape.log")

        self.assertEqual(self.run_tool(), 1)
        self.assertEqual(self.manifest()["refused"], [{"path": "target/../../escape.log",
                                                       "reason": "unsafe reference",
                                                       "cited_by": ["docs/production-release.md:3"]}])
        self.assertEqual(sorted(path.name for path in self.destination.iterdir()), ["manifests"])

    def test_absolute_citation_into_the_checkout_is_preserved(self):
        self.write("target/tmp/run.log", b"tmp\n")
        self.ledger("docs/production-release.md",
                    f"TMPDIR was `{self.repository}/target/tmp`.\n")

        self.assertEqual(self.run_tool(), 0, self.stderr)
        entry = self.entry(self.manifest(), "target/tmp")
        self.assertEqual((entry["kind"], entry["cited_by"]),
                         ("directory", ["docs/production-release.md:1"]))
        self.assertEqual(self.copied("target/tmp/run.log").read_bytes(), b"tmp\n")

    def test_this_tools_own_readme_is_not_a_ledger(self):
        self.write("target/run/test.log", b"ok\n")
        self.cite("target/run/test.log")
        self.ledger(str(Path(preserve.MANIFEST).parent / "README.md"),
                    "Copies cited paths such as `target/<run>/<file>`.\n")

        self.assertEqual(self.run_tool(), 0, self.stderr)
        self.assertNotIn(str(Path(preserve.MANIFEST).parent / "README.md"),
                         [item["path"] for item in self.manifest()["ledger"]])

    def test_missing_ledger_document_is_refused(self):
        (self.repository / "docs/first-release-goals.md").unlink()
        self.cite()

        self.assertEqual(self.run_tool(), 1)
        self.assertEqual(self.manifest()["refused"], [{"path": "docs/first-release-goals.md",
                                                       "reason": "missing ledger document"}])

    def test_destination_inside_repository_is_rejected(self):
        self.cite()
        self.destination = self.repository / "target/evidence"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            self.run_tool()
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
