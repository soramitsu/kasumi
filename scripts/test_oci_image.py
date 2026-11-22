"""Deterministic image assembly, and the smoke runner against a stand-in runtime.

The base image, package and container runtime here are synthetic. They prove
the assembler, verifier and adapter contracts, never a real image or runtime.
"""
import copy
import gzip
import hashlib
import http.server
import io
import json
from pathlib import Path
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import unittest
from unittest.mock import patch

import attempt_index
import domain_run
import oci_image
import release_gate
import run_oci_image_owned
import verify_release_acceptance as acceptance
import repeatable_assembly as owned
import run_oci_smoke as smoke
import test_domain_runs

TARGET = test_domain_runs.TARGET
STATUS = b"""Package: libc6
Status: install ok installed
Architecture: arm64
Source: glibc
Version: 2.36-9+deb12u10

Package: removed-tool
Status: deinstall ok config-files
Architecture: arm64
Version: 1.0

Package: dash
Status: install ok installed
Architecture: arm64
Version: 0.5.12-2
"""
RUNTIME = r'''
import json, shutil, sys, tarfile
from pathlib import Path
state = Path(__file__).with_name("runtime-state.json")
knobs = Path(__file__).with_name("runtime-behavior.json")
behavior = json.loads(knobs.read_text()) if knobs.exists() else {}
memory = json.loads(state.read_text()) if state.exists() else {}
args = sys.argv[1:]
if args[0] == "load":
    with tarfile.open(args[2]) as archive:
        index = json.loads(archive.extractfile("index.json").read())
    memory["id"] = index["manifests"][0]["digest"]
    print("Loaded image")
elif args[:2] == ["image", "inspect"]:
    print(behavior.get("image_id", memory["id"]))
elif args[0] == "run" and "--detach" in args:
    assert args.count("--volume") == 1
    print("container")
elif args[0] == "exec" and args[-1] == "ready":
    memory["polls"] = memory.get("polls", 0) + 1
    state.write_text(json.dumps(memory))
    sys.exit(0 if memory["polls"] > behavior.get("ready_failures", 0) else 1)
elif args[0] == "exec" and args[-1] == "collections":
    print(json.dumps({"ok": behavior.get("native_ok", True), "result": {"collections": []}}))
elif args[0] == "cp":
    source = Path(args[1].split(":", 1)[1]).relative_to("/var/lib/kasumi/installation")
    target = Path(args[2])
    assert target.parent.stat().st_mode & 0o777 == 0o700
    assert not target.exists()
    shutil.copy2(Path(behavior["installation"]) / source, target)
    memory.setdefault("copied", []).append(source.as_posix())
elif args[0] == "inspect":
    print(behavior.get("exit", "0 false"))
state.write_text(json.dumps(memory))
'''


class ImageFixture(test_domain_runs.DomainFixture):
    def setUp(self):
        super().setUp()
        self.layout = self.root / "base-layout"
        (self.layout / "blobs/sha256").mkdir(parents=True)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as layer:
            for name, data in (("var/lib/dpkg/status", STATUS), ("bin/sh", b"shell")):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                layer.addfile(entry, io.BytesIO(data))
        compressed = gzip.compress(raw.getvalue(), mtime=0)
        config = oci_image.canonical({
            "architecture": "arm64", "os": "linux", "variant": "v8",
            "config": {"Env": ["PATH=/usr/bin:/bin"], "User": "0"},
            "rootfs": {"type": "layers", "diff_ids": [oci_image.digest(raw.getvalue())]},
            "history": [{"created_by": "synthetic base"}]})
        manifest = oci_image.canonical({
            "schemaVersion": 2, "mediaType": oci_image.MANIFEST,
            "config": {"mediaType": oci_image.CONFIG, "digest": oci_image.digest(config),
                       "size": len(config)},
            "layers": [{"mediaType": oci_image.LAYER + "+gzip",
                        "digest": oci_image.digest(compressed), "size": len(compressed)}]})
        for blob in (compressed, config, manifest):
            (self.layout / "blobs/sha256" / oci_image.digest(blob)[7:]).write_bytes(blob)
        self.base_manifest = oci_image.digest(manifest)
        pin = {"source": "docker.io/library/debian:bookworm-slim", "index_digest": "sha256:" + "a" * 64,
               "manifest": {"manifests": [
                   {"digest": self.base_manifest, "mediaType": oci_image.MANIFEST,
                    "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}},
                   {"digest": "sha256:" + "b" * 64, "mediaType": oci_image.MANIFEST,
                    "platform": {"architecture": "unknown", "os": "unknown"}}]}}
        self.source = self.evidence / "source"
        (self.source / oci_image.BASE_PIN).write_text(json.dumps(pin))
        self.rewrite_inventory()
        self.functional["source_files_sha256"] = release_gate.sha256(
            self.evidence / "source-files.json")
        self.package = self.pack("kasumi-0.1.0-" + TARGET)
        self.candidates = {name: digest for name, (_, digest) in self.binaries.items()}

    def pack(self, stem, **replaced):
        path = self.root / (stem + ".tar.gz")
        raw = io.BytesIO()
        members = {"bin/" + name: (Path(binary).read_bytes(), 0o755)
                   for name, (binary, _) in self.binaries.items()}
        members.update({"sbom.spdx.json": (b'{"spdxVersion":"SPDX-2.3"}', 0o644),
                        "provenance.json": (b'{"target":"' + TARGET.encode() + b'"}', 0o644),
                        "LICENSE": (b"license\n", 0o644)})
        members.update(replaced)
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, (data, mode) in sorted(members.items()):
                entry = tarfile.TarInfo(stem + "/" + name)
                entry.size, entry.mode = len(data), mode
                archive.addfile(entry, io.BytesIO(data))
        path.write_bytes(gzip.compress(raw.getvalue(), mtime=0))
        return path

    def assemble(self, name, epoch=1767225600, package=None):
        return oci_image.assemble(self.source, self.layout, package or self.package, TARGET,
                                  epoch, self.root / name)


class AssemblyTests(ImageFixture):
    def test_original_native_assembly_binds_delivered_image_and_session(self):
        self.functional["build_environment"] = {"SOURCE_DATE_EPOCH": "1767225600"}
        evidence = self.evidence / "evidence.json"
        evidence.write_text(json.dumps(self.functional))
        provenance = {key: self.functional[key] for key in ("source_commit", "source_tree", "lockfile_sha256")}
        provenance.update(target=TARGET, source_date_epoch=1767225600, executables=self.candidates,
                          functional_evidence_sha256=release_gate.sha256(evidence))
        archive = self.pack("kasumi-release", **{"provenance.json": (json.dumps(provenance).encode(), 0o644)})
        output = self.root / "native-image"
        with patch.object(run_oci_image_owned, "native_target", return_value=TARGET):
            run_oci_image_owned.launch(self.root, "image-1", output, self.evidence, self.layout, archive)
        record = json.loads((output / "image/image.json").read_text())
        ref = lambda path: attempt_index.file_ref(self.root, path)
        primary = {"functional": ref(evidence)}
        products = {"oci:" + TARGET: {"file": ref(output / "image" / record["image"]["path"])},
                    "image-sbom:" + TARGET: {"file": ref(output / "image" / record["image_sbom"]["path"])},
                    "package:" + TARGET: {"file": ref(archive)}}
        selected = acceptance.selected_oci_outcome(self.root, TARGET, products, primary)
        attempts = [{"id": "image-1", "receipt": ref(self.root / "attempts/image-1/attempt.json")}]
        acceptance.verify_attempts(self.root, attempts, {selected: "oci-image"})
        duplicate = self.root / "other-sbom.json"
        shutil.copyfile(output / "image" / record["image_sbom"]["path"], duplicate)
        products["image-sbom:" + TARGET] = {"file": ref(duplicate)}
        with self.assertRaisesRegex(ValueError, "same native assembly"):
            acceptance.selected_oci_outcome(self.root, TARGET, products, primary)

    def test_owned_image_seals_preflight_and_post_dispatch_failures(self):
        with patch.object(run_oci_image_owned, "native_target", side_effect=ValueError("wrong target")):
            with self.assertRaisesRegex(ValueError, "wrong target"):
                run_oci_image_owned.launch(self.root, "wrong-host", self.root / "wrong-host",
                                           self.evidence, self.layout, self.package)
        self.functional["build_environment"] = {"SOURCE_DATE_EPOCH": "1767225600"}
        with patch.object(run_oci_image_owned, "native_target", return_value=TARGET):
            with self.assertRaises((ValueError, OSError)):
                run_oci_image_owned.launch(self.root, "wrong-package", self.root / "wrong-package",
                                           self.evidence, self.layout, self.package)
        for name, dispatched in (("wrong-host", False), ("wrong-package", True)):
            record = json.loads((self.root / name / "outcome.json").read_text())
            self.assertEqual((record["status"], record["dispatch_started"], record["products"]),
                             ("failed", dispatched, []))
        attempts = [{"id": name, "receipt": attempt_index.file_ref(self.root, self.root / "attempts" / name / "attempt.json")}
                    for name in ("wrong-host", "wrong-package")]
        acceptance.verify_attempts(self.root, attempts, {})

    def test_same_inputs_give_identical_bytes_and_a_self_consistent_sbom(self):
        first, second = self.assemble("image-a"), self.assemble("image-b")
        self.assertEqual(first, second)
        archive = self.root / "image-a" / first["image"]["path"]
        self.assertEqual(archive.read_bytes(),
                         (self.root / "image-b" / second["image"]["path"]).read_bytes())
        sbom_path = self.root / "image-a" / first["image_sbom"]["path"]
        image = oci_image.verify(self.source, archive, sbom_path, TARGET, self.candidates)
        self.assertEqual(image["manifest_digest"], first["manifest_digest"])
        sbom = json.loads(sbom_path.read_text())
        names = {package["name"] for package in sbom["packages"]}
        # OS packages the dependency SBOM cannot see, minus the removed one.
        self.assertLessEqual({"libc6", "dash", "docker.io/library/debian:bookworm-slim"}, names)
        self.assertNotIn("removed-tool", names)
        self.assertEqual({item["fileName"] for item in sbom["files"]},
                         {"/opt/kasumi/bin/" + name for name in oci_image.BINARIES})
        self.assertIn(hashlib.sha256(b'{"spdxVersion":"SPDX-2.3"}').hexdigest(),
                      sbom["packages"][0]["comment"])
        # Another build time is another image, not a silent rewrite of this one.
        self.assertNotEqual(self.assemble("image-c", epoch=1767225601)["manifest_digest"],
                            first["manifest_digest"])
        with tarfile.open(archive) as bundle:
            layer = bundle.extractfile("blobs/sha256/" + first["layer_digest"][7:]).read()
        with tarfile.open(fileobj=io.BytesIO(layer)) as contents:
            members = {member.name: member for member in contents}
        self.assertEqual((members["var/lib/kasumi"].uid, members["var/lib/kasumi"].mode),
                         (oci_image.RUNTIME_USER, 0o700))
        self.assertEqual(members["opt/kasumi/bin/kasumid"].mode, 0o755)
        self.assertTrue(all(member.mtime == 1767225600 for member in members.values()))

    def test_base_must_be_the_pinned_platform_manifest(self):
        blob = self.layout / "blobs/sha256" / self.base_manifest[7:]
        original = blob.read_bytes()
        blob.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "blob differs from its digest"):
            self.assemble("tampered-base")
        blob.unlink()
        with self.assertRaisesRegex(ValueError, "image blob is absent"):
            self.assemble("missing-base")
        blob.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "no single manifest for amd64"):
            oci_image.assemble(self.source, self.layout, self.package,
                               "x86_64-unknown-linux-gnu", 1767225600, self.root / "other-arch")

    def test_package_must_hold_executable_binaries_sbom_and_provenance(self):
        broken = self.pack("kasumi-broken-" + TARGET,
                           **{"bin/kasumid": (b"not executable", 0o644)})
        with self.assertRaisesRegex(ValueError, "lacks its binaries"):
            self.assemble("not-executable", package=broken)

    def test_verifier_rejects_other_candidates_platform_base_and_sbom(self):
        record = self.assemble("image")
        archive = self.root / "image" / record["image"]["path"]
        sbom = self.root / "image" / record["image_sbom"]["path"]
        with self.assertRaisesRegex(ValueError, "differs from the qualified candidate: kasumid"):
            oci_image.verify(self.source, archive, sbom, TARGET, {**self.candidates, "kasumid": "0" * 64})
        with self.assertRaisesRegex(ValueError, "no single manifest for amd64"):
            oci_image.verify(self.source, archive, sbom, "x86_64-unknown-linux-gnu", self.candidates)
        edited = json.loads(sbom.read_text())
        edited["packages"] = [item for item in edited["packages"] if item["name"] != "libc6"]
        omitted = self.root / "omitted-sbom.json"
        omitted.write_text(json.dumps(edited))
        with self.assertRaisesRegex(ValueError, "SBOM differs from the image's own contents"):
            oci_image.verify(self.source, archive, omitted, TARGET, self.candidates)
        # The same archive under another pinned base is not this release's image.
        pin = json.loads((self.source / oci_image.BASE_PIN).read_text())
        pin["manifest"]["manifests"][0]["digest"] = "sha256:" + "c" * 64
        (self.source / oci_image.BASE_PIN).write_text(json.dumps(pin))
        with self.assertRaisesRegex(ValueError, "lacks a referenced blob"):
            oci_image.verify(self.source, archive, sbom, TARGET, self.candidates)

    def test_verifier_rejects_a_rewritten_runtime_configuration_or_extra_layer(self):
        record = self.assemble("image")
        archive = self.root / "image" / record["image"]["path"]
        sbom = self.root / "image" / record["image_sbom"]["path"]

        def rebuilt(change):
            """Rewrite config and manifest consistently, as a careful forger would."""
            with tarfile.open(archive) as bundle:
                members = {member.name: bundle.extractfile(member).read() for member in bundle}
            index = json.loads(members["index.json"])
            manifest = json.loads(members["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
            config = json.loads(members["blobs/sha256/" + manifest["config"]["digest"][7:]])
            change(config, manifest, members)
            blob = oci_image.canonical(config)
            manifest["config"].update(digest=oci_image.digest(blob), size=len(blob))
            members["blobs/sha256/" + oci_image.digest(blob)[7:]] = blob
            blob = oci_image.canonical(manifest)
            members["blobs/sha256/" + oci_image.digest(blob)[7:]] = blob
            index["manifests"][0].update(digest=oci_image.digest(blob), size=len(blob))
            index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = \
                "kasumi:" + oci_image.digest(blob)[7:19]
            members["index.json"] = oci_image.canonical(index)
            forged = self.root / "forged.oci.tar"
            with tarfile.open(forged, "w") as bundle:
                for name, data in sorted(members.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    bundle.addfile(entry, io.BytesIO(data))
            return forged

        root_user = rebuilt(lambda config, manifest, members: config["config"].update(User="0:0"))
        with self.assertRaisesRegex(ValueError, "runtime configuration differs"):
            oci_image.verify(self.source, root_user, sbom, TARGET, self.candidates)

        def extra_layer(config, manifest, members):
            extra = b"unreviewed layer"
            members["blobs/sha256/" + oci_image.digest(extra)[7:]] = extra
            manifest["layers"].insert(1, {"mediaType": oci_image.LAYER,
                                          "digest": oci_image.digest(extra), "size": len(extra)})
            config["rootfs"]["diff_ids"].insert(1, oci_image.digest(extra))
        with self.assertRaisesRegex(ValueError, "does not extend the pinned base by one runtime layer"):
            oci_image.verify(self.source, rebuilt(extra_layer), sbom, TARGET, self.candidates)


@unittest.skipUnless(shutil.which("openssl"), "the MCP probe needs a generated TLS identity")
class SmokeTests(ImageFixture):
    def setUp(self):
        super().setUp()
        self.record = self.assemble("delivered")
        self.image = self.root / "delivered" / self.record["image"]["path"]
        self.sbom = self.root / "delivered" / self.record["image_sbom"]["path"]
        self.runtime = self.root / "runtime/docker"
        self.runtime.parent.mkdir()
        self.runtime.write_text("#!" + sys.executable + "\n" + RUNTIME)
        self.runtime.chmod(0o755)
        installation = self.root / "runtime/installation"
        (installation / "tls").mkdir(parents=True)
        (installation / "profiles").mkdir()
        key, certificate = installation / "tls/key.pem", installation / "tls/mcp.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                        str(key), "-out", str(certificate), "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate, key)
        context.load_verify_locations(certificate)
        context.verify_mode = ssl.CERT_REQUIRED
        requests = self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, self.headers["Authorization"], body["method"]))
                reply = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "tools": [{"name": "kasumi_get"}, {"name": "kasumi_query"}]}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]
        inside = smoke.INSTALLATION
        (installation / "kasumi.json").write_text(json.dumps(
            {"mcp": {"tls": {"certificate": inside + "/tls/mcp.pem"}}}))
        (installation / "profiles/mcp.token").write_text("unit-token")
        shutil.copy2(certificate, installation / "tls/ca.pem")
        shutil.copy2(certificate, installation / "profiles/client.pem")
        shutil.copy2(key, installation / "profiles/client-key.pem")
        (installation / "operator").mkdir()
        (installation / "operator/ca-key.pem").write_text("unit-operator-key")
        (installation / "profiles/mcp.json").write_text(json.dumps({
            "mcp_endpoint": f"https://localhost:{self.port}/mcp",
            "server_ca": inside + "/tls/ca.pem", "bearer_file": inside + "/profiles/mcp.token",
            "identity": {"certificate": inside + "/profiles/client.pem",
                         "private_key": inside + "/profiles/client-key.pem"}}))
        self.behave_runtime()

    def behave_runtime(self, **knobs):
        (self.runtime.parent / "runtime-behavior.json").write_text(json.dumps(
            {"installation": str(self.root / "runtime/installation"), **knobs}))
        (self.runtime.parent / "runtime-state.json").unlink(missing_ok=True)

    def smoke(self, attempt):
        output = self.root / "runs" / attempt
        output.parent.mkdir(exist_ok=True)
        export = self.root / ("export-" + attempt)
        export.mkdir(mode=0o700)
        parameters = {"attempt_id": attempt, "runtime": str(self.runtime), "base_port": self.port,
                      "image": str(self.image), "export": str(export)}
        with domain_run.Run(smoke.KIND, smoke.RUNNER, smoke.MODULES, self.evidence, output,
                            self.root, attempt, parameters, domain_run.QUALIFYING) as run:
            smoke.execute(run, parameters, self.image, self.sbom,
                          self.root / "delivered/image.json", .02)
        return output

    def bundle(self, custody):
        delivered = {"oci:" + TARGET: {"id": "oci:" + TARGET, "file": owned.ref(self.root, self.image)},
                     "image-sbom:" + TARGET: {"id": "image-sbom:" + TARGET,
                                              "file": owned.ref(self.root, self.sbom)}}
        consumed = {key: value["file"]["sha256"] for key, value in delivered.items()}
        record, identity, configs = self.gate(
            custody, {"report": owned.ref(self.root, custody / "report.json")}, consumed)
        candidates = {TARGET: {"primary": {"functional": owned.ref(
            self.root, self.evidence / "evidence.json")}}}
        return record, identity, configs, delivered, candidates

    def test_delivered_image_is_loaded_exercised_restarted_and_stopped(self):
        self.behave_runtime(ready_failures=2)
        custody = self.smoke("oci-1")
        report = json.loads((custody / "report.json").read_text())
        self.assertEqual({item["id"] for item in report["scenarios"]},
                         {"load-image", "fresh-install", "native", "mcp", "restart", "clean-stop"})
        self.assertEqual(len(report["details"]["ready_polls"]), 2)
        self.assertEqual([request[2] for request in self.requests], ["tools/list", "tools/list"])
        self.assertTrue(all(request[:2] == ("/mcp", "Bearer unit-token") for request in self.requests))
        copied = json.loads((self.runtime.parent / "runtime-state.json").read_text())["copied"]
        self.assertEqual(copied, list(smoke.MCP_FILES) * 2)
        for stage in ("start", "restart"):
            directory = self.root / "export-oci-1" / stage
            self.assertEqual({p.relative_to(directory).as_posix()
                              for p in directory.rglob("*") if p.is_file()}, set(smoke.MCP_FILES))
        self.assertFalse(any("mcp.token" in path.name or path.name == "key.pem"
                             for path in custody.rglob("*")))
        self.assertNotIn(b"unit-token", b"".join(
            path.read_bytes() for path in custody.rglob("*") if path.is_file()))
        record, identity, configs, delivered, candidates = self.bundle(custody)
        self.assertEqual(self.accept(record, identity, configs, delivered, candidates),
                         ("oci-smoke", "runs/oci-1/outcome.json"))

        def rejected(message, change):
            altered = copy.deepcopy((record, identity, configs, delivered, candidates))
            change(*altered)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.accept(*altered)

        # Another image than the one that was smoked, even a validly assembled one.
        other = self.assemble("other", epoch=1767225601)

        def substitute(r, i, c, d, k):
            d["oci:" + TARGET]["file"] = owned.ref(self.root, self.root / "other" / other["image"]["path"])
            r["artifacts"]["oci:" + TARGET] = d["oci:" + TARGET]["file"]["sha256"]
        rejected("did not run the delivered image and SBOM", substitute)
        rejected("did not run the delivered image and SBOM",
                 lambda r, i, c, d, k: r["artifacts"].update({"oci:" + TARGET: "0" * 64}))
        rejected("did not run the delivered image and SBOM",
                 lambda r, i, c, d, k: r["artifacts"].pop("image-sbom:" + TARGET))
        rejected("omitted or substituted an original owned process",
                 lambda r, i, c, d, k: r["processes"].reverse())
        rejected("registered frozen runner", lambda r, i, c, d, k: r.update(runner={
            "source_path": "scripts/run_ha_soak.py", "sha256": release_gate.sha256(
                self.source / "scripts/run_ha_soak.py")}))

    def test_runtime_that_loaded_another_image_or_killed_the_daemon_fails(self):
        for attempt, knobs, message in (
                ("oci-other", {"image_id": "sha256:" + "d" * 64}, "loaded another image"),
                ("oci-killed", {"exit": "137 false"}, "did not exit zero on its stop signal"),
                ("oci-denied", {"native_ok": False}, "native request did not succeed")):
            self.behave_runtime(**knobs)
            with self.subTest(attempt=attempt), self.assertRaisesRegex(ValueError, message):
                self.smoke(attempt)
            outcome = json.loads((self.root / "runs" / attempt / "outcome.json").read_text())
            self.assertEqual((outcome["status"], outcome["dispatch_started"]), ("failed", True))

    def test_image_whose_binaries_are_not_the_candidates_is_never_loaded(self):
        (self.binaries["kasumid"][0]).write_text("#!" + sys.executable + "\n# rebuilt\n")
        self.binaries["kasumid"] = (self.binaries["kasumid"][0],
                                    release_gate.sha256(self.binaries["kasumid"][0]))
        with self.assertRaisesRegex(ValueError, "differs from the qualified candidate: kasumid"):
            self.smoke("oci-stale")
        self.assertFalse((self.runtime.parent / "runtime-state.json").exists())
        outcome = json.loads((self.root / "runs/oci-stale/outcome.json").read_text())
        self.assertEqual((outcome["status"], outcome["dispatch_started"]), ("failed", False))

    def test_command_plan_is_a_pure_function_of_the_retained_parameters(self):
        parameters = {"attempt_id": "Oci-1", "runtime": "/usr/bin/docker", "base_port": 9440,
                      "image": "/bundle/image.oci.tar", "export": "/private/export"}
        image = {"reference": "kasumi:abc", "manifest_digest": "sha256:m", "config_digest": "sha256:c"}
        steps = smoke.plan(parameters, image, "/usr/bin/python3", "/frozen/scripts/mcp_probe.py")
        self.assertEqual(steps, smoke.plan(parameters, image, "/usr/bin/python3",
                                           "/frozen/scripts/mcp_probe.py"))
        commands = {step: command for step, _, command in steps}
        init = commands["init"]
        self.assertEqual(init[init.index("kasumi:abc"):][:5],
                         ["kasumi:abc", "init", "--mode", "standalone", smoke.INSTALLATION])
        self.assertEqual(init[-2:], ["--tenant", "smoke"])
        self.assertEqual(sum(argument.startswith("--") and argument.endswith("-policy")
                             for argument in init), 2)
        for step in ("ready-start", "ready-restart"):
            self.assertEqual(commands[step][-3:], ["--profile", smoke.INSTALLATION + "/profiles/control.json", "ready"])
        self.assertIn("kasumi-smoke-oci-1:/var/lib/kasumi", commands["start"])
        self.assertEqual(commands["mcp"][:5], ["/usr/bin/python3", "-I", "-B", "-S",
                                               "/frozen/scripts/mcp_probe.py"])
        self.assertIn('"mcp_listen":"127.0.0.1:9440"', commands["inputs"][-1])
        directory = self.root / "policy-inputs"
        script = commands["inputs"][-1].replace(smoke.INPUTS, shlex.quote(str(directory)))
        subprocess.run(["/bin/sh", "-c", "umask 022; " + script], check=True)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for name, expected in smoke.init_inputs(parameters["base_port"]).items():
            policy = directory / (name + ".json")
            self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(policy.read_text()), expected)
        self.assertEqual({scenario for _, scenario, _ in steps if scenario},
                         {"load-image", "fresh-install", "native", "mcp", "restart", "clean-stop"})


if __name__ == "__main__":
    unittest.main()
