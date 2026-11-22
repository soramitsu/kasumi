#!/usr/bin/env python3
"""Assemble a Linux image from the native functional build and journal the original products."""
import argparse
import os
from pathlib import Path
import platform
import sys

if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise SystemExit("run the native image producer with Python -I -B -S")
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import attempt_index
import domain_run
import oci_image
import package_release
import release_host
import repeatable_assembly as owned
from release_gate import sha256


def native_target():
    system, machine = platform.system(), platform.machine()
    target = release_host.host_target(system, machine)
    owned.require(target in oci_image.ARCHITECTURES, "OCI release assembly requires native Linux")
    _, translation = release_host.linux_emulation(machine)
    owned.require(not translation, "OCI release assembly requires an untranslated Linux process")
    return target


def launch(journal, attempt_id, output, evidence, layout, archive):
    journal = attempt_index.custody(journal)
    attempt_index.begin(journal, attempt_id, "oci-image", output, domain_run.now())
    output.mkdir(parents=True, mode=0o700)
    products, processes, facts = {}, [], {}
    dispatched = False
    status = "failed"
    try:
        target = native_target()
        owned.require(attempt_index.head(journal)["target"] == target, "native image journal target differs")
        evidence = evidence.resolve(strict=True)
        source = evidence / "source"
        build, _, build_target, binaries = package_release.verify_evidence(evidence)
        owned.require(build_target == target, "functional build target differs from the image host")
        hashes = {name: digest for name, (_, digest) in binaries.items()}
        facts["source_scripts"] = domain_run.frozen_scripts(source, owned.read(evidence / "source-files.json"),
            {"scripts/run_oci_image_owned.py", "scripts/oci_image.py", "scripts/release_host.py"})
        archive = archive.resolve(strict=True)
        layout = layout.resolve(strict=True)
        facts["package_sha256"] = sha256(archive)
        facts["functional_sha256"] = sha256(evidence / "evidence.json")
        epoch = int(build["build_environment"]["SOURCE_DATE_EPOCH"])
        payload = output / "image"
        command = [str(Path(sys.executable).resolve()), "-I", "-B", "-S", str(source / "scripts/oci_image.py"),
                   "--source", str(source), "--base-layout", str(layout), "--package", str(archive),
                   "--target", target, "--source-date-epoch", str(epoch), "--output", str(payload)]
        env = {"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC"}
        dispatched = True
        child = owned.run_owned(output, "assemble", command, str(source), env, 1800)
        processes.append({"id": "assemble", **{
            name: attempt_index.file_ref(journal, output / child[key]["path"])
            for name, key in (("log", "stdout"), ("executable", "executable"), ("receipt", "receipt"))}})
        facts["stderr"] = child["stderr"]
        owned.check_owned(output, child, command, str(source), 1800)
        record = owned.read(payload / "image.json")
        image = package_release.verify_file(payload, record["image"]["path"], record["image"]["sha256"])
        sbom = package_release.verify_file(payload, record["image_sbom"]["path"], record["image_sbom"]["sha256"])
        provenance = {key: build[key] for key in ("source_commit", "source_tree", "lockfile_sha256")}
        provenance.update(target=target, source_date_epoch=epoch, executables=hashes,
                          functional_evidence_sha256=facts["functional_sha256"])
        verified = oci_image.verify(source, image, sbom, target, hashes, provenance=provenance)
        owned.require(all(record.get(k) == v for k, v in verified.items())
                      and record["target"] == target and record["source_date_epoch"] == epoch
                      and record["package_sha256"] == facts["package_sha256"] == sha256(archive),
                      "original OCI products differ from the verified build")
        products = {"image": image.relative_to(output).as_posix(),
                    "image-sbom": sbom.relative_to(output).as_posix()}
        facts["image_record"] = attempt_index.file_ref(output, payload / "image.json")
        status = "passed"
    except (Exception, KeyboardInterrupt) as error:
        facts["error"] = repr(error)
        status = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        raise
    finally:
        attempt_index.finish_outcome(journal, attempt_id, status, domain_run.now(), products=products,
                                     processes=processes, dispatch_started=dispatched, facts=facts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    for name in ("output", "evidence", "base-layout", "package"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    launch(args.journal, args.attempt_id, args.output, args.evidence, args.base_layout, args.package)


if __name__ == "__main__":
    main()
