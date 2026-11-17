#!/usr/bin/env python3
"""Assemble the Kasumi OCI image deterministically, with its image SBOM.

No container build runs. The pinned base image is supplied as an OCI layout
whose platform manifest must hash to the digest in release/oci/base-image.json.
One uncompressed layer is added: the delivered package under /opt/kasumi and an
empty private /var/lib/kasumi owned by the numeric runtime user. The same
inputs always produce the same archive bytes.

The image SBOM lists what the dependency SBOM cannot: the base image and every
installed Debian package, read from the base layers' dpkg database. It names
the packaged dependency SBOM by hash. ``verify`` recomputes all of this from
the archive alone, so an adapter can bind a delivered image to candidate
binaries and to its SBOM without trusting either file's name.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tarfile

from release_gate import sha256, write_json

SCHEMA = "kasumi-oci-image-v1"
ARCHITECTURES = {"x86_64-unknown-linux-gnu": "amd64", "aarch64-unknown-linux-gnu": "arm64"}
BINARIES = ("kasumi-authority", "kasumictl", "kasumid")
RUNTIME_USER = 65532
PREFIX, STATE = "opt/kasumi", "var/lib/kasumi"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
INDEX = "application/vnd.oci.image.index.v1+json"
BASE_PIN = "release/oci/base-image.json"
MAX_JSON_BYTES = 4 << 20
RUNTIME = {"User": f"{RUNTIME_USER}:{RUNTIME_USER}", "WorkingDir": "/" + STATE,
           "Entrypoint": ["/" + PREFIX + "/bin/kasumid"],
           "Cmd": ["serve", "/" + STATE + "/installation/kasumi.json"], "StopSignal": "SIGTERM"}


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pinned_base(source, target):
    """The reviewed base manifest digest for this target's architecture."""
    pin = json.loads((Path(source) / BASE_PIN).read_text())
    architecture = ARCHITECTURES[target]
    matches = [item for item in pin["manifest"]["manifests"]
               if item["platform"].get("os") == "linux"
               and item["platform"].get("architecture") == architecture]
    require(len(matches) == 1 and matches[0]["mediaType"] == MANIFEST,
            "pinned base image has no single manifest for " + architecture)
    return {"source": pin["source"], "index_digest": pin["index_digest"],
            "manifest_digest": matches[0]["digest"], "architecture": architecture}


def read_blob(layout, reference, limit=None):
    """A layout blob, verified against its own digest."""
    algorithm, _, value = reference.partition(":")
    require(algorithm == "sha256" and len(value) == 64 and all(c in "0123456789abcdef" for c in value),
            "unsupported image digest")
    path = Path(layout) / "blobs" / "sha256" / value
    require(path.is_file() and not path.is_symlink(), "image blob is absent: " + reference)
    require(limit is None or path.stat().st_size <= limit, "image metadata blob exceeds work limit")
    require(sha256(path) == value, "image blob differs from its digest: " + reference)
    return path


def package_files(archive):
    """The delivered package's regular files under its single root directory."""
    files = {}
    with tarfile.open(archive, "r:gz") as package:
        prefix = None
        for member in package:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and name.parts,
                    "package member escapes its root")
            prefix = prefix or name.parts[0]
            require(name.parts[0] == prefix and (member.isdir() or member.isfile()),
                    "package has an unsafe member")
            if member.isfile():
                relative = PurePosixPath(*name.parts[1:]).as_posix()
                require(len(name.parts) > 1 and relative not in files, "package repeats a member")
                files[relative] = (package.extractfile(member).read(), bool(member.mode & 0o111))
    require(all("bin/" + name in files and files["bin/" + name][1] for name in BINARIES)
            and "sbom.spdx.json" in files and "provenance.json" in files,
            "package lacks its binaries, dependency SBOM or provenance")
    return files


def runtime_layer(files, epoch):
    """One deterministic uncompressed layer: sorted, fixed owner and time."""
    def entry(name, mode, owner, kind=tarfile.REGTYPE, size=0):
        info = tarfile.TarInfo(name)
        info.type, info.mode, info.size, info.mtime = kind, mode, size, epoch
        info.uid = info.gid = owner
        info.uname = info.gname = ""
        return info

    checksums = "".join(hashlib.sha256(files["bin/" + name][0]).hexdigest() + "  bin/" + name + "\n"
                        for name in BINARIES).encode()
    contents = {**{name: data for name, data in files.items()}, "binary-sha256": (checksums, False)}
    directories = {PREFIX}
    for name in contents:
        directories |= {PREFIX + "/" + parent.as_posix()
                        for parent in PurePosixPath(name).parents if parent.as_posix() != "."}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as layer:
        rows = [(name + "/", None) for name in directories] + \
            [(PREFIX + "/" + name, value) for name, value in contents.items()]
        for name, value in sorted(rows):
            if value is None:
                layer.addfile(entry(name, 0o755, 0, tarfile.DIRTYPE))
            else:
                data, executable = value
                layer.addfile(entry(name, 0o755 if executable else 0o644, 0, size=len(data)),
                              io.BytesIO(data))
        # The numeric runtime user owns only its empty private state directory.
        layer.addfile(entry(STATE + "/", 0o700, RUNTIME_USER, tarfile.DIRTYPE))
    return raw.getvalue()


def dpkg_packages(layout, layers):
    """Installed Debian packages from the last dpkg database in the base layers."""
    status = None
    for layer in layers:
        with tarfile.open(read_blob(layout, layer["digest"]), "r:*") as archive:
            for member in archive:
                name = member.name.lstrip("./")
                if name == "var/lib/dpkg/.wh.status" or name == "var/lib/.wh.dpkg":
                    status = None
                elif name == "var/lib/dpkg/status" and member.isfile():
                    status = archive.extractfile(member).read()
    require(status is not None, "base image has no dpkg database to inventory")
    packages = []
    for paragraph in status.decode("utf-8", "replace").split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line[:1] not in (" ", "\t") and ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if fields.get("Status") == "install ok installed":
            require(all(fields.get(key) for key in ("Package", "Version", "Architecture")),
                    "base dpkg database has an incomplete installed package")
            packages.append({"name": fields["Package"], "version": fields["Version"],
                             "architecture": fields["Architecture"],
                             "source": fields.get("Source", fields["Package"]).split(" ")[0]})
    require(packages and len({(p["name"], p["architecture"]) for p in packages}) == len(packages),
            "base dpkg database is empty or repeats a package")
    return sorted(packages, key=lambda item: (item["name"], item["architecture"]))


def image_sbom(image, packages, files, base, epoch):
    """SPDX for the image: base, OS packages, Kasumi binaries, dependency SBOM link."""
    def identifier(kind, text):
        return "SPDXRef-" + kind + "-" + hashlib.sha256(text.encode()).hexdigest()[:20]

    dependencies = hashlib.sha256(files["sbom.spdx.json"][0]).hexdigest()
    entries = [
        {"SPDXID": "SPDXRef-Image", "name": "kasumi-oci-" + base["architecture"],
         "versionInfo": image["manifest_digest"], "downloadLocation": "NOASSERTION",
         "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
         "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
         "checksums": [{"algorithm": "SHA256", "checksumValue": image["manifest_digest"][7:]}],
         "comment": "Rust dependencies of the Kasumi binaries are in the packaged dependency "
                    "SBOM /opt/kasumi/sbom.spdx.json, SHA256 " + dependencies + "."},
        {"SPDXID": "SPDXRef-Base", "name": base["source"], "versionInfo": base["manifest_digest"],
         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
         "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
         "copyrightText": "NOASSERTION",
         "checksums": [{"algorithm": "SHA256", "checksumValue": base["manifest_digest"][7:]}]}]
    relations = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                  "relatedSpdxElement": "SPDXRef-Image"},
                 {"spdxElementId": "SPDXRef-Image", "relationshipType": "DESCENDANT_OF",
                  "relatedSpdxElement": "SPDXRef-Base"}]
    for item in packages:
        spdx = identifier("deb", item["name"] + ":" + item["architecture"])
        entries.append({
            "SPDXID": spdx, "name": item["name"], "versionInfo": item["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION", "sourceInfo": "dpkg source " + item["source"],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": "pkg:deb/debian/" + item["name"] + "@"
                              + item["version"] + "?arch=" + item["architecture"]}]})
        relations.append({"spdxElementId": "SPDXRef-Base", "relationshipType": "CONTAINS",
                          "relatedSpdxElement": spdx})
    executables = []
    for name in BINARIES:
        spdx = identifier("file", name)
        executables.append({"SPDXID": spdx, "fileName": "/" + PREFIX + "/bin/" + name,
                            "checksums": [{"algorithm": "SHA256", "checksumValue":
                                           hashlib.sha256(files["bin/" + name][0]).hexdigest()}],
                            "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"})
        relations.append({"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS",
                          "relatedSpdxElement": spdx})
    created = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "kasumi-oci-image-" + image["manifest_digest"][7:],
            "creationInfo": {"creators": ["Tool: kasumi-oci-image-1"], "created": created},
            "packages": entries, "files": executables, "relationships": relations}
    sbom["documentNamespace"] = "https://spdx.org/spdxdocs/kasumi-" + \
        hashlib.sha256(canonical(sbom)).hexdigest()
    return sbom


def compose(source, layout, package, target, epoch):
    """Every image blob and the SBOM, as pure bytes of the verified inputs."""
    require(target in ARCHITECTURES and type(epoch) is int and epoch > 0,
            "unsupported image target or build time")
    base = pinned_base(source, target)
    manifest_bytes = read_blob(layout, base["manifest_digest"], MAX_JSON_BYTES).read_bytes()
    manifest = json.loads(manifest_bytes)
    require(manifest.get("schemaVersion") == 2 and manifest["config"]["mediaType"] == CONFIG
            and manifest["layers"], "pinned base manifest is not an OCI image manifest")
    config_bytes = read_blob(layout, manifest["config"]["digest"], MAX_JSON_BYTES).read_bytes()
    config = json.loads(config_bytes)
    require(config.get("os") == "linux" and config.get("architecture") == base["architecture"]
            and len(config["rootfs"]["diff_ids"]) == len(manifest["layers"]),
            "pinned base configuration differs from its platform")
    for layer in manifest["layers"]:
        require(read_blob(layout, layer["digest"]).stat().st_size == layer["size"],
                "base layer size differs from its descriptor")
    files = package_files(package)
    layer = runtime_layer(files, epoch)
    created = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    config["created"] = created
    config["config"] = {**config.get("config", {}), **RUNTIME}
    config["rootfs"]["diff_ids"] = [*config["rootfs"]["diff_ids"], digest(layer)]
    config["history"] = [*config.get("history", []),
                         {"created": created, "created_by": "kasumi oci_image.py",
                          "comment": "delivered package under /" + PREFIX}]
    image_config = canonical(config)
    image_manifest = canonical({
        "schemaVersion": 2, "mediaType": MANIFEST,
        "config": {"mediaType": CONFIG, "digest": digest(image_config), "size": len(image_config)},
        "layers": [*manifest["layers"],
                   {"mediaType": LAYER, "digest": digest(layer), "size": len(layer)}],
        "annotations": {"org.opencontainers.image.base.digest": base["manifest_digest"],
                        "org.opencontainers.image.base.name": base["source"]}})
    platform = {"architecture": base["architecture"], "os": "linux"}
    if "variant" in config:
        platform["variant"] = config["variant"]
    index = canonical({"schemaVersion": 2, "mediaType": INDEX, "manifests": [{
        "mediaType": MANIFEST, "digest": digest(image_manifest), "size": len(image_manifest),
        "platform": platform,
        "annotations": {"org.opencontainers.image.ref.name":
                        "kasumi:" + digest(image_manifest)[7:19]}}]})
    image = {"manifest_digest": digest(image_manifest), "config_digest": digest(image_config),
             "layer_digest": digest(layer), "reference": "kasumi:" + digest(image_manifest)[7:19]}
    # The pinned base manifest and configuration ride along unreferenced, so a
    # verifier can prove the inherited layers from the archive alone.
    blobs = {digest(data): data for data in (layer, image_config, image_manifest,
                                             manifest_bytes, config_bytes)}
    base_layers = [item["digest"] for item in manifest["layers"]]
    sbom = image_sbom(image, dpkg_packages(layout, manifest["layers"]), files, base, epoch)
    return image, index, blobs, base_layers, sbom


def assemble(source, layout, package, target, epoch, output):
    """Write the image archive, its SBOM and an assembly record into a new directory."""
    output = Path(output)
    require(output.is_absolute(), "image output must be absolute")
    image, index, blobs, base_layers, sbom = compose(source, layout, package, target, epoch)
    output.mkdir(exist_ok=False)
    stem = Path(package).name.removesuffix(".tar.gz")
    archive = output / (stem + ".oci.tar")

    def entry(name, size):
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = size, 0o644, epoch
        info.uname = info.gname = ""
        return info

    with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as bundle:
        members = {"oci-layout": canonical({"imageLayoutVersion": "1.0.0"}), "index.json": index}
        members.update({"blobs/sha256/" + key[7:]: data for key, data in blobs.items()})
        members.update({"blobs/sha256/" + key[7:]: None for key in base_layers})
        for name in sorted(members):
            if members[name] is None:
                path = read_blob(layout, "sha256:" + PurePosixPath(name).name)
                with path.open("rb") as stream:
                    bundle.addfile(entry(name, path.stat().st_size), stream)
            else:
                bundle.addfile(entry(name, len(members[name])), io.BytesIO(members[name]))
    write_json(output / (stem + ".image-sbom.spdx.json"), sbom)
    record = {"schema": SCHEMA, "target": target, "source_date_epoch": epoch, **image,
              "image": {"path": archive.name, "sha256": sha256(archive)},
              "image_sbom": {"path": stem + ".image-sbom.spdx.json",
                             "sha256": sha256(output / (stem + ".image-sbom.spdx.json"))},
              "package_sha256": sha256(package)}
    write_json(output / "image.json", record)
    return record


def verify(source, archive, sbom, target, binaries):
    """Bind a delivered image archive to the pinned base, candidates and SBOM.

    Reads only the archive: platform, manifest and layer identities, inherited
    base layers, the runtime layer's exact contents and the runtime
    configuration. The SBOM must be the one this image's bytes produce.
    """
    base = pinned_base(source, target)
    blobs = {}
    with tarfile.open(archive, "r:") as bundle:
        members = {member.name: member for member in bundle}
        require(len(members) == len(bundle.getmembers())
                and all(member.isfile() for member in members.values()),
                "image archive has a repeated or special member")
        index = json.loads(bundle.extractfile(members["index.json"]).read(MAX_JSON_BYTES))
        for name, member in members.items():
            if name.startswith("blobs/sha256/"):
                with bundle.extractfile(member) as stream:
                    observed = hashlib.file_digest(stream, "sha256").hexdigest()
                require(observed == PurePosixPath(name).name, "image blob differs from its digest")
                blobs["sha256:" + observed] = member

        def blob(reference):
            require(reference in blobs, "image archive lacks a referenced blob: " + reference)
            return bundle.extractfile(blobs[reference]).read()

        require(index.get("mediaType") == INDEX and len(index["manifests"]) == 1,
                "image archive does not hold exactly one image")
        descriptor = index["manifests"][0]
        require(descriptor["platform"].get("os") == "linux"
                and descriptor["platform"].get("architecture") == base["architecture"],
                "image platform differs from the gate target")
        manifest = json.loads(blob(descriptor["digest"]))
        config_bytes = blob(manifest["config"]["digest"])
        config = json.loads(config_bytes)
        inherited = json.loads(blob(base["manifest_digest"]))
        inherited_config = json.loads(blob(inherited["config"]["digest"]))
        layer = manifest["layers"][-1]
        require(manifest["layers"][:-1] == inherited["layers"]
                and config["rootfs"]["diff_ids"][:-1] == inherited_config["rootfs"]["diff_ids"]
                and layer["mediaType"] == LAYER
                and config["rootfs"]["diff_ids"][-1] == layer["digest"]
                and all(item["digest"] in blobs for item in manifest["layers"]),
                "image does not extend the pinned base by one runtime layer")
        require(config.get("os") == "linux" and config.get("architecture") == base["architecture"]
                and all(config["config"].get(key) == value for key, value in RUNTIME.items()),
                "image runtime configuration differs from the release contract")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(blob(layer["digest"])), mode="r:") as contents:
            for member in contents:
                name = member.name.rstrip("/")
                state = name == STATE
                require((member.isdir() or member.isfile()) and not member.mode & 0o7000
                        and (state or name == PREFIX or name.startswith(PREFIX + "/"))
                        and member.uid == member.gid == (RUNTIME_USER if state else 0)
                        and (not state or (member.isdir() and member.mode == 0o700)),
                        "image runtime layer has an unexpected member: " + member.name)
                if member.isfile():
                    files[name[len(PREFIX) + 1:]] = (contents.extractfile(member).read(),
                                                     bool(member.mode & 0o111))
    for name in BINARIES:
        require(name in binaries and "bin/" + name in files and files["bin/" + name][1]
                and hashlib.sha256(files["bin/" + name][0]).hexdigest() == binaries[name],
                "image binary differs from the qualified candidate: " + name)
    image = {"manifest_digest": descriptor["digest"], "config_digest": manifest["config"]["digest"],
             "layer_digest": layer["digest"],
             "reference": descriptor["annotations"]["org.opencontainers.image.ref.name"]}
    require(image["reference"] == "kasumi:" + image["manifest_digest"][7:19],
            "image reference does not name its own manifest")
    epoch = int(dt.datetime.fromisoformat(config["created"].replace("Z", "+00:00")).timestamp())
    packages = _dpkg_from_archive(archive, inherited["layers"])
    require(json.loads(Path(sbom).read_text()) == image_sbom(image, packages, files, base, epoch),
            "image SBOM differs from the image's own contents")
    return image


def _dpkg_from_archive(archive, layers):
    """dpkg_packages over an image archive: stage the base blobs as a layout."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="kasumi-oci-verify-") as directory:
        blobs = Path(directory) / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        with tarfile.open(archive, "r:") as bundle:
            for layer in layers:
                member = bundle.getmember("blobs/sha256/" + layer["digest"][7:])
                with bundle.extractfile(member) as stream, \
                        (blobs / layer["digest"][7:]).open("wb") as copy:
                    while block := stream.read(1 << 20):
                        copy.write(block)
        return dpkg_packages(directory, layers)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base-layout", type=Path, required=True,
                        help="OCI layout holding the pinned base image's blobs")
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--target", required=True, choices=sorted(ARCHITECTURES))
    parser.add_argument("--source-date-epoch", type=int,
                        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        record = assemble(args.source, args.base_layout, args.package, args.target,
                          args.source_date_epoch, args.output)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print("OCI image assembly rejected: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
