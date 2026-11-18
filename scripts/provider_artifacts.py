"""Verify and read only the pinned native provider executables from release archives."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import tarfile

from domain_run import require
import fetch_openbao
from release_gate import sha256

MINIO_INDEX = "14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
MINIO_RELEASE = "RELEASE.2025-09-07T16-13-09Z"
MAX_LAYER = 1 << 30
MAX_BINARY = 256 << 20
TARGETS = {"x86_64-unknown-linux-gnu": ("linux", "amd64"), "aarch64-unknown-linux-gnu": ("linux", "arm64")}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def executable(handle, item):
    require(item.isfile() and 0 < item.size <= MAX_BINARY and item.mode & 0o111,
            "provider executable has an invalid size, mode or type")
    return handle.extractfile(item).read()


def openbao(path, target):
    require(sha256(path) == fetch_openbao.DIGESTS[target], "OpenBao release archive differs")
    with tarfile.open(path, "r:gz") as handle:
        members = [item for item in handle if item.name in {"bao", "./bao"}]
        require(len(members) == 1, "expected exactly one official bao executable")
        return executable(handle, members[0])


def minio(path, arch, index=MINIO_INDEX):
    """An offline OCI export must retain the published multiarch index as a blob.

    Check each selected layer in base-to-top order. A whiteout or replacement
    above a binary affects what the service would have executed in the image.
    Read only regular files, never extract a supplied pathname onto the host.
    """
    from io import BytesIO
    require(path.stat().st_size <= 3 << 30, "OCI archive exceeds work bound")
    names = {}
    with tarfile.open(path, "r:") as archive:
        for item in archive:
            name = item.name.removeprefix("./")
            require(len(names) < 10000 and name not in names, "OCI archive has repeated or excess members")
            names[name] = item

        def blob(desc, limit):
            name = desc["digest"]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", name), "invalid OCI digest")
            member = names.get("blobs/sha256/" + name[7:])
            if member is None and name == "sha256:" + index:
                member = names.get("index.json")
            require(member and member.isfile() and 0 < member.size <= limit
                    and member.size == desc.get("size", member.size), "OCI blob size or type differs")
            data = archive.extractfile(member).read()
            require(digest(data) == name[7:], "OCI blob digest differs")
            return data

        manifest_list = json.loads(blob({"digest": "sha256:" + index}, 2 << 20))
        manifests = [entry for entry in manifest_list["manifests"]
                     if entry["platform"]["os"] == "linux" and entry["platform"]["architecture"] == arch]
        require(len(manifests) == 1, "MinIO native image missing or ambiguous")
        manifest = json.loads(blob(manifests[0], 2 << 20))
        config = json.loads(blob(manifest["config"], 2 << 20))
        require(config["os"] == "linux" and config["architecture"] == arch, "MinIO config targets another host")
        require(0 < len(manifest["layers"]) <= 64, "MinIO layer count outside bound")
        result = None
        for desc in manifest["layers"]:
            with tarfile.open(fileobj=BytesIO(blob(desc, MAX_LAYER)), mode="r:*") as layer:
                replacement = None
                hides_lower = False
                seen = 0
                for i, item in enumerate(layer):
                    require(i < 100000 and item.offset + item.size <= 2 << 30, "MinIO layer exceeds work bounds")
                    name = str(PurePosixPath(item.name))
                    path = PurePosixPath(name)
                    require(not path.is_absolute() and ".." not in path.parts, "invalid MinIO layer path")
                    if name in {"usr", "usr/bin"}:
                        require(item.isdir(), "MinIO executable ancestor is not a directory")
                    if name in {".wh.usr", ".wh..wh..opq", "usr/.wh.bin", "usr/.wh..wh..opq",
                                "usr/bin/.wh.minio", "usr/bin/.wh..wh..opq"}:
                        hides_lower = True
                    if name == "usr/bin/minio":
                        seen += 1
                        require(seen == 1, "MinIO layer repeats an executable")
                        replacement = executable(layer, item)
                if hides_lower:
                    result = None
                if replacement is not None:
                    result = replacement
        require(result is not None, "native MinIO executable missing in final image")
        return result
