#!/usr/bin/env python3
"""Fetch a pinned OpenBao test dependency into the existing Cargo target directory.

SHA-256 values are from the official v2.6.2 GitHub release asset metadata.
Nothing is installed globally and the downloaded binary is never executed here.
"""
import hashlib
import pathlib
import platform
import shutil
import tarfile
import urllib.request

VERSION = "2.6.2"
DIGESTS = {
    ("darwin", "arm64"): "4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52",
    ("darwin", "amd64"): "64fdf1ce8f410bbc1531d2f0ea142d21b4e755b986542025a00294999a8cfaa5",
    ("linux", "arm64"): "1b408e01f3565ac0cbcb88d637dca271d0515148fb72efdeff4473a34fa50c4e",
    ("linux", "amd64"): "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa",
}


def main():
    system = platform.system().lower()
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    expected = DIGESTS.get((system, arch))
    if expected is None:
        raise SystemExit("No pinned OpenBao asset for this platform")
    workspace = pathlib.Path(__file__).resolve().parent.parent
    destination = workspace / "target" / "tools" / f"openbao-{VERSION}" / f"{system}-{arch}"
    destination.mkdir(parents=True, exist_ok=True)
    name = f"openbao_{VERSION}_{system}_{arch}.tar.gz"
    archive = destination / name
    if not archive.exists():
        partial = archive.with_suffix(".part")
        urllib.request.urlretrieve(f"https://github.com/openbao/openbao/releases/download/v{VERSION}/{name}", partial)
        with partial.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                partial.unlink()
                raise SystemExit("OpenBao checksum mismatch")
        partial.replace(archive)
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise SystemExit("Cached OpenBao archive checksum mismatch")
    with tarfile.open(archive) as bundle:
        binaries = [member for member in bundle.getmembers() if member.name in ("bao", "./bao") and member.isfile()]
        if len(binaries) != 1:
            raise SystemExit("Unexpected OpenBao archive layout")
        # Only copy the verified regular member into this fixed path. Older
        # production Python releases lack tarfile's extraction filters; avoiding
        # archive paths and mode bits also avoids requiring those filters.
        with bundle.extractfile(binaries[0]) as source, (destination / "bao").open("wb") as output:
            shutil.copyfileobj(source, output)
        (destination / "bao").chmod(0o755)
    print(destination / "bao")


if __name__ == "__main__":
    main()
