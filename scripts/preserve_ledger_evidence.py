#!/usr/bin/env python3
"""Preserve the development evidence that the release ledger cites under target/.

The ledger (docs/production-release.md, docs/first-release-goals.md and every
README.md under docs/evidence/) cites logs, patches, reviews and JSON receipts
that exist only in the gitignored target/ directory, where a cargo clean or
target pruning would destroy them.  This script copies every cited file to the
same repository-relative path under an external evidence directory and writes
a manifest that binds each reference to its bytes.

Every `target/...` token in the ledger is accounted for.  Inside Markdown code
(code spans, fenced blocks at any indentation and indented code blocks) a
token is a citation, with `{a,b}` brace lists expanded; `./target/...` and
absolute paths into the checkout's target/ are citations too.  A token in
prose is preserved as a prose citation when its path exists.  Otherwise it is
missing when it is shaped like a path, recorded when it is a known prose
phrase and refused.  Naming target/ itself is recorded and cites nothing.

A cited directory is preserved recursively, except for build caches marked by
a CACHEDIR.TAG, which are recorded by path.  Binaries larger than the copy cap
are hashed and recorded instead of copied.  Each directory's per-file listing
is stored in a content-addressed inventory under the destination and bound by
its SHA-256.

target/ is only read, so the script is safe to run alongside cargo.  Copies are
published create-only: a destination whose bytes differ is refused and never
overwritten.  Symlinks, non-regular files, unreadable or unsafe references and
sources that change while being read are refused.  Missing references are
listed.  Every refusal and missing reference is recorded in the manifest and
gives a nonzero exit after everything else has been preserved.  A destination
write failure aborts the run without writing a manifest; a rerun resumes
idempotently.  On macOS every fsync is followed by F_FULLFSYNC, because fsync
there leaves the data in the drive's write cache.
"""
from __future__ import annotations

import argparse
import bisect
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys

SCHEMA = "kasumi-ledger-evidence-preservation-v2"
INVENTORY_SCHEMA = "kasumi-ledger-evidence-directory-inventory-v1"
LEDGER = ("docs/production-release.md", "docs/first-release-goals.md")
EVIDENCE = "docs/evidence"
MANIFEST = "docs/evidence/development-evidence-manifest-20260925/manifest.json"
DEFAULT_BINARY_CAP = 1 << 20
CHUNK = 1 << 20
# Git's heuristic: a NUL byte in the first 8000 bytes marks a binary file.
BINARY_PROBE = 8000
CACHEDIR_TAG = "CACHEDIR.TAG"
CACHEDIR_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
# Only macOS defines it; there fsync(2) does not flush the drive's write cache.
FULL_FSYNC = getattr(fcntl, "F_FULLFSYNC", None)

FENCE = re.compile(r"`{3,}|~{3,}")
LIST_ITEM = re.compile(r"([-*+]|\d{1,9}[.)])( +|$)")
SPAN = re.compile(r"(?<!`)(`+)(?!`)((?:(?!\n[ \t]*\n).)+?)(?<!`)\1(?!`)", re.S)
TOKEN = re.compile(r"(?<![\w./-])(?:\./)?target/[^\s`'\"()<>\[\]]*")
# Sentence punctuation after a path in prose ends the token.
TRAILING = ".,;:!?*"
BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
COMPONENT = re.compile(r"[A-Za-z0-9._+=@,~-]+\Z")
# Ledger prose that reads like a target/ path but names none.
PROSE_PHRASES = frozenset({
    "target/archive", "target/issuer", "target/local", "target/scratch", "target/signing",
    "target/source/custody",
})

READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
DIRECTORY = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC


class Refusal(Exception):
    """A source-side reason why one cited path was not preserved."""


class Missing(Exception):
    """A cited path, or one of its parents, does not exist."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def pretty(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def indentation(line):
    """Return a line's indentation in columns, with tab stops every four, and its content."""
    columns = 0
    for index, character in enumerate(line):
        if character == " ":
            columns += 1
        elif character == "\t":
            columns += 4 - columns % 4
        else:
            return columns, line[index:]
    return columns, ""


def segments(text):
    """Yield (first line number, text, is code) covering a whole Markdown document.

    Code is every code span, every fenced line (fences may be indented, as in
    list items) and every indented code block line, which sits four columns
    past the enclosing list item's content after a blank line or a heading.
    The prose, everything else, is yielded last with the code blanked out.
    """
    prose = []
    fence = None
    items = []  # content columns of the open list items, innermost last
    blank = True
    opens = True  # no paragraph is open, so an indented code block may start
    for number, line in enumerate(text.split("\n"), 1):
        columns, content = indentation(line)
        if fence is not None:
            closing = content.rstrip()
            if closing.startswith(fence) and set(closing) == {fence[0]}:
                fence = None
                opens = True
            else:
                yield number, line, True
            prose.append("")
            continue
        if not content:
            blank = opens = True
            prose.append(line)
            continue
        if blank:
            # After a blank line, a shallower line leaves the items it is not indented into.
            while items and columns < items[-1]:
                items.pop()
        blank = False
        if opens and columns >= (items[-1] if items else 0) + 4:
            yield number, line, True
            prose.append("")
            continue
        item = LIST_ITEM.match(content)
        if item:
            while items and items[-1] > columns:
                items.pop()
            spaces = len(item.group(2))
            items.append(columns + len(item.group(1)) + (spaces if 1 <= spaces <= 4 else 1))
            content = content[item.end():]
        opening = FENCE.match(content)
        # A backtick in a backtick fence's info string makes the line a code span.
        if opening and not (content[0] == "`" and "`" in content[opening.end():]):
            fence = opening.group(0)
            prose.append("")
            continue
        opens = content.startswith("#")
        prose.append(line)
    # Code lines are blanked so that code spans never pair across them.
    text = "\n".join(prose)
    starts = [0] + [match.end() for match in re.finditer("\n", text)]
    remainder = []
    end = 0
    for match in SPAN.finditer(text):
        yield bisect.bisect_right(starts, match.start(2)), match.group(2), True
        remainder += [text[end:match.start()], re.sub(r"[^\n]", " ", match.group(0))]
        end = match.end()
    remainder.append(text[end:])
    yield 1, "".join(remainder), False


def expand(token):
    match = BRACES.search(token)
    if match is None:
        return [token]
    return [expanded for choice in match.group(1).split(",")
            for expanded in expand(token[:match.start()] + choice + token[match.end():])]


def reference_path(token):
    """Return the normalized cited path, or None for an unsafe token."""
    value = token.rstrip("/")
    parts = value.split("/")
    if (len(parts) < 2 or parts[0] != "target"
            or not all(COMPONENT.match(part) and part not in (".", "..") for part in parts)):
        return None
    return value


def path_shaped(path):
    """A prose token names a file when it has several components or a dotted leaf."""
    parts = path.split("/")[1:]
    return len(parts) > 1 or "." in parts[-1]


def citations(where):
    """Format (document, line) pairs in document and numeric line order."""
    return [f"{document}:{number}" for document, number in sorted(where)]


def references(ledger, repository=""):
    """Classify every target/ token in the ledger.

    Returns three maps.  The first maps each safe path to (cited_by,
    prose_cited_by): all its citations, and those found only in prose.  The
    second maps each unsafe token to its citations.  The third lists where
    target/ itself is named.  An absolute path into the repository's target/
    counts as the relative path.
    """
    absolute = None
    if repository:
        absolute = re.compile(r"(?<![\w./-])" + re.escape(repository.rstrip("/")) + r"/(?=target/)")
    cited = {}
    unsafe = {}
    named = set()
    for document, text in ledger:
        if absolute is not None:
            # Removing the prefix keeps every line number.
            text = absolute.sub("", text)
        for number, fragment, code in segments(text):
            starts = [0] + [match.end() for match in re.finditer("\n", fragment)]
            for match in TOKEN.finditer(fragment):
                token = match.group(0).removeprefix("./")
                if not code:
                    token = token.rstrip(TRAILING)
                where = (document, number - 1 + bisect.bisect_right(starts, match.start()))
                if token == "target/":
                    # The build directory itself is named, not a path inside it.
                    named.add(where)
                    continue
                for expanded in expand(token):
                    path = reference_path(expanded)
                    if path is None:
                        unsafe.setdefault(expanded, set()).add(where)
                    else:
                        cited.setdefault(path, (set(), set()))[0 if code else 1].add(where)
    return ({path: (citations(code | prose), citations(prose - code))
             for path, (code, prose) in cited.items()},
            {token: citations(where) for token, where in unsafe.items()},
            citations(named))


def unreadable(error, where=None):
    reason = error.strerror or str(error)
    return "unreadable: " + (where + ": " + reason if where else reason)


def ledger_documents(repository):
    """Return the ledger paths, fixed documents plus every evidence README, and
    refusals for evidence directories that could not be searched.

    This tool's own README describes the preservation and is not a ledger.
    """
    excluded = PurePosixPath(MANIFEST).parent
    documents = list(LEDGER)
    refused = []

    def relative(path):
        return PurePosixPath(Path(path).relative_to(repository).as_posix())

    def failed(error):
        refused.append({"path": relative(error.filename).as_posix(),
                        "reason": "ledger directory " + unreadable(error)})

    evidence = repository / EVIDENCE
    if evidence.is_symlink():
        return documents, [{"path": EVIDENCE, "reason": "ledger directory is a symlink"}]
    for directory, names, files in os.walk(evidence, onerror=failed):
        here = relative(directory)
        if here == excluded:
            names[:] = []
            continue
        # os.walk lists a symlinked directory without entering it.
        for name in [name for name in names if os.path.islink(os.path.join(directory, name))]:
            refused.append({"path": (here / name).as_posix(),
                            "reason": "ledger directory is a symlink"})
            names.remove(name)
        names.sort()
        if "README.md" in files:
            documents.append((here / "README.md").as_posix())
    return documents, refused


def open_parent(root_fd, parts):
    """Open the directory holding parts[-1] beneath root_fd without symlinks."""
    descriptor = os.dup(root_fd)
    try:
        for index, part in enumerate(parts[:-1]):
            prefix = "/".join(parts[:index + 1])
            try:
                status = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(status.st_mode):
                    raise Refusal("symlink: " + prefix)
                if not stat.S_ISDIR(status.st_mode):
                    raise Refusal("not a directory: " + prefix)
                child = os.open(part, DIRECTORY, dir_fd=descriptor)
            except FileNotFoundError:
                raise Missing(prefix) from None
            except OSError as error:
                raise Refusal(unreadable(error, prefix)) from None
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_ledger(repository_fd, relative):
    parts = relative.split("/")
    parent = open_parent(repository_fd, parts)
    try:
        try:
            status = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(status.st_mode):
                raise Refusal("not a regular file")
            descriptor = os.open(parts[-1], READ, dir_fd=parent)
        except FileNotFoundError:
            raise Missing(relative) from None
        except OSError as error:
            raise Refusal(unreadable(error)) from None
    finally:
        os.close(parent)
    try:
        with os.fdopen(descriptor, "rb") as document:
            return document.read()
    except OSError as error:
        raise Refusal(unreadable(error)) from None


def is_cache_directory(directory_fd):
    """Recognize a build cache by its Cache Directory Tagging signature."""
    try:
        status = os.stat(CACHEDIR_TAG, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(status.st_mode):
        return False
    descriptor = os.open(CACHEDIR_TAG, READ, dir_fd=directory_fd)
    try:
        return os.read(descriptor, len(CACHEDIR_SIGNATURE)) == CACHEDIR_SIGNATURE
    finally:
        os.close(descriptor)


def full_sync(descriptor):
    """fsync a descriptor and, on macOS, flush the drive's write cache as well."""
    os.fsync(descriptor)
    if FULL_FSYNC is not None:
        fcntl.fcntl(descriptor, FULL_FSYNC)


def sha256_descriptor(descriptor):
    digest = hashlib.sha256()
    count = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, CHUNK)
        if not block:
            return digest.hexdigest(), count
        digest.update(block)
        count += len(block)


class Destination:
    """The external evidence tree; every file in it is published create-only."""

    def __init__(self, root):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = root.resolve(strict=True)
        self.verified = {self.root}
        self.dirty = set()

    def directory(self, parts, create):
        """Return the destination directory for parts, or None when absent."""
        path = self.root
        for part in parts:
            path = path / part
            if path in self.verified:
                continue
            try:
                status = path.lstat()
            except FileNotFoundError:
                if not create:
                    return None
                path.mkdir(mode=0o700)
                self.dirty.add(path.parent)
                self.verified.add(path)
                continue
            if not stat.S_ISDIR(status.st_mode):
                raise Refusal("destination parent is not a directory: "
                              + path.relative_to(self.root).as_posix())
            self.verified.add(path)
        return path

    def existing(self, parts):
        """Open an existing destination file, or return None when it is absent."""
        parent = self.directory(parts[:-1], create=False)
        if parent is None:
            return None
        path = parent / parts[-1]
        try:
            status = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(status.st_mode):
            raise Refusal("destination is not a regular file")
        return os.open(path, READ)

    def present(self, parts):
        """Report whether a destination file exists, refusing anything else."""
        descriptor = self.existing(parts)
        if descriptor is None:
            return False
        os.close(descriptor)
        return True

    def matches(self, parts, digest, length):
        """Compare an existing destination; None means there is none yet."""
        descriptor = self.existing(parts)
        if descriptor is None:
            return None
        try:
            if os.fstat(descriptor).st_size != length:
                return False
            return sha256_descriptor(descriptor) == (digest, length)
        finally:
            os.close(descriptor)

    def staging(self, parts):
        parent = self.directory(parts[:-1], create=True)
        temporary = parent / (".preserve-" + secrets.token_hex(8) + ".partial")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600)
        return temporary, descriptor

    def publish(self, parts, temporary, digest, length):
        """Link a synced staging file into place without replacing anything."""
        final = self.root.joinpath(*parts)
        try:
            os.link(temporary, final)
        except FileExistsError:
            if not self.matches(parts, digest, length):
                raise Refusal("destination differs") from None
        else:
            self.dirty.add(final.parent)
        finally:
            os.unlink(temporary)

    def write(self, parts, data):
        """Publish generated bytes create-only; identical bytes are a no-op."""
        digest = hashlib.sha256(data).hexdigest()
        existing = self.matches(parts, digest, len(data))
        if existing is not None:
            if not existing:
                raise Refusal("destination differs")
            return
        temporary, descriptor = self.staging(parts)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fchmod(output.fileno(), 0o644)
                full_sync(output.fileno())
            self.publish(parts, temporary, digest, len(data))
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise

    def sync(self):
        for path in sorted(self.dirty, key=lambda value: len(value.parts), reverse=True):
            descriptor = os.open(path, DIRECTORY)
            try:
                full_sync(descriptor)
            finally:
                os.close(descriptor)
        self.dirty.clear()


class Preservation:
    def __init__(self, repository_fd, destination, binary_cap, refused):
        self.repository_fd = repository_fd
        self.destination = destination
        self.binary_cap = binary_cap
        self.files = {}
        self.refused = refused

    def refuse(self, path, reason, **origin):
        self.refused.append(dict(path=path, reason=reason, **origin))

    def file(self, parent_fd, relative):
        """Preserve one source file opened beneath parent_fd, once per run."""
        if relative in self.files:
            return self.files[relative]
        parts = relative.split("/")
        try:
            record = self.copy(parent_fd, parts)
        except Refusal as refusal:
            record = refusal
        self.files[relative] = record
        return record

    def copy(self, parent_fd, parts):
        relative = "/".join(parts)
        try:
            status = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode):
                raise Refusal("symlink")
            if not stat.S_ISREG(status.st_mode):
                raise Refusal("not a regular file")
            source = os.open(parts[-1], READ, dir_fd=parent_fd)
        except FileNotFoundError:
            raise Refusal("vanished while preserving") from None
        except OSError as error:
            raise Refusal(unreadable(error)) from None
        try:
            opened = os.fstat(source)
            if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino) \
                    or not stat.S_ISREG(opened.st_mode):
                raise Refusal("changed while preserving")
            try:
                head = os.pread(source, BINARY_PROBE, 0)
            except OSError as error:
                raise Refusal(unreadable(error)) from None
            copied = not (b"\0" in head and opened.st_size > self.binary_cap)
            if copied and not self.destination.present(parts):
                digest, length = self.stage(source, opened, parts)
            else:
                # An earlier copy is kept only while its bytes still match.
                digest, length = self.read(source, opened, None)
                existing = self.destination.matches(parts, digest, length)
                if existing is False:
                    raise Refusal("destination differs")
                if existing is None and copied:
                    raise Refusal("destination changed while preserving")
                copied = existing
        finally:
            os.close(source)
        return {"bytes": length, "sha256": digest, "mtime_ns": opened.st_mtime_ns,
                "disposition": "copied" if copied else "hash-only", "path": relative}

    def read(self, source, opened, output):
        """Hash the whole source, optionally copying it, and detect changes."""
        digest = hashlib.sha256()
        count = 0
        offset = 0
        while True:
            try:
                block = os.pread(source, CHUNK, offset)
            except OSError as error:
                raise Refusal(unreadable(error)) from None
            if not block:
                break
            offset += len(block)
            digest.update(block)
            count += len(block)
            if output is not None:
                output.write(block)
        after = os.fstat(source)
        if count != opened.st_size \
                or (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise Refusal("changed while preserving")
        return digest.hexdigest(), count

    def stage(self, source, opened, parts):
        temporary, descriptor = self.destination.staging(parts)
        try:
            with os.fdopen(descriptor, "wb") as output:
                digest, length = self.read(source, opened, output)
                output.flush()
                os.fchmod(output.fileno(), 0o755 if opened.st_mode & 0o111 else 0o644)
                os.utime(output.fileno(), ns=(opened.st_atime_ns, opened.st_mtime_ns))
                full_sync(output.fileno())
            self.destination.publish(parts, temporary, digest, length)
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise
        return digest, length

    def directory(self, directory_fd, relative, record):
        """Preserve a cited directory recursively, pruning build caches."""
        try:
            if is_cache_directory(directory_fd):
                record["pruned_cache_directories"].append(relative)
                return
            with os.scandir(directory_fd) as entries:
                names = sorted((entry.name, entry.is_symlink(), entry.is_dir(follow_symlinks=False))
                               for entry in entries)
        except OSError as error:
            self.refuse(relative, unreadable(error), via=record["path"])
            return
        for name, symlink, is_directory in names:
            child = relative + "/" + name
            if symlink:
                self.refuse(child, "symlink", via=record["path"])
            elif is_directory:
                try:
                    descriptor = os.open(name, DIRECTORY, dir_fd=directory_fd)
                except FileNotFoundError:
                    self.refuse(child, "vanished while preserving", via=record["path"])
                    continue
                except OSError as error:
                    self.refuse(child, unreadable(error), via=record["path"])
                    continue
                try:
                    self.directory(descriptor, child, record)
                finally:
                    os.close(descriptor)
            else:
                result = self.file(directory_fd, child)
                if isinstance(result, Refusal):
                    self.refuse(child, str(result), via=record["path"])
                else:
                    record["inventory"].append(result)

    def reference(self, path, origin):
        """Preserve one cited path.

        Returns its manifest entry, {} when it was refused, or None when it
        does not exist.  origin holds the citations copied into the entry.
        """
        parts = path.split("/")
        try:
            parent = open_parent(self.repository_fd, parts)
        except Missing:
            return None
        except Refusal as refusal:
            self.refuse(path, str(refusal), **origin)
            return {}
        try:
            try:
                status = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as error:
                self.refuse(path, unreadable(error), **origin)
                return {}
            if stat.S_ISDIR(status.st_mode):
                return self.cited_directory(parent, parts, origin)
            result = self.file(parent, path)
        finally:
            os.close(parent)
        if isinstance(result, Refusal):
            self.refuse(path, str(result), **origin)
            return {}
        return dict(result, kind="file", **origin)

    def cited_directory(self, parent, parts, origin):
        path = "/".join(parts)
        try:
            descriptor = os.open(parts[-1], DIRECTORY, dir_fd=parent)
        except OSError as error:
            self.refuse(path, unreadable(error), **origin)
            return {}
        record = {"path": path, "inventory": [], "pruned_cache_directories": []}
        try:
            self.directory(descriptor, path, record)
        finally:
            os.close(descriptor)
        files = record["inventory"]
        inventory = canonical({"schema": INVENTORY_SCHEMA, "directory": path, "files": files,
                               "pruned_cache_directories": record["pruned_cache_directories"]})
        digest = hashlib.sha256(inventory).hexdigest()
        location = "inventories/" + digest + ".json"
        try:
            self.destination.write(location.split("/"), inventory)
        except Refusal as refusal:
            self.refuse(location, str(refusal), via=path)
        copied = [item for item in files if item["disposition"] == "copied"]
        hashed = [item for item in files if item["disposition"] == "hash-only"]
        return dict(origin, path=path, kind="directory",
                    files=len(files), bytes=sum(item["bytes"] for item in files),
                    copied_files=len(copied), copied_bytes=sum(item["bytes"] for item in copied),
                    hash_only_files=len(hashed), hash_only_bytes=sum(item["bytes"] for item in hashed),
                    pruned_cache_directories=record["pruned_cache_directories"],
                    inventory=location, inventory_sha256=digest)


def preserve(repository, destination_root, manifest_path, binary_cap):
    """Run one preservation pass and return the manifest."""
    repository = Path(repository).resolve(strict=True)
    destination_root = Path(destination_root).resolve()
    manifest_path = Path(manifest_path)
    if destination_root.is_relative_to(repository) or repository.is_relative_to(destination_root):
        raise ValueError("the evidence destination must be outside the repository")
    repository_fd = os.open(repository, DIRECTORY)
    try:
        ledger = []
        inputs = []
        documents, refused = ledger_documents(repository)
        for document in documents:
            try:
                data = read_ledger(repository_fd, document)
                text = data.decode("utf-8")
            except Missing:
                refused.append({"path": document, "reason": "missing ledger document"})
                continue
            except (Refusal, UnicodeDecodeError) as problem:
                refused.append({"path": document, "reason": "ledger document: " + str(problem)})
                continue
            ledger.append((document, text))
            inputs.append({"path": document, "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()})
        cited, unsafe, named = references(ledger, repository.as_posix())
        for token, where in sorted(unsafe.items()):
            refused.append({"path": token, "reason": "unsafe reference", "cited_by": where})
        not_citations = []
        if named:
            not_citations.append({"token": "target/", "reason": "names the build directory itself",
                                  "cited_by": named})

        destination = Destination(destination_root)
        preservation = Preservation(repository_fd, destination, binary_cap, refused)
        entries = []
        missing = []
        for path in sorted(cited):
            cited_by, prose = cited[path]
            origin = {"cited_by": cited_by}
            if prose:
                origin["prose_cited_by"] = prose
            entry = preservation.reference(path, origin)
            if entry:
                entries.append(entry)
            elif entry is None:
                in_code = len(prose) < len(cited_by)
                if not in_code and path in PROSE_PHRASES:
                    not_citations.append({"token": path, "reason": "known prose phrase",
                                          "cited_by": cited_by})
                elif in_code or path_shaped(path):
                    missing.append(dict(path=path, **origin))
                else:
                    preservation.refuse(path, "prose mention is neither an existing path "
                                        "nor a known prose phrase", **origin)
    finally:
        os.close(repository_fd)

    files = [record for record in preservation.files.values() if not isinstance(record, Refusal)]
    copied = [record for record in files if record["disposition"] == "copied"]
    hashed = [record for record in files if record["disposition"] == "hash-only"]
    phrases = sum(1 for item in not_citations if item["token"] != "target/")
    manifest = {
        "schema": SCHEMA,
        "destination": str(destination.root),
        "binary_copy_cap": binary_cap,
        "ledger": inputs,
        "references": entries,
        "missing": missing,
        "refused": sorted(preservation.refused, key=lambda item: (item["path"], item["reason"])),
        "not_citations": not_citations,
        "summary": {
            "references": len(cited) - phrases,
            "file_references": sum(1 for entry in entries if entry["kind"] == "file"),
            "directory_references": sum(1 for entry in entries if entry["kind"] == "directory"),
            "prose_references": sum(1 for entry in entries if "prose_cited_by" in entry),
            "distinct_files": len(files),
            "copied_files": len(copied),
            "copied_bytes": sum(record["bytes"] for record in copied),
            "hash_only_files": len(hashed),
            "hash_only_bytes": sum(record["bytes"] for record in hashed),
            "missing": len(missing),
            "refused": len(preservation.refused),
            "not_citations": len(not_citations),
        },
    }
    data = pretty(manifest)
    location = "manifests/" + hashlib.sha256(data).hexdigest() + ".json"
    try:
        destination.write(location.split("/"), data)
    except Refusal as refusal:
        # The manifest cannot list its own copy's refusal; the exit still fails.
        manifest["summary"]["refused"] += 1
        manifest["refused"].append({"path": location, "reason": str(refusal)})
        data = pretty(manifest)
    destination.sync()
    write_manifest(manifest_path, data)
    return manifest


def write_manifest(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".partial")
    try:
        with temporary.open("xb") as output:
            output.write(data)
            output.flush()
            full_sync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    descriptor = os.open(path.parent, DIRECTORY)
    try:
        full_sync(descriptor)
    finally:
        os.close(descriptor)


def byte_count(value):
    count = int(value)
    if count < 0:
        raise argparse.ArgumentTypeError("the binary copy cap cannot be negative")
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="Kasumi checkout whose ledger and target/ are read")
    parser.add_argument("--destination", type=Path, required=True,
                        help="external evidence directory; cited paths keep their relative path")
    parser.add_argument("--manifest", type=Path,
                        help="manifest output (default: the repository's " + MANIFEST + ")")
    parser.add_argument("--binary-cap", type=byte_count, default=DEFAULT_BINARY_CAP,
                        help="larger binaries are hashed, not copied (default: %(default)s bytes)")
    arguments = parser.parse_args(argv)
    manifest_path = arguments.manifest or arguments.repository / MANIFEST
    try:
        manifest = preserve(arguments.repository, arguments.destination, manifest_path,
                            arguments.binary_cap)
    except ValueError as error:
        parser.error(str(error))
    except OSError as error:
        print("preservation aborted, no manifest written: " + str(error), file=sys.stderr)
        return 1
    summary = manifest["summary"]
    print(f"{summary['references']} references: {summary['file_references']} files, "
          f"{summary['directory_references']} directories ({summary['prose_references']} "
          f"cited in prose), {summary['missing']} missing, {summary['refused']} refused")
    print(f"{summary['copied_files']} files copied ({summary['copied_bytes']} bytes), "
          f"{summary['hash_only_files']} hash-only ({summary['hash_only_bytes']} bytes)")
    for item in manifest["not_citations"]:
        print("not a citation: " + item["token"] + ": " + item["reason"] + " ("
              + str(len(item["cited_by"])) + " mentions)")
    for item in manifest["missing"]:
        print("missing: " + item["path"] + " (cited by " + ", ".join(item["cited_by"]) + ")",
              file=sys.stderr)
    for item in manifest["refused"]:
        print("refused: " + item["path"] + ": " + item["reason"], file=sys.stderr)
    return 1 if manifest["missing"] or manifest["refused"] else 0


if __name__ == "__main__":
    sys.exit(main())
