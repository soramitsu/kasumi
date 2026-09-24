"""Verify an offline advisory Git checkout using owned native Git outputs.

This module parses retained command outputs independently. Git handles loose and
packed objects; the verifier hashes commit bytes and every scanner-visible blob.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from release_gate import inventory

TIMEOUT = 14400
OBJECT_FORMAT = "git-object-format"
HEAD = "git-head-commit"
COMMIT = "git-commit-object"
TREE = "git-commit-tree"


def require(value, message):
    if not value:
        raise ValueError(message)


def prepare(root):
    root = Path(root).resolve(strict=True)
    git = root / ".git"
    require(git.is_dir() and not git.is_symlink(), "advisory database lacks a real Git directory")
    require(not (git / "objects/info/alternates").exists() and
            not (git / "objects/info/alternates").is_symlink(),
            "advisory Git object alternates are forbidden")
    require(not list((git / "objects/pack").glob("*.promisor")),
            "advisory partial-clone objects are forbidden")
    config = (git / "config").read_text() if (git / "config").is_file() else ""
    require(not re.search(r"(?i)(?:promisor|partialclone|alternates)", config),
            "advisory partial-clone configuration is forbidden")
    return root


def command(git, root, operation, argument=None):
    root = Path(root)
    require(root.is_absolute(), "advisory Git path is not absolute")
    prefix = [str(git), "--git-dir=" + str(root / ".git"), "--work-tree=" + str(root)]
    if operation == OBJECT_FORMAT:
        return prefix + ["rev-parse", "--show-object-format"]
    if operation == HEAD:
        return prefix + ["rev-parse", "--verify", "HEAD^{commit}"]
    require(isinstance(argument, str) and re.fullmatch(r"[0-9a-f]{40}", argument),
            "advisory Git object ID differs")
    if operation == COMMIT:
        return prefix + ["cat-file", "-p", argument]
    if operation == TREE:
        return prefix + ["ls-tree", "-r", "-z", "--full-tree", argument]
    raise ValueError("unknown advisory Git operation")


def environment(base):
    result = dict(base)
    result.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                  GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
                  GIT_OPTIONAL_LOCKS="0")
    require(not any(name.startswith("GIT_") for name in base),
            "advisory Git inherited an override")
    return result


def commit_tree(payload, declared):
    require(hashlib.sha1(b"commit " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
            == declared, "advisory Git commit object digest differs")
    lines = payload.split(b"\n\n", 1)[0].splitlines()
    trees = [line[5:] for line in lines if line.startswith(b"tree ")]
    require(len(trees) == 1 and re.fullmatch(rb"[0-9a-f]{40}", trees[0]),
            "advisory Git commit tree differs")
    return trees[0].decode("ascii")


def verify_tree(root, output):
    require(output.endswith(b"\0"), "advisory Git tree output is truncated")
    entries = {}
    for row in output[:-1].split(b"\0"):
        head, separator, encoded = row.partition(b"\t")
        match = re.fullmatch(rb"(100644|100755) blob ([0-9a-f]{40})", head)
        require(separator and match, "advisory Git tree has an unsupported entry")
        try:
            relative = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("advisory Git tree path is not UTF-8") from error
        parts = Path(relative).parts
        require(relative and not Path(relative).is_absolute() and
                all(part not in {".", "..", ".git"} for part in parts) and
                relative not in entries and relative == Path(relative).as_posix(),
                "advisory Git tree path differs")
        entries[relative] = (match[1] == b"100755", match[2].decode("ascii"))
    observed = {name: item for name, item in inventory(root).items()
                if name != ".git" and not name.startswith(".git/")}
    require(entries and set(entries) == set(observed),
            "advisory worktree differs from committed Git tree")
    for relative, (executable, oid) in entries.items():
        payload = (Path(root) / relative).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        require(blob == oid and observed[relative]["executable"] == executable,
                "advisory worktree bytes or mode differ from Git blob")
    return {"files": len(entries)}


def verify_outputs(root, declared, outputs):
    """Re-evaluate retained bytes; outputs map operation name to raw stdout."""
    prepare(root)
    require(set(outputs) == {OBJECT_FORMAT, HEAD, COMMIT, TREE},
            "advisory Git command roster differs")
    require(outputs[OBJECT_FORMAT] == b"sha1\n", "advisory Git object format is not SHA-1")
    require(re.fullmatch(r"[0-9a-f]{40}", declared) and
            outputs[HEAD] == (declared + "\n").encode(),
            "advisory Git HEAD differs from declared commit")
    tree = commit_tree(outputs[COMMIT], declared)
    files = verify_tree(root, outputs[TREE])
    return {"commit": declared, "tree": tree, **files}
