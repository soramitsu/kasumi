"""Reviewed stable test matrix for every vendored dependency package.

Each Cargo feature, workspace member and test target of a reviewed vendor root
is either run on the pinned stable toolchain or carries an explicit exclusion
class. An excluded suite is recorded in the roster and is never counted as
passed. The roster is derived from the reviewed inventory and the frozen
manifests, so a new upstream feature, member or target fails closed until it
is classified here.

A reviewed package's ``product`` case enables exactly the feature set Cargo
resolves for the Kasumi workspace; ``check_dependency_patches`` compares that
set with locked Cargo metadata.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import tomllib

# Why a suite is recorded instead of run.
EXCLUSION_CLASSES = {
    "nightly-only": "needs unstable compiler features the pinned stable toolchain rejects",
    "external-runtime": "launches a language runtime outside the declared native inputs",
    "external-tool": "needs a Cargo subcommand outside the declared native inputs",
    "external-native-library": "links a native library outside the declared native inputs",
    "external-store": "an alternative storage backend Kasumi neither builds nor ships",
    "unselected": "stable, but neither compiled into Kasumi nor part of a reviewed patch",
}


def _excluded(kind, reason):
    return {"class": kind, "reason": reason}


def _case(identifier, features=(), default_features=True):
    return {"id": identifier, "default_features": default_features, "features": list(features)}


_OPENRAFT_REVIEWED = ("serde", "storage-v2", "single-term-leader", "generic-snapshot-data")
_RMCP_HTTP = ("client", "elicitation", "reqwest", "transport-streamable-http-client-reqwest",
              "transport-streamable-http-server")
_RMCP_UNSELECTED = ("auth", "auth-client-credentials-jwt", "auth-enterprise-managed", "local",
                    "request-state", "skills-fs",
                    "reqwest-tls-no-provider", "transport-child-process", "transport-io",
                    "transport-streamable-http-client-unix-socket", "which-command")

# root -> member directory ("." is the root package) -> reviewed selection.
MATRIX = {
    "vendor/lru-0.16.4": {
        "packages": {".": {
            "name": "lru", "product": ("default", "hashbrown"),
            "cases": (_case("product"),),
            "excluded_features": {"nightly": _excluded(
                "nightly-only", "enables hashbrown/nightly")}}},
    },
    "vendor/serde_json-1.0.151": {
        "packages": {".": {
            "name": "serde_json",
            "product": ("alloc", "arbitrary_precision", "default", "float_roundtrip",
                        "raw_value", "std"),
            "cases": (_case("product", ("alloc", "arbitrary_precision", "float_roundtrip",
                                        "raw_value")),
                      _case("default"),
                      _case("arbitrary-precision", ("arbitrary_precision",)),
                      _case("raw-value", ("raw_value",)),
                      _case("combined", ("arbitrary_precision", "raw_value", "float_roundtrip",
                                         "preserve_order"))),
            "excluded_features": {"unbounded_depth": _excluded(
                "unselected", "no Kasumi crate disables the recursion limit")}}},
    },
    "vendor/rmcp-3.11.0": {
        "packages": {".": {
            "name": "rmcp",
            "product": ("base64", "default", "macros", "schemars", "server", "server-side-http",
                        "tower", "transport-async-rw", "transport-streamable-http-server",
                        "transport-streamable-http-server-session", "transport-worker", "uuid"),
            "cases": (_case("product", ("transport-streamable-http-server",)),
                      _case("upstream-http", _RMCP_HTTP)),
            "excluded_features": {
                "reqwest-native-tls": _excluded(
                    "external-native-library", "links the host TLS library through native-tls"),
                **{name: _excluded("unselected", "outside the patched HTTP server transport")
                   for name in _RMCP_UNSELECTED}},
            "excluded_targets": {
                "test_with_js": _excluded("external-runtime", "launches node"),
                "test_with_python": _excluded("external-runtime", "launches uv")}}},
    },
    "vendor/openraft-0.9.25": {
        "packages": {
            "openraft": {
                "name": "openraft", "product": ("serde", "storage-v2"),
                "cases": (_case("product", ("serde", "storage-v2")),
                          _case("upstream-stable"),
                          _case("reviewed", _OPENRAFT_REVIEWED)),
                "excluded_features": {
                    "bench": _excluded("nightly-only", "enables #![feature(test)]"),
                    "bt": _excluded("nightly-only",
                                    "enables #![feature(error_generic_member_access)]"),
                    # anyhow and serde_json are implicit optional-dependency features.
                    **{name: _excluded("unselected", "no Kasumi crate enables it")
                       for name in ("anyhow", "compat", "loosen-follower-log-revert",
                                    "serde_json", "singlethreaded", "tracing-log")}}},
            "macros": {
                "name": "openraft-macros", "product": (),
                "cases": (_case("product"),),
                "excluded_features": {"singlethreaded": _excluded(
                    "unselected", "no Kasumi crate enables it")},
                "excluded_targets": {
                    name: _excluded("external-tool", "macrotest runs cargo-expand")
                    for name in ("test_expand", "test_since")}},
            "memstore": {
                "name": "openraft-memstore", "product": None,
                "cases": (_case("upstream-stable"),),
                "excluded_features": {"bt": _excluded("nightly-only", "enables openraft/bt")}},
            "tests": {
                "name": "tests", "product": None,
                "cases": (_case("upstream-stable"),),
                "excluded_features": {
                    "bt": _excluded("nightly-only", "enables openraft/bt"),
                    **{name: _excluded("unselected", "no Kasumi crate enables it")
                       for name in ("loosen-follower-log-revert", "single-term-leader")}},
                # The fixture logs under its package directory; the runner moves
                # this one declared directory out of the frozen source afterwards.
                "generated_output": "_log"},
        },
        "excluded_members": {
            "rocksstore": _excluded("external-native-library", "links RocksDB"),
            "sledstore": _excluded("external-store", "sled backend"),
        },
    },
}


def require(value, message):
    if not value:
        raise ValueError(message)


def product_features():
    """Reviewed package name -> exact feature set compiled into Kasumi."""
    result = {}
    for root in MATRIX.values():
        for package in root["packages"].values():
            if package["product"] is not None:
                require(package["name"] not in result, "duplicate reviewed matrix package")
                result[package["name"]] = sorted(package["product"])
    return result


def feature_table(cargo):
    """Declared features plus Cargo's implicit optional-dependency features."""
    table = {name: list(values) for name, values in cargo.get("features", {}).items()}
    require(all(isinstance(value, str) for values in table.values() for value in values),
            "vendored feature table is malformed")
    optional = set()
    tables = [cargo.get("dependencies", {})]
    tables += [target.get("dependencies", {}) for target in cargo.get("target", {}).values()]
    for dependencies in tables:
        optional |= {name for name, spec in dependencies.items()
                     if isinstance(spec, dict) and spec.get("optional") is True}
    named = {value[4:] for values in table.values() for value in values
             if value.startswith("dep:")}
    implicit = optional - named
    require(not implicit & set(table), "optional dependency shadows a declared feature")
    table.update({name: [] for name in implicit})
    return table, implicit


def enabled_features(table, implicit, case):
    pending = list(case["features"])
    if case["default_features"] and "default" in table:
        pending.append("default")
    enabled = set()
    while pending:
        feature = pending.pop()
        require(feature in table, "matrix case names an unknown feature: " + feature)
        if feature in enabled:
            continue
        enabled.add(feature)
        for value in table[feature]:
            if value.startswith("dep:"):
                continue
            dependency, separator, _ = value.partition("/")
            if not separator:
                pending.append(value)
            elif dependency in implicit:
                pending.append(dependency)
    return enabled


def discovered_targets(cargo, files, member):
    """Cargo's test executables, named from the reviewed inventory alone."""
    prefix = "" if member == "." else member + "/"
    local = [PurePosixPath(name[len(prefix):]) for name in files if name.startswith(prefix)]
    require(not any(table in cargo for table in ("bin", "example", "bench")),
            "vendored package declares an unclassified target table")
    require(not any(path.parts[0] in {"examples", "benches"} or path.parts[:2] == ("src", "bin")
                    for path in local), "vendored package has an unclassified automatic target")
    package = cargo["package"]
    tests = {}
    for item in cargo.get("test", []):
        require(isinstance(item.get("name"), str) and item["name"] not in tests,
                "vendored test target is unnamed or duplicated")
        tests[item["name"]] = sorted(item.get("required-features", []))
    if package.get("autotests", True):
        for path in local:
            if path.parts[0] != "tests":
                continue
            if len(path.parts) == 2 and path.suffix == ".rs":
                tests.setdefault(path.stem, [])
            elif len(path.parts) == 3 and path.name == "main.rs":
                tests.setdefault(path.parts[1], [])
    return {"lib": "lib" in cargo or PurePosixPath("src/lib.rs") in local,
            "bins": ([package["name"]] if PurePosixPath("src/main.rs") in local
                     and package.get("autobins", True) else []),
            "tests": tests}


def package_roster(source, root, member, selection, files):
    path = PurePosixPath(root) / ("" if member == "." else member) / "Cargo.toml"
    cargo = tomllib.loads((Path(source) / path).read_text())
    require(cargo.get("package", {}).get("name") == selection["name"],
            "vendored package identity differs from the reviewed matrix: " + selection["name"])
    table, implicit = feature_table(cargo)
    excluded_features = selection.get("excluded_features", {})
    excluded_targets = selection.get("excluded_targets", {})
    require(all(item["class"] in EXCLUSION_CLASSES
                for item in (*excluded_features.values(), *excluded_targets.values())),
            "unknown dependency suite exclusion class")
    targets = discovered_targets(cargo, files, member)
    require(set(excluded_targets) <= set(targets["tests"]),
            "reviewed matrix excludes an absent test target")
    cases = []
    covered = set()
    ids = set()
    for case in selection["cases"]:
        require(case["id"] not in ids, "duplicate dependency matrix case")
        ids.add(case["id"])
        enabled = enabled_features(table, implicit, case)
        require(not enabled & set(excluded_features),
                "matrix case enables an excluded feature: " + selection["name"])
        covered |= enabled
        cases.append({**case, "enabled": sorted(enabled),
                      "tests": sorted(name for name, needed in targets["tests"].items()
                                      if name not in excluded_targets and set(needed) <= enabled)})
    require(covered | set(excluded_features) == set(table)
            and not covered & set(excluded_features),
            "unclassified or misclassified vendored feature: " + selection["name"])
    if selection["product"] is not None:
        product = [case for case in cases if case["id"] == "product"]
        require(len(product) == 1 and product[0]["enabled"] == sorted(selection["product"]),
                "product case differs from the reviewed product features: " + selection["name"])
    run = {name for case in cases for name in case["tests"]}
    excluded = []
    for name, needed in sorted(targets["tests"].items()):
        if name in excluded_targets:
            excluded.append({"name": name, **excluded_targets[name], "blocked_by": []})
        elif name not in run:
            blocked = sorted(set(needed) & set(excluded_features))
            require(blocked, "vendored test target is run by no matrix case: " + name)
            excluded.append({"name": name, "class": excluded_features[blocked[0]]["class"],
                             "reason": "requires an excluded feature", "blocked_by": blocked})
    generated = selection.get("generated_output")
    return {"member": member, "name": selection["name"], "manifest": path.as_posix(),
            "product": None if selection["product"] is None else sorted(selection["product"]),
            "lib": targets["lib"], "bins": targets["bins"], "cases": cases,
            "excluded_features": [{"name": name, **excluded_features[name]}
                                  for name in sorted(excluded_features)],
            "excluded_targets": excluded,
            "generated_output": None if generated is None else
            (PurePosixPath(root) / member / generated).as_posix()}


def roster(source, manifest):
    """Validate the frozen vendor manifests against the reviewed matrix."""
    require(manifest.get("format") == 2 and isinstance(manifest.get("inventories"), list),
            "unsupported reviewed vendor manifest")
    suites = []
    seen = set()
    for item in manifest["inventories"]:
        root = item.get("path")
        require(root in MATRIX and root not in seen, "unknown or duplicate reviewed vendor root")
        seen.add(root)
        selection = MATRIX[root]
        files = item.get("files")
        require(isinstance(files, dict) and {"Cargo.toml", "Cargo.lock"}.issubset(files),
                "reviewed vendor root manifest is absent")
        reviewed = sorted(package["name"] for package in selection["packages"].values()
                          if package["product"] is not None)
        packages = item.get("packages")
        require(isinstance(packages, list)
                and sorted(package.get("name") for package in packages) == reviewed,
                "reviewed package roster differs")
        cargo = tomllib.loads((Path(source) / root / "Cargo.toml").read_text())
        workspace = "workspace" in cargo
        excluded_members = selection.get("excluded_members", {})
        excluded_unlocked = []
        if workspace:
            table = cargo["workspace"]
            members, excluded = table.get("members"), table.get("exclude", [])
            require(isinstance(members, list)
                    and sorted(members) == sorted([*selection["packages"], *excluded_members])
                    and len(members) == len(set(members))
                    and all(member + "/Cargo.toml" in files for member in members),
                    "vendored workspace members differ from the reviewed matrix")
            require(isinstance(excluded, list) and all(
                isinstance(name, str) and name + "/Cargo.toml" in files
                and name + "/Cargo.lock" not in files for name in excluded),
                "vendored workspace excluded manifests need separate lock review")
            manifests = {"Cargo.toml"} | {name + "/Cargo.toml" for name in members + excluded}
            excluded_unlocked = sorted(excluded)
        else:
            require(set(selection["packages"]) == {"."} and not excluded_members,
                    "vendored package suite selection differs")
            manifests = {"Cargo.toml"}
        require({name for name in files if PurePosixPath(name).name == "Cargo.toml"} == manifests,
                "unclassified reviewed vendor package manifest")
        require(all(value["class"] in EXCLUSION_CLASSES for value in excluded_members.values()),
                "unknown dependency suite exclusion class")
        suites.append({
            "root": root, "workspace": workspace,
            "packages": [package_roster(source, root, member, selection["packages"][member], files)
                         for member in sorted(selection["packages"])],
            "excluded_members": [{"member": member, **excluded_members[member]}
                                 for member in sorted(excluded_members)],
            "excluded_unlocked": excluded_unlocked})
    require(seen == set(MATRIX), "reviewed vendor suites are incomplete")
    return sorted(suites, key=lambda suite: suite["root"])


def step_name(suite, package, case):
    name = PurePosixPath(suite["root"]).name.replace(".", "-").replace("_", "-")
    if suite["workspace"]:
        name += "-" + package["name"]
    return name + "-" + case["id"]


def steps(cargo, source, suites, jobs):
    """Every stable matrix command, with the test executables it must launch."""
    result = []
    for suite in suites:
        manifest = str(Path(source) / suite["root"] / "Cargo.toml")
        for package in suite["packages"]:
            for case in package["cases"]:
                base = [cargo, "test", "--manifest-path", manifest]
                if suite["workspace"]:
                    base += ["-p", package["name"]]
                base += ["--locked", "--offline"]
                if not case["default_features"]:
                    base.append("--no-default-features")
                if case["features"]:
                    base += ["--features", ",".join(case["features"])]
                base += ["--no-fail-fast", "-j", str(jobs)]
                selected = (["--lib"] if package["lib"] else []) + \
                    (["--bins"] if package["bins"] else []) + \
                    [argument for name in case["tests"] for argument in ("--test", name)]
                require(selected, "matrix case selects no test executable")
                name = step_name(suite, package, case)
                generated = package["generated_output"] if case["tests"] else None
                result.append({"id": name + "-targets", "kind": "rust", "mode": "targets",
                               "command": base + selected + ["--", "--test-threads=2"],
                               "launches": int(package["lib"]) + len(package["bins"])
                               + len(case["tests"]), "generated_output": generated})
                if package["lib"]:
                    result.append({"id": name + "-doctests", "kind": "rust", "mode": "doc",
                                   "command": base + ["--doc", "--", "--test-threads=2"],
                                   "launches": 1, "generated_output": None})
    return result


def exclusions(suites):
    """Flat record of everything the matrix does not run, for the retained report."""
    result = []
    for suite in suites:
        for member in suite["excluded_members"]:
            result.append({"root": suite["root"], "kind": "member", "name": member["member"],
                           "class": member["class"], "reason": member["reason"]})
        result += [{"root": suite["root"], "kind": "unlocked-manifest", "name": name,
                    "class": "unselected", "reason": "outside the vendored workspace lock"}
                   for name in suite["excluded_unlocked"]]
        for package in suite["packages"]:
            for kind in ("features", "targets"):
                result += [{"root": suite["root"], "kind": kind[:-1],
                            "name": package["name"] + ":" + item["name"],
                            "class": item["class"], "reason": item["reason"]}
                           for item in package["excluded_" + kind]]
    return result
