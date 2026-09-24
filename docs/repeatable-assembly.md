# Repeatable candidate assembly input contract

The assembly runner executes the frozen packager twice in distinct exclusive
output directories. It retains each original process group, stdout, stderr,
executable bytes, deadline, terminal result and drain. A failure stops selection;
its original directory is preserved and cannot be reused. This performs candidate
assembly. It neither recompiles the binaries nor completes release acceptance.

The semantic verifier reconstructs both exact commands, checks native tool
probes, verifies unchanged source and dependency observations, follows each
packager's original metadata child, binds actual imported Python modules and
metadata package roots, and compares the resulting source and native package
archives. Arbitrary copied archives and a report claiming success are insufficient.
The acceptance bridge is implemented as `repeatable_assembly.domain_adapter`;
its registry entry remains disabled pending reviewed native runner validation.
The owned launcher also reconstructs the exact seven nested spawns from their
original receipts: three probes and two packagers belong to the runner, and each
metadata command belongs to its own packager. The registered ledger must match
that ordered graph's parent PID, child process group, executable hash and birth
observation; the terminal census must retain those same identities. A ledger
containing only the expected numerical process groups is insufficient.

## Required declaration

`--native-inputs` accepts one canonical JSON document with these exact fields:

- `schema`: `kasumi-assembly-inputs-v1`.
- `target`: one supported native Linux x86-64, Linux ARM64 or macOS ARM64 triple.
- `tools`: exactly `python`, `cargo` and `rustc`. Each has an absolute canonical
  `path` and its actual lowercase `sha256`. Cargo and rustc must be the direct
  `bin/cargo` and `bin/rustc` of `roots.rust-sysroot`; Rustup proxies are rejected.
- `roots`: exactly `python-runtime`, `rust-sysroot` and `cargo-registry`, each an
  absolute canonical directory. Their regular file bytes are inventoried and
  retained. Symlink or special file trees are unsupported; prepare actual
  directory trees. The Python runtime must include every imported module outside
  the frozen source; `-B -S` disables bytecode writes and site initialization.
- `cargo_home`: the original native Cargo home. `cargo-registry` must be its
  `registry` directory. Home configuration is rejected; frozen source Cargo
  configuration cannot introduce compiler wrappers or environment overrides.
- `host_files`: a nonempty list of `{path, sha256}` declarations for actual native
  shared-library/loader dependencies and required host tools. macOS must include
  the actual selected `ps` executable used for process census.
- `host_inventory`: `{path, sha256}` for the retained operator evidence supporting
  that host dependency inventory, including native OS/build image identity and
  the loaded library/loader source of the declared executables.

All declared tools, runtime/dependency files and host inventory evidence are
retained as content-addressed blobs. The runner also retains exactly the frozen
source, source archive, functional provenance/transcripts and production binaries
consumed by packaging. It does not duplicate unrelated Cargo object files.
Native Cargo 1.97.1 and rustc 1.97.1 version/host probes must pass, their binary
headers must match the target, and Python must be at least 3.11. Metadata dispatch
uses the exact direct Cargo with an explicit rustc, offline mode and an explicit
environment. It does not use a Rustup selector, inherited Python paths, or ambient
Cargo override variables.

The inventory has the same trusted-producer boundary as the release host
attestation. Host dependency completeness is an operator declaration backed by
retained evidence. These checks do not authenticate an adversarial producer or
claim universal filesystem-read tracing. An observed Python import, metadata
package, process-census executable or other required input outside the declared
set fails. A host whose native dependencies cannot be represented by this
contract is unsupported by this runner until an explicit adapter is implemented.

In the candidate workflow, `KASUMI_ASSEMBLY_INPUTS_DIR` identifies the provisioned
host directory containing `inputs.json` and its host inventory evidence. The
Linux job mounts that directory at `/assembly-inputs`; declare actual paths
inside its native build container. The macOS declaration uses actual host paths.
Both native invocations retain their full attempt directory in CI artifacts.
No passing native run or release acceptance manifest is produced by unit tests.
