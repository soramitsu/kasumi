# Repeatable assembly successor proposal

Only `/Users/mtakemiya/dev/kasumi`, on `master`, was used. All edits and test
artifacts are under this target directory. No actual source, Git index, branch,
worktree, native Cargo invocation, release gate, or archived evidence was changed.

`assembly.patch` contains nine files. `manifest.json` gives the actual dirty
baseline hashes, proposed hashes, exact test results, and limitations.
`git apply --check` and Python AST parsing passed. The final Python epoch ran 44
tests, including twelve new assembly/input tests. Every actual test subprocess
terminated, the original process group drained, and the 149 imported file hashes
were unchanged; there were no new imports. All subprocesses used workspace
`target/tmp`. Earlier tested proposal revisions and their 42-test results remain
under `revisions/` and `python-tests-01`/`python-tests-02`.

The implementation provides:

- Two actual independent packager invocations with fixed commands and exclusive
  output directories, original stdout/stderr/executable retention, and bounded
  ownership/drain. A failed second invocation preserves the first and the failure.
- Mandatory direct native Cargo/rustc/Python declarations, native version/host
  probes and binary-header checks. Metadata no longer dispatches through Rustup.
- Retained actual consumed frozen source/provenance/gate/binary inputs, declared
  runtime and registry files, host dependency inventory evidence, and actual
  Python-import/metadata-package binding. Source/dependency changes reject.
- Read-only semantic archive, source, executable, metadata-child and pair checks,
  plus an acceptance-domain bridge with exact seven-child custody and actual
  scenario/output relationships.
- Direct migration of both CI packaging callers and documentation to the new
  mandatory declaration. The original repeated shell commands are replaced by
  the owned runner; its full directory is retained as CI evidence.

`DOMAIN_ADAPTERS` deliberately remains empty. The new domain adapter must not be
registered on the strength of these unit tests. No native Cargo probe or complete
frozen candidate assembly was permitted in this subtask. The full semantic
adapter's native acceptance-positive path, the workflow, actual Cargo-home
operational-state behavior and platform loader/library declarations remain
unvalidated. Host dependency completeness explicitly relies on operator inventory
evidence; it is not presented as complete system-call tracing or authentication
of a dishonest evidence producer.

The twelve new tests exercise actual synthetic child process custody, original
failed result retention, no overwrite/retry, timeout with drain, substituted
command/cwd/executable/deadline/output/drain, copied-archive rejection, unbound
Python imports/package roots, exact environment selection, native version/host
parsing, and declaration identity/wrapper/host/configuration rejection. Synthetic
executables and version text are unit fixtures, never native release evidence.
