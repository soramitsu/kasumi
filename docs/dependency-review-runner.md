# Owned dependency upstream runner prerequisite

`scripts/run_dependency_review_owned.py` is a prerequisite for the G11
`dependency-review` acceptance adapter. It does not register that adapter,
perform an advisory scan, dispose of advisories, or close G11.

Run the frozen script with native Python 3.11+ using `-B -S` and the exact
selected Linux ARM64 primary functional evidence and native input declaration:

```sh
/absolute/native/python -B -S /absolute/evidence/source/scripts/run_dependency_review_owned.py \
  --evidence /absolute/evidence \
  --native-inputs /absolute/native-inputs.json \
  --output /absolute/new/dependency-upstream-attempt
```

The output directory must be fresh and outside the frozen evidence. Its
`attempt.json` retains the source commit, source archive/inventory/lockfile
hashes, runner and supporting-script hashes, exact command for every step,
direct native tool paths and hashes, version probes, parsed test counts,
failure counts, logs, and original process-group drain receipts. Failed and
interrupted attempts remain on disk. A successful upstream-only run has status
`passed-locked-upstream-only`; that status is never a release acceptance result.

The fixed roster first runs the official dependency-patch verifier and its
own Python regression suite. It then runs all-target/all-feature tests and
doctests for the reviewed bitmaps, lru, serde_json, and rmcp packages,
plus the whole reviewed OpenRaft workspace. The
workspace command includes its `tests` integration crate and reviewed sibling
packages. OpenRaft's excluded examples and benchmark crates have no reviewed
lockfiles; their manifest paths are retained as `excluded_unlocked` and are
not counted as passing suites. Every Cargo
command is locked, offline, uses the pinned direct Rust 1.97.1 toolchain,
and writes build outputs outside source. The runner requires a Linux ARM64
runtime and verifies that the declared Python, Cargo, and Rustc executables
are ARM64 ELF binaries before dispatch. A missing source inventory entry,
changed reviewed tree, missing suite summary, failed test command, or
incompletely drained child process group rejects the attempt.

The official verifier's stdout must exactly match its manifest-ordered
package lines, with empty stderr. Each Rust test summary must have a matching
Cargo `Running` or `Doc-tests` launch marker; unmatched or missing summaries
reject the run. Process custody covers each child's original process group,
including descendants that inherit it. The receipt does not claim to drain
independently daemonized processes.

The dependency verifier's Python regression fixture uses the process-owned
temporary directory. The runner sets `TMPDIR` inside the evidence output so
those synthetic files cannot alter the frozen source inventory.

Before an acceptance adapter can be registered, a separate source-bound
scanner runner and machine-checked advisory disposition contract must bind
real current findings to exact resolved packages and reviewed fixes. This
upstream runner intentionally contains no advisory field other than `null`.
