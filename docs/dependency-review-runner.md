# Owned dependency review prerequisite

`scripts/run_dependency_review_launcher.py` owns the G11 dependency review
runner, its upstream test children, an offline advisory scan and the terminal
process census. The acceptance verifier has an unregistered semantic bridge
that checks the original launcher and its retained native primary. The bridge
does not close G11 or qualify a release.

Run the frozen script with native Python 3.11+ using `-I -B -S` and the exact
selected Linux ARM64 primary functional evidence, native input declaration and
reviewed advisory declaration:

```sh
/absolute/native/python -I -B -S /absolute/evidence/source/scripts/run_dependency_review_launcher.py \
  --evidence /absolute/evidence \
  --native-inputs /absolute/native-inputs.json \
  --advisory-inputs /absolute/advisory-inputs.json \
  --output /absolute/new/dependency-upstream-attempt
```

The launcher and its child reject cached Python bytecode and aliased local
sources before importing their frozen helpers. `-B` stops cache writes but
would otherwise still permit stale or unchecked cache reads.

The output directory must be fresh and outside the frozen evidence. Its
`launcher.json` and `review/attempt.json` retain the selected primary's exact
functional receipt bytes, source commit, source archive/inventory/lockfile
hashes, runner and supporting-script hashes, exact command for every step,
direct native tool paths and hashes, version probes, parsed test counts,
failure counts, advisory findings/dispositions, logs, and original
process-group drain receipts. Failed and interrupted attempts remain on disk.
A successful owned review is still only a prerequisite.

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

The launcher verifier reconstructs the scanner command and parses its original
stdout against the projected frozen lock and retained advisory database. The
unregistered acceptance bridge also binds that runner to the final manifest's
selected primary receipt, exact configuration IDs and scenario logs. Native
Linux ARM64 execution, authenticated current advisory inputs, durable attempt
custody and final-source qualification remain outstanding. The empty adapter
registry prevents a source-only bridge from passing the final release gate.
