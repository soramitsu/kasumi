# Initial combined functional gates

Frozen source `27b0ebcee94d6e73d1674149a6a6fa6ffea4f0ab`, tree
`b0a66e98d0eb7556dd4b39ad823d545cfcfeea8a`, passed 19 tests in the
first four focused gates on Rust 1.97.1/macOS ARM64:

| Gate | Actual tests | Seconds |
| --- | ---: | ---: |
| Verifier worker registration/shutdown | 1 passed | 10.988 |
| Audit workers and uncertain commits | 5 passed | 167.092 |
| Tenant audit worker ownership | 2 passed | 6.115 |
| Physical-memory admission | 11 passed | 0.433 |

The fifth command compiled successfully but selected zero tests because its
filter was the source filename `lease_retention_tests`. The runner rejected the
empty result and stopped. Its process returned zero; this is a test-selection
failure, not an executed lease-retention assertion failure. All five process
groups drained, and source, tree, lock and tracked-file hashes stayed unchanged.
The later 21 gates did not run in this cohort. The overall cohort remains failed.

The already compiled engine's `--list` output confirmed the actual module is
`state::lease_retention::tests`. The prepared continuation selects that module
and explicitly requires all five lease tests by name before proceeding to the
remaining gates. It does not repeat the preceding 19 passing tests. The captured
continuation plan is preparation only; it is not execution evidence.

[evidence.json](evidence.json), raw logs, source inventory, actual compiled
features, executable hashes and process receipts are retained. Actual test and
build-script executables were separately copied and hash-verified before target
reuse. [preservation.json](preservation.json) binds the exact copied run files.
The same combined source also passed all 44 Python checks in 3.781 seconds,
recorded in `combined-python.log`; this validates the merged release tooling.

Each functional gate used one compiler job, one test thread and a 900-second
original timeout. The temporary dispatcher used the frozen source's tested
process-custody helper. Other permitted light host work overlapped this run;
these are correctness checks, without capacity or performance claims. Native
TLS, restore, complete workspace strict lint and production compilation remain
unrun in this initial cohort.
