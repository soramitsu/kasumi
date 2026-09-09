# Combined typed snapshot functional evidence and guard rejection

Frozen source `b17eaf5bd558f6b629d8cbf68efdbc2dd4aa090e`, tree
`554803b4a52ee5e17469c54e56bd15a066a00e2e`, ran seven gates on Rust1.97.1 /
macOS ARM64. Six gates were accepted: atomic immutable-table publication2,
typed snapshot codec13, actual public512-terminal preparation1, production
backup verification1, production restore-workspace handoff1, and positive
recovery receiver/coordinator phases3. These are21 accepted tests. Timings,
exact commands, required names, compiled features and preserved executable
hashes are in `evidence.json`.

The seventh gate's two worker-failure tests also actually passed (exit0,
2 passed/0 failed/0 ignored), but the runner rejected its required-name check.
Expected panic stderr split `test <name> ...` and `ok` across lines under
`--nocapture`, so the exact single-line matcher failed. The raw log preserves
the injected panic and successful test summary; the original cohort remains
FAILED. This is an evidence-driver formatting rejection, not a passing full
matrix or an ignored database failure. The other19 gates did not execute.
The continuation uses normal captured libtest output, preserving failing test
diagnostics while avoiding this expected-panic interleaving. These23 actually
passed tests will not be rerun merely to repair the guard report.

All seven owned process groups drained and all source/tree/lock hashes remained
unchanged. Raw diagnostics, plan, source inventory and dispatcher are retained
byte-for-byte. Actual executables remain at the hashed preserved paths in the
original output; `preservation.json` binds the committed records.

The512-row test uses an80MiB fixture governor without production maintenance
lanes. The distinct384/512MiB backup gates exercise production reserves.
These are not3GiB or hardRSS measurements. Independent source review still found
external-history JSON structural admission and established-quorum coordinator
availability/deadline admission gaps; those fixes are separate successors.
Final release, complete recovery and endurance acceptance remain open.
