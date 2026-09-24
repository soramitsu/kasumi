# Actual-master integration and authority-route evidence

The first combined native run on the mandated `master` checkout is a **failed,
invalidated trial**, not release qualification. Formatting, all-target/all-feature
workspace check and strict Clippy, no-run test compilation, and 46 exact test
binary inventories completed. Cargo's unfiltered workspace run stopped after
the authority library reported 62 passes and one failure in
`permanent_target_stop_defeats_missing_and_prepared_generations_then_reopens_after_full_drain`.
The other 45 test targets and doctests did not execute. An independent final
inventory found `crates/kasumi-engine/src/service.rs` changed during the run by
two `Box::pin` wrappers; the source drift also invalidates the earlier passing
phases as qualification of one frozen checkout. The original log, runner,
terminal receipt and exact two-hunk source change are retained here.

The official dependency checker and its 18 Python regressions passed in a
separate source-bound supplement against the final observed checkout. That
result does not repair the failed native run. The engine's new `Box::pin`
allocations still require memory-admission and resource-bound review.

The authority test's final activation used a cached service after its earlier
administrative helper followed a leader move. The exact one-file correction
reuses that helper for the same final command and still requires a `Rejected`
receipt. It was applied to `master` with verified before/after hashes. A fresh
source-bound run compiled the authority test binary, inventoried all 63 names,
and passed the exact original failing case: one pass, zero failures, 62 other
names filtered. All inputs and that binary were unchanged, and all process
groups drained without timeout or cleanup signal. This focused result does not
qualify the entire authority or workspace cohort.

`manifest.json` hashes every copied evidence file and records its original
repository-relative source. The original target-run directories remain intact;
their detailed phase inventories and binary records are referenced by the
terminal receipts. All fourteen release goals remain open.
