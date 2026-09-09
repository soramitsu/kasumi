# First compilation of permanent prefixes and target completion

Source `743754d0b76548be15daf108d9f513d880b50867` reconciles the prepared
staged terminal prefix, distinct target completion table, positive preparation
status, canonical Control completion digest and durable signer dispatch work.
This is separate from the preceding validated SDK/shutdown checkpoint.

Its first all-target/all-feature workspace `cargo check` failed in 141.646
seconds with six stale fixture API errors across three engine test files:

- Literal snapshot capture omitted both terminal owners; decoding omitted the
  scratch owner and accessed fields on the new `Decoded` wrapper incorrectly.
- Recovery codec capture omitted the target-resolution owner.
- The lease-retention fixture's generation omitted `target_resolutions`.

No tests executed. The following formatting gate did not run. Source, tree and
lock hashes remained unchanged, and the owned compiler process group drained.
Successor `8bf5e27` updates only these fixtures to use the exact owned prefixes
and decoded state, preserving their assertions. Its validation is separate.

[evidence.json](evidence.json) retains the exact compiler feature graph,
original deadline and process receipt. [preservation.json](preservation.json)
binds the raw diagnostics, source inventory, dispatcher and plan. This failed
compile is not functional, recovery, capacity or release acceptance evidence.
