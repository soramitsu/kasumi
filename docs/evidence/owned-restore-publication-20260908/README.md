# Owned blocking restore publication

At `f401a09`, four restore-filter tests, one deadline queue test, one real
three-node TLS lifecycle case, two stopped local recovery cases, strict
workspace Clippy, fixture-free server checks and formatting pass. A new actual
blocked-redb-write fixture verifies that the Tokio timer stays responsive and
cancellation retains the target and memory reservation until disk work drains.
The worker owns the original bootstrap lock, source audit, target store, finite
work registration and reservation; stores/state drop before lock release on error.

This is focused macOS ARM64 evidence. It does not establish a real 3 GiB tenant,
full source-unavailable coordinator workflow or final-source endurance gates.
The lockfile changes only the engine dev-dependency edge to already-locked redb.
