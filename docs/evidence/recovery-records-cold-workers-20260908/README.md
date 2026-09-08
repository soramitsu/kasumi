# Recovery records and owned cold-history workers

Intermediate macOS ARM64 evidence for `ee0b1e0`, integrated at `3ccc932`.
Canonical snapshots include mandatory Control recovery state and bounded typed
records; application backups reject Control recovery data. Cold-history chunk
parsing, hashing and encrypted lookups run in owned blocking workers with their
existing deadline, cancellation state and reservations.

Fourteen snapshot tests and ten backup tests passed, followed by strict engine/types
Clippy and fixture-free server binary checks. `evidence.json` binds source, logs
and executables. All logs were hash-checked when copied; the earlier moved-value
compile error is preserved. Initial checks remain distinguished from final source.

The full Control recovery reducer and dispatch remain separate work. The capacity
fixture contains about 30 MiB; this is not 3 GiB/RSS or endurance acceptance.
Shared scratch-disk admission was not installed at this checkpoint.
