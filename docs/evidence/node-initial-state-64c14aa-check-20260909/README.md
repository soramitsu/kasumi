# Atomic initial state and node envelope compilation

Frozen `64c14aa8785f6389a3f95d4f3331e49ad695a731` failed its first
all-target/all-feature store compilation gate. No functional tests or strict
lint gate ran. Rust1.97.1 on macOS ARM64.

The new complete-domain initialization helper calls `Table::range` without
importing `redb::ReadableTable` (`storage_domains.rs:435`, E0599). Both library
and library-test compilation reject the same missing trait. Successor `d5fb231`
adds that one import and requires a fresh run of the original store cohort;
this failed result remains unchanged.

The command ended after21.919seconds with exit101. Exact process group30862
drained with no remaining children, signals or cleanup errors. All tracked
source, tree and lockfile hashes remained unchanged. Raw logs, runner, original
plan and complete source inventory are retained byte-for-byte.

`evidence.json` SHA-256:
`524b7b62a1402a788c66a563b5f7b10babf7f0ddf72bbb92fea34e2e16646cd9`.

This store-only gate does not validate cold HA/authority enrollment, composite
open cancellation ownership, permanent ordinary receipts or final release
readiness. Its original deadlines and required tests are not weakened.
