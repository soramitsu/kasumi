# Obsolete canonical reclaim helper removal

Frozen target-only proposal after gate143 passed all142 vendor library tests; this removal has not been compiled or run. No actual source changes.

Remove only `BtreeMut::force_uncommitted` and `TableTree::open_table_and_flush_table_root`. The latter was the sole caller of the former. Its former production caller belonged to the removed SYSTEM_FREED publication path. The canonical format4 path uses `create_table_and_flush_table_root` for fresh allocator state and does not use these helpers. Whole-workspace Rust text search, excluding immutable target and docs/evidence copies, finds only the two definitions and their internal call. Historical evidence references remain preserved. Neither method is public API. No imports or supported production calls change; no dead-code suppression.

This two-file patch applies to the currently integrated canonical/compile-corrected source and commutes with frozen bounded-allocation-purge78a20485, whose three paths are disjoint. The original f210 and purge artifacts are untouched.

Checks are target rustfmt --check and git apply --check only. Root owns actual application and Cargo validation.
