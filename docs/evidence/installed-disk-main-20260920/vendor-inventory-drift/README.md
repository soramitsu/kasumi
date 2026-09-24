# Vendor inventory drift audit

Read-only audit of master in `/Users/mtakemiya/dev/kasumi`, pinned to run 162 input and the applied payload candidate. Final vendor scan was stable. No release manifest or source was changed, and no Cargo/native command was run.

| Inventory | Recorded files | Current files | Changed recorded files | Unrecorded files | Missing |
| --- | ---: | ---: | ---: | ---: | ---: |
| `vendor/bitmaps-3.2.1` | 11 | 11 | 0 | 0 | 0 |
| `vendor/lru-0.16.4` | 8 | 8 | 0 | 0 | 0 |
| `vendor/serde_json-1.0.151` | 90 | 90 | 0 | 0 | 0 |
| `vendor/rmcp-3.2.0` | 173 | 173 | 0 | 0 | 0 |
| `vendor/redb-4.2.0` | 97 | 109 | 25 | 12 | 0 |
| `vendor/openraft-0.9.25` | 600 | 600 | 0 | 0 | 0 |

Only redb differs. Its 25 changed recorded files comprise 23 source/test files plus the updated `KASUMI_PATCH.md` and `CHANGELOG.md`. All 12 unrecorded files are intentional applied release additions: nine still match exact preserved run 161 source bytes; two existing additions and one new payload module match the applied five-file payload patch and run 162 input. Across changed and added source files, 30 match run 161 and five match the applied payload patch. No unexplained file, missing file, symlink, special input, or executable-mode change was found. The preserved run 162 result now records exit 0, unchanged source and a drained process group; its 211 unit tests include the payload producer/layout/native fixtures. The three CHANGELOG bullets were added afterward and do not alter those Rust inputs. Strict run 163 is outside this inventory audit.

The four root vendor support entries differ only at `vendor/README.md`. That completed disposition edit now distinguishes the original 97-file import from later source and acknowledges the pending inventory refresh. `vendor/serde-json-literal-keys.md`, `vendor/rmcp-terminal-ownership.md`, and `vendor/serde_json-1.0.151-literal-keys.patch` still exactly match hash, byte count and mode. `KASUMI_PATCH.md` is part of the redb package inventory, not a root support entry.

Both original review bindings remain intact: redb provenance still hashes exactly as recorded and describes the original 97-file inventory; OpenRaft checkpoint and source inventory still match their references and all 600 current files. The original redb provenance does not describe the later applied source. Updating only file hashes would also conflict with `verify_review`; release qualification needs an explicit reviewed current inventory/provenance binding. Original evidence should remain immutable.

The current `verify_sources()` would first reject `vendor/redb-4.2.0/CHANGELOG.md` as a changed recorded input, before reaching its global extra-file check. Its normal entry point was not invoked because it calls Cargo metadata; this audit reproduced the read-only file/mode/hash/inventory and review-reference comparisons using Python. Cargo resolver selection was not evaluated.

Changed redb inventory paths:

- `CHANGELOG.md` — three release-note bullets added after run 162.
- `KASUMI_PATCH.md` — disposition documentation update after run 161.
- `src/admission.rs` — exact run 161 source.
- `src/admission/tests.rs` — exact run 161 source.
- `src/db.rs` — exact run 161 source.
- `src/error.rs` — exact run 161 source.
- `src/lib.rs` — exact run 161 source.
- `src/transactions.rs` — exact run 161 source.
- `src/tree_store/btree.rs` — exact run 161 source.
- `src/tree_store/btree_base.rs` — exact run 161 source.
- `src/tree_store/btree_cursor.rs` — exact run 161 source.
- `src/tree_store/btree_mutator.rs` — exact run 161 source.
- `src/tree_store/mod.rs` — exact run 161 source.
- `src/tree_store/page_store/bitmap.rs` — exact run 161 source.
- `src/tree_store/page_store/buddy_allocator.rs` — exact run 161 source.
- `src/tree_store/page_store/cached_file.rs` — exact run 161 source.
- `src/tree_store/page_store/header.rs` — exact run 161 source.
- `src/tree_store/page_store/lru_cache.rs` — exact run 161 source.
- `src/tree_store/page_store/mod.rs` — applied payload patch; run 162 input.
- `src/tree_store/page_store/page_manager.rs` — applied payload patch; run 162 input.
- `src/tree_store/page_store/region.rs` — exact run 161 source.
- `src/tree_store/page_store/savepoint.rs` — exact run 161 source.
- `src/tree_store/table_tree.rs` — exact run 161 source.
- `tests/canonical_format.rs` — exact run 161 source.
- `tests/integration_tests.rs` — exact run 161 source.

Unrecorded redb paths:

- `src/allocator_state_key_tests.rs` — applied payload patch; run 162 input.
- `src/cache_admission_tests.rs` — exact run 161 source.
- `src/page_list_tests.rs` — exact run 161 source.
- `src/retained_database.rs` — exact run 161 source.
- `src/retained_database_tests.rs` — exact run 161 source.
- `src/retained_opening.rs` — exact run 161 source.
- `src/retained_opening_tests.rs` — exact run 161 source.
- `src/retained_transaction.rs` — exact run 161 source.
- `src/retained_transaction_tests.rs` — exact run 161 source.
- `src/tree_store/allocator_state.rs` — applied payload patch; run 162 input.
- `src/tree_store/page_store/allocator_snapshot.rs` — applied payload patch; run 162 input.
- `src/tree_store/page_store/checked_backend_tests.rs` — exact run 161 source.

`report.json` records every expected and observed hash, size, permission and classification, plus review/input hashes. The initial scan and earlier reports are preserved separately. The earliest report preceded payload application and contains an outdated note about README wording; the before-changelog report predates the final release-note bullets. This final report supersedes those preliminary notes.
