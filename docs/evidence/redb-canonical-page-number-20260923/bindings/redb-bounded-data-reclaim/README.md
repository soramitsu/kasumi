# Canonical format4 and bounded DATA reclamation candidate

This is a target-only, uncompiled vendor proposal on the current master checkout. It has not been applied. No Cargo, native test, deadline, byte quota, row quota, cache payload policy, relocation allowance, or process memory policy was changed. Target-only rustfmt and `git apply --check` passed. `manifest.json` binds all 14 actual-source baselines and proposed files to `reclaim.patch`.

The first-release contract permits only the new canonical representation. There is no old-format reader, migration, alias, or alternate maintenance format. Format3 evidence remains historical evidence; it does not qualify format4.

## Direct format replacement

The only accepted commit-slot and savepoint version is 4. Version 0, 1, 2, 3, 5 and 255 are explicit rejection cases. The old `UpgradeRequired` error is replaced directly by `UnsupportedFileFormat`. The sole writer uses zero region-header pages; nonzero region-header layouts are rejected. Existing mandatory two-phase header validation remains.

The `system_pages_unreachable` reserved system-table name is forbidden. The implementation checks that raw name without instantiating the obsolete key/value table decoder. The SYSTEM_FREED definition, PageList kind, writer, pagination builder, repair traversal and debug traversal are removed. Ordinary canonical DATA_ALLOCATED and DATA_FREED records retain their original 400-entry, 3202-byte buffer shape; unused writer padding is not given an alternative interpretation. The obsolete 200-entry/1602-byte shape has no decoder.

Raw-name rejection precedes construction repair, allocator loading/rebuilding, new write transactions, and publication. Read-only construction rejects the name before its unclean-file refusal. Low-level opening and integrity reload previously normalized the header before higher-level namespace validation; that early write is removed. Normalization remains in memory until validated repair or `begin_writable` publishes it. Corrupt-file tests assert byte-for-byte unchanged storage and zero repair callbacks on rejection. Savepoints bind only the user root; their canonical record version changes directly too.

## Fixed historical work and retained ownership

Each commit selects at most 400 historical DATA page IDs, using the original DATA record capacity as the batch size. Its transaction owns one inline `[PageNumber; 400]` plus a length. Native `size_of::<PageNumber>()`, rather than its eight-byte encoding, governs this resident storage. This proposal introduces no second deferred vector and does not claim that the inline array accounts for the rest of the transaction.

Selection walks ordered records once. Every selected record has checked exact shape and a nonzero count before any extraction. Consequently there are at most 400 selected records plus one lookahead. A record larger than the remaining batch is retained whole. Ineligible records are not decoded; the first is sufficient to report retained debt. A malformed eligible lookahead fails before removal. Malformed later rows remain untouched and are checked when a subsequent bounded selection reaches them.

The plan retains the original root, reader horizon, final selected key, record count and page count. Extraction rechecks the root and horizon and removes only through that key. The actual system lock and writer guard serialize the transition. ExtractIf is explicitly closed on success and error. Original close/iteration errors propagate and poison the transaction; partial extraction cannot be committed after ignored cleanup. On a positive abort the original rows return and the inline IDs clear. On uncertain terminal failure the actual transaction still owns its original state under the existing retained-terminal protocol.

Selected historical DATA pages stay allocated in the live allocator until the winning header completes. An allocator snapshot excludes them only in its prepared copy. Current system frees remain in their one existing transaction-owned Vec, are borrowed into the same prepared allocator exclusion, and are physically freed after the successful winning commit. No SYSTEM history is created. Allocator growth that has already been admitted stays charged through failure and rollback; this patch never relabels capacity or physical I/O errors.

## Why current system pages can be excluded directly

ReadTransaction captures the user root only. Savepoints retain the user root and transaction horizon, not a system root. System readers are either under the actual write transaction guard or are private construction/repair/integrity operations; integrity requires exclusive memory ownership and drained ephemeral savepoints. Read-only file opening has the existing separate backend lock contract. This proposal does not strengthen unsupported-platform/file-backend locking.

`create_table_and_flush_table_root` reserves the master-tree entry before its callback and guarantees no page allocation/free after the callback. `reserve_allocator_state` runs before the borrowed current-system list is observed. Snapshot insertion uses reserved values; remaining checksum finalization and master-root insertion do not allocate/free physical pages. Their heap work is still part of the separately open workspace estimate. Retry cleanup drops removed guards before the next prepared snapshot.

The live allocator still owns selected DATA and current system pages while `mem.commit` computes shrinking, writes the preparation header, synchronizes, writes the winning header and synchronizes again. The prepared allocator becomes authoritative only for the winning generation. Error/panic handling retains existing allocator invalidation and owner fencing. Recovery marks the winning roots and retained DATA lists, or loads that generation's prepared allocator; it does not reinterpret SYSTEM history. The former system path's recovery and header fault evidence must be rerun against this successor, not inferred from the old result.

## Bounded maintenance completion

Each maintenance helper invocation still performs exactly two immediate empty commits. Compact still invokes the helper before and after its one bounded relocation batch. No all-history commit loop is added, and `max_relocation_bytes` is unchanged.

Before each empty commit, a bounded preview reports any unselected DATA row, including rows beyond the current reader horizon. This is deliberate: a reader can disappear after preview, making more rows eligible and leaving a partial batch. Reporting only eligible debt could falsely return completion. Because the writer guard holds the DATA root stable and empty commits add no DATA rows, a preview with no unselected row cannot hide later retained debt. A reader release may conservatively cause one extra compaction observation. True indicates relocation or observed debt; false cannot hide unselected DATA rows at the batch observation.

## Explicitly open requirements

This candidate bounds historical DATA collection and fixes its format/visibility contract. It does **not** complete G02 or the full scratch batching prerequisite.

* There is no reserved physical maintenance capability yet. Store NodeFile's current StorageAdmission growth uses foreground admission, and the vendor trait cannot request a maintenance work class. A COW cleanup at the physical cap may therefore receive the original capacity denial before reclaim can free space. The next coherent slice must fund a maintenance reserve through the same physical owner before use and prove a finite per-batch COW requirement. Increasing the cap, bypassing admission, or adding a hidden all-history loop is not a substitute.
* Current DATA_ALLOCATED purge and savepoint-restore bookkeeping can still traverse historical records. The current-system-frees Vec, allocator snapshot copies, dirty/checksum metadata, guards and page/cache payload remain separate workspace owners requiring bounds. Fixed historical DATA storage alone is not a total transaction-memory or RSS proof.
* The existing consuming compact API remains consuming. Tests for it are explicitly separate from actual retained transaction commit/abort/disposal tests. Production task/transaction owner adoption is not implied by this patch.
* PageList shape validation is not semantic validation of duplicate/page-range IDs. That pre-existing deeper corruption validation remains separate; selected IDs retain the same trusted canonical-writer assumption.

## Prepared tests and required execution

No tests below have been compiled or run in this package.

* Exact canonical DATA shape and fixed inline storage boundaries, with allocation counter assertions.
* Malformed first/second selected DATA record: no removal, no deferred IDs, poisoned commit, positive retained abort/disposal and cold reopen.
* Original early extraction-close failure scenario, still eight real pending page records and actual exhausted free pages/growth/sync failure. Its obsolete SYSTEM table is replaced by canonical DATA rows. The geometry changes from 1602 to 3202 bytes per record; the original failure file is preserved, and this successor must independently prove the close still reaches actual growth. Original I/O identity and actual retained transaction/database custody assertions remain.
* 817 historical IDs across 400/400/17 records: bounded removal, exact unselected rows and clean reopen between batches.
* Selected pages remain physically allocated before the winning commit; abort restores the original rows.
* Reader-horizon advance between real maintenance preview and commit cannot hide the remaining 17 IDs.
* A pinned user reader sees its original payload through sixteen immediate system commits; DATA history stays pinned, then drains after reader release and reopens read-only with the new value.
* Five full DATA records with a one-byte relocation allowance: compact reports actual retained debt after its four bounded maintenance commits, then a later call/reopen finishes without chasing a new SYSTEM tail.
* Obsolete table and unsupported slot/savepoint version cases, including unchanged rejected-file bytes and no repair callback.

Required coordinated qualification includes the complete original vendor library, admission fault matrix (both header writes and sync/resize failures), cache/retained-terminal tests, integrity/repair/savepoint tests, full public basics/integration/crash cases, and strict lint. Original fault coverage is not removed or claimed to have passed from static review.
