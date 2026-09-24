# Bounded allocation-history purge prerequisite

Target-only, uncompiled successor to canonical format4 patch f2103f19 plus gate142 compile correction 6eb30fe4. Those immutable packages remain unchanged. Three files are proposed: transactions.rs, db.rs and page_list_tests.rs. No actual source, Cargo/native process, cap, deadline, row limit, format compatibility path, or physical-maintenance bypass is introduced.

## Why this phase must precede DATA free

A historical DATA_ALLOCATED record can still name a page also queued in DATA_FREED. Previously every eligible allocation record was removed in a single all-history pass before publication. Once this removal is bounded, freeing DATA while an eligible allocation record remains could publish an allocator which marks a still-referenced page free. The successor conservatively holds all historical DATA freeing until the eligible allocation prefix is fully purged. It does not infer safety from disjoint counts or drop the retained rows.

The DATA read horizon is frozen at durable-commit entry with the existing oldest-live-read rule. Current user allocation records are written as before, then the allocation horizon uses the existing oldest surviving savepoint rule (including this transaction's pending persistent-savepoint deletions). Neither threshold is widened later if an external reader/savepoint releases. New savepoints cannot be installed by another writer while the actual writer guard is held.

The two named tables use the same existing canonical400/3202-byte PageList representation. PendingPageList distinguishes their roles and binds each plan to its real namespace; it does not add a second decoder or format version. Selection retains table, root, horizon, last key, exact record/page counts, any unselected row, and any unselected eligible row. A commit removes at most400 allocation page IDs, in complete records, and—only if no eligible allocation row remains—at most400 historical DATA IDs.

When DATA can run, both selected prefixes are validated before either namespace is extracted. When eligible allocation debt blocks DATA, DATA is intentionally not selected or removed. Every extraction rechecks its own root/role/horizon/count and explicitly closes its actual iterator. Allocation purge drops checked record views directly; it has no page-ID vector. The original inline DATA array remains the sole deferred historical page collection. Current system COW frees still enter their one existing Vec and are excluded from the prepared allocator while staying physically allocated until the winning commit.

Ineligible allocation rows remain for surviving savepoints. At the frozen DATA horizon, canonical history guarantees that pages freed by then were allocated before the relevant savepoint allocation threshold; ineligible rows cannot reference the selected free prefix. The existing savepoint restore suffix traversal and current-transaction page tracking are unchanged. Positive abort restores both table roots; error/close failure poisons publication and retains the actual transaction/error custody.

## Maintenance and progress

The internal preview is directly renamed to reclaim_backlog_after_batch; there is no alias. It checks both queues. Ineligible rows count as retained debt, and an allocation-blocked DATA phase reports even a small DATA prefix as unfinished. Reader/savepoint release after preview can therefore cause a conservative extra observation but cannot create false completion. Compact retains its existing two commits per helper and its existing relocation allowance. There is no all-history cleanup loop in production.

For finite existing allocation debt, an admitted empty commit removes a nonempty eligible prefix of at most400 IDs. Repeated admitted maintenance commits eventually finish that phase, then DATA400 batches progress. This is conditional progress, not a claim that the physical reserve already exists or that concurrent producers cannot outpace cleanup. Ordinary foreground writes may still be denied under the unchanged policies.

## Prepared tests (all uncompiled/unrun)

* 817 real physical pages referenced by allocation and DATA history: allocation400/400/17 purges first; DATA remains unchanged until eligible allocation debt is gone; exact DATA400/400/17 progress follows. Every positive batch closes/reopens the database and validates retained allocation IDs against the real debug allocator.
* Malformed selected allocation versus DATA records: both remain untouched when either selected validation fails, actual retained abort/disposal succeeds, and cold reopen has no partial records.
* A real held savepoint disappears between preview and commit; unfinished allocation and DATA rows remain reported and charged.
* A live user reader keeps the original DATA horizon while allocation history is purged; DATA begins only after that reader releases.
* A persistent savepoint and original user payload survive cold reopen with allocation debt, restore correctly, and remain valid through deletion and partial purge; no reference to a freed page is accepted on reopen.
* The original DATA extraction-close failure fixture is preserved. A separate allocation-prefix counterpart uses the same eight real records, actual free-page exhaustion and growth/sync failure, original error identity, retained transaction/database and failed-owner assertions. It persists a savepoint solely to keep allocation rows present before direct extraction; it cannot publish after the injected failure.

## Remaining finite-workspace and physical-reserve work

This replaces the empty-commit all-history allocation purge with a bounded phase. It does not yet supply a typed maintenance permit or protect allocator-internal free-page headroom. A DiskWork enum at resize alone is insufficient: foreground writes can consume already-grown free pages without resizing. The next permit must cover an exact restricted maintenance transaction, a checked finite COW/allocator-state reconstruction requirement, and protected free-page plus extension allowance tied to the actual file owner. Its reservation must survive rollback, close and uncertainty through the retained transaction owner.

Both prefixes still use the source-pinned ExtractIf cursor/removal/survivor/branch-builder scratch described in the parent allocation inventory. Two plans are inline; extraction scratch is sequential, not two retained extraction owners. Allocator-state rebuilding, full allocator copies, user transaction lists, debug structures, savepoint restore and pending-deletion metadata require their existing separate bounds. No payload-size or total-RSS claim is made. Physical capacity and memory/workspace qualification remain release prerequisites.
