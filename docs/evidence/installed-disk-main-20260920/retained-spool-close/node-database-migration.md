# Mandatory NodeDatabase migration: concrete next dependencies

Design only. All 12 production commits must adopt one required boundary together; no old consuming fallback or user-selected mode is allowed. The borrowed spool prerequisite is packaged independently because switching its backend before NodeDatabase would make current Complete reporting false.

## Exact caller inventory

| File | Production commits | Required behavior retained |
| --- | ---: | --- |
| `lib.rs` | 333, 383, 953 | Initial CATALOG/RECORDS creation; wrapped-key catalog; encrypted batch and post-commit access check |
| `scratch_table.rs` | 126, 146, 165 | Staged table creation; duplicate-rejecting point insert; replacing accumulator point set |
| `read_view.rs` | 37 | Atomic namespace replacement and metadata publication |
| `live_trust.rs` | 121 | Atomic signer-trust/key-use/receipt mutation |
| `storage_domains.rs` | 200, 358 | Application/custody binding and atomic paired-domain replacement |
| `single_catalog.rs` | 350 | Fresh-only single catalog publication |
| `storage_domains/catalog_initialization.rs` | 341 | Fresh-only paired catalogs under the same transaction |

The two table-creation transactions currently run before NodeDatabase exists. The aggregate therefore must be admitted and registered before constructing/opening redb and before those writes. Installing a wrapper only after initialization cannot satisfy that requirement. All pre-commit `?`, `ensure!` and panic exits must pass through an explicitly observed abort; only changing `.commit()` misses ordinary failure paths.

## Serial writer shape

A private synchronous `with_write(typed_plan, callback)` boundary can prevent raw WriteTransaction escape. Publish each accepted queued writer's exact strong registration and resident charge before waiting for redb's writer slot. Keep the shared NodeDatabase owner reachable through the core-owned registry independently of the invoking stack or worker JoinHandle. The active callback borrows an already-installed RetainedWriteTransaction; the aggregate catches its original failure/panic and records commit or abort exactly once. No state/census lock may span a blocking writer wait. A separate nonblocking close observation (`try_lock` of active resource state) reports Retained promptly while writers are queued or running.

Only one actual write transaction can be active or uncertain per Database because redb serializes writers. An uncertain transaction permanently fences further writes to that database, so it does not require an unbounded sequence of uncertain transaction objects. This does not eliminate queued-writer registrations: each queued owner needs its own admitted strong cell and original operation outcome. Successful/settled error reports can outlive actual transaction work as separately charged diagnostic owners.

A concrete store-defined `StorageCensus` can be owned as a mandatory MemoryCore field and exposed through a required NodeDiskMemoryAdmission trait method; this avoids a store-to-engine dependency. Fixed capacity can derive from validated max_reservations if every database/queued cell necessarily owns a distinct live reservation. That relation must be enforced in the constructor, and the fixed slots must be included in MemoryCore and test-provider initial bookkeeping before allocation. Do not borrow max_inflight_operations alone: embedded synchronous and maintenance storage callers do not all hold an engine operation permit. This is a proposed interface, not implemented or funded code.

Remove a census generation only after actual transaction/database/output transfer or positive cleanup is established. Credit cannot return while its Arc/Box allocation survives. Use the reviewed concrete into_inner/inner-scope retirement patterns and keep external callbacks/wakes outside census/resource locks; ordinary raw Arc Drop field order is insufficient. Closing one NodeDatabase must not globally stop other tenants sharing the MemoryCore.

## Concrete missing positive-settlement disposal API

Current RetainedWriteTransaction contains a completed WriteTransaction and its original terminal/rollback cells. It exposes borrowed observations only. That WriteTransaction still retains its writer guard until actual Drop. A settled capacity refusal with successful rollback must preserve original diagnostics, but keeping the wrapper intact blocks all subsequent writers; dropping it releases the writer and destroys those diagnostics. The vendor boundary needs a non-consuming positive-settlement disposal/into-outcomes operation: reject Retained, retire the exact completed transaction, leave/transfer the original diagnostic objects intact, and only then release writer/cell credit. It cannot replay a terminal operation. The parent owns this next prerequisite.

## Memory and typed drain blockers

NodeDiskMemoryAdmission currently provides only reserve_installed(bytes); it has no actual database/writer census. WorkFence is a growable active-work map with cancellation and removal, not original outcome custody. Startup/snapshot foundations require a concrete backing proof and cannot accept an arbitrary existing DrainReport as a fixed diagnostic allowance. Existing DrainReport allocates Vec/BTreeMap/Arc/anyhow objects during close; it cannot be relabeled a bounded report.

The redb agent's current restricted staging derivation covers one fixed table, one writer, no external readers/savepoints/escaping guards and fixed custody/terminal batch profiles. Ordinary NodeDatabase supports two tables, many tenants, concurrent pinned read roots, replacements that stream a whole namespace and internal callbacks. Its general memory proof cannot borrow that restricted profile. The existing 64MiB/65,536-operation batch bound applies to write_batch, not all streamed replacement work; the 8MiB scratch cache is a soft payload target. No total transaction/cache/diagnostic coefficient is established by current source. The derivation is in `../redb-staging-workspace/workspace-derivation.md`.

The direct adopter must have typed per-operation plans, fixed body/terminal/rollback/close outcome cells, an original-error transport that preserves identity, and real resident ownership before effects. Opaque panic backing remains Retained unless its originating allocation was admitted. The retained spool boundary intentionally transfers one original cause to the already-registered aggregate rather than copying it into two layers. Existing point durability, logical quotas, deadlines, and full replacement atomicity stay unchanged.
