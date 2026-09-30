# Disk-backed storage with full residency below the memory bound

Status: **active; implementation and qualification open**. Established
2026-09-30 from the user's storage proposal and clarification. These goals
extend G02 and its dependent query, snapshot and resource-admission work.

## Central requirement

Kasumi should use a large, configurable memory cache. **Keep the entire working
database in memory whenever it fits within the configured bounds.** This
includes documents, account data, query indexes and the key directory, with
their actual resident overhead. Do not evict valid data merely because it is
old or infrequently accessed while the complete resident set fits. Disk-backed
serving begins when the resident set exceeds the bound; frequency and recency
then determine what remains hot. This is a capacity-driven transition, not a
small demand cache that routinely leaves fitting data cold.

Disk remains authoritative in both modes. Writes must persist atomically
before publishing their new versions or acknowledging success. Keeping all
reads in memory below the bound does not defer durable writes until eviction.
Eviction must never be the event that makes a write durable.

Reopen necessarily reads storage. Bound startup work and preload the complete
working set if it fits; for larger databases, warm useful data within the same
budget. Define and expose warm-up completion so full-residency verification
does not hide persistent demand misses behind an indefinite warm-up period.
When a larger database shrinks enough to fit, restore full residency with
bounded background work. Security expiry, deletion and invalidation still
apply in either mode.

This direction supersedes the full-resident-only assumption, RAM-limited
database capacity and permanently resident key index in
[binding decision 3 of 2026-09-26](first-release-goals.md#binding-decisions-2026-09-26).
Kasumi still owns `kasumi-kv`; redb stays removed. Retain atomic durable batches,
encryption, bounded incremental reclamation, resource ownership and close
custody. Specify how disk index pages and checkpoints compose with the
segmented-log direction before implementing the physical change. Preserve the
first-release rule: replace obsolete APIs/formats directly and reject old
formats, with no migration, fallback reader or dual writer.

## Goals and completion criteria

All implementation goals below are open. Recording this plan does not qualify
the current source or close any existing release gate.

| Goal | Deliverable | Evidence required to close |
| --- | --- | --- |
| C01 — Residency and accounting contract | Define the large cache setting, validated default, ownership hierarchy, full-residency/warm-up states, byte accounting and capacity behavior. Inventory all data-sized allocations. | Configuration boundary tests; a documented budget equation covering documents, indexes, key directory, retained versions, cache metadata, allocator overhead, transient work and maintenance; no hidden unbounded term proportional to database size. |
| C02 — Durable native lookup and index foundation | Give `kasumi-kv` a disk-backed ordered key directory and snapshot/version lookup with a bounded page cache; compose it with durable log publication, checkpoints and incremental reclamation. | Atomic multi-table and multi-key tests, crash/restart and injected I/O failures, corruption rejection, snapshot retention through compaction, and reopen of a dataset larger than the memory budget without rebuilding a resident map of every key. |
| C03 — Full-resident cache with pressure eviction | Keep all eligible documents and pages while they fit. Under pressure use frequency and recency, resist one-pass scan pollution, and support bounded collection reservations within the same total limit. | Zero document/index storage reads after warm-up for a fitting workload; deterministic budget tests across inserts, replacements, deletes, concurrent loads and budget changes; scan/hot-set tests and oversized-entry handling without exceeding admission. |
| C04 — Versioned document and query access | Replace direct all-document and resident-index assumptions with snapshot-aware access. Persist secondary, unique and text indexes with cached pages. | Identical point/range/filter/order/projection/aggregate/search/pagination results below and above the bound, including text ranking and analyzers; preserved cancellation, atomic document/index publication, schema, uniqueness, CAS, batches, receipts, append-only and retention behavior. |
| C05 — Snapshot and security parity | Bind cache identity to tenant, database incarnation, collection, document and version (and relevant schema/index generation). Apply current authorization and key-access/expiry checks to every hit and miss. | Concurrent update/delete/recreate tests; transactions and pagination never mix versions; tenant/incarnation isolation; revocation and key expiry on cache hits and during misses; retained versions and outputs stay charged until released. |
| C06 — Operational integration | Integrate standalone and replicated execution, restart, snapshot transfer, backup/restore, audit/history, maintenance, shutdown and configuration. | Focused end-to-end checks above the memory bound; streaming work stays bounded; held snapshots and saturated foreground memory cannot consume maintenance reserves or cause unsafe reclamation; strict older-format rejection and all supported caller updates. |
| C07 — Capacity and performance qualification | Demonstrate full residency for fitting databases and bounded memory for larger databases on final source. Publish metrics and operating documentation. | The workload matrix below, source-pinned measurements, regression comparison against the resident implementation, and required repository/release checks. All limitations and failed runs remain recorded. |

## Budget and eviction rules

- Give the cache a large explicit byte allocation within the installed memory
  owner. Choose and justify the default using the available deployment budget;
  do not invent a fixed RAM fraction before accounting for other owners.
- Count decoded object capacity, keys, indexes, directory pages, cache policy
  metadata, shared allocations and retained historical versions. Count each
  shared allocation once and keep its charge until its last holder releases it.
- Include archived documents, history archives, audits, receipts and staged
  transaction state in the inventory. Move data-sized resident structures onto
  bounded storage access; bounding document bodies alone does not close C01.
- Bound request/decode/write buffers, in-flight cache misses, query workspace,
  pinned outputs and maintenance separately within the installed total.
  A cache limit alone is not a bound on process RSS or operating-system page
  cache. Measure those separately and document the process memory envelope.
- Use pressure eviction only when needed to admit work within the bound. Do
  not flush the entire cache at the threshold. An entry that cannot fit may be
  served through admitted bounded work without cache insertion; reject work
  that cannot fit even the permitted workspace before publication.
- Collection reservations share the total cache budget and have validated
  aggregate limits. They must not create unlimited pins or displace unrelated
  resource and maintenance reservations. Define their behavior when unused.
- Snapshots may retain durable versions without retaining every decoded object.
  Never evict an allocation still held by a reader and credit its bytes early,
  or substitute a newer document when an older snapshot misses the cache.
- Under pressure, scans use bounded pages and must not displace a repeatedly
  accessed hot set merely by visiting more unique historical records.

## Required workload matrix

1. **Fits in memory:** populate all supported object/index types below the
   accounted bound, complete warm-up, then read the entire dataset repeatedly.
   Verify full residency, no pressure evictions and no document/index fetches
   from storage. Authorization, strict-read audit and durability I/O are
   measured separately and remain enforced.
2. **Crosses the bound:** grow through the limit under concurrent reads and
   writes. Verify gradual eviction, durable acknowledged writes, exact snapshot
   results and bounded charged memory without whole-database rejection merely
   because total persisted data exceeds RAM.
3. **Much larger than memory:** exercise datasets several times the configured
   budget, hot accounts alongside cold scans, large documents, index builds,
   mixed updates, retained versions, backup/restore and compaction. Measure cache
   hits, misses, evictions, admission denials, page reads, latency, RSS, swap and
   maintenance progress. Hit-rate and latency targets must name the workload.
4. **Restart and failure:** repeat fitting and oversized cases through crash,
   strict reopen, injected I/O failures, key expiry and replica recovery. Verify
   bounded replay/warm-up and all-or-nothing durable state.
5. **Returns below the bound:** delete data or increase the configured budget,
   complete bounded refill and prove full residency again, including indexes.

Use focused checks during implementation and the final gates in
[CONTRIBUTING.md](../CONTRIBUTING.md), the
[release ledger](production-release.md) and the
[acceptance checklist](release-checklist.md) for qualification. Changes to
durability, authorization, recovery and ownership require failure/restart
coverage; passing cache unit tests alone cannot close this goal.

## Execution order and scope

Start with C01 and C02. Build C03 on admitted durable lookup, then integrate
C04 and C05 together before C06 and final C07 qualification. Security and
version consistency constrain every stage, rather than being added at the end.

The starting implementation retains document maps in
[`CollectionState`](../crates/kasumi-types/src/lib.rs), serves queries through
resident structures in [`kasumi-query`](../crates/kasumi-query/src/lib.rs), and
keeps a key `BTreeMap` in [`kasumi-kv`](../crates/kasumi-kv/src/core.rs).
`TenantState` also retains growing history, audit and staged-transaction data.
[`TenantReadView`](../crates/kasumi-store/src/read_view.rs) supplies encrypted
snapshot reads to build on. These are foundations, not completed cache goals.

Disk-size reduction is a separate objective: compact encoding, compression and
effective reclamation may reduce storage use, but are not implied by eviction.
Do not claim a universal cache hit rate or a reduction in on-disk database size.
