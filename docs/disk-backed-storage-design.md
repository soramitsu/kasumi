# Disk-backed storage implementation design

This is the implementation companion to the
[active cache goals](disk-backed-cache-goals.md), inspected on 2026-09-30.
It describes the required cutover and identifies partial foundations. It does
not certify a disk-backed application engine or a production memory bound.

Current execution order and completion gates are maintained in the
[M01–M07 milestones](disk-backed-cache-goals.md#current-implementation-sequence),
refined on 2026-10-02. The staged design and dated checkpoints below retain their
original scope; use the goal document and evidence ledger for current status.
The required end state is full residency of all eligible data and indexes while
their complete accounted footprint fits, followed by pressure-driven eviction
and bounded disk reads when it does not.

## Durable application state

The existing document maps cannot simply discard entries. Ordinary engine
mutations publish immutable `Generation` maps after ordered application, while
the document bodies are recoverable from Raft commands and opaque snapshot
records. Receipt rows are addressable on the encrypted store; live documents
and query index roots are not yet independently addressable there.

Introduce a small selected application root per tenant/database incarnation,
with collection metadata and references to immutable encrypted document and
index pages. A mutation must persist document changes, index changes, counts,
the application revision and the associated receipt/terminal changes in one
atomic publication before releasing the new generation. Replaying after a crash
between application publication and Raft applied-position persistence must
recognize the same ordered command without duplicating changes or receipts.

`TenantReadView` already selects an encrypted native snapshot and rechecks key
access while reading. Its logical keys are HMAC-addressed, so a physical range
does not preserve logical document or index ordering. Use encrypted ordered
tree pages addressed by opaque page IDs; do not use `TenantStore::scan` to
materialize and sort a whole namespace for ordinary queries.

The application primary tree will be a separate private logical B+ tree above
the encrypted store. The native directory couples physical value locations,
arena references, one entry-count aggregate, native failure fencing, workspace
admission and page synchronization. Extracting its reader/editor into a shared
core would also affect packing, walking and reclamation; changing only its leaf
codec or backend would not preserve those contracts. Keep the qualified native
implementation intact and give the logical tree its own adversarial and
publication tests. Reuse invariant scenarios, not copied native modules or
fabricated physical locations. A private write overlay does not claim durability;
the existing paired application/custody publisher remains authoritative.

Logical page aggregates must preserve existing quota semantics.
`TenantState.logical_bytes` counts encoded **live document bodies** only;
overflow-object bytes also contain ID/version/DTO framing and are a different
quantity. Archived-reference bytes have their own accounting, and indexed
projections may duplicate body data. Store the necessary semantic metrics
explicitly rather than inferring them from physical record sizes. The page
codec, bounded reader/editor and real paired-view fixture remain pending.

Each reader retains the selected durable roots and incarnation/revision, then
loads immutable documents or pages through the cache. Authorization, suspension,
retirement, key expiry and the current continuation fences remain outside the
cache and execute on hits too. A missing old version must never resolve to the
current document. Reclamation retains pages/log records reachable from every
live snapshot root until their exact owners drain.

### Application cutover: C04 (in progress)

The first vertical slice is encrypted ordered pages, snapshot-bound publication,
ordinary document mutations with primary/typed/unique indexes, then point,
range, filter, order, projection, aggregate and pagination reads. This proposal
does not change the Core cutover status below. The native source pins validate
their named component sources, not this application design or its memory bound.

Replace the document and archived-reference maps in
[`CollectionState`](../crates/kasumi-types/src/lib.rs) with collection metadata,
checked counts and durable roots. A small document view in
[`Generation`](../crates/kasumi-engine/src/state.rs) should bind those roots to
tenant/incarnation, revision and a pinned
[`TenantReadView`](../crates/kasumi-store/src/read_view.rs). Native ciphertext
residency can supply zero-disk reads for fitting documents and pages; JSON
decoding remains admitted request work. This does not itself supply decoded
object residency or collection reservations. Cache hits still execute current
authorization, access and key-expiry checks. A missing record referenced by the
selected root, or a mismatched version, is corruption, never a fallback to the
latest document.

[`TenantStore::record_key`](../crates/kasumi-store/src/lib.rs) HMACs logical keys,
so physical record ranges cannot implement document-ID or scalar ordering.
Introduce encrypted pages addressed by opaque IDs, with selected roots for the
primary ID directory, field-value/presence postings and unique tuples. Define
the page-reader abstraction and typed ordering in
[`kasumi-query`](../crates/kasumi-query/src/lib.rs), with its store adapter in
the engine. Preserve [`Scalar`](../crates/kasumi-query/src/scalar.rs) ordering,
exact decimals, Missing/Null semantics, array deduplication and missing-tuple
uniqueness. Existing indexed strings can exceed a fixed page-key limit; bounded
overflow references/comparison must preserve them. Reusing the native 4 KiB key
limit would introduce a new application rejection.

Change [`QueryIndexes`](../crates/kasumi-query/src/lib.rs) and
[`Structured`](../crates/kasumi-query/src/structured.rs) to selected roots plus
bounded schema/validator metadata. Mutation preparation receives admitted old/new
documents for changed IDs, not two full collection maps. Remove all changed old
unique mappings before inserting replacements, preserving atomic swaps. Route
[`seek.rs`](../crates/kasumi-query/src/seek.rs),
[`service.rs`](../crates/kasumi-engine/src/service.rs),
[`snapshot_leases.rs`](../crates/kasumi-engine/src/snapshot_leases.rs) and
[`history_reads.rs`](../crates/kasumi-engine/src/history_reads.rs) through point
reads and bounded cursors. Preserve predicate validation before empty-result
shortcuts, cancellation and candidate/output limits; do not hydrate every
candidate body before sorting or aggregation. Encrypted scratch can hold
admitted work that exceeds the in-memory query workspace.

Publication in [`mutation_apply.rs`](../crates/kasumi-engine/src/mutation_apply.rs)
and [`state.rs`](../crates/kasumi-engine/src/state.rs) must atomically activate
documents, index roots, counts, receipt/audit effects and an exact applied
manifest before `publish_generation`. The current callback cutover prepares a
private candidate and encoded response, invokes one synchronous publisher under
the mutation guard, then releases the candidate only after success. It covers
successful, rejected, revision-only and metadata applications. Authority prepares
its application writes for the same callback. The Raft adapter jointly publishes
application and custody writes through
[`TenantStorageSet`](../crates/kasumi-store/src/storage_domains.rs), then advances
its in-memory applied cursor and membership after backend release. Covered
custody replay must still execute application writes.

[`mutation_receipt::Pending::stage`](../crates/kasumi-engine/src/mutation_receipt.rs),
staged terminals and target-resolution histories retain their bounded immutable
row/index staging commits. Old Views hide rows beyond their selected heads;
exact replay validates staged canonical bytes. Combining all terminal rows in
one write vector would exceed existing transaction limits for permitted inputs.
This callback work is a prerequisite under validation, not the document/index
root cutover: resident document maps and indexes still exist. Recovery must
reconcile an exact command identity across any application/applied-cursor gap.
Capture the selected read view before releasing the tenant mutation locks.
Delete replaced application-page keys from the new native root in that
publication; pinned old native roots preserve historical keys. Otherwise native
warming counts obsolete application pages as live. Separately staged pages need
explicit bounded orphan tracking and reclamation.

Streaming construction is a prerequisite, not established by the current import
API: `read_view::replace_domain` visits incrementally but accumulates writes in
[`tables::Pending.writes`](../crates/kasumi-kv/src/tables.rs), under the native
96 MiB transaction bound. TenantStore batches have a separate 64 MiB bound.
Index fanout from allowed definitions (up to 64 indexes, eight fields and
4,096 array values) can exceed either bound despite a valid input mutation.
Large builds therefore need bounded unpublished page staging with atomic root
activation, or a streamed native builder/root-install primitive. A whole-build
write vector or a resident restore overlay is insufficient.

Text remains a required follow-on before C04 completion.
[`search.rs`](../crates/kasumi-query/src/search.rs) owns a RAM Tantivy directory
and growing `ids`/`rows` maps. Preserve its analyzers, phrase/prefix/fuzzy behavior
and ranking. An encrypted Tantivy `Directory` alone does not bound memory:
Pinned Tantivy 0.26.1's `fst_termdict` readers load complete FST/term-info regions into
`OwnedBytes`, and `SegmentReader` loads alive-document bitsets. Bound immutable
segment sizes and simultaneously retained reader state, or change those readers;
also account for global scoring, segment metadata and writer workspace. Publish
the selected search state with the same application manifest.

Finally, remove dataset-sized staging chunks, change-feed records, archived
references, history manifests, audits and lifecycle/recovery histories from
`TenantState` through the same addressable storage. Replace
[`lease_retention.rs`](../crates/kasumi-engine/src/lease_retention.rs)'s retained
ID/divergence maps with admitted root pins and output/cache owners.
[`snapshot_codec.rs`](../crates/kasumi-engine/src/snapshot_codec.rs) must stream
semantic records from a selected view and restore into unpublished durable
structures; [`accounting.rs`](../crates/kasumi-engine/src/accounting.rs) should
use stored per-record lengths and bounded deltas. Qualify the vertical slice
with cold and warm reads, pressure, overwrite/delete churn, old snapshots,
unique swaps, long keys and failures at publication boundaries. Use direct
first-release formats, without legacy fallback readers or dual writers.

## Native ordered directory

The starting `Core` retained a table/key `BTreeMap` and linked version nodes.
The public Core now uses the segmented log and immutable directory in DiskState;
the native API and installed-backend cutover is undergoing validation. A
sequential checkpoint reader alone cannot provide the required ordered index.
Its per-segment summary and the NodeDisk group's file-identity bookkeeping also
require separate allocation accounting and namespace-cap qualification.

Use an immutable ordered page tree for table existence and key-to-value
locations. Leaves name the batch version and segmented value location. A
snapshot names the database group, directory generation and immutable tree
root, not a linked in-memory copy of every key version. Reopen selects that
root and validates pages through bounded workspace; it must not reconstruct an
all-key resident map. Cache pages under the same admitted-memory hierarchy.

The directory module supplies canonical immutable pages, sorted streaming
construction, point/successor lookup and incremental copy-on-write mutations.
Mutations copy the search path with two page buffers and fixed admitted scratch,
balance splits by bytes, remove empty pages and shrink unary roots. Old roots
remain immutable. Operational errors poison the private mutation batch, and
`finish` synchronizes its pages before an owner may publish it.

The segmented superblock now encodes a selected directory root together with
its exact batch sequence, chain and replay position, plus separate durable arena
allocation/confirmation counters. Adjacent root selection rejects rollback and
same-version substitution. The retired root layout is explicitly rejected.
Append-only `.kvdir` arenas roll through synchronized headers and names; each
new writer allocates a fresh arena instead of reusing uncertain page offsets.
The NodeDisk group owner recognizes this kind with independent identity counters
and its existing bounded descriptor custody. Internal `DiskState` reclamation
now proves whole-file unreachability from the selected root and retained
snapshot roots before retiring a segment or directory arena.

The internal `DiskState` now composes these components: prepare operation records
and their value locations, synchronize the private directory, write and sync its
canonical preparation record, bind the exact root into `BatchCommit` and its
chain digest, sync the commit, then publish the superblock. Only publication
makes those bytes eligible for cache retention. Recovery selects validated
commit roots after the superblock's exact anchor without rebuilding a resident
key map. The replayed commit boundary is distinct from the writer's resume
position, which may follow a later abandoned batch. Interrupted arena allocation
is repaired only from the selected intent and exact identity-header prefix.

`DiskState` now registers snapshots in an admitted registry with an internal
limit of 256 slots. Each independent pin owns one admitted allocation; clones
share that allocation and slot until the last clone drops. Reads validate the
exact registry identity as well as the root and current owner. A matching group
ID alone cannot authorize a snapshot from another owner. This slot limit and
the associated metadata accounting are internal settings, not a completed
deployment configuration contract.

The internal maintenance path in `disk_compact.rs` now rotates the segment and
directory-arena appenders, then evacuates the selected tree in leaf batches. This
replaces the historical one-record-per-commit primitive. Each admitted, validated
leaf plan holds one page and a bounded ancestor path, with at most 512 records.
Keys borrow the leaf buffer; the retained continuation key and bounded descriptor
backing are admitted before effects. Batches target 1 MiB of encoded records,
allowing one oversized record up to `MAX_VALUE_BYTES` while independently
enforcing operation-count and transaction-byte limits. All sources are preflighted
before any relocation writes, then old values stream through 64 KiB windows.

Each batch copies its leaf and ancestor path once, preserving row logical batch
sequences, table birth sequences and untouched values. An already fresh leaf
without old value locations needs no maintenance commit. The cursor reads the
current selected root between steps, allowing foreground writes to interleave;
writes behind the cursor already use the rotated appenders. It advances only
after publication or a verified skip. Old snapshot pins protect their original
physical roots and values. No all-key resident map is built.

The subsequent internal density phase in `disk_density.rs` packs adjacent pages
from leaves upward through internal levels. `directory_pack.rs` holds two admitted
input pages and fixed paths, validates adjacency across parent boundaries, and
greedily emits one or two pages. Both paths are rebuilt together at their lowest
common ancestor before a single `DirectoryOnly` root publication. Empty branches,
longer separator splits and checked unary-root collapse are handled without
changing logical records. Three fixed output carries suffice for ancestors;
simultaneous carry scratch and two mutation buffers are admitted before effects.
One operation appends at most `2 + 4(h - 1) + 1` pages at tree height `h`.

Density retains an admitted inclusive logical cursor, reselecting from the current
root each step. Merged output stays eligible for its next neighbor; two-output
or unchanged pairs advance to the right minimum. Expected generation advances
after the phase's own commits. A foreground generation change dirties an unfinished
pass; at its end, only density restarts, retaining completed evacuation and frozen
cutoffs. Only a pass without intervening foreground publication sets density
completion and proceeds to GC. A foreground change during subsequent GC restarts
density before reclamation resumes; a change after the entire compaction completed
starts a new compaction cycle. Continuous writes may prevent a clean pass, so
this does not promise density or reclamation completion under continuous writes.
The [35-file density source pin](evidence/disk-backed-cache-20260930/density-selected.sha256)
passes 365 native library tests in 222.74 seconds, 22 focused density tests in
187.95 seconds, 30 native integration tests, strict native all-target Clippy and
package formatting. The initial Clippy failure is retained; three test-style
corrections preceded the passing check. This is an internal component checkpoint.
Its 1,200-row workload evacuates 4,800 value bytes in seven commits and 14 directory
page writes, then packs in six commits and 15 page writes, reducing reachable
pages from eight to five. These callback counts do not measure device bytes.

Root-only replay streams operation validation and selects committed directory
roots without retaining decoded operation keys or a key map. Its bounded workspace helper
reserves approximately 2.38 MiB; other fixed owners, cache data, request outputs
and maintenance allocations remain separately charged. This is an admission
ledger bound for the helper, not a process RSS measurement. Normal prepared-batch
abort now uses root-only replay bounded by the prepared operation count. Its
reservation includes fixed replay workspace and exact returned value-location
backing, independently of borrowed payload size; it no longer reserves a full
decoded-record replay copy. A focused leaf-batch check exposed the former
over-reservation. Abort now verifies the exact synchronized batch, end position,
operation count and operation digest before discarding bytes. Damaged or
substituted prepared data cannot be treated as a torn append. Native component
validation is recorded in the [leaf-batch checkpoint](evidence/disk-backed-cache-20260930/README.md#leaf-batched-maintenance-and-shared-residency-checkpoint).
Maintenance uses segment format version 4 and directly rejects version 3, with
no fallback reader or migration path.

`DiskState` now backs the public Core. Its lifecycle facade retains failed-open
custody, notifies the physical admission owner exactly once on failure, and
counts admitted snapshot pins for retained-reader close. The exact backend
owner remains held through failure and observed native close. Final validation
of the composed installed paths remains outstanding.

The native group and NodeDisk now use shared file/root types and one backend
trait. Namespace census streams the existing NodeDisk directory cursor; root
census retains only fixed flags and garbage bookkeeping. Cursor-close errors
take precedence over callback cancellation. The group owner still has a growing
file-identity/envelope vector, but each expansion is admitted against installed
memory. NodeDisk's underlying two inode-ledger banks are preallocated and charged
at installation from explicit file/subdirectory/root caps. Neither is hidden
unbounded RAM; the group vector duplicates some already enrolled information
and can cause capacity denial while opening a large group. A 64 MiB segment
requires one file record, not one record per key, so explicit namespace caps can
support datasets much larger than RAM. Include both layers in the total budget,
expose the caps and qualify maximum-group creation/reopen with a small descriptor
cache. The initial server policy's one-million file and one-million subdirectory
limits make their fixed cost particularly important. Removing the duplicate
vector is an optional optimization, requiring preserved NodeDisk enrollment and
envelope-state receipts; fresh stat/envelope checks alone cannot replace exact
ownership and close custody. Checkpoint summary maps likewise require their
own accounting or bounded replacement before entering the production path.
Root publication, bounded recovery, incremental reclamation and retained readers
must be integrated together. Do not rewrite a complete directory on every commit
or retain a complete directory in a replay overlay.

### Core and installed-store cutover under validation

Core/Builder/retained now use one segmented backend. Direct constructors close
their exact backend on failed opening; retained constructors leave close custody
with their registered owner. Core issues the physical-owner failure notification
and retains callback panics. Snapshots acquire admitted immutable roots under
the state lock, and close rechecks their count under that lock before entry.

`next_key_admitted` implements a table-wide lower bound; prefix iteration uses a
separate filter. Existence decisions read directory metadata without value bodies.
Public output allocation precedes optional cache loading and can fall back to
reading directly into its admitted buffer if a second temporary value cannot fit.
`committed_position` names the published replay boundary, including when an
appender has rolled without publishing another commit.

RegisteredNodeOpening now retains an Arc<NodeSegmentGroup>. The bounded encrypted
scratch backend uses one encrypted spool per group file and an explicit native
cache budget; it has no old Core fallback. Installed policies supply per-group
cache/descriptor ceilings and scratch cache bytes. Their values remain subject
to aggregate installed memory admission and still need workload qualification.

Server recovery and cleanup now bind a NodeGroupIdentity containing both the
directory identity and root-file identity. Local recovery journal format 4 rejects
the previous single-file shape. Namespace ownership, partial close/transfer and
interrupted cleanup must pass the composed recovery tests; an `is_dir()` check
alone never establishes ownership. Production compilation and tests are still
in progress, so these edits do not close C02 or C06.

### Ordinary commit space admission under qualification

Ordinary native commits now acquire a complete physical-space claim before
`prepare_batch` or any roll-intent publication. The canonical plan binds the
group incarnation, actual selected root generation, fresh batch sequence,
existing append positions and never-reused file-ID ranges. Both installed and
scratch backends validate the actual mirrored root images. Native header minima
are fixed by the format; a caller cannot lower them to settle an incomplete file.

The segment planner follows actual record lengths and rolling positions. The
directory planner bounds COW appends across the complete batch, including splits,
deletions and pre-existing unary paths. The ordinary splitter now leaves at least
two records on each side even with unequal separator widths. This bound is
conservative: large-batch over-reservation and its availability impact still
require workload qualification.

Installed claims atomically reserve aggregate bytes, filesystem promises,
namespace/file rights, reusable descriptor capacity and ledger backing. Scratch
claims also prepare the exact encrypted buffers and bounded file slots before
native acquisition. Growth transfers promised bytes into actual file owners
without repeating quota admission. Descriptor rights return only after observed
successful close. A claimed parent cannot be removed, including when its claim
has no new files. Allocation or operating-system failures after entry can still
have unknown outcomes; preadmission does not make those effects infallible.

Only explicit pre-effect refusal returns `TransactionReserveError::CapacityDenied`.
Generic `StorageFull` or `OutOfMemory` from an entered I/O operation retains its
original error and fences the owner. Pristine cancellation requires exact claim
identity and no entered effect. Positive completion synchronizes and checks the
actual consumed prefixes and file lengths before returning unused rights.
Abandonment never uses Drop as a refund or rollback proof.

A directory-workspace refusal after a complete prepared log batch first settles
its physical claim, then uses the existing exact prepared-batch replay/truncation
protocol. No partial preparation is passed to that rollback path. On success,
the durable commit and mirrored root publication precede physical claim
settlement and selected/cache publication. A failure after durable publication
remains `UnknownCommit`; reopening selects the actual saved version.

Focused qualification passes 25 installed/scratch foundation cases, six actual
public-transaction orchestration cases and all five previously failing Store
commit-capacity regressions, each on its recorded source selection. The full
activated native package also passes 475 unit and 31 integration cases on its
765-file source selection. Full Store/Engine and release gates remain open. These results do
not qualify every maintenance/compaction write corridor, complete memory
accounting, ordinary document/index serving or C01–C07. Exact commands, failures
and source pins are retained in the [evidence ledger](evidence/disk-backed-cache-20260930/README.md).

Internal reclamation uses an uncached resumable tree walk with admitted bounded
page/path state and at most 128 candidate-file proofs per batch. It scans the
selected tree and a bounded, deduplicated capture of pinned roots, excluding
active/pending files, the selected commit anchor and replay suffix. Publication
changes invalidate the scan. Coverage checks allow captured pins to retire and
new pins of the already-scanned current root, so ordinary current-reader churn
does not restart every bounded step. An uncaptured historical root invalidates
coverage. Acquisition and reclamation remain serialized by the enclosing owner.

The completed proof publishes garbage to both root slots before exact unlink
and parent synchronization; only successful unlink permits forgetting the record.
Reopen re-proves recorded garbage against the selected tree before unlinking.
Failed steps release scan scratch, and pruning retired file identities from the
cache preserves existing output guards and their admission charges. Physical GC
still deletes only wholly unreachable files; the new leaf-batched maintenance
commits can move live records out of older files before this proof runs.

The maintenance work limit counts rotations, leaf batches or verified skips,
density plans/pass transitions and reclamation steps, not bytes or elapsed time.
A batch can synchronously process
one `MAX_VALUE_BYTES` value (currently 40 MiB) despite its 1 MiB encoded-record
target and fixed-window buffers. Leaf batching removes repeated per-row path
copies, and the subsequent density phase packs sparse neighboring leaf/internal
pages. Repeated path replacement can still leave orphan pages in partially live
arenas. Reclamation currently follows evacuation and a clean density pass;
periodic GC scheduling and progress during continual root publication remain
open and the proposed continuation proof is unimplemented. The exact-root
reachability proof must not be weakened to claim that progress. The current
primitive does not guarantee dense files or complete disk-space recovery.

Compaction reports confirmed directory-page read/write and arena-sync deltas
alongside copied value bytes, entry counts, commits, fresh-leaf skips, evacuation
completion and density pairs/commits/pass counts/restarts/clean completion. Page
counters exclude cache hits and arena-header payloads; syncs include arena-header
and roll syncs but exclude mirrored-root and namespace syncs. Successful callbacks
are counted even if a later owner/digest check fails. Failed callbacks can have
unknown partial effects, so these counters are not device-byte measurements or
complete maintenance I/O. Standalone intent recovery is excluded. Full production
compaction, live Core integration and close/cancellation behavior remain open.
A no-op replacement for `compact` or `prepare_write` would not preserve the feature.

## Memory ownership

The installed total must cover fixed runtime owners, cache-retained allocations,
request/query/decode work, pending writes, retained outputs and a separate
maintenance reserve. The native cache share is only one part of that total.
The existing `AdmissionConfig` workspace/RSS defaults are not a large hot-cache
allocation and must not be reused as one without an explicit configuration cut.

The cache keeps all eligible data while it fits, including its directory and
policy metadata. Only pressure triggers eviction/admission competition. Shared
objects retain their original byte charge until their last reader releases them;
evicting a lookup entry cannot credit a still-pinned payload. Collection
reservations consume the same total and will be implemented at the application
cache, where collection identity is available. Native ciphertext offsets alone
do not supply that policy identity. The
[unimplemented reservation contract](#bounded-collection-reservations-unimplemented)
below defines the protection and its limits.

Native cache configuration is explicit in Core/Database constructors and can be
changed through `configure_cache`; `cache_stats` reports admitted retained bytes.
`warm_cache` reconciles obsolete membership and refills selected/pinned roots in
bounded work steps. Complete and fully_resident are distinct outcomes. Writes
persist before publishing and optionally retaining their immutable bytes. Optional
cache capacity denial cannot roll back an already committed batch, and rejected
writes never install candidates. Owner and snapshot checks apply to hits too.
Optional describes cache-fill failure after an already durable commit; it does
not permit leaving eligible data cold when the complete accounted allocation
set fits.

The installed persistent generated profile supplies a 1 GiB per-group ceiling;
scratch supplies 512 MiB per table. These explicit initial settings require final
capacity qualification, rather than proving a universal suitable default. Native
byte residency does not imply decoded document or query-index residency. The
foreground publication reconciler below now preserves a fitting previously
resident union, subject to its stated pin/workspace conditions; broader
validation, automatic bounded warming and application-level residency remain open.

The native cache now accepts complete inline identity keys, comparing equality
even when hashes collide and charging each key's actual slot size. The directory
page adapter binds one backend owner for its lifetime and keys pages by the full
group incarnation, arena, page and full SHA-256 digest. It rechecks physical ownership on
hits and after loads; directory readers still validate root generation and parent
bounds on hits. If optional retention cannot be admitted, it reads into the
caller's already admitted page buffer. Private COW updates use a cache-lookup-only
view: committed hits are reusable, and misses go to the raw arena without admitting
unpublished intermediate roots or recording private access frequency. Published
and pinned roots use the cache and bounded warming; shared unchanged pages have
one cache identity across generations.

Whole-file reclamation removes the retired file's page/value cache identities
without allocating a key list; output guards keep their bytes and charges until
release. A newer internal reconciliation implementation in `disk_warm.rs` also
prunes obsolete identities inside partially live files. This source follows the
density checkpoint and has its own
[43-file residency source pin](evidence/disk-backed-cache-20260930/residency-selected.sha256)
with 406 passing native library cases. The
[validation record](evidence/disk-backed-cache-20260930/README.md#resident-cache-reconciliation-checkpoint)
separates development failures, final selected-source checks and open production
qualification.
It keeps a fixed cursor over resident cache slots, not an all-disk page registry.
A structural version detects membership/layout changes; conditional removal
checks the candidate's full identity, slot and payload owner, then revisits the
slot affected by backward-shift deletion.

For a page candidate, its validated minimum key and level select at most one
directory path under each current or pinned root. Exact physical reference and
digest comparison proves membership, including parent bounds. Values retain
trusted table/key lengths with their cache identity. The allocation-free
`segment_locator.rs` helper uses 5,180 bytes of caller-admitted scratch and one
bounded read of the record envelope immediately preceding the payload. It
checks the fixed Put and Relocate layouts, position/group-bound header, canonical
lengths, logical version and complete body checksum against the cached payload.
It never scans backward for magic or reads the payload from disk; malformed or
ambiguous envelopes fail closed. The recovered logical key permits exact value
location/version comparison through the same bounded root set.

Root captures do not themselves pin files. Before every serialized warm step,
the selected root and unique pinned roots are recaptured and compared; a changed
union restarts the continuation before a retired root can be read. The enclosing
state lock excludes publication, new-pin acquisition and physical GC during the
step. Concurrent pin drops cannot unlink a file there, and repeated pins of the
current root do not prevent finite completion. Proven-dead identities are removed
only under current coverage. Retryable proof errors reset the continuation rather
than skip an unproved candidate. Source corruption and I/O failures fence the
owner; cache pruning itself never authorizes durable unlink.

After pruning, excess hash backing is trimmed and a logical successor cursor
refills the current and pinned roots without eviction or demand-policy training.
Refill shares cold physical aliases only when the logical table/key and batch
version match, with matching value length/checksum; each identity remains charged
and the immutable payload is charged once. Optional retention denial is reported
through explicit completion/residency status and can be retried in a new pass.
`DiskState::warm` and compaction after density but before GC use this path.

`DiskState` uses one shared cache for pages and values with complete typed
identities, so spare capacity is available to either. Post-publication warming
descends only through pages created by that commit, validating unchanged child
pages once and skipping their subtrees. It retains final visible Put bytes from
the original batch after publication, including correct handling of repeated
puts and deletes. Private intermediate COW pages never enter the cache. Abort
workspace is reserved before preparing records and released before cache fill;
prepared value-location storage keeps its separate charge until released.
Native buffer sizes include exact writer capacity and simultaneous root-codec
buffers. Direct page fallbacks are counted as uncached loads, so bounded warm-up
cannot falsely report full residency when page retention was denied.

Maintenance reads source values and directory pages through raw bounded access,
so a sweep does not fill the cache with cold source data. Post-publication page
warming uses non-evicting, policy-neutral lookup/fill: it does not train frequency,
touch existing recency or increment demand-read counters. Old and new addresses
share one immutable resident payload, charged once; each identity's directory
metadata remains charged. Cache memberships distinguish aliases from external
reader pins through rehash, removal and close. If additional metadata cannot fit,
the cache moves the existing identity to the new address without evicting
unrelated entries; original output guards keep their bytes and charges, while
an old snapshot can reload its still-retained durable location.

Production integration now assigns this cache an explicit installed share.
Exact tenant/incarnation scope, current access checks and collection reservations
still belong outside the native retention pool. The internal snapshot and
maintenance/reclamation implementations are wired into Core and still require
composed installed-path checks and application cutover. Neighboring-leaf/internal-page packing is implemented
internally and covered by the density checkpoint; partial-arena disk growth, periodic
GC progress and production qualification remain unfinished. The prior leaf-batch
and shared-residency source has its own selected-source component checkpoint
above (343 native, 30 integration and 21 store-boundary passes); neither that pin
nor earlier per-record results validate the subsequent density implementation.
The density source pin and checks are separate from those historical results.
They also exclude the subsequent residency regression and reconciliation source.
The later 43-file residency checkpoint passes 406 native library cases, including
the exact six-page current/pinned budget regression, eight page-membership checks,
eight value-locator cases, composed admission/failure tests and cold alias sharing.
This does not establish immediate full residency under arbitrary ongoing
foreground publication or complete production qualification.
Reconciliation work is memory-bounded, not strictly byte/time-bounded: a value
checksum may consume up to 40 MiB, a proof can visit the configured pin count
times maximum tree height, and metadata trimming can rehash resident capacity.
All C01–C07 completion criteria and the production cutovers remain open.

Scan qualification must use the actual query/range path. Repeated successor
lookups can touch the same historical leaf once per row and inflate its apparent
frequency. A sequential cursor should reuse its admitted current page, or pass
an explicit scan admission hint, so dense one-pass scans cannot masquerade as
repeated account access. The current synthetic cache scan tests alone do not
close that workload requirement.

Directory references now carry full SHA-256 digests at every tree edge. The
canonical 96-byte root, including its digest, is bound into both the selected
superblock and commit chain. Tests include a modified page whose CRC32C is
unchanged but whose parent SHA-256 rejects it. Retired directory, segment and
root layouts are rejected directly; there is no migration or fallback reader.

### Bounded collection reservations (UNIMPLEMENTED)

Implement reservation policy in C04's logical document and ordered-page cache.
[`NativeIdentity`](../crates/kasumi-kv/src/page_cache.rs) currently carries physical
addresses, checksums and trusted key lengths. The store places tenant records in
the shared `encrypted_records_v1` table; HMAC-addressed keys do not expose their
logical collection. [`TenantStore::decode_record`](../crates/kasumi-store/src/lib.rs)
authenticates the encrypted namespace and key, and
[`TenantReadView`](../crates/kasumi-store/src/read_view.rs) binds reads to the selected
snapshot and current access checks. Native directory pages can mix collections
and tenants. Adding native priority tags alone would not reserve logical query
pages or guarantee that a protected ciphertext lookup avoids directory I/O.

The minimal proposed API is
`configure_reservations([{ collection_scope, protected_bytes }])`, with an
installed maximum reservation count and fixed, admitted policy slots. Validate
aggregate allowances and policy metadata against the same total cache limit
before changing policy. A trusted collection owner mints an opaque class handle
containing slot and generation; untrusted requests cannot supply arbitrary tenant
or priority tags. One aggregate cache reservation funds retained allocations;
individual entries borrow inline credit rather than acquiring governor slots.

All eligible objects remain resident while their complete accounted allocation
set fits. Reservations affect victim selection only under pressure: protect each
collection's selected hot objects up to its allowance, and let its excess compete
through frequency and recency. Unused allowances remain borrowable. An oversized
object does not acquire an unlimited pin. An allowance is not a permanent claim
that every document in the collection stays resident.

Once populated, a protected set cannot be evicted by unrelated cache traffic
while its policy remains installed. This does not promise instantaneous population
when mandatory-work admission is exhausted or unrelated reader guards retain
the bytes needed for insertion. Report retryable provider or pinned-output
pressure in that case. Do not silently spend maintenance reserves, credit live
guards early, or claim that a declared allowance makes borrowed bytes immediately
reclaimable. A stronger availability promise would require additional custody
rules for borrowers and output guards; it is outside this minimal contract.

The implementation must also satisfy these integration constraints:

- Scope identity includes tenant, database incarnation and a stable collection
  birth identity. [`CollectionState`](../crates/kasumi-types/src/lib.rs) currently
  has a name and mutable data epoch; neither alone distinguishes drop/recreate.
  C04 must supply the birth identity. Retirement invalidates the policy-slot
  generation without refunding surviving output guards.
- Shared immutable payloads count once across snapshot roots; identity metadata
  counts separately. Collection-specific application pages inherit that class.
  Cross-collection pages initially remain in the shared pool, avoiding either
  duplicate charges or unbounded per-page membership lists. Native directory
  pages continue to use the global native policy.
- Native and application caches share the installed total. Retaining both
  ciphertext and decoded objects consumes two real allocations; both must be
  charged. Their warmers cannot assume independent capacity or duplicate a
  residency promise without accounting for both representations.
- Authorization, suspension, retirement and key expiry run before logical cache
  hits. Reservation membership grants no access and cannot substitute a newer
  version for the selected snapshot.
- Reject a cache shrink below validated aggregate protection before changing
  policy. Failed policy admission preserves the old configuration. Protection
  metadata, retained versions and output pins remain part of the same bound.

This is an implementation contract, not a completed C03 feature. Qualification
must cover unused-share borrowing, pressure against protected hot sets,
drop/recreate isolation, shared-page accounting, pinned-output refusal/retry and
full residency without pressure below the complete bound.

## Growing allocation inventory and required replacements

| Current owner | Required disk-backed access |
| --- | --- |
| `CollectionState.documents` and archived references | Versioned document/reference records and selected ordered ID roots |
| `QueryIndexes` structured presence/value/unique sets | Transactionally published secondary index pages |
| Tantivy in-memory directory and row-ID maps | Encrypted persistent search storage with bounded page and writer workspace; preserve analyzers and ranking |
| `TenantState` active staged transactions | Point/chunk records and selected transaction heads |
| Change feed, history manifests, hot audits, schema and retirement outcomes | Bounded ordered enumeration and immutable selected heads |
| Lifecycle, recovery, restore lineage and target histories | Addressable records with snapshot-consistent heads rather than growing resident metadata maps |
| Native KV key/version maps | Immutable disk directory roots and cached pages |
| Encrypted `ScratchTable` temporary KV key maps | A bounded group-backed scratch directory or bounded temporary ordered structure; do not retain the old resident Core as a fallback |
| Raft log ID directory | Ordered persisted log metadata with bounded lookup |
| Snapshot lease document/index roots | Durable root identities plus admitted pinned cache objects |
| Snapshot restore/replay | Bounded durable builders followed by bounded preload, not full state materialization |
| Native checkpoint segment summaries and namespace census | Bounded disk-backed summaries/cursors; no unbounded vectors/maps on reopen |

Request-local candidates, sorts/aggregations, hydrated archive chunks, cursor
responses, compiled schema/policy state, key catalogs and analyzer dictionaries
also need explicit admission. Removing document residency does not account for
these allocations automatically.

Snapshot framing already separates record kinds and has streaming semantic
validation. Reuse it to populate unpublished durable roots, then preload within
the configured cache bound. Validation must exercise both fitting and oversized
datasets through restart, restore, replication, queries and long-lived readers.

## Foreground publication cache reconciliation (under validation)

Explicit warm-up and compaction reconciliation alone left obsolete paths and
values occupying capacity during foreground publication. The new source prunes
touched obsolete identities before filling the new generation, preserving a
fitting current/pinned union. Focused regressions pass, while broader validation
and the remaining C03 completion criteria are open.

A publication-scoped intrusive candidate chain lives inside the cache entries,
with its link/mark fields included in each slot's charge. A dedicated private
mutation view marks cached page identities on the actual paths it reads without
admitting private misses. Before each row mutation, a policy-neutral lookup
against the evolving private root marks its old cached value identity. Marks
deduplicate in place; private intermediate pages and values never enter the
cache. Candidate storage is bounded by cache capacity, with no separate
operations-times-height queue. Conservative extra candidates are safe because
marking alone does not remove an entry or change frequency/recency policy.

Replaying operation paths only against the pre-batch root is insufficient. For
example, let adjacent leaves have minima 0 and 10. Deleting key 10 can raise the
right minimum to 20; a subsequent insertion of 15 then rewrites the left leaf.
Both keys search the right leaf in the original root, missing the actual left
replacement. The new view observes each real private mutation path instead.
Links use full cache keys, preserving their meaning through backward-shift
deletion and rehash. While a publication scope is active, unrelated membership
changes are prohibited; only its current proved-dead candidate may be removed.

Before private effects, the code admits the bounded root capture, reusable
page-proof buffer and value-locator scratch. Admission denial is then an ordinary
retryable capacity failure. These buffers are reused after publication without
requesting mandatory proof workspace for the first time after a durable commit.
The owner lock covers mutation, final atomic root installation, candidate
reconciliation and fill; captured roots cover pins acquired before that lock.
After assigning the selected root, it drains candidates using exact identity
and payload-owner checks and reachability proofs against the selected and
captured pinned roots. It removes only proven-dead identities, releases their
cache ownership, then retains final published pages and visible values through
non-evicting refill. No full-cache scan is needed for an ordinary write, and
unrelated hot entries are untouched. Existing output guards retain their
payload admissions after lookup removal. Disabled caches skip this optional
publication work entirely.

An aborted private batch clears its marks without removing previously visible
cache entries. Drop cleanup invokes no admission callbacks. Failed proofs never
authorize removal. Errors after durable
publication retain the existing commit/owner failure semantics; a cache fill
denial cannot roll back the commit or justify a full-residency claim. Completion
requires draining all candidates for that publication, so synchronous work is
bounded by its distinct cached candidates and pin/path proofs, not a constant
latency allowance. Qualification must cover changing separators within one
batch, repeated puts/deletes, pinned snapshots, returned guards, rehash/removal,
pressure and failures at each preflight, proof and publication boundary.

The immediate preservation guarantee applies only to a previously fully
resident, reconciled union with a stable pinned-root set, when the final union,
retained guards, metadata and required workspace fit their admitted bounds.
Becoming fitting after earlier pressure, opening cold, or dropping an unrelated
historical pin still needs quiescent bounded reconciliation/refill. Changed
write paths cannot discover every newly obsolete historical entry or reload
unrelated cold records.

A later stronger option is one reachability witness per resident identity: the
current root or one pinned historical root, with intrusive lists for each
witness bucket. When the last pin for a historical root disappears, only that
bucket becomes candidates; survivors receive another valid witness. Buckets
need fixed capacity derived from the pin limit and nonce-safe reuse. Concurrent
pin drops would only signal work, with proofs and removals under the owner lock.
This additional design and its failure/accounting rules are also unimplemented.

### Commit warming pressure limit (implemented; qualification open)

The development-profile Raft capacity run was sampled while staging 4,200
custody commands through bounded scratch-table batches. Its sampled stack ran
from commit refill through `warm_generation_with_workspace`, `load_if_fits` and
encrypted spool reads. These were admitted loader calls, not refused-cache
fallbacks; the sample does **not** establish the cause of the long runtime or a
throughput result. The scratch fixture configures an 8 MiB cache. A zero-byte
cache already skips publication reconciliation and refill entirely.

The previous pressure path in
[`retain_committed`](../crates/kasumi-kv/src/disk_state.rs) and
[`MaintenanceDirectoryBackend`](../crates/kasumi-kv/src/page_cache.rs) set a
retention-denied flag that the commit caller never inspected. The
[`generation walker`](../crates/kasumi-kv/src/directory.rs) loads each older
child before skipping its subtree and reconstructs ancestor bounds on sibling
changes. Thus a rebuilt root over leaves visits every leaf; under pressure,
refused pages and ancestor rereads can continue decrypting into the temporary
buffer even though this optional warming cannot retain them. This is not an
unconditional whole-tree scan at every height, and the observed stack alone
does not prove that this refusal path was active.

The implemented commit-only optional warming view now stops at the first
retention refusal before uncached fallback. Mandatory reachability proofs and
bounded per-operation visibility checks retain their ordinary read paths;
those checks may still need storage reads under pressure. Fatal errors continue
to fence an already committed owner. Fitting publication follows the complete
admitted traversal, and existing current/pinned identities are reconciled before
new pages and values are retained. This limits refused-page I/O, not all CPU work
visiting resident boundary pages.

An adjacent quote-classification correction preserves `OwnerFailed` from
`quote_cache_memory` instead of converting it to an optional no-fit result,
even when a later owner check succeeds. Tests cover fitting trees, disabled
caches, provider/local-budget refusal before I/O, old snapshots, final batch
visibility, corruption/expiry and durable reopen after warming failure. Their
current source pin and actual outcomes belong to the evidence ledger; this
implementation statement does not qualify the complete workload matrix.
The costly capacity case remains incomplete at this checkpoint; qualify it
separately in a recorded optimized profile rather than weakening its workload
or treating an interrupted development run as a pass.

The later optimized 65,536-operation allocation run exposes a separate batch
design concern, also present with caching disabled: `commit_inner` calls
`DirectoryMutator::set` for each operation, appending a 16 KiB leaf and each
changed ancestor, then rereading private pages for subsequent operations.
The observed long-running fixture and intermediate file size are not a measured
runtime attribution, but the source establishes repeated path copying. A
later Engine phase trace locates its restore timeout in structural index
construction, and a native 16-row one-leaf baseline measures 32 page reads and
16 appends. A bounded root-leaf merge now handles at most 16 ordered distinct
edits, appending one page if they fit and delegating to the existing sequential
editor before any append otherwise. It does not cover taller trees. All 439
native unit tests and 26 crash/ownership/rollback integrations pass, as does
strict native all-feature/all-target Clippy. The same fitting fixture measures
2 page reads and one append, preserving the old snapshot, crash-reopened data
and zero serving reads below its memory bound. On the same 689-file selection,
all 11 focused Engine checks pass in 51.66s and direct 32-collection structural
construction takes 3.714s. On that earlier source the full encrypted restore
fails its original 60,000ms deadline inside structural-index construction;
the root-leaf change
is insufficient to qualify this path. The integration takes 341.73s including
setup/restart, and the complete Cargo runner takes 555.04s including compilation
and unit tests. These totals are not structural-index durations. Exact results
remain in the [evidence ledger](evidence/disk-backed-cache-20260930/README.md).

The subsequent source extends this bounded editor to a maximal prefix routed
to one leaf, still at most 16 distinct ordered edits. One validated descent
finds the prefix; its merged leaf and every ancestor separator must fit before
the first append. A successful change copies that leaf and each ancestor once.
Leaf overflow, an empty nonroot leaf or ancestor growth beyond one page returns
to the ordinary editor before effects. Native publication consumes the accepted
prefix and reconsiders the remaining edits against the resulting private root,
preserving original ordering and prepared value locations. Native qualification
passes all 444 unit tests and 26 crash/ownership/rollback integrations, strict
native all-feature/all-target Clippy and formatting on the recorded 64-file
native/Cargo selection. Height-two and height-three tests cover prefix bounds,
changed minima, no-op generations, fallback before effects, corruption and
append/sync failures. Sixteen updates within one height-two leaf measure
38 directory reads, two appends, one arena sync and 92 backend reads before
verification; fitting pinned/current snapshots then serve their checked values
without backend reads or pressure evictions, preserve crash-reopen parity and
drain admitted memory. The root-leaf fixture remains at 2/1/1/4 for the same
counters. The subsequent 689-file Engine selection passes all 13 focused unit
checks and the selected encrypted restart/full-restore integration. Actual
restore completes in 25,066ms with 34,933ms remaining from the unchanged
60,000ms deadline; all source hashes still match. Structural construction takes
18,937ms, including 23 batch commits totaling 17,846ms. This qualifies that
regression on the selected source, not the whole-runtime or full release gates.
Closer source inspection finds mandatory per-collection release audits in
schema reads and activation-status lookup, even with ordinary strict-read audit
disabled. The actual installed trace confirms 131 audits, one header, 32
collections and one activation: 165 records, 48,656 framed bytes and 330
structural point/group rows, compared with the empty fixture's 33 records and
66 rows. The corrected isolated fixture matches those counts and bytes but
takes 39,916ms for indexing, versus installed construction's 18,937ms in the
same runner. These variable observations do not establish a controlled
speedup or justify treating the small fixture as full-restore performance
evidence. Larger structural and corrected activation/audit fixtures verify
exact point/group contents and resource drain separately.

A general multi-leaf batch editor remains **unimplemented**. Pre-admit an ordinal vector over
the existing operation inputs; keep original-order table validation and the
original log stream, while sorting final row deltas by logical key and selecting
the last operation's exact prepared location. Merge all changes to each touched
leaf using the original immutable subtree intervals, reuse untouched children,
and stream replacement summaries upward so each dirty ancestor is rebuilt once.
Keep traversal buffers bounded by the maximum height and retain current
append/sync/commit/fencing rules. Do not replace this with a whole-directory
rewrite for small batches or collect every existing record in memory.

Native operations have no table drop. Preserve first-create ordering, existing
table birth sequences and the 65,536-operation/96 MiB limits on original input,
including superseded writes. Cache reconciliation must mark affected original
pages/values while retaining old pinned roots, then admit final committed pages.
Qualification requires model parity, separator/split/collapse cases, sparse
subtree sharing, repeated-key ordering, exact-fit pinned residency, allocation
denial before effects and failure/reopen boundaries. Measure page reads/writes
and admitted allocation peaks separately from elapsed time with both enabled
and disabled caching. This performance work does not replace the C04 document
and index cutover.

## Automatic cache warm-up driver (under validation)

The native scheduler and installed worker now have implementations; production
qualification and C03 completion remain open. Foreground reconciliation preserves
an already fitting resident union under the conditions above. Automatic work
addresses cold reopen, budget growth, historical-pin retirement and shared
admission pressure without requiring a foreground read to trigger loading.

`warm_cache_if_needed(work_limit)` and `cache_warmup_status()` use the same
serialized Core, Database, NodeDatabase and RegisteredNodeOpening path as other
accepted work. Fixed admitted scheduling metadata retains exact pin roots,
including current roots that become historical during publication. Ordinary
current-reader churn does not restart a pass. Deleted rows, shorter replacements,
cache reconfiguration, released output capacity and retirement of the last
historical pin can request another attempt. Pure growth does not repeatedly
restart an already completed oversized pass. New root unions invalidate active
continuations before any old root is read.

A pass preserves its observed output-pin high water until it completes fully
resident. Sampling occurs before each bounded item, after temporary proof
owners retire. This catches an output whose lookup was pruned during the pass
and whose retained bytes disappear immediately after a refill refusal. Manual
resumption of an incomplete automatic pass preserves the same observation.
Completion cannot erase this release and leave a now-fitting union parked cold;
the next attempt can refill it. Proof-only temporary owners do not trigger
repeated scans of an unchanged oversized union.

Status distinguishes pending, running, resident, capacity-limited and disabled,
with completion separate from residency and a cumulative work count. Fatal
errors remain errors retained by the owning worker. A completed pass limited
only by the cache byte budget parks with zero further data reads or admission
until eligibility changes. Shared-provider refusal is different: it leaves the
pass incomplete at the refused item. Optional refill does not advance past that
item; denied proof workspace restores its candidate cursor. The worker retries
one bounded step after backoff. This permits recovery even when external memory
is released during the same step that observed the denial, without restarting
an entire scan or relying on a later availability notification. Such retries can
repeat bounded directory/proof work under pressure; they are not zero-allocation
or zero-I/O idle polls. Explicit warm-up can restart a completed manual pass;
required workspace or metadata-trim refusal returns retryable CapacityDenied
while preserving the continuation.

Each NodeStore owns one admitted worker control and at most one tracked blocking
child. Synchronous constructors require no Tokio runtime. Startup first retains
the node and prepares a dormant supervisor; acknowledged runtime handoff opens
its ready gate. Target replacement/recovery generations use the same retained
ownership and registration boundary, including a parent readiness gate for
reconciliation started before handoff. Offline provisioning and cleanup do not
start recurring workers.

The worker uses BackgroundWork custody for both exact handles. It joins one
blocking step before dispatching another through the accepted database owner;
it never opens a second Core. Shutdown stops acceptance and scheduling, drains
the supervisor and any surviving child, then closes the database. Cancellation
leaves those handles available for retry, and original failures remain retained.
Control, task metadata and both live task slots share a fixed installed-memory
reservation. Destructors only signal stop; they do not perform I/O or claim drain.

The promise is eventual full residency after a fitting state becomes quiescent,
not a warm cache when synchronous open returns. Work units remain bounded
operations rather than milliseconds or bytes: a checksum can process 40 MiB,
and a proof can inspect every configured pinned-root path. Focused tests cover
cold reopen, exact pin retirement, unchanged oversized polls, budget growth,
pressure release inside a denied step, dormant handoff and cancellation during
a blocked read. Their implementation is not passing evidence until the
source-pinned validation record reports actual results. Final workload,
configuration, throughput and application document/index qualification remain
required.

## C01 aggregate cache admission pool (qualification in progress)

The previous per-payload installed admission path imposed a structural limit
before a large cache reached its byte bound. Every unique
[`CachedBytes`](../crates/kasumi-kv/src/cache.rs) payload, including directory
pages, owned an individual workspace lease. Shared relocation aliases correctly
shared that lease. The persistent
[`NodeSegmentGroup`](../crates/kasumi-store/src/node_file/segment_group.rs) and
encrypted [`scratch group`](../crates/kasumi-store/src/scratch_group.rs) acquire
these leases through the same installed memory provider. Ordinary
[`MemoryCore::reserve_installed`](../crates/kasumi-engine/src/admission/disk_memory.rs)
calls consume individual slots in the global admission ledger. The
[`AdmissionConfig`](../crates/kasumi-engine/src/admission.rs) default is 4,096
slots shared by all resident owners, operations and workspace, not 4,096 slots
per cache. Thus fewer than 4,096 small cached objects can exhaust the ledger;
1 KiB values can stall with less than 4 MiB of payload resident. Increasing this
count also grows the fixed storage census and does not remove the per-record
scaling problem.

On the current 64-bit layout, each ordinary native lease adds 8,232 charged
bytes beyond its native workspace request: the store admits a 16-byte
`DiskMemoryLease` box plus its 4,096-byte allocator allowance, and the engine
admits a 24-byte `Reservation` box plus another 4,096-byte allowance. These are
conservative ledger charges, not measured physical RSS. They are additional to
the previous native cache's lease allowance and were not reflected in its
`CacheStats.resident_bytes`. They could therefore exhaust shared admission while
the native cache still reported substantial room. The aggregate implementation
below now includes provider overhead in that statistic.

The generated configuration already sets an explicit **2 GiB total admission
cap** in [`example_config`](../crates/kasumi-server/src/runtime.rs), a **1 GiB
ceiling per persistent group** in
[`initial_config`](../crates/kasumi-server/src/persistent_disk.rs), and **512 MiB
per scratch cache**. It does not use the omitted admission total's
`min(high_water / 4, 512 MiB)` default. These cache ceilings share one installed
memory owner; they are not independent reserved promises. Fixed installed
metadata, retained guards, other groups and transient work also consume that
total, and the existing RSS/pressure checks remain applicable.

The replacement under qualification is a lazy, native-cache-owned aggregate
admission pool. Retained payloads and cache metadata borrow byte credit from
one growable reservation; uncached outputs and mandatory proof/directory
workspace retain their ordinary workspace path. The existing governor supports
in-place reservation growth and shrink, so multiple chunks and their descriptor
inventory are unnecessary. One pool consumes one governor slot independent of
record count and repeated cache-budget increases. An inline sublease retains the
exact pool and a checked byte count. Aliases share one payload and one sublease.

All pool control, payload owners and provider wrappers
must be admitted before allocation. A serialized ledger tracks used credit,
admitted credit and pending work, with fixed control metadata. Growth must fail
before allocating or changing retention; local byte refusal remains
cache-limited and provider refusal remains provider-limited. Metadata rehash
must fund both old and new backing until the old allocation actually retires.
An admitted transient optional-cache reservation can cover old backing during
transactional credit transfer so a final fitting hash directory does not require
both backings to fit permanently inside the cache limit. The shared installed
total still bounds their overlap.

The allocation-free provider quote and opaque growable-lease interface include
the complete installed charge. The cache's byte limit
must cover admitted credit, unused credit, pool metadata and wrapper overhead;
used payload credit must not be counted twice. Report used/cached/pinned bytes
separately from admitted credit and unused slack. Configuration must budget the
complete installed total and preserve a bounded mandatory-work reserve rather
than merely enlarge `max_reservations` or assume every group can consume its
ceiling simultaneously.

Subleases must survive eviction, cache clear, Core close and the final
cross-thread reader release. Opaque cloneable byte handles keep their shared Arc
private, including its weak-reference API. Final consuming retirement frees the
Arc allocation and payload before returning their credit. The same rule covers
pool control and boxed provider tokens; a naive token destructor must not refund
its own still-live allocation. Drop must perform no admission, owner-check
callback or I/O. Owner expiry rejects new borrowing/growth while existing leases
remain available for exact cleanup. A smaller cache limit cannot refund live
guards. Allocation-free in-place credit shrink uses the existing
[`Reservation::retain`](../crates/kasumi-engine/src/admission.rs) primitive or an
equivalent opaque interface. Shrink must not depend on admitting overlapping
old and replacement reservations under pressure.

Optional cache reservations use a distinct resident admission origin. The
installed provider redirects ordinary in-scope native workspace reservations to
[`NodeAuditMaintenance`](../crates/kasumi-engine/src/audit_maintenance.rs)'s
thread-local escrow. Long-lived cache credit must not strand that protected
maintenance capacity. Mandatory audit work keeps its existing escrow route;
cache fill denial remains optional and cannot spend the required-work reserve.
Cache admission also leaves configurable shared byte and slot headroom, in
addition to installed audit protection. This preserves bounded read/maintenance
room; it does not guarantee admission of every maximum-size foreground batch.

The following qualification is required before claiming this proposal works:

| Case | Required observation |
| --- | --- |
| More than 16,384 distinct small rows plus pages, with a real installed governor limited to 128 slots and a fitting byte budget | Full residency and zero backend reads after warming; each cache retains one aggregate governor reservation independent of row count |
| Exact byte bound, unused credit and provider-wrapper costs | All admitted credit and slack stay inside the cache bound; refusal leaves membership and charges unchanged |
| Failed or interrupted reservation growth, allocation failure and rehash overlap | No allocation before admission; pending credit rolls back; both live backings remain charged until actual retirement |
| Aliases, eviction, cache clear and Core close with surviving guards | One unique payload charge; exact provider custody survives until the last guard drops, including on another thread |
| Shrink below pinned usage, then final guard release | No early refund; bounded in-place credit reduction restores the smaller limit without replacement-allocation headroom |
| Owner expiry during growth or cleanup | New work fails closed; cleanup requires neither owner callbacks nor I/O and releases only proven-retired backing |
| Shared provider pressure during credit growth, including release inside the failed admission call | Automatic warm-up retries bounded refused work and eventually completes without restarting the whole scan |
| Audit scope and concurrent ordinary work | Optional retention never consumes protected audit escrow or the mandatory-work reserve |

The aggregate pool is implemented and under qualification. The installed
13-case admission selector passes on the source pinned in the evidence ledger:
16,513 rows plus 91 directory pages fit with zero evictions, and two complete
read passes issue no segment/directory reads. Its 20,779,032-byte complete cache
charge consumes one aggregate governor slot; total live slots rise from seven
to nine including warm-up custody. The corrected owner-refusal paths pass the
423-case native library run, strict native Clippy and formatting. This selected native/governor evidence
does not qualify application document/index accounting, process RSS, production
integration or completion of C01/C03.

The cardinality workload is also not a bulk-ingestion performance qualification.
Its empty-store seed currently applies each row through `DirectoryMutator`,
which writes a new immutable path and validates fixed-size pages for every row.
Workspace remains bounded, but private-page writes and repeated hashing greatly
exceed the logical input size. A possible later optimization is a strictly
sorted, unique, empty-root batch through the existing streaming
`DirectoryBuilder`; this is unimplemented and must preserve arbitrary batch
ordering, deletion, rollback and atomic publication on the general path.

## C04 production tranche (in progress)

### Installed filesystem prerequisite discovered during qualification

The original node handoff fixture failed before cache-worker activation: first Control
membership publication reached a native directory-file sync whose allocated
extent exceeds the admitted logical-length rounding. The source-pinned extent
diagnostic records a 434,176-byte expected/actual EOF with 466,944 allocated
bytes, a 32,768-byte overrun, and no EOF change. The workspace volume reports
APFS. The original parallel signer and target fixtures also exposed physical-owner
failures; their isolated/serial successes did not qualify those parallel paths. The original
errors and interrupted runs remain in the evidence ledger.

The implementation introduces a required `file_allocation_policy`
with `maximum_extra_extent_bytes`. Each regular inode retains a standing charge
of `round_up(logical_limit, filesystem_unit) + round_up(allowance, filesystem_unit)`.
Live growth uses its reserved EOF; settlement and census use actual EOF. The
unused part remains an explicit disk promise across close/reopen and is
reconstructed by census. This preserves later writes to preallocated backup
terminal records and root publication without post-commit capacity admission.
Deletion releases the allowance only after verified unlink and retirement.

The policy adds up to file-count × rounded allowance in disk promises. It is
required, has no production default, and must be qualified for the installed
filesystem and supported operations. Explicit zero asserts that allocation
never exceeds rounded EOF. The local fixture selects 1 MiB; neither that value
nor the observed extra 32 KiB establishes a filesystem maximum. Exact EOF and
identity checks remain mandatory. A physical overrun must retain its measured
charge before fencing. Shrink retains its old charge until synchronization
proves the new ceiling; it cannot refund blocks the filesystem still retains.
Eight focused allocation regressions, 26 backup filesystem cases (including a
real-process restart at full capacity), node cache-worker handoff, and 13 parallel
signer cases pass. Broader validation remains open. These fixtures do not prove
a production filesystem allocation bound or complete cache qualification.

### Application publication and document access

The prepared application publication callback below is implemented across Raft,
Engine and Authority; focused validation and fixture corrections are in progress
in the evidence ledger. Immutable history pairs now use the name `stage`, and
Engine selects a private Generation only after the callback succeeds. The
document-source and durable-index cutover that follows remains unimplemented.
Native cache checks do not qualify these application changes; reader refactoring
alone does not remove resident documents or establish a memory bound.

The prepared application publication protocol in
[`StateMachineBackend`](../crates/kasumi-raft/src/lib.rs) replaces the previous
ordering: [`mutation_apply.rs`](../crates/kasumi-engine/src/mutation_apply.rs)
published its in-memory Generation before
[`Raft application`](../crates/kasumi-raft/src/storage.rs) persisted its custody
cursor. Independent document writes would have added another crash gap. The
canonical interface requires synchronous
`apply_with_publisher(position, input, publisher) -> anyhow::Result<()>`, where
input is a command or consensus metadata. Its single-use `commit` consumes and
stores the preencoded `AppliedResponse` with prepared application writes. The
publisher has explicit `Ready`, `Running`, `Committed` and `Failed` phases;
enter `Running` before invoking commit work. Any duplicate attempt records a
sticky protocol violation, including one made after success or failure.
`commit` returns only a non-owning `Copy` error marker; the publisher retains
the exact original `anyhow::Error`, so a typed reducer cannot lose its failure
owner by converting or swallowing the marker. Fully build the private candidate
Generation and response before commit; keep its point views and apply guard on
the blocking thread's stack. Existing standalone apply and fixture entry points
use the same reducer with their local publisher, not a default that runs the old
publishing implementation before the callback.

After backend return, `finish(self, backend_outcome)` consumes both owners. It
releases the stored response only for `Committed`, no protocol violation and
backend `Ok(())`, after successful Generation release. Missing commit, swallowed
failure, a caught unwind leaving `Running`, or backend failure after commit must
not produce success. If publication and the backend independently fail, retain
both original errors in one owning result; do not stringify either or duplicate
custody through `Arc` wrappers. Preserve error downcasts and destruction of each
retained owner exactly once.

This callback is a deliberate lifetime choice. The
[`audit apply path`](../crates/kasumi-engine/src/tenant_audit.rs) holds a
thread-local admission scope and a mutex guard borrowed from a locally cloned
maintenance owner. A returned boxed prepared object cannot retain that guard
without an owned-guard redesign. Preparation, callback and Generation release
must all remain inside the existing `spawn_blocking` closure, with no await or
thread transfer between them. Cancellation of the async waiter must not release
these owners. Keep `StorageWorkFailure` active through the callback and memory
publication, and advance the in-memory Raft cursor only after both succeed.

Catch backend unwind inside that blocking worker with the publisher outside the
catcher. Retain a panic payload as `Mutex<Box<dyn Any + Send>>`, using static
diagnostics rather than requiring it to be a string or `Sync`. The publisher's
original callback error and an independent backend panic must survive together.
Recording only the returned error is insufficient: the current storage-error
adapter formats it, and a canceled waiter can discard the blocking result. Keep
the first apply failure in a fixed, pre-admitted lifecycle-owned slot before the
worker returns. Shutdown now inspects that slot after `StorageDrain` proves work
completion; the previous snapshot-report census ran before that wait and could
miss a late detached-worker failure. Qualify this with a canceled waiter followed by a
callback error and a drop-counted, non-string, non-`Sync` backend panic payload.

The slot also binds the exact custody-store Arc with its group fence before
opening effects. A fence keyed by a store address must keep that allocation and
its existing charge alive: retaining only the boolean allowed an unrelated
future allocation to inherit a false duplicate-open conflict. Size-based slot
admission includes the inline identity holder. Positive completed shutdown
clears the fence and releases the identity immediately; uncertain shutdown
retains both. Actual-store and drop-order regressions cover this lifetime.

Split
[`control::persist_applied`](../crates/kasumi-raft/src/control.rs) into validated
preparation and publication; preserve its exact replay, membership and retirement
checks under the existing serialized owners and control publication gate. The
existing store API can commit prepared application and custody writes through one
[`TenantStorageSet`](../crates/kasumi-store/src/storage_domains.rs) transaction.
Return an explicit `Advance` or `CoveredReplay` decision: replay reconstructs
application state without lowering or rewriting the already-covered custody
cursor. It must still apply prepared application writes where necessary;
Authority restore replaces its mutable namespace, so skipping those replay
writes would lose later application state.
Deterministic rejections remain encoded outcomes and still reach the publisher,
including revision-only audit-capacity fallbacks; they are not outer storage
errors. Derive retirement from the prospective state before the callback.
Closed custody commands keep their separate access rules. The other production
backend, [`Authority`](../crates/kasumi-authority/src/state.rs), now prepares its
administrative, lifecycle, signer-coverage and maintenance writes with their
outcome while retaining the authority mutation guard. Owned-backend forwarding
and fixtures also use this interface.

This publication barrier can precede document cutover, but is not yet durable
application-root recovery. Preserve reconstruction from the selected semantic
snapshot and retained log; add no new latest-head marker in this first slice.
At the later cutover, the selected manifest binds tenant/incarnation/revision,
document/index roots, counts,
receipt/terminal/audit effects, previous position, log identity and command
digest. It cannot skip rebuilding resident maps or be overwritten backward
during replay.

Keep the existing immutable-row staging before the callback in
[`mutation_receipt`](../crates/kasumi-engine/src/mutation_receipt.rs),
[`staged_terminal`](../crates/kasumi-engine/src/staged_terminal.rs) and
[`target_resolution`](../crates/kasumi-engine/src/target_resolution.rs); renaming
`Pending::persist` to `stage` is sufficient if its returned View stays private
until Generation release. Each point row and ordinal index commit together;
rows beyond the old selected count remain invisible, and replay requires exact
row/index bytes. A staged-terminal overlay can contain 65 rows of up to 2 MiB
each, so retain separate bounded pair commits rather than collecting their
writes into the publisher's one 64 MiB store batch. The staged point View keeps
only the source owner and selected head, with no new history map or
native read pin. Production backup-binding appends remain outside this slice
because their current `Pending` implementation is test-only.

Preparation is not automatically rollback-safe:
[`TextSnapshot::update`](../crates/kasumi-query/src/search.rs) advances a shared
writer generation before returning. Resolve deterministic rejection and budget
checks before effectful text materialization. Later materialization, publication
or release failures must fence the owner, not discard a candidate and continue
from its now-stale text generation. Cleanup must not call `TenantEngine::seal`
while still holding its apply guard, because sealing takes that same lock.

After commit, the backend only releases the prepared Generation; it performs no
additional row writes or candidate construction. This is not an allocation-free
promise: existing [`LeaseManager::publish`](../crates/kasumi-engine/src/lease_retention.rs)
refreshes retained lease metadata, may request admission and expires leases on
denial. Preserve those semantics and keep `StorageWorkFailure` active through
release and unwind. A release failure cannot become a rolled-back deterministic
rejection. At the later durable-root cutover, capture the selected read view
before releasing tenant mutation locks and pre-admit its fallible pin/custody
resources where possible. Postcommit failure then fences and recovers the exact
committed manifest; replay must recognize already-applied identity.

The next selected-root foundation must distinguish the root's actual application
transition from the durable custody position that covers it. During reopen,
Raft can restore an older application snapshot while custody is already ahead,
then publish covered replay entries. Therefore selection cannot require every
intermediate generation revision to equal the latest durable applied index.
Validate the complete canonical Entry, Snapshot or authenticated Bootstrap
identity through the same paired view, with an explicit startup/replay context.
Serving remains fenced until reconstruction reaches the required barrier.
Never fabricate an Entry digest for a snapshot or reduce the identity to an
index alone.

Snapshot checkpoints bind authenticated portable logical content. They do not
pin physical primary-page references across restart: native snapshot pins keep
deleted keys available only while those pins remain alive in the process.
Reopen and restore must rebuild fresh physical primary pages and overflow
objects from the authenticated portable Document/ArchivedDocument stream.
An older captured snapshot's checkpoint callback must never replace the live
primary selector. Durable physical checkpoint reachability and its garbage
collector are not part of this chosen first-release design.

The selected-root registry must exist before startup decode/replay can acquire
a view. Bind its exact cleanup obligation into the existing retained
SnapshotBufferOwner before startup runs; transfer ownership into Database
infallibly on success. A startup error or cancelled caller must retain that
registry through actual storage and source drain. Generation aliases may keep
immutable selection metadata, but a synchronized root cell must allow explicit
parent-view close after forks have been sealed and drained. Do not hold a
registry/seal mutex across fallible provider callbacks; use an admitted
in-flight permit so concurrent seal can settle the actual child. These are
unimplemented publication/lifecycle requirements, not proof that the current
resident document maps have acquired memory ownership.

Exact native snapshot forks are now implemented and pass the selected full
native suite. Their registered encrypted-view companion is applied and its
ten new tests pass; four affected Store accounting/failure checks also pass
after correcting the targeted-denial fixture. These APIs give independent
failure/close state to a child
without selecting a new native root. They do not yet attach selected views to
Engine generations or activate disk document/index serving. The large-cache
requirement remains unchanged: retain all eligible current and pinned data
while the accounted union fits, and use eviction only under capacity pressure.

The first source tranche adds storage-independent `DocumentSource` point/header
reads in [`kasumi-query`](../crates/kasumi-query/src/lib.rs). Index preparation
now uses ordered `CollectionRecords` and replayable old/final `DocumentChanges`
inputs. An initial resident-map
adapter permits parity checks without dual writes; remove it from production
when switching the source. Use lending point callbacks and an ordered
ID/header cursor: returning an `Arc<Document>` would let the current candidate
vector pin every decoded body. Each callback borrows one document while its
source owns admission and the snapshot pin; a replayable old/new delta borrows
at most two. Cursor state is bounded and distinguishes live from archived
records. Check cancellation before and after read work and before lending the
result; mutation deltas do not inherit client query cancellation. Remove every
changed old unique mapping before inserting replacements, preserving atomic
swaps. An
engine application view binds collection roots to a retained
[`TenantReadView`](../crates/kasumi-store/src/read_view.rs). Use an encrypted
logical ID tree addressed by opaque page IDs, not HMAC physical-key order. Its
leaves distinguish live documents from archived references. Missing referenced
records or wrong versions are corruption, never a fallback to current data.
Current authorization, continuation fences and key-access checks remain active
on cache hits.

The source-interface tranche is **implemented; focused validation passes**. The source
is collection-scoped and bound to an opaque retained view identity plus the
tenant, incarnation and collection identity; a revision or document version
alone cannot identify its owner. The initial view retains the exact captured
`Generation`; the durable implementation must retain the selected application
roots and their `TenantReadView`. Use lending operations shaped as
`with_record(id, expected_version, cancellation, callback)` and
`header_after(exclusive_id, cancellation, callback)`. A header carries the
borrowed logical ID, version and live/archived kind. Query entry points verify
the captured index owner and bind the original source identity across every
loan, including separate candidate and output passes. The initial production
source is explicitly infallible at the storage boundary; query validation,
corruption and cancellation still return typed errors. It retains the captured
generation, merges live and archived headers, and prefers a same-version
verified hydration overlay. Its source is still resident memory, not a disk
document implementation.

A bounded `HeaderCursor` remains **unimplemented**. It must
own an admitted continuation ID and that same view owner, check exact source
identity on each step, and never collects the collection's IDs. Seeking again
from the bound is sufficient initially; a later bounded page/path cursor can
preserve this contract. The canonical query and ordered-seek APIs use this
source directly, with no parallel map-access fallback.

Before adding fallible disk sources, give the query worker/output an owned
source-error channel distinct from typed query validation and cancellation
errors. Preserve the original storage or explicit view-close error and its
custody through canceled waiters and shutdown; converting it to a query error
string loses that ownership. This seam changes document access and candidate
body lifetimes, not the resident structured or text index implementations.

The applied test-only worker adapter now passes nine real encrypted-view cases
plus 39 existing worker/pool/cache-admission regressions on a matching 707-file
selection. It retains the original query grant/token, source failures and
registration through cleanup; successful claim transfers worker cancellation
authority without disabling original caller cancellation. Preparation checks
borrow the plan, so a memory-sampler unwind returns that exact plan and opaque
payload. Production `QueryWork` is unchanged; selected lint/formatting and
service activation remain open.

An exact selected-view fork is also required for independent disk query readers.
Current store view constructors capture the current native root. Their report
facades share one reader and cannot be closed independently. The underlying
native `ReadSnapshot` can clone the actual SnapshotPin, but a new reader needs
its own admitted snapshot Arc and census/close state: cloning the parent's Arc
would make each reader's descendant check wait for the other. Retain the exact
root/index pairing and recheck current key access; never substitute a fresh
current view for an older captured generation. A bounded per-Database directory
should identify only its exact workers in the existing strong census and drain
them before WorkFence/storage shutdown. This avoids a second unobservable owner
or a scan that drains other tenants' work.

The first actual map cutover must cover ordinary mutation, staged finalization,
recovery, history archival, schema validation/rebuild, bootstrap and semantic
snapshot/restore together. Route point reads, queries, ordered seeks and snapshot
leases through the selected view; replace `ReadIds` and retained body/divergence
maps with admitted root pins. Keep bounded IDs/sort keys/scores instead of
retaining every candidate body, and decode rows or aggregate incrementally.
Ordinary query execution must still produce the complete bounded result;
engine pagination, not this source adapter, applies the requested page size.
Count borrowed body/projection serialization against output capacity before
cloning it. Decode workspace and variable-size sort keys also need explicit
admission; a document byte limit alone does not account for JSON allocations.
The synchronous source seam cannot silently replace asynchronous archive
hydration. Qualify a synthetic source permitting only one live document loan,
including cancellation after reading, source errors and archived references.
Current archive hydration inserts a verified body into `documents` while
retaining its `archived_documents` reference. The initial source must deduplicate
that overlay and prefer its verified live body; dual presence alone is not
corruption. The durable cutover should retain a bounded hydration overlay on the
captured view rather than clone the collection. Unindexed predicate scans in
`structured.rs`, ordered seeks, snapshot reads and lease scans must all use the
same lending contract; changing only `execute` leaves direct body-map readers.
The current worker budget estimates 64 bytes per sort field per candidate;
variable-length strings and exact decimals need explicit charged capacity before
their sort/group keys are copied. A borrowed row/projection serializer must
enforce the output bound before cloning selected values.

The source tranche installs that borrowed serializer for query rows and retains
only candidate IDs, versions, sort keys and scores between loans. It does not
qualify the current workspace formula: the 128-byte candidate allowance misses
long IDs and container overhead, sort and group strings have variable length,
exact aggregate arithmetic can grow intermediate decimal allocations, and wire
bytes do not measure decoded JSON node allocation. Engine reservations already
support `reserve_additional` on the same admitted slot. The new query ownership
contract connects that facility to the worker and output lifetime. The following
typed-allocation slice replaces selected ID/String sort-key and row/page clone
estimates, while planner/group/decimal terms remain provisional. Do not
substitute a worst-case reservation of every candidate times the maximum
document size, which would reject ordinary small queries. Allocation-specific
accounting remains **incomplete** and C01/C04 remain open. Ordinary shared
point reads and asynchronous history hydration
still use their existing retained `Arc<Document>` path; converting them must
preserve shared-body lifetime and current key/access checks without introducing
an extra full-body clone.

`QueryWorkspace::ensure_peak(total_bytes)` and `QueryMemory<W>` now implement
the ownership foundation. The ledger separates current logical live bytes from
the peak allowance owned by its provider. Checked growth and admission denial
leave both counters unchanged on failure. Nested scopes preserve their input
baseline and earlier query outputs; scratch locals drop before an error or
unwind resets that scope. Invalid retained-output accounting destroys the
output before resetting the baseline. Releasing logical scratch never reduces
the provider's peak, and `into_workspace` transfers that unchanged owner.
`empty` takes custody infallibly so already-owned payloads can be placed before
the ledger in a struct before the first fallible baseline claim. Source loans
and owned source errors retain their separate admission responsibilities.

Canonical `execute`, `execute_with_cancellation` and `indexed_candidate_ids`
require the explicit ledger. Preflight precedes allocating scalar validation
and candidate construction. Candidate output is now an owned `Vec<String>`;
the maintained `imbl` index representation is unchanged. The initial query
estimate, 128-byte-per-candidate estimate and three-times-wire-output retained
estimate remain **provisional**, not decoded heap bounds. The provider retains
the entire admitted peak even when a successful query records a smaller logical
output allowance. Seek-paged queries (`"paging": "seek"`) use the same ledger.

Engine integration uses the existing reservation and grows its actual charge
only when the requested peak exceeds it, without taking a new operation slot
or adding a cache eviction policy. Request and selected-input owners precede
their memory owner during fallible preparation. Worker and uncollected-output
owners keep the charge through cancellation, panic and asynchronous access
release; post-worker `retain_workspace` preserves the peak. Snapshot queries
carry earlier outputs as a live baseline. Pre-worker archive planning uses the
same ledger, and hydrated IDs/new input metadata that escape into a read view
must retain their input credit rather than be released with temporary planning
sets. The owned archived-body reservations remain separate. The final 692-file
Engine selection passes 20 focused unit tests, six contract integrations, one
archived-prefix/restart integration and two schema integrations. Custody cases
exercise denied growth, cancelled preparation, prior output baselines, lease
expiry and abandoned worker output; the scan fixture uses the real selector
and retains its private scratch owner. All hashes match after the run. The
earlier compile and fixture-setup failures remain in the evidence ledger.

The query-only 18-file source selection passes all **65 query unit tests** and
strict all-feature/all-target query Clippy. Tests cover initial denial, growth
denial after prior admission, overflow, nested error/unwind, retained output
between sequential queries, denial before document loans and provider custody.
The evidence ledger records the commands, timings and matching source hashes.
`cargo fmt --all --check` also passes in 11.84s on the matching source. No
Engine/workspace strict-Clippy pass is claimed; existing audit dead-code
warnings remain. These selected passes qualify the ledger foundation,
not complete query allocation accounting,
resident indexes or the retained disk-source error census.

The next typed-allocation slice now passes **71 query unit tests and two
counting-allocator integrations** on a matching initial 20-file query selection.
Strict Clippy found two redundant test-only drops; the repaired test source
passes strict query Clippy and all 71 plus two tests again. Final review confirms
bounded request metadata has independent admission and allocation-free duplicate
checks. The corrected 695-file Engine selection passes **25 unit tests and nine
integrations**, including both new saturation regressions. All Engine hashes
and the final 20-file query selection still match. Final formatting passes in
**13.52s** on the matching corrected 695-file selection. `allocation.rs` borrows
JSON values to quote destination clones
without serializing, decoding or allocating a traversal buffer. It counts
String and arbitrary-precision Number lexeme lengths, array Vec slots and each
object's key/child heaps. The pinned non-`preserve_order` serde_json Map uses
std BTreeMap; the policy charges a complete maximum internal node per entry,
including unused slots and edges. Empty clones allocate no node in the pinned
Rust implementation. Every nonempty allocation request rounds to the next
power of two plus 64 bytes of policy slack. Checked arithmetic rejects overflow.
These are conservative destination-allocation charges, not an exact allocator
size-class or RSS census, and must not replace source-capacity accounting.

Selected vectors and each copied ID/String sort key claim their backing before
construction. Candidate enumeration borrows the maintained `imbl` tree and
admits both possible cursor stacks before iteration; consuming a shared tree
would otherwise collect leaves and clone shared leaf contents. Individual keys
and IDs release their logical claims only after destruction, while the selected
Vec backing stays charged until its consuming iterator drops. Row output uses
separate Vec and JSON clone claims. Flat projection keys and overlapping selected
subtrees each incur their own clone cost. Explicit map insertion avoids
`BTreeMap::from_iter`'s temporary collector and sort buffer. A bounded stack
decoder replaces allocating JSON-pointer token replacement in these query
paths, preserving validated escape, Unicode, empty-token and array semantics.
`Number::as_str` also avoids a formatting allocation during scalar preflight.

Engine pagination quotes the chosen row range and all aggregates before cloning
them. Fresh queries retain the full result and new page under the same operation
ledger; cursor handoff preserves its entire physical peak. Continuations keep
the old cursor's full-result charge and a separate operation ledger for their
new page. Cancellation, failed growth and pending asynchronous access release
must destroy the page before dropping its provider. Counting-allocator fixtures
measure zero allocations during sizing and compare actual clone requested-heap
peaks against the quote; both allocator integration tests pass on the new query
selection. The corrected Engine selection passes page and custody cases.

Review of the initial Engine source found an operation-count regression:
fresh `QueryResultOwner` keeps its ordinary operation count until after
`self.release`, while strict release submits an audit that needs an ordinary
slot. A query that uses the last available slot can therefore reject its audit,
although the prior path released that count before audit submission. The
applied correction calls `cursor_reservation` immediately after `clone_page`
and before the audit, including on a final page. It preserves all admitted
bytes through page destruction and leaves continuation behavior unchanged.
The new owner regression proves the handoff releases only the operation count,
preserves byte/ledger custody and leaves continuations unchanged. The actual
strict Database regression occupies 63 of 64 ordinary operation counts after
setup, then checks fresh cursor and final pages plus their durable release
audits. Both pass in the corrected-source run, together with the prior 23 unit
cases and nine selected integrations. The initial unsaturated pass remains
pre-fix evidence. No Engine/workspace strict-lint or full release pass is claimed;
existing audit dead-code warnings remain.

The typed-allocation boundary remains partial. Recursive candidate/text ID nodes, group strings
and nodes, accumulator backing, aggregate construction, decimal arithmetic and
formatting scratch still use provisional estimates. Tantivy scorers, fuzzy
automata, Lindera and other opaque library allocations require separate bounds
and measurement. Cursor token construction and Arc/map metadata are not fully
itemized. Complete egress ownership, ordered-seek admission, durable document/index
cutover and whole-runtime memory qualification remain open. The central
requirement is unchanged: keep all fitting data resident and move to disk-backed
reads only under pressure. C01–C07 remain open.

The following custody slice implements canonical `AdmittedOutput<T>` returns for
`Database::query`, `read_snapshot`, `read_snapshot_page` and `scan_snapshot_page`.
Private fields put the payload before its shared retained charge. Borrowing and
serialization are supported; there is no raw extraction, mutable dereference or
owner-clone API. The complete grown peak stays charged. Arc backing is admitted
before allocation, and `retain_workspace` releases the completed operation count
while keeping bytes and the ledger slot. The public handoff releases the work
registration, so an externally held result does not keep shutdown open.

Fresh pages share their full-result charge. Continuations retain two distinct
charges: the old cursor's full result and a new page/request charge. The pending
query owner keeps its own copy of that new charge through final authorization
and release failures; dropping the outgoing page first cannot uncharge the
still-live request. Both fresh and continuation preparation release completed
operation counts before strict audit submission. Snapshot outputs also become
admitted owners before their strict release checks.

The retained Engine charge is immutable after handoff because `CancelOnDrop`
cancels the completed operation's query token. Adapter conversion instead grows
an independently live `ResponseFence`, keeping the original admitted output
intact throughout the overlap. Native conversion separately quotes protobuf
vectors, strings and JSON buffers before constructing them. JSON encoding first
counts bytes, then writes into a buffer limited to that census; a serializer
changing between passes cannot grow the buffer without admission. Native codec
admission includes its 8 KiB initial buffer, conservative growth overlap and
fixed wrappers. The public `native_data_service()` factory always wraps ownership
across HTTP extensions, the lazy body and owner-backed emitted `Bytes`.
Detached HTTP parts and frame clones retain the same charge until their last
holder drops. Its raw protobuf handler is crate-private, preventing external
embedders from registering an unwrapped generated service or extracting a raw
direct-call protobuf response.

MCP retains the admitted source through SDK conversion and terminal body
materialization. Its admitted terminal buffer and source/fence owner accompany
the emitted bytes. Original source ownership precedes the adapter fence in
error and cancellation destruction paths. The 4096-byte wrapper allowance has
an explicit pinned-type inventory; it is allocation policy for these unary and
terminal paths, not a generic streaming bound or process-RSS proof. Authorization
stays at the existing native protobuf handoff and MCP post-materialization
boundaries; keeping memory charged does not renew authority.

The initial corrected transport selection passes 19 focused checks on a matching
698-file source/config selection, including real HTTP body/parts/frame custody
and credential-release failures. A test-only audit quiescence boundary reaps
completed authentication jobs before the exact response census; fitting native
cache growth remains allowed and separately measured. TLS and lint qualification
of the final opaque public factory now pass. Final runtime evidence comprises
17 passing public-boundary checks followed by the two corrected MCP census
fixtures and public-factory TLS integration on later source; it is not a single
final 19-test run. Both compile-fail API checks pass. Strict server Clippy
(`--no-deps`, all features and targets) passes in 241.88s and final
whole-workspace formatting in 4.64s, each with 698/698 selected source/config
hashes matching. Existing Engine dependency warnings remain; this is no
Engine/workspace strict-lint, full-release or full-fit cache qualification.
All failed and incomplete runs remain separate evidence.
Point reads (`get`/`get_shared`), collection listings and other public outputs
still require an ownership audit and canonical cutover. Thus qualifying these
four paths does not qualify all public egress or close the whole-runtime memory
gate. The separate change-feed ownership implementation now passes its selected
runtime, lint and format checks.

The follow-on change-feed migration addresses bare after-image document Arcs
that previously escaped after their local reservation dropped, and operation
counts held through strict audits. Merely wrapping the page is insufficient:
public after-image Arcs can be cloned out of the borrowed page without its charge.
The canonical public event now owns its document after-image, with an admitted
deep clone; persisted records keep their internal shared Arcs. The SDK decoder
constructs the owned document directly, preserving wire JSON. Event/cursor
backing and iterator workspace are claimed before construction. A private owner
holds the captured generation through preparation and strict release, retires
the completed operation count before audit, and carries the admitted page into
the native frame owner. There is no MCP change-feed endpoint.

Selected feed checks pass four Engine unit cases across two runs, two history
integrations, three measured-allocation cases, four SDK feed cases and three
native/SDK transport cases. They cover retained pages after source destruction
and shutdown, strict release at the operation limit, restart/cursor/gap/scoped
deletion semantics, exact literal values and final frame/parts disposal. An
actual public cancellation test proves that the prepared page and release future
retire while an admitted durable audit keeps its own charge and work registration
until completion. The request allowance and three-times-result physical floor
remain provisional; these checks do not qualify complete source heap accounting
or full-fit cache behavior. All run details and the initial fixture compiler
failure remain in the evidence ledger.

Strict all-feature/all-target Clippy for Types, Query, Client and Server passes
in 357.79s; final whole-workspace formatting passes in 13.31s, both with 699/699
selected source/config hashes matching. Existing Engine/dependency warnings
remain. Engine/workspace strict lint and the complete release gate remain open.

The next applied point slice returns `AdmittedOutput<Document>` from `get`
and immutable `SharedDocument` from `get_shared`; its selected qualification passes.
The shared handle clones both document custody and charge ownership, exposing
only borrowed document access. A raw `AdmittedOutput<Arc<Document>>` would allow
an autodereferenced Arc clone to escape its charge. Point work registers before
the consistency barrier, claims clone/owner backing before allocation, retires
the operation count before strict audit and retains registration through the
outer audit. Native and MCP Get retain the admitted source through conversion
and final frame disposal. Catalogs still need typed schema/definition clone accounting and
registration through final audit. Control-plane catalog lookup and topology
decoding should borrow these outputs; a decoded topology also needs its own
ownership. Schema/policy readback, activation status, mutation receipts, staged
status and snapshot-lease headers remain additional raw-output inventory items.

The shared-document boundary now lives below Engine and SDK. A private
shared owner exposes only `&Document`; cloning the handle shares the real source
and admission together. Engine can retain a cached document and its source
custody, while the SDK bridge reuses its existing admitted decoded owner.
There is no ownerless `Deserialize`, default, raw-Arc extraction or dummy
charge path. The downstream provider trait is a documented trusted-producer
contract, not compile-time proof of accounting. Cold archive handles retain
the actual decoded-chunk cache and its charge after the read future ends;
hot handles keep their selected document without retaining an entire generation.
The SDK bridge does not add a typed point-read network endpoint. The same
702-file source selection passes six Engine unit cases, eight integrations,
three compile-fail API checks, four allocator cases, the SDK bridge test and
19 selected Server cases. Strict Types/Query/Client/Server Clippy passes in
384.58s and final formatting in 17.39s; all selected hashes match. Existing
Engine/dependency warnings remain, and whole-runtime/release qualification
is still open. These runs qualify the selected output boundary, not source
capacity accounting or a typed SDK Get network corridor.

That output boundary alone does not complete resident document accounting.
Clone sizing by lengths cannot measure retained String/Vec spare capacity or
private number storage. The final document source needs one admitted owner per
physical allocation, installed during construction or decode and shared by cache
membership, version pins and returned handles. Repeated shared reads then reuse
that charge. The existing point-read workspace floor remains provisional until
this source cutover; do not present a lifetime wrapper as exact heap accounting
or evict fitting data to compensate for duplicate per-read charges.

The concrete next source boundary should use one growable resident document
pool with inline credits, following the native cache pool's ownership pattern.
Creating a separate governor reservation for every document would exhaust the
fixed reservation-slot census before using the intended large byte budget.
Generations, feed records, archive runtime chunks, hydration overlays, leases
and returned shared handles must all clone the same physical document owner.
The pool's initial reservation and every growth must preserve the installed
foreground cache headroom and ordinary-operation maintenance protection,
including their reservation slots. General resident admission does not enforce
those floors and is insufficient for this source pool. Pool control accounting
must include synchronization backing as well as the inline Arc allocation;
destroy all of that backing before returning the final provider reservation.
The applied test-only pool component now exercises these requirements: its
11 new cases and all 28 selected existing worker/cache-admission cases pass
with 705/705 source/config hashes matching. Four Query allocation checks,
strict Query Clippy and whole-workspace formatting also pass on that selection.
No production constructor or
document producer uses this pool yet; these results do not account the current
resident maps or qualify full-fit serving.

A clone-only source factory can avoid adopting unmeasured spare capacity. It
must preclaim the known destination clone bound and concrete owner backing,
then construct a compact immutable document. It must not quote a borrowed
document's lengths and adopt its arbitrary existing String/Vec/number backing.
Wire records may contain ordinary documents only under admitted decode
workspace; normalizing those records into runtime owners must preserve both
charges through the overlap. Runtime state containing charged handles must
have no ownerless deserializer. Snapshot and cold-history decoding therefore
need explicit pool and workspace context before repeated point-body charges
can be removed. This can precede replacement of the resident primary maps;
it does not itself provide disk serving above the bound.

Local source-admission denial during replicated apply must remain an outer
preparation/publication failure. It must not become a deterministic mutation
or staged rejection receipt, because local memory pressure differs by replica.
Use a distinct source-admission error through mutation and staged preparation,
before the existing publication callback. The existing Raft fatal-apply path
retains the original failure and leaves the applied cursor unchanged; the
committed entry remains durable for fenced drain/reopen/replay after capacity
is available. This does not imply rollback or automatic in-place retry. The
source-owner step alone still cannot recover a resident dataset exceeding its
budget; the later durable document/index cutover remains required.

The index-construction seam now uses an ordered `CollectionRecords` source
without an index requirement (new collections cannot already own their indexes)
and replayable `DocumentChanges` loans of `{ id, old, new }`. Each delta lends
at most two live/archive records and binds both exact source identities and
definitions. Its strictly ordered, deduplicated changed IDs must come from the
trusted mutation journal; repeated mutations of one ID produce one original
and final pair. Every pass must observe the same pair. Incremental unique
updates first remove **all** old mappings, verifying each maps to its expected
ID, then insert all replacements in a second pass. A live-to-archive transition
retains logical IDs and declared structured fields. Rebuilds consume ordered
rows directly, including text row assignment, without a full ID vector and sort.

Canonical `QueryIndexes::{build, update, validate_unique_changes}` now use these
inputs together with definition/document validation and text-field change
detection. Unchanged, delta, rebuild and removal are explicit actions; missing
change information is an invariant error rather than a rebuild fallback.
Initial Engine adapters borrow existing collection roots and the bounded
mutation journal, including both live and archived roots. They do not copy
document bodies or retain an old production map overload. Integration covers
ordinary mutation, staged uniqueness/materialization, recovery,
bootstrap/reconstruction, schema changes and snapshot validation; focused
qualification is in progress.

Checked inputs retain the original source owners, definitions and prior index
owner across preparation and materialization. A fixed 256-byte continuation
checks strict ID ordering; a streaming digest compares the replayed IDs,
presence, kinds and versions without retaining an ID vector or rehashing full
bodies. Immutable payload stability and complete mutation journals remain
source responsibilities. A definition fingerprint binds a delta to the actual
prior index definition. Two-phase index updates finish every collection's
deterministic validation and private structured/unique preparation before
advancing shared text writers. Engine acceptance budgets still precede this
effect; later failures remain outer failures requiring fencing. This source
seam does not move postings, unique maps, Tantivy state or row directories to
disk, and its collection metadata and allocation admission remain part of the
open memory-accounting work.

The existing `admission::snapshot_work` foundation retains the actual blocking
child, output and original failure in an admitted census. It has no production
query adapter yet. Merely changing `QueryOutput` or `SnapshotOutput` to carry an
`anyhow::Error` is insufficient: an abandoned join handle eventually destroys
that output. Adapt the retained operation owner before installing a fallible
disk source, including explicit source-close failure and unclaimed output
cleanup; uncertain native ownership stays retained. A resident-only adapter
cannot be used as evidence that this failure path is qualified.
The initial resident adapter can use `Infallible` as its source failure type,
with canonical `ReadFailure<E> { Query(Error), Source(E) }` query results.
Production workers must eliminate `Source(never)` with exhaustive
`match never {}`. Installing any fallible source then deliberately breaks those
sites until retained worker ownership is wired; a blanket message conversion
must not let that cutover silently discard the original error.
[`snapshot_codec`](../crates/kasumi-engine/src/snapshot_codec.rs) must continue
streaming semantic records, not export local physical page references. Existing
secondary/text indexes may temporarily consume deltas while preserving features,
but that remains partial: the structured-workload bound requires disk primary,
typed and unique indexes, with text and remaining histories still outstanding.

Bounded construction is required before that cutover. Allowed staged input is
64 MiB; [`TenantStore`](../crates/kasumi-store/src/lib.rs) batches are also capped
at 64 MiB, and the native bound is 96 MiB. Encryption, changed paths and index
fanout can exceed these bounds for valid input. Current replacement visitors
in [`replace_domain`](../crates/kasumi-store/src/read_view.rs) stream source rows
but still accumulate the whole replacement in native
[`Pending.writes`](../crates/kasumi-kv/src/tables.rs). They therefore cannot
install arbitrarily large valid tables within the native transaction bound.
Receipt, terminal and target-resolution restore already choose fresh UUID
namespaces: fill these in bounded commits, then activate their catalog bindings
with the snapshot manifest and custody cursor in one small final commit. This
requires exact durable staging-attempt ownership and bounded orphan reclamation,
not a resident map of imported keys. Current
[`custody records`](../crates/kasumi-raft/src/custody_records.rs) instead replace
fixed `raft.custody-commands` and `raft.custody-audit` namespaces. Add a selected
generation binding for those names before allowing prepublication staging;
writing directly into the live namespaces would expose partial replacement.
The same bounded staging/root-activation prerequisite applies to later document
and index construction, without lowering existing input limits. Obsolete
application keys must cease being live to native warming while old selected
snapshots remain readable. This restore work is separate from the initial
callback barrier; neither phase may claim all staged bytes were one physical
transaction.

The structural snapshot lookup index now batches only its offset and group
metadata through the existing bounded encrypted scratch transaction. It flushes
before each record-kind transition so references to earlier kinds remain
visible, and after complete framing validation before exposing the private
index. Pending failures abort; previously committed batches remain unpublished
scratch. This removes per-entry commits from that construction pass. It neither
implements the durable namespace activation described above nor eliminates
per-entry writes in other semantic verification tables. Failure, cancellation
and ownership checks pass. Initial encrypted 32-collection restore runs exceed
their unchanged verification deadline; the later native leaf-prefix source
passes the selected full restore, as detailed below.

When an independently validated snapshot has no history archive records,
`relocate` now preserves its exact image and indexes. Validation already proves
there are no dangling archived references and the archive metadata count is
zero, so changing the destination/session cannot change any record. The path
retains the live check, reservation handoff and final live check; the caller
still rechecks current access. Its focused custody/failure tests and encrypted
restore results are separate: both new unit tests pass, but the integration
retry still exceeds the original deadline. That fixed-field trace, after
the bounded native root-leaf merge, starts structural-index construction with
59,288ms remaining. The restore guard ends at 60,005ms, and no snapshot semantic
section or relocation begins. The subsequent bounded leaf-prefix editor passes
the same selected integration: actual restore takes 25,066ms under the unchanged
60,000ms deadline, including 18,937ms structural construction, 19,675ms total
application validation and 0ms relocation wait at timer resolution. This
qualifies the selected regression while broader restore performance remains open.
Images with archive records retain the existing rewrite and revalidation path.

Restore parity also exposed a separate, pre-existing causal-state bug:
`target_resolution::Builder::push` and
`snapshot_validation::validate_target_resolutions` used duplicate-rejecting
`insert` for the mutable per-incarnation causal cursor. Both now use `set`
only for that cursor. Immutable row and ordinal identities still reject
repetition. A shared fixture constructs two valid linked seals through the
completion state machine; both restore paths have positive and missing/wrong
predecessor tests, plus duplicate identity rejection. Source digests are
recomputed around malformed candidates so failures exercise semantic checks.
All four new causal regressions and the existing earlier-seal rejection now
pass, using 64-slot fixtures under the unchanged 64 MiB cap. This issue is
independent of the encrypted schema-restore timeout, whose snapshot contains
no such target rows.

Opt-in DEBUG timing at `kasumi_engine::restore_phase` now distinguishes gate,
session/graph verification, structural/semantic passes, relocation, genesis
materialization and publication. Waiters and their blocking workers have
separate timers. Events contain only fixed labels, a local numeric correlation
ID, elapsed milliseconds and time remaining from the original deadline. A
guard dropped by early error, cancellation or unwind emits `unfinished`, which
makes no statement about rollback. A blocking-worker guard ending likewise
does not independently prove that all resource owners have drained; that needs
ownership/census evidence. In the latest failed restore, the wait guard ends
after 59,306ms, while structural and worker guards end after 64,162ms and
64,180ms of their respective lifetimes. The disabled target retains no timer state.
The later passing leaf-prefix run records successful structural and worker
guards and completes the selected restore with 34,933ms remaining. Phase
success alone still does not replace ownership/census assertions.
The selected integration test can enable an exact-target global subscriber with
`KASUMI_TEST_RESTORE_TRACE=1`; the daemon's logging policy is unchanged. A direct
32-empty-collection index fixture separately measures capture, construction,
lookup and teardown, including exact resource drain. No deadline, cache budget
or crypto/optimization profile was increased to obtain these diagnostics.

Qualify three separately reviewable slices:

- Prepared publication: faults before commit, ambiguous commit, failure before
  Generation release and exact replay, covering success, rejection, metadata
  and retirement effects, standalone entry points, Authority, audit-scope
  lifetime, async waiter cancellation and failed text materialization. Exercise
  missing commit, swallowed failure markers, duplicate attempts after success
  and failure, caught commit unwind, backend failure after commit, and joint
  publication/backend errors with exact downcast and owner-drop custody.
- Reader/delta parity: unique swaps, Missing/Null and decimal ordering, long
  keys, cancellation, predicate validation and output limits.
- Durable map cutover: cold reopen, zero backend reads for a fitting warmed
  state, old-snapshot overwrite/delete, expiry on hot reads, staged finalization,
  archival, schema changes and bounded streamed restore.


### Planned primary selection and readiness boundary

The next persisted-primary implementation will validate its compact expected
root/catalog/producer identity in the same immutable paired application/custody
view as the canonical selected-application proof. The producer supplies the
actual Bootstrap, Entry or Snapshot boundary; a physically newer projection
found on disk is not evidence that sealed reconstruction has completed. Primary
pages, DTO chunks and manifests will be immutable, with bounded staged writes
and a durable attempt/inventory journal; current catalog point mappings remain
versioned by the native snapshot. This format/installer is still a draft, not
production document serving.

The selector does **not** need a persistent Reconstructing/Serving flag. Its
reserved byte must be zero. Readiness remains the existing in-memory
SourceRoots/startup transition: complete both root and custody proof before
settling a selected generation, refuse non-frozen covered reconstruction at
handoff, and recheck that condition under the same gate when an in-flight
capture settles after handoff. No fresh-current recapture or promotion write
is required. An asynchronous portable checkpoint can replace the current
custody representation of an Entry with a same-position Snapshot while an
older exact Entry pin remains valid. That checkpoint must never change the
primary selector/catalog/journal. A new promotion write would create an
unnecessary race with that checkpoint and complicate the established apply,
state and control lock order.

Primary Scope must use the receiving database's original authenticated
bootstrap digest, alongside tenant and incarnation. Live Snapshot installation
keeps that Scope; its actual backend/envelope identity belongs to the boundary
proof. Newly authorized incarnation/target bootstrap uses its own authenticated
Scope. Frozen retirement remains a terminal application boundary and never
grants ordinary document-serving permission. These decisions preserve the
full-residency requirement: none introduces demand-only caching or early
eviction for fitting data. Actual persisted producers/readers, complete
ownership accounting and full-fit/over-budget workloads remain open.
