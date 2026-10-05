# Archived disk-backed-cache implementation checkpoints

This preserves the goal document immediately before the 2026-10-02 status
consolidation. Consult [current goals](disk-backed-cache-goals.md) for present
status. All content below is historical and retains its original source-specific
scope; no open requirement is waived by archiving it. Original document SHA-256:
`f720f2e891ec86c687e26feb4ecc6da2fcf07e03550f288d56209381afd21237`.

---

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

## Current primary-storage component progress

The encrypted selected-primary point reader and fixed page/manifest staging
components pass a combined 51-case source selection. Reads bind catalog,
manifest, pages and document chunks to the exact selected native snapshot;
current storage access is checked even on no-I/O misses. Staging atomically
journals each fixed object and its counters, and cleanup resumes in bounded
steps while refusing corrupt or impossible progress. These components remain
under `cfg(test)`. Production reads still use resident documents and indexes;
atomic primary publication, a bounded builder/editor, index storage and full
fitting-cache retention must be integrated before pressure eviction is enabled.

Fresh catalog staging now has a fixed-size membership record and bounded
construction, verification and abort steps. Membership names remain separate
from snapshot-versioned manifest mappings. All nine catalog cases and the
prior 51 source/reader/staging cases pass on their matching 779-file selection.
The bounded collection builder remains under `cfg(test)` and its eleven new
tests pass on their matching 783-file selection. The deeper recursive-frontier
test also passes on its matching 787-file selection, traversing all 52 actual
encrypted pages. These components do not yet authorize a production selector
or prove the accepted application projection.

The native protected-pin foundation passes 489 unit and 31 integration tests
on its matching 787-file selection. Its retained-read follow-up and warm-up
release correction pass 514 unit and 27 selected integration tests on a
matching 802-file selection. Outputs released during an unfinished pass now
request another refill attempt without making oversized passes spin.
Core and Database can prepare actual backing before capturing the current root;
two protected physical lanes transfer exact pins to ordinary history. Canonical
retained-reader disposal observes final native failures and preserves Database
custody. Protected acquisition is not yet activated through Store or Engine,
and source-byte capacity is still open.

The accepted-application owner now retains the actual apply guard, previous
and final generations, and existing changed-ID map through publication. Its
six new semantic tests pass on a matching 789-file selection. Later receipt
qualification passes 35 active producer/caller checks on matching 805-file
selections; this does not provide candidate allocation funding
or authorize primary serving. The constructor-owned native and encrypted-read
quotes pass five tests on a matching 795-file selection, including actual
temporary-buffer overlap with cache retention disabled. Quotes do not reserve
capacity. Forty selected Store reader, fork, retirement and quote cases now
pass on a matching 801-file selection, including the enlarged actual read-report
layout. Standing source funding and Engine integration remain open.

The Engine Entry path now requires an opaque receipt bound to its live
publication invocation and exact prepared source plan. Thirty-two Raft
selection/publisher cases, five lifetime checks and twenty-eight Engine
source/quote/allocation-tail cases pass on their matching 805-file selections.
The receipt binds actual paired effects before source capture, but does not
verify accepted primary graph semantics or integrate bootstrap/snapshot
publication. Standing source capacity and the broader recovery route remain
open. The recovery route has progressed beyond its stack abort. One retained
failure is localized to physical storage acquisition returning `InvalidData`
before native database opening. Other runs stall during quorum resolution,
with no outcome and divergent election terms. The latest full run reaches a
leader-barrier timeout without a physical-acquisition failure marker; its
evidence does not identify which reopen/checkpoint was active. Passing a point
on a later run does not establish a repair. Both investigations preserve the
original timeouts and capacity.

The native source funding implementation now reserves two logical publication
assignments through the actual installed MemoryCore. It retains charges through
native allocation cleanup and exchanges an old reader to ordinary history
funding before reusing its assignment. Ten native protocol cases, nine actual
provider/allocation cases and three privacy doctests pass on their matching
814-file selections. The native regression run also passes 524 unit and 27
selected integration tests. The Store bridge remains test-only; registered
reader/census funding, encrypted content checks and production source activation
remain open.

The registered source funding follow-up now couples the real MemoryCore to
control, metadata, reader and census ownership. Eight census cases and four
owning-layout quote cases pass on a matching 830-file selection; eight Engine
lifecycle cases and an actual five-target allocation-retirement case pass
within the initial matching 831-file combined run. After correcting its
separate COW fixture runtime and two test-only lexical scopes, all 32 selected
Engine cases pass on the corrected 831-file selection, including two further
actual contention cases. The complete new corridor remains under test/test-utils.
Default Store strict lint, default Engine compilation, corrected all-feature
Store strict lint, two metadata privacy doctests and 128 active Store
reader/census/quote regressions also pass on their matching 831-file selections;
one pre-existing Store helper is ignored. Corrected all-feature/all-target
Engine Clippy also passes with its existing audit dead-code warnings retained.
This does not yet fund encrypted source loans or activate application eviction.

The accepted existing-key primary update verifies an initial graph once, then
copies and verifies only the affected path while sharing unchanged pages. Its
ten new tests pass on a matching 821-file selection, including accepted/source
identity, real row-diff completeness, bounded staging/abort, corruption refusal
and allocation retirement. The first implementation remains test-only and
excludes reconstructed baseline authority and production publication. Two
synthetic recovery tests now pass on the 831-file selection: two uncertain
staging batches and three uncertain abort boundaries. They preserve original
errors, complete durable batches, old document/inventory records and exact
replayed source identity; incomplete replay is still refused. Both tests and
all ten preceding COW cases pass again in the corrected 32-case run noted
above. Installed crash coverage, insert/delete editors, committed reclamation
and the remaining application/index cutover are still required.

The next publication prerequisite records the actual Raft producer origin in
the invocation-bound plan. Its advancing-only test API rejects CoveredReplay
before new application writes while keeping exact replay reads valid. All
33 selected Raft publication/selection cases and 28 Engine source/quote/lifetime
cases pass on their matching 831-file selections; measured enclosing owner
sizes are unchanged on this target. Strict Raft default and all-feature lint
also pass. Final atomic primary replacement, pre-staging predecessor checks
and captured graph verification are now applied under tests with eight new
cases. After correcting the test-only cancellation constructor and asserted
native admission error type, all 20 selected COW preparation, publication and
recovery cases pass on their matching 834-file selection, including final
uncertain-commit recovery. All-feature/all-target Engine Clippy and default
Engine compilation also pass on matching 834-file selections, retaining existing
audit warnings. Production command/response provenance, retained completion ownership,
all edit kinds, initial/recovered baselines and document/index activation remain
open; the current primary publisher is a closed test fixture.

The next production ownership slice is now applied: the Command dispatcher
checks exact raw bytes against their recorded digest before any prefix decoding
or staging, and ordinary preparation keeps the real reducer's response, borrowed
context and accepted-or-frozen apply owner together. COW fixtures now use that
same producer. After correcting the target fixture to assert its actual early
InvalidArgument input rejection, all 60 active selected cases pass on the
matching 837-file selection; one pre-existing capacity cohort stays ignored.
This includes all six new production-owner cases. The separate
retirement-seed encrypted reopen passes, while the full retirement integration
fails earlier during archive_history. Its retained original is ResourceExhausted
from the 8 KiB document-source cell reservation: charged work plus required cache
headroom exceeds the configured limit by 38,191,738 bytes. Slots and RSS are not
exhausted. Temporary diagnostics were removed after retaining the measurement;
publication capacity must be owned before competing work is accepted.
All-feature/all-target Engine Clippy also passes on the corrected
837-file selection. This does not activate primary storage, establish full
context authenticity before preparation, or solve the outer completion lifetime.

A narrow production native-read change now fills the already-admitted output
directly when optional cache retention is refused. Normal fitting retention,
frequency/recency policy, immutable zero-copy readers and owner/CRC checks are
preserved. It removes the redundant temporary value workspace and fixes direct
load counters. After correcting the fixture's final cache-owner retirement,
all 534 native unit and 27 selected integration tests pass on matching 839-file
selections. Four encrypted-read quote tests, default Engine compilation,
all-feature/all-target native/Store/Engine strict lint and workspace formatting
also pass. All 60 active selected Engine mutation/publication/recovery cases pass
again with this native change on the composed 839-file selection; the existing
capacity cohort remains ignored. This does not fund cold descriptors or protected
source loans, or enable application document/index eviction.

The backup cancellation regression remains open. Exact diagnostics show an
8 KiB mandatory source-control reservation fails because already admitted
ordinary work plus required headroom exceeds the configured byte limit. The
new actual-metadata quote does not solve that publication-capacity obligation.
Keep the limit/headroom unchanged and own publication capacity before accepting
the competing work. This is not slot exhaustion or observed RSS pressure.

## Goals and completion criteria

All implementation goals below are open. Recording this plan does not qualify
the current source or close any existing release gate.

Installed-runtime qualification exposed a physical disk prerequisite:
directory-file allocation can exceed logical EOF rounding on the local APFS
volume. The implemented required standing file-allocation policy now funds
that overhead before I/O and retains it across close/reopen. Focused allowance,
backup restart, node cache-worker handoff and parallel signer tests pass;
broader validation remains in progress. The [design](disk-backed-storage-design.md)
and [evidence ledger](evidence/disk-backed-cache-20260930/README.md) retain exact
measurements and failed runs. This is fixture coverage, not a qualified bound
for every filesystem operation or completion of any cache goal.

The current C04 prerequisite introduces one prepared publication callback across
Raft, Engine and Authority. Engine keeps its candidate generation private until
the callback commits; Authority publishes its prepared rows with the custody
cursor atomically. Failure custody and exact replay are being validated. This
does not yet replace resident document maps or indexes. The current tranche changes
query, ordered-seek and snapshot body reads to a collection-scoped lending
source bound to the exact captured generation. Candidate results retain IDs and
versions rather than shared document handles. Its initial adapter still reads
resident maps; durable sources, index storage and variable-size query workspace
admission remain open. All seven goals remain open, and the full-residency
requirement above is unchanged.

Index construction and mutation preparation now consume ordered borrowed rows
and replayable old/final document pairs through their canonical APIs. Explicit
catalog actions replace the missing-delta rebuild fallback, and all collections
complete private validation before any shared text writer advances. Engine
adapters still borrow resident roots; focused verification of this next source
slice passes its query and Engine adapter/publication checks. Persisted
document/index storage and full memory accounting remain required before C04
can close.

The query-workspace ownership slice now provides an explicit `QueryMemory`
ledger with checked growth on one retained provider, nested live baselines,
denial/unwind handling and peak custody through output ownership. All **65
query unit tests** and strict query Clippy pass on the verified 18-file query
selection. The final 692-file Engine selection passes **20 unit checks and nine
integrations** covering custody, contracts, archive/restart and schema behavior;
both source selections still match after testing. Formatting also passes;
earlier compilation and fixture failures remain recorded. Engine/workspace
strict lint and full release qualification remain open.
The following typed-allocation slice passes **71 query unit tests and two
counting-allocator integrations** on its verified initial 20-file query selection.
Strict Clippy then found two redundant test-only drops; after their removal,
strict query Clippy and all 71 plus two tests pass again on matching selections.
Final review confirms bounded request metadata has independent admission and
allocation-free duplicate checks. The corrected 695-file Engine selection passes
**25 unit tests and nine integrations**, including both new saturation regressions;
all Engine hashes and the final 20-file query selection still match. Final
formatting passes in **13.52s** on the matching corrected 695-file selection.
Review found that a fresh query
kept its ordinary operation count through strict audit release, which itself
needs an operation slot. The applied correction releases that count immediately
after page cloning while retaining every admitted byte. Passing owner-level and
strict Database saturation cases now cover that correction; the initial passing
run remains explicitly pre-fix evidence. No Engine/workspace strict-lint or full
release pass is claimed; existing audit dead-code warnings remain.
Selected ID and String sort-key copies, their Vec backing, borrowed candidate
traversal, row JSON clones and Engine page clones
now claim destination allocation bounds before allocation. The JSON walk counts
nested string/number backing, array slots and conservative BTreeMap nodes,
including separately copied overlapping projections. Rounding and metadata
slack are admission policy, not an RSS guarantee; allocator tests measure
requested heap only. These selected passes do not qualify whole-runtime memory.

Recursive candidate trees, group keys/accumulators and aggregate construction,
decimal scratch and opaque Tantivy/Lindera allocations remain provisional.
Cursor tokens, remaining Arc/map metadata, ordered-seek admission, durable
document/index cutover and complete public output ownership remain open.
This adds no cache eviction policy:
full residency for fitting data is still the central requirement, and C01–C07
remain open.

The next implemented slice introduces canonical `AdmittedOutput<T>` returns for
queries and the three snapshot read/page methods. Payloads retain their actual
peak admission through public handoff, while completed operation counts and
work registrations are released. Continuations preserve their own page/request
charge independently from the old cursor's full-result charge, including final
release failures. Native RPC and MCP keep the original source intact through
conversion and use a separate live response fence for added representations;
the body, detached HTTP parts and last emitted frame clone retain both owners.
The corrected Engine selection passes **30 unit tests and nine integrations**
with **556/556 source hashes matching**. The initial corrected transport
selection passes **19 focused tests**, with **698/698 source hashes matching**.
Final API review closes a public construction bypass by making the raw native
handler private and exposing an opaque service factory with mandatory custody;
selected qualification records **17 public-boundary passes**, followed by
**two corrected census passes and the TLS integration on later source**, plus
**two compile-fail API checks**. These are separate runs, not a single final
19-test pass. Final strict server Clippy and whole-workspace formatting pass
with **698/698 selected hashes matching**; existing Engine dependency warnings
remain, and no Engine/workspace strict-lint or full-release pass is claimed.
Earlier test-fixture failures and an incomplete broad run remain in the evidence
ledger. Point reads, shared document handles, collection listings and other
outputs still need canonical ownership work. The separate change-feed ownership
implementation now passes four focused Engine unit cases across two runs,
two history integrations, three allocator cases, four SDK feed cases and three
native/SDK transport cases. The new public cancellation test preserves an
independently admitted audit child after its caller drops. Selected source
hashes match. Strict Types/Query/Client/Server Clippy and final formatting pass
with 699/699 selected hashes matching. Its request/source sizing limits and the
durable document/index cutover remain open. All C01–C07 remain open.

The following point-output slice passes its selected qualification.
Owned `get` returns an admitted document and `get_shared` returns an immutable
handle whose clones retain source custody. Cold handles retain their decoded
archive cache and real reservations; hot handles avoid pinning the complete
generation. Native/MCP Get carry the source through frame disposal. Six Engine
unit cases, eight integrations, three compile-fail API checks, four allocation
checks, one SDK bridge case and 19 selected Server cases pass on the same
702-file selection. Strict Types/Query/Client/Server Clippy and final formatting
also pass with every selected hash unchanged. Existing Engine/dependency
warnings remain; Engine/workspace strict lint and full release gates stay open.
The existing source-size floors remain provisional, and repeated shared reads still need
the aggregate per-allocation document-pool cutover. These changes do not add
disk-backed document/index serving or close any goal.

An aggregate document-pool component is now applied under `cfg(test)` only.
Its 11 cases and 28 existing worker/cache-admission regressions pass on a
matching 705-file selection. Thousands of immutable documents share one real
growable reservation; allocation and final-release checks preserve both
foreground and ordinary protected capacity. Four Query allocator checks,
strict Query Clippy and whole-workspace formatting pass on the same matching
705-file selection. Production constructors,
wire/runtime separation and document producers still need the pool cutover;
the component adds no cache policy or disk document serving.

The following retained fallible-source worker component passes nine new cases
and all 39 selected pool/worker/cache-admission regressions on a matching
707-file selection. It reuses the query's original grant/token and preserves
source failures, cancellation handoff and preparation-panic custody. Selected
Clippy subsequently found two test-only lints, now corrected; rerunning the
affected tests and lint on the corrected source remains pending. Its adapter
remains test-only; actual source
provenance, per-Database drain integration and independent readers of an exact
selected native snapshot are still required before production activation.

The logical primary-page codec and production borrowed metadata/genesis
validation slice are applied. All-feature/all-target caller compilation passes
across Types, Query, Client, Engine, Server and Bench with 711/711 source hashes
matching. The codec remains test-only and has no I/O or publication path.
A subsequent reviewed API change makes resident indexes and the document-source
adapter private; existing fixture queries use the exact captured generation.
Component tests and caller qualification of this later source are in progress.
Raw generation state and admitted Control document observations remain open.
These boundaries prepare the durable source replacement; they do not establish
disk-backed document/index serving or full-cache residency.

The following 711-file component run passes 59 of 61 tests and fails two new
fixtures: metadata setup exceeds its 32-slot provider while opening an
unrelated receipt table, and a malformed-page test expects the wrong rejection
for a partially changed length. Test-only corrections retain the same limits;
all 61 component tests now pass on the corrected 717-file selection. Exact
native snapshot forks and their charged
backing ownership are now applied, alongside borrowed Control validation and
streaming enrollment hashes. The 713-file selection passes all 484 native
unit/integration checks and seven topology tests. Its Store selection passes
22 of 24 tests; two stale output-charge fixtures are corrected without changing
limits. The registered/paired encrypted fork layer is now applied, with ten
new tests passing on the later 717-file selection. The remaining targeted-denial
fixture exposed a collision with an optional cache allocation; keeping refusal
armed through the operation resolves it. Four affected accounting/failure
checks pass on the corrected source. Four Engine integrations, six Server
tests, Engine/Query Clippy, strict affected-package Clippy and workspace
formatting also pass with all 717 selected hashes unchanged. Existing Engine
audit warnings leave its strict-warning gate open. A URL-only
workspace quote passes nine selected Types tests and the isolated cold/warm
allocator test on that same selection. The next applied slice uses it inside
an admitted local Control topology decoder and independent output/failure
owner; only borrowing management consumers migrate. A checked plaintext-get
workspace quote is also applied for future selected reads. Their focused
722-file qualification passes the selected Store, Types, Engine and Server
tests, Engine/Query Clippy, strict Types/Store/Server Clippy and formatting.
The evidence ledger retains the test fixture stack failure and equivalent
memory-quote lint repair. Consuming Control producers and actual selected
primary readers remain open. A canonical selected-application metadata proof
is now applied: its initial eight focused tests, 34 Raft regressions and seven
Engine bootstrap tests pass. A later failure-representation repair passes nine
focused tests, strict Raft/Store Clippy and formatting, each with its matching
728-file source pin. The next local Control ownership, Raft source-lifecycle
hook and file-key factory sizing batch is applied and undergoing 734-file
qualification. Its eight Store and 35 Raft checks pass. After recorded
test-assertion and startup-import repairs, six Engine unit checks, two Control
integrations, six Server checks, caller compilation, selected package Clippy
and formatting pass, each with its matching source pin. Existing Engine audit
warnings leave Engine/workspace strict-warning qualification open.
Routine reader diagnostics are now applied and undergoing 736-file qualification:
original reports can outlive positively disposed native reader custody while
their own credit remains retained. Unknown outcomes still retain native custody.
The production Engine source registry and primary publication
are still required before eviction is safe.
Selected-root publication, admitted semantic outputs and document/index cache
integration remain open. No cache goal is complete.

The selected-source lifecycle now pairs root, cell, view and original-failure
handles with external source credit, including weak allocation tails. The Raft
callback binding frees its Box before releasing that credit. A canonical opaque
diagnostic handle prevents raw Weak escape and frees its shared issue allocation
before destroying its original error; its actual allocator and API-boundary
checks pass. All seven Engine source allocator cases, their selected lifecycle
checks and 11 Raft source-custody cases pass on the corresponding recorded source.
The later prospective source preparation is undergoing integration qualification.
Enclosing anyhow error boxes and diagnostic collection backing remain explicit
C01 obligations, so this slice does not qualify total memory accounting.
Routine read diagnostics retain original errors while allowing positively
disposed native readers to retire; unknown acquisition and close outcomes remain
retained until proven. Full residency for a fitting accounted set is unchanged.

The candidate lifecycle's scoped audit-publication reservations also do not
close C06: retained historical generations can keep several real selected-source
grants after their maintenance scopes end and exhaust the free publication
room. The unchanged node limit still refuses work; it is not a guarantee of
maintenance progress. Retained-version admission must protect the next
publication peak, or bounded preparation credit must transfer to ordinary
historical ownership before a pin can retain it. Single-cycle saturation tests
cannot substitute for that retained-history proof.

Restore qualification exposed per-entry commits in the private structural
snapshot index before document validation. That index now uses the existing
bounded encrypted transaction for metadata batches, preserving parent-reference
ordering and abort semantics. Its focused failure and snapshot ownership
checks pass, but the encrypted 32-collection restore still exceeds
its unchanged verification deadline. A subsequent no-history relocation path
preserves the already-validated image and avoids rebuilding identical indexes;
its custody and callback-failure tests pass, but that restore retry fails
the same deadline. Fixed-field traces locate the timeout inside structural-index
construction, before snapshot semantic validation. A bounded native root-leaf
merge reduces the 16-row fixture from 32 page reads/16 appends to 2 reads/one
append, and that direct 32-collection construction takes 3.714s. The full
encrypted restore fails its unchanged 60,000ms deadline on that source;
the local improvement is insufficient to qualify restore performance.
The subsequent bounded editor handles a maximal prefix within one leaf of a
taller tree, copying its leaf and ancestor path once after proving they fit.
All 444 native unit tests and 26 crash/ownership/rollback integrations pass,
along with native strict Clippy and formatting, on the 64-file native/Cargo
selection. A height-two 16-update fixture measures 38 directory reads and two
appends, with fitting current/pinned reads served without backend I/O and with
crash parity and full admission drain. The later 689-file Engine selection
passes all 13 focused unit tests and the selected encrypted restart/full restore.
Actual restore takes 25,066ms, leaving 34,933ms of the unchanged 60,000ms deadline.
Its trace confirms 165 records, 48,656 framed bytes and 330 index rows, including
131 audits (128 mandatory schema release audits and three write audits).
Structural construction takes 18,937ms;
the isolated equivalent fixture takes 39,916ms, so these observations do not
establish a controlled speedup or complete the broader performance gates.
Separately, both restore paths now accept valid linked seals by updating their mutable causal
cursor while preserving duplicate identity rejection; all 11 focused timing,
causality and ownership checks pass. These changes do not complete streamed durable
document/index installation.

Focused lending/index-source validation passes 55 query tests and 38 distinct
Engine checks covering captured versions, hydration, pagination, unique swaps,
structural batching, snapshot custody, relocation, and structured/text schema publication.
The selected encrypted restore now passes; historical deadline failures remain
recorded and the complete integration gate stays open. The prior 689-file
source selection
passes 439 native unit tests, 26 crash/ownership/rollback integrations, native
strict Clippy, formatting and all 11 focused Engine timing/causality/ownership
checks. The newer 444-case native qualification has its separate 64-file pin;
the 13-check Engine and selected full-restore pass use the later 689-file pin,
whose hashes match after completion. The earlier native integration selection
passed 31 checks. Query,
Authority and KV pass their selected strict Clippy gates, and
server/benchmark callers compile with all features and targets. These results
and earlier failed fixture attempts are source-pinned in the evidence ledger;
they do not close the whole-runtime memory or release gates.

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
   Include never-revisited records and a one-pass scan. After warm-up, exercise
   inserts, replacements, deletes and compaction while the selected/pinned
   allocation union and required workspace remain within their admitted bounds.
   Newly published live data and indexes must remain resident, with no
   subsequent serving fetches from storage.
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

The [implementation design and allocation inventory](disk-backed-storage-design.md)
records the current durable application gap, native directory design, memory
ownership and staged integration. It distinguishes reusable foundations from
the unfinished production cutover.

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

## 2026-09-30 native foundation checkpoint

- Native immutable-byte caching is integrated in `kasumi-kv` through the Core
  and Database APIs. It retains every fitting value, uses frequency/recency
  admission under pressure, accounts for directory/object/allocation overhead
  and reader pins, and supports gradual budget shrink and bounded refill.
  The embedding owner must explicitly assign a budget; server configuration
  and the decoded document/index cache remain open.
- Durable commits populate the cache only after publication and obsolete-version
  pruning. Rejected writes leave no cache entries. Terminal writers release only
  their own read snapshot before publication; surviving readers and output
  guards still retain theirs. Compaction relocates immutable cache identities.
- The new disk-directory module has immutable ordered pages, streaming sorted
  construction, snapshot-root reads, bounded successor traversal and incremental
  COW updates with balanced splits and root shrink. Tests cover a directory
  larger than its admitted workspace. A scoped page cache retains complete
  identities; `.kvdir` arenas and the segmented superblock's selected directory
  plus replay anchor now have implementation and fault tests. The NodeDisk
  group owner recognizes directory files. Full SHA-256 page references now bind
  the canonical root into synchronized segment commits and their chain; replay
  retains the exact commit boundary. Interrupted-arena recovery and streaming
  namespace census have implementations and focused fault coverage.
- The internal `DiskState` composes the directory, log, root and one shared
  page/value cache. It retains fitting writes after publication, warms only
  their reachable new pages, and reuses cached committed pages during private
  mutation without retaining intermediate roots. Abort memory is reserved
  before effects. Its admitted internal snapshot registry now has 256 slots;
  clones share a slot and allocation, and reads require exact owner identity.
  Uncached bounded tree walks prove at most 128 candidate files per batch
  unreachable from the selected and pinned roots. Mirrored garbage publication,
  exact unlink/forget and reopen revalidation are implemented. Coverage checks
  tolerate current-reader churn; output guards retain their bytes and charges.
  Physical GC deletes wholly unreachable files only; the new maintenance
  primitive below can first move their live records. The 256-pin limit and its
  metadata accounting remain internal configuration, with live Core lifecycle
  integration and the application/storage consumer cutover still open.
- A subsequent C03 reconciliation implementation now addresses obsolete cached
  page and value identities inside partially live files; this is new source,
  beyond the validated density checkpoint. A fixed cache-slot cursor carries a
  structural version, and conditional removal checks the exact identity and
  payload owner. A page's validated minimum key selects one bounded membership
  path per root. Values retain trusted table/key lengths: a 5,180-byte fixed
  locator reads only the preceding record envelope and checks it against the
  cached payload, without a disk payload read or backward scan.
  Each serialized step recaptures the selected and unique pinned-root union;
  changed unions restart the continuation before old roots are read, while
  ordinary current-root reader churn does not prevent completion. Proven-dead
  identities are pruned, excess metadata is trimmed, then current and pinned
  roots receive non-evicting, policy-neutral refill with explicit completion.
  Cold physical aliases share bytes only for the same logical key and batch
  version; output guards retain their charges. Explicit warm-up and compaction
  before GC use this path. The 43-file residency checkpoint passes 406 native
  library tests, including exact-budget zero-I/O reads, cold alias sharing,
  snapshot churn, proof/admission failure retry and corruption rejection.
  See the [validation record](evidence/disk-backed-cache-20260930/README.md#resident-cache-reconciliation-checkpoint)
  for commands, retained failures and scope.
  Immediate full residency under arbitrary ongoing foreground publication,
  production qualification and C03 completion remain open. One work unit may
  checksum a value up to 40 MiB, inspect configured pins times maximum tree
  height, or rehash bounded resident metadata; it is not a byte or time ceiling.
- Internal maintenance now rotates segment and arena appenders and processes
  admitted leaf batches instead of the historical per-record commits. A validated
  leaf plan and bounded descriptor backing have a 512-record ceiling. Keys borrow
  the page; the retained cursor is admitted before effects. Each batch targets
  1 MiB of encoded records, allowing one larger record up to `MAX_VALUE_BYTES`;
  independent operation-count and transaction-byte limits still apply. All source
  records are preflighted before writes, then values stream through 64 KiB windows.
  Each batch copies one leaf and its ancestor path once, preserving row batch
  versions and table birth versions. Fresh leaves without old value locations
  are skipped without publication. The cursor permits foreground writes between
  steps and retains old snapshot roots through the pin registry, without an
  all-key resident map. Root-only replay uses a bounded helper of approximately
  2.38 MiB, separately from other charged owners; segment version 4 directly
  rejects version 3. Normal prepared-batch abort now uses root-only replay bounded
  by the prepared operation count, reserving fixed replay workspace plus exact returned
  location backing independently of borrowed value size. A focused check exposed
  the former over-reservation. Abort now verifies the exact synchronized batch,
  end position, operation count and digest before discarding bytes, rejecting
  damaged or substituted prefixes. The prior 343-case native suite covers this
  correction and the leaf-batched maintenance source before density was added.
  Raw maintenance inputs and non-evicting, policy-neutral page warming avoid
  training demand policy with a sweep. Relocated cache identities share one
  immutable payload allocation, keeping both addresses hot when their metadata
  fits. Metadata pressure moves the cached identity while old output guards
  stay charged. Unique payload charges survive until the final cached alias or
  reader releases them. A composed 512 KiB value under a 700 KiB cache retains
  both snapshot identities and their pages with no storage reads after compaction.
  Confirmed directory-page read/write and arena-sync deltas accompany value-copy,
  commit and fresh-leaf-skip counts. They are successful callback counts, not
  device bytes or complete maintenance I/O: page counts exclude header payloads,
  sync counts exclude mirrored-root/namespace I/O, and failed callback effects
  can be unknown. This remains an internal primitive: one work unit may
  synchronously process `MAX_VALUE_BYTES`. Periodic GC progress during foreground
  publication, strict byte/time work limits and full production compaction
  qualification remain open.
- A separate internal density phase now follows evacuation, greedily packing
  adjacent leaf and then internal pages. Two admitted input pages and fixed paths
  prove adjacency across parents; both paths are rebuilt together at their common
  ancestor for one `DirectoryOnly` publication. Three fixed ancestor carry slots
  cover separator growth and branch removal; a height-`h` operation appends at
  most `2 + 4(h - 1) + 1` pages. Its admitted logical cursor keeps merged output
  eligible for the next neighbor and advances only after publication or verified
  skip. Expected generation tracks the phase's own commits; foreground changes
  dirty a pass. At the end of a dirty pass, density alone restarts, preserving
  completed evacuation and its cutoffs. Only a clean pass proceeds to GC; a later
  foreground change during GC resets density. After the entire compaction has
  completed, a new foreground generation starts a new compaction cycle. No
  completion guarantee is made under continuous writes. The density checkpoint
  below validates the internal component. Partially live arena garbage and temporary disk growth remain;
  the periodic-GC scheduling/continuation proposal is still unimplemented.
- The completed internal snapshot/reclamation checkpoint passes 272 native
  library cases and 30 integration cases, strict all-target native-crate Clippy and package
  formatting. Earlier evidence includes 21 store group-owner cases. That
  checkpoint's selected-source pin covers 25 files; it does not qualify
  subsequent work or close production gates. The initial focused run's three fixture failures are
  retained alongside its corrected passing run. Commands, source pins and
  limitations are in the
  [checkpoint record](evidence/disk-backed-cache-20260930/README.md).

The earlier per-record maintenance source is recorded separately in a
[29-file selected-source pin](evidence/disk-backed-cache-20260930/maintenance-library-selected.sha256).
The [maintenance validation appendix](evidence/disk-backed-cache-20260930/README.md#streamed-maintenance-development-checkpoint)
records 310 passing native library cases, 30 integration cases, 21 store boundary
cases, strict Clippy and formatting on that source. This is historical development
evidence; it does not validate the subsequent leaf-batch source or close C02.
The prior [leaf-batch and shared-residency checkpoint](evidence/disk-backed-cache-20260930/README.md#leaf-batched-maintenance-and-shared-residency-checkpoint)
records 343 passing native library tests, 30 integration tests, 21 store boundary
tests, strict Clippy and formatting under a 31-file selected-source pin. Its
1,200-row structural workload writes 14 directory pages across seven maintenance commits; this is
not a device benchmark or production qualification and does not validate the
subsequent density source.

The [35-file density source pin](evidence/disk-backed-cache-20260930/density-selected.sha256)
has [365 native library passes](evidence/disk-backed-cache-20260930/density-library.log)
in 222.74 seconds, [22 focused passes](evidence/disk-backed-cache-20260930/density-focused.log)
in 187.95 seconds, and [30 native integration passes](evidence/disk-backed-cache-20260930/density-integrations.log).
[Strict native all-target Clippy](evidence/disk-backed-cache-20260930/density-clippy.log)
and [package formatting](evidence/disk-backed-cache-20260930/density-format.log)
pass. The [initial Clippy failure](evidence/disk-backed-cache-20260930/density-clippy-initial.log)
is retained; three test-style corrections preceded the passing check. The current
1,200-row structural workload evacuates 4,800 value bytes in seven commits and
14 page writes; six density commits then write 15 pages and reduce reachable
pages from eight to five. This does not measure device bytes or qualify production
performance. The subsequent residency regression and reconciliation source are
not included in this density pin or validated by those results. The later
43-file residency checkpoint records its own selected-source validation; neither
checkpoint closes C03 or qualifies the final production source. The
[compaction follow-up](disk-compaction-followup.md) records implemented internal
leaf batching/density and the open reclamation-progress, arena-space and production
Core cutover work.

Continue with C02's live segmented commit/directory/Core integration, then
the addressable encrypted application records and query/index cutover described
in the [implementation design](disk-backed-storage-design.md). The whole-goal
and C01–C07 completion criteria remain open.

## Production cutover in progress

The public native Core now uses the segmented log and immutable disk directory;
its resident per-key `BTreeMap` and contiguous-file backend API have been removed.
Strict creation and opening both require an exact group incarnation and explicit
cache configuration. Core preserves admitted outputs, pinned snapshot roots,
owner fencing, retained opening failures and observed one-shot close. Review
also added a snapshot-count recheck under the close lock and distinguished the
published commit position from an uncommitted appender roll.

Installed persistent groups and encrypted scratch groups now use this same
native path. Persistent policy requires `native_storage.byte_limit` and
`native_storage.cached_files`; scratch policy requires `native_cache_bytes`.
Generated profiles set explicit large budgets (1 GiB persistent per-group
ceiling and 512 MiB per scratch table), all subordinate to aggregate installed
memory admission. These are initial policy choices, not qualified defaults.
Smaller fixture budgets do not establish production capacity or performance.

This cutover is undergoing validation. The Core cutover passed 372 library and
26 crash/fencing/rollback tests before the subsequent publication reconciler.
Its first 32 focused checks pass, including exact-fit mutations and recovery
faults. The old
single-file crash and allocation fixtures have been ported to segmented groups;
failed runs and their fixture corrections remain recorded in the evidence
folder. Final source validation is still required. The native allocation test
uses real temporary backing files so its measurement cannot confuse the test
backend's simulated disk bytes with admitted database memory.

C01–C07 remain open. Foreground publication now marks actual mutation paths,
proves obsolete identities against current/pinned roots, and removes them before
non-evicting refill. Its full validation remains pending; becoming fitting after
pressure or unrelated pin drops still requires bounded reconciliation/refill.
Ordinary commits now reserve complete physical capacity before log/root effects;
25 installed/scratch foundation tests, six native orchestration cases and the
five previously failing Store commit-capacity regressions pass on their recorded
selections. The activated native package passes 475 unit and 31 integration
cases; full Store/Engine and release qualification remain open. Continuously
progressing reclamation, decoded document/history state, persistent query/text
indexes and final end-to-end qualification are not completed by this API cutover. Under-bound full residency remains mandatory; explicit warm-up
coverage alone does not close that requirement.

The subsequent automatic-residency checkpoint passes 410 native library tests,
strict native all-target Clippy and formatting, plus nine installed worker
lifecycle tests. Bounded warm-up now restores fitting residency after cold open
or released pressure; successful serving handoff activates the prepared worker.
The installed scratch and persistent selectors separately pass 44 and 48 cases
on the earlier store executable. Source pins, failures, exact scope and remaining
integration validation are in the [evidence record](evidence/disk-backed-cache-20260930/README.md#automatic-residency-and-installed-worker-checkpoint).

An installed admission audit found that the previous per-payload lease consumed
one shared governor slot and substantial wrapper charges. Consequently the
4,096-slot default can prevent small records from filling a large byte budget.
C01/C03 require the aggregate admission pool and a real-governor
workload exceeding 16,384 small rows with only 128 slots before large-cache
residency can be claimed. The pool implementation now uses one growable
reservation per cache. The native library passes 423 tests after
owner-expiry corrections, with strict all-target native Clippy and formatting. The installed governor's
13-case selector passes: 16,513 rows plus 91 directory pages become fully
resident under 128 governor slots, with zero evictions and zero backing reads
on two complete read passes. The cache charges 20,779,032 bytes, including
metadata, unused credit and provider overhead. Source pins, build settings and
exact scope are recorded in the evidence ledger. Application documents/indexes,
whole-process memory and production integration remain unqualified; all goals
stay open.

The same native runtime now passes 30 allocation/crash/fencing/rollback
integration cases. A separate counting-allocator test passes with 16,513 cached
values, including metadata overlap and final reader release on another thread;
all measured requested heap remains admitted until actual retirement. Strict
native all-target Clippy and formatting also pass with this test included.
This qualifies the selected native cache implementation, not allocator-internal
overhead, whole-process memory or the application document/index cutover.
