# Disk-backed storage with full residency below the memory bound

Status: **active; all seven implementation goals remain open**. Established
2026-09-30 from the user's proposal and clarification; current status consolidated
2026-10-05. These goals extend G02 and its query, snapshot and resource-admission
requirements.

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

## Current production status

**C01–C07 remain open.** The native key directory is disk-backed, but production
still uses resident document maps and structured/text indexes. Application changes are being
implemented and tested in isolated integration cohorts; they have not been
promoted to the live checkout. No combination of component passes closes
a production goal.

The [2026-10-04 production-checkout checkpoint](evidence/release-resume-20261004/README.md)
passes the rebuilt native library **563/563**, including **8** actual staging
allocation/refund regressions. Its fallible node ownership repair is active in
the native table path; it does not fund complete application successor work
before Raft acceptance, activate disk document/index serving or prove full-fit
residency. Required installed incarnation and Transit trust cutovers and the
G11 preflight-failure repair have separate scoped passes. Later shared
plaintext/Raft changes are preserved and require their own source-bound
validation. C01–C07 and M01–M07 remain open.

The later [2026-10-04 explicit audit-placement checkpoint](evidence/audit-placement-cutover-20261004/README.md)
requires caller-selected Control/application policy and independent target
policy. Immutable target/local journal bindings retain the original supplied
cache and its physical owner; external failure cannot choose local storage.
Target/local journals use format 5 and local physical markers format 2, directly
rejecting superseded inputs. Standalone init, CLI and staging publish explicit
choices without missing-row repair.

Separate development checks pass **295** Python, **49** server, **16** earlier
Store audit, **18** fresh Store ownership, **21** Engine journal, **6** snapshot
and **12** capacity/error-retirement cases. Strict all-feature/all-target
Store/Engine/server Clippy and scoped formatting pass. The bounded test observer
now records all actual grants; its sample capacity changes no production budget.
The selected-source fixture releases its inspected original clean write refusal
before final drain. Original failures and shared-source custody remain archived.
This C05/C06 prerequisite cut does not activate disk document/index serving,
fund complete preacceptance publication, prove full-fit residency or qualify
Control-only topology or production stack limits. C01–C07, M01–M07 and G01–G14
remain open; no source revision is release-qualified.

| Component | Verified progress | Remaining production dependency |
| --- | --- | --- |
| Native lookup/publication | The v3 cohort passes all 605 native tests, including actual 100,000-row / >96 MiB images. The contraction correction passes all 191 NodeDisk tests and the original large byte-bound Store image. Retained reclamation passes the complete 158-case selection. The serialized image owner now passes the unchanged 65,539-operation encrypted Store release workload through commit, capture, replay and disposal: 1/1 in 1,279.25s, runner exit 0 with 2,654/2,654 unchanged pins. The earlier pre-effect StorageFull failure remains recorded. | Preserve the fixed-root promise, generic parked writer bound and original operation-count assertions through final integration. Finish production preacceptance ownership and sustained reclamation; this component pass does not activate disk serving. |
| Documents and writes | Protected current/old sources, accepted primary edits, mandatory structured catalogs and an actual indexed Edit commit/selected receipt have scoped passes. Primary command staging and fixed point backing are allocated before candidate construction. | Complete candidate/journal/index/verification ownership before local Raft acceptance, all ingress/recovery paths, full index graph proof and activation. |
| Query and text | Query 124, the strengthened Query4 checks, both actual document/order allocator observations, Session reuse and boxed role receivers have scoped passes. The corrected original raw metadata witness passes receiver5/5 in release/default stack. Both corrected original sparse scenarios now pass 2/2 in 7,146.96s with caches disabled, unchanged budgets/rows and2,960/2,960 unchanged pins; runner exit 0. Earlier receiver4/5 and sparse0/2 failures remain preserved. | Finish complete native writer/finalizer/tokenizer/parser admission, repeated disk merges and one atomic all-role publisher. Qualify the reviewed combined posting/position/term-info/FST and source-custody owners. Complete entry/record growth, analyzers/Japanese work, fast-field/store/meta finalization and canonical parsing. The long sparse runtime is an unresolved performance limit, and these component passes do not activate serving. |
| Cache and refill | Large-cache sampling/churn, same-Core reclamation and collection protection have focused passes. All 58 latest refill/worker/child checks pass, now including the finite selected-lease Session phase and mutation races. Three closed Generation-handle and six actual control/weak-tail accounting tests pass. Structured traversal verifies a zero-new-read second pass. | Finish native text parsing and semantic readiness, the funded census of all retained public generations, all-role completion, automatic service startup/shutdown and final accounting/workload qualification. PrimaryAndStructured cannot claim whole-database residency. |
| Operations and consensus | The unchanged expiry/reopen/shutdown service scenario now passes on corrected v6. Its journal checks pass 5/5 and accepted-producer checks 19/19; OpenRaft passes 254 standard and 263 generic-snapshot library tests. Snapshot install/reopen, source-retirement and audit cancellation retain their recorded scoped evidence. | Engine-wide admission before acceptance, remaining operational cases, final feature/platform/release checks on one promoted source. |

The new point pressure fixture initially used an API that preserves ordinary
headroom to request the entire ledger remainder. Its narrow reservation-origin
correction keeps the same byte total and assertions; it now passes together with
all five encrypted statistics-spool checks. Exact original failures and subsequent
corrections remain in the
[evidence ledger](evidence/disk-backed-cache-20260930/README.md).

Production residency blockers remain visible in
[`CollectionState`](../crates/kasumi-types/src/lib.rs),
[`GenerationDocumentSource`](../crates/kasumi-engine/src/document_source.rs) and
[`QueryIndexes`](../crates/kasumi-query/src/lib.rs). Native
[`Core`](../crates/kasumi-kv/src/core.rs) already opens `DiskState`; its old
resident per-key map is no longer pending implementation.

Generated policy currently assigns a 1 GiB persistent per-group cache ceiling and
512 MiB per scratch table under aggregate admission. These are explicit large
settings, **not validated deployment defaults** or independently available budgets.
Historical measurements and earlier intermediate failures are preserved in the
[2026-10-03 qualification history](disk-backed-cache-progress-20261003.md).

## Current implementation sequence

The active execution goal is to finish the implementation and its final evidence,
not merely write this plan. The following milestones divide the remaining code
into reviewable production changes. They do not replace or weaken C01–C07.

### Production milestones

| Milestone and C goals | Production outcome still needed | Executable exit gate |
|---|---|---|
| **M01: Repair current failures** — C05, C06, C07 | Corrected receiver5 and both original sparse scenarios pass in release/default stack. Corrected fresh Registry passes AP 1836, Query 124, focused 81 in all four profiles and native referencing 141, with every source pin unchanged. Preserve their earlier failures, ENOSPC trace and exact corrections through final integration. The unchanged large Store image, protected setup8, target reopen18, encrypted2,500-counter workload and focused close/reentry checks also have scoped passes. | Each original scenario reaches its intended assertion on the final integrated source. Keep source-derived fixture units and concrete owner capacity boundaries; retain invalid configurations as negative cases. Final operational selection passes, including exact reopen. Do not change caps, deadlines, row counts or ownership assertions to mask failures; do not accept unknown outcomes or prematurely release old roots. |
| **M02: Reusable encrypted reads** — C01, C05, C06; supports C02 | Route earlier control planning, selected capture and installed terminal scans through their actual operation-owned point backing. Finish constructor/retirement custody and the exact read-owner handoff. | Real encrypted reads reuse bounded backing without mandatory per-record reservations; snapshot, table, provider, authentication and current expiry checks remain exact. Two distinct cleanup failures retain both originals. Verify the large capture path separately from fixture setup. This does not yet prove postcommit capacity. |
| **M03: Protected publication capacity** — C01, C05, C06 | Activate real current/next source rights and reusable workspace; fund escaped historical sources before return. Bind complete successor capacity to local leader/follower acceptance, recovered accepted suffixes, membership/catalog changes and snapshot installation. | After accepted admission, saturating ordinary capacity cannot introduce a new mandatory source/planner/capture refusal. Several writes progress while old snapshots stay readable and charged. Refusal happens before local acceptance; canceled waiters cannot release accepted capacity. Recovery and all ingress paths use the same owned guarantee. |
| **M04: Authoritative disk documents** — C03, C04, C05, C06 | Install and retain the actual committed baseline and bound query metadata in the production apply lane; preserve the prior and accepted candidate through publication, capture failure and exact recovery resolution. Wire primary construction, edits, deletes and recovery into actual ordered publication. Switch document queries to exact durable roots and activate full-fit document caching. Remove the resident all-document serving alternative. | The real service performs point reads, scans, CAS, batches, idempotent replay, retained-version reads and restart with documents larger in total than RAM. Fitting new/updated/rarely read documents stay resident after warm-up. Document publication and all associated metadata are atomic. Coordinate the cutover with M05 so existing index features remain available. |
| **M05: Disk indexes and growing metadata** — C01, C03, C04, C05, C06 | Persist structured/unique/text indexes and bound their build/edit/query work. Replace remaining data-sized resident history, archive references and active staging. Preserve the implemented scalar retained-log endpoints and streaming header fold; qualify their exact immutable-source proof through append, truncate and snapshot transitions. Finish bounds for protocol-owned term metadata, requested entry batches and opaque response bytes; retain the exact active window needed for consensus. Keep already-disk-backed receipts/terminal rows on their canonical paths. | All supported filters, ordering, projections, aggregates, pagination and text analyzers/ranking agree below and above the bound. Documents and index roots commit together; schema/uniqueness behavior is preserved. Startup, log/header traversal and builders do not materialize a full data-sized map/vector. |
| **M06: Complete residency and accounting** — C01, C03, C05, C07 | Integrate one total budget across native and decoded caches, query/output work, protected sources, retained versions and bounded collection reservations. Expose finite preload/refill completion and budget-change behavior. Develop this alongside M04/M05. | A complete fitting dataset has zero serving document/index/directory fetches and no capacity eviction after warm-up, including after writes. Growth through the bound evicts gradually; cold scans preserve the hot set; deletion/budget growth refills everything that fits. Actual live and weak/pinned tails stay charged until release. RSS/swap are measured separately from cache accounting. |
| **M07: Final operational qualification** — all C01–C07 | Run the final canonical implementation through standalone/replicated operation, restart, snapshots, backup/restore, archive/audit, maintenance, security and shutdown. Validate deployment defaults and document measured limits. | The five existing workload classes pass on final source, together with repository/release gates. Preserve the completed 100,000-row recovery and 4,200-command permanent-custody snapshot/reopen results; rerun affected checks on final source. Demonstrate bounded maintenance progress and actual physical reclamation; reject older formats. Publish measured cache/RSS/swap/latency results without a universal hit-rate or disk-size claim. |

Security, durability, snapshot correctness and memory ownership apply during
every milestone. M01 can expose dependencies on M02/M03; carry a specifically
identified failure into the relevant repair instead of repeatedly rerunning it
or declaring the whole milestone blocked. A component test or test-only path
cannot close a production milestone. Mark a milestone complete only when its
code is active in the supported production paths and its acceptance gate passes.

### Current integration checkpoint

The current work is closing the following concrete prerequisites. None is a
production completion claim; all C01–C07 and M01–M07 remain open.

| Prerequisite | Latest result | Next exit condition |
| --- | --- | --- |
| Native publication | The integrated writer passes 10 native and two encrypted Store cases. The unchanged 65,539-operation release test now passes 1/1 in 1,279.25s on its immutable source snapshot; runner exit 0, 2,654/2,654 matching pins. | Preserve this result on the final joined source and fund the actual writer before every acceptance path. Keep the original operation count and assertions. |
| Sparse text | Corrected raw metadata receiver5/5 passes2.27s. Both source-derived corrected sparse scenarios pass 2/2 in 7,146.96s on release/default stack, caches disabled and original workload limits. Runner 7,859.70s exit 0;2,960/2,960 source/configuration pins unchanged. Earlier boxed receiver4/5 and sparse0/2 failures are recoverable and preserved. | Preserve logical-group versus physical/live counter semantics, callback failure identity and positive retirement on the final joined source. Finish native parser/tokenizer/finalizer ownership and qualify spill performance separately; the long correctness run does not establish acceptable latency. |
| Schema frontend | Corrected URI/meta Registry qualification is terminal: AP1836/1836, Query 124/124, focused 81/81 in each of four profiles and native referencing 141/141; runner exit 0 with 2,172/2,172 unchanged pins. Its earlier compile, ENOSPC, concrete capacity-boundary and native-inventory failures remain preserved. The separate 30-image reviewed schema successor joins large properties, annotation/format, prepared references and legacy collectors; runtime is pending. | Qualify the joined owners and exact new inventory, then finish actual default-meta compiler/runtime, user compiler branches, retained cache owners and the production frontend. Fixed platform/thread backing must remain funded for its real lifetime. These scoped passes do not activate the frontend. |
| Reopen and typed responses | Target passes all 18 machine/resolution checks, including exact-prefix reopen, using the canonical separate temporary importer scope. The durable node retains its original 64 MiB / 32-slot provider, 8 MiB table limits and exact-prefix assertions. Engine response 10/10, Types 1/1 and Raft constructor/response 7/7 each pass. Earlier slot exhaustion and the physical lease trace remain recorded. | Qualify the reviewed actual Custody bank, both admission providers, authenticated pending-tail recovery and pre-write response consumers. Finish its enrolled source drain and actor terminal paths, then complete aggregate production admission. A fixture’s separate importer scope does not prove the whole process budget. |
| Native task retirement | Seven actual native task checks pass. Original upstream abort, panic, task-ID and join-set suites pass 8/7/17/19 respectively; the final join-set harness enables its required `test-util` feature without changing upstream source. The canonical caller-owned drain, production caller migration, strict vendor inventory and forward merge are reviewed but unexecuted. | Qualify independent original Waker registration/cancellation, admitted notification/cleanup joins, actual inline controls and diagnostic tails. Verify the actual selected control features. Native data completion must remain distinct from notification metadata retirement. A connected Custody source must positively retire the actual A data owner and retain separately charged B notification, Frame, caller and diagnostic tails; a completed join or callback cannot certify their physical deallocation. |
| Atomic baseline and metadata | All eight actual protected baseline/effects/coupled-capture/metadata checks pass on 2,654 unchanged pins. The fixture now prepares the exact response tail for every protected command and retains its actual capacity owner through the operation. Target passes 18/18 and response-bank checks pass 10/10. Earlier publish-only and missing-tail failures remain recorded. | Integrate the complete accepted primary, structured, unique and text producer into one atomic publication. Replace ordinary empty publication effects with that verified all-role producer. Pending text evidence remains a refusal; test fixture admission does not close production ingress. |

After these prerequisites, finish all-role atomic publication, production disk
queries and the service's finite full-residency refill. Then qualify the five
workload classes on one promoted source. This is the critical path; additional
component passes must answer a specific unresolved exit condition.

Earlier source-scoped prerequisites and failure traces are preserved in the
[qualification history](disk-backed-cache-progress-20261003.md#source-scoped-prerequisite-history-preserved-during-goal-refinement--2026-10-05).
Their original ownership and capacity obligations remain binding in M02/M03.
The current checkpoint above identifies what has passed and what still needs an
exit result; historical component totals do not replace production acceptance.

The next atomic publication dependency is an actual full Rebuild text producer.
Its distinct accepted Rebuild input must independently close physical statistics,
live-term membership, every declared role, the mandatory Manifest and final
source census. The reviewed successor is still unverified until runtime and
native/metadata admission pass. It cannot mint a selected root or replace the
production empty-write publisher by itself.

The next connected deliverables are:

1. **Finish M02/M03 ownership:** integrate the passing native update/counter and
   retired text construction scopes; finish the sparse text-edit stack repair
   and preserve the passing serialized image admission. Complete the schema frontend,
   candidate shared tails and one concrete response buffer
   for every accepted/unapplied entry, including constructor recovery.
2. **Finish M04/M05 atomic serving:** join the actual accepted primary and every
   structured, unique and text role to one durable receipt and selected reader;
   activate fresh/snapshot/history reads together and remove resident alternatives.
3. **Finish M06 complete residency:** connect the finite Session to service
   startup, mutations, shrink, budget growth and joined shutdown. Count all live,
   pinned and weak tails. Whole-database completion includes every index role.
4. **Finish M01/M07 final qualification:** pass the original operational failures,
   then the five workload classes and repository/release gates on one promoted
   source. Publish measured cache, storage-read, RSS, swap and latency evidence.

Original cleanup/close, command, compiler and text-refill requirements remain
binding in the [preserved checkpoint history](disk-backed-cache-progress-20261003.md#checkpoint-history-consolidated-after-decoder16-qualification--2026-10-04).
Exact source hashes, failure identities, test inventories and recoverable archives
are recorded in the [evidence ledger](evidence/disk-backed-cache-20260930/README.md).
Component passes do not close C01–C07 or activate the production cutover.

### Next executable exits

Keep the active goal at the complete redesign scope. The next work is ordered
by these finite exits; finish a failed prerequisite before enlarging its source
cohort or repeating unrelated checks.

| Order | Concrete work | Exit evidence |
| --- | --- | --- |
| 1 | Preserve the now-qualified sparse and schema repairs, their original failures and the warm build lane; carry their exact owners into the integrated source. | Recoverable unchanged-source checkpoint; boxed receiver 5/5; both original sparse semantics and failure-custody scenarios pass with their original limits and default stack. The fresh Registry owner passes its actual capacity cuts and all four existing feature profiles. |
| 2 | Qualify actual native text document/order, postings, fieldnorm, finalizer output and recorder backing; qualify canonical caller-owned source draining and the connected Custody source. | Exact original native suites and installed Engine/replica consumers pass. The original retained error/panic owner and actual backing survive refusal. Separate data retirement from physical control/notification/Frame/diagnostic retirement. No component may claim full native writer or whole-source closure until every remaining allocation is owned. |
| 3 | Finish schema compilation and accepted primary/structured/unique/text ownership, then join one durable all-role publisher. | Complete compiler/default-meta/runtime allocation inventory and one exact accepted journal/semantic graph/selected generation. Ordinary production publication uses that inventory; an empty effect list or test-only producer cannot close the gate. |
| 4 | Switch every production document, query, snapshot, history and lease path to that exact durable generation; connect finite preload/refill to the service. | Every supported caller uses canonical selected access, with authorization/expiry on hits and misses. No resident-map serving path remains. Startup, mutation, shrink, budget growth and shutdown finish finite owned work. |
| 5 | Qualify and promote one complete source. | The five workload classes, final operational/security/restart coverage and repository/release gates pass on the exact promoted source. Fitting data stays fully resident with zero serving storage fetches; oversized data remains within admitted memory. |

Space recovery is an operational prerequisite, not an accounting result for
Kasumi. Removing obsolete single-link loose build objects preserves incremental
backing, linked outputs, frozen sources and all failure evidence. These isolated
cohorts remain unpromoted until the integrated production gates pass.

### Gates for the integrated source

Use one final integration cohort and preserve every already-qualified owner
when combining successors. Older native and newer decoder/response cohorts
have different source histories; source equality and recorded forward ancestry
must establish each merge. Every final Cargo invocation uses the build identity
guard in the existing warm target. A passing component on another cohort is a
prerequisite, not the final source's acceptance evidence.

| Gate | Current state | Concrete result required |
| --- | --- | --- |
| Original failure repair — M01 | Store, corrected receiver5 and both corrected original sparse scenarios pass. Corrected URI/meta passes AP 1836, Query 124, focused 81×4 and native referencing 141. All recorded source/configuration pins match. | Preserve these exact semantics, failure identities and limits through final integration; run affected checks on that source. Keep the sparse performance issue visible and retain every earlier terminal failure. |
| Ownership before acceptance — M02/M03 | The 147-image native source joins ordinary Snapshot B disposal, last-caller/held-Weak metadata and the preinstallation race correction with posting/position/term-info/FST and canonical/Custody ownership. Exact source, mode and 15-package vendor checks pass. Two narrow Raft compile repairs make the normal Engine/Authority/Raft library check pass; ownership-test compilation then hits ENOSPC, so runtime qualification remains open. The 137-image schema pattern successor is source-reviewed with full frontend ownership still open. | Own the complete native writer/FST/tokenizer/parser, schema frontend, candidate/index journal and every typed response before leader, follower or recovered entry acceptance. Qualify original task installation, DATA/B disposal and the separate Frame/caller/diagnostic/Weak census. Accepted work must not encounter a new mandatory capacity refusal. |
| One atomic publication — M04/M05 | Production still has an empty application-write publisher and resident document/index serving. Its apply lane retains a selected receipt but lacks the actual closed committed baseline and bound query metadata needed by the primary factory. The frozen effects/CompletionLoan bridge remains gated and unqualified. | The real accepted primary and every structured, unique and text role produce one canonical durable receipt and exact selected generation. Connect fresh, snapshot, point, query, pagination and history reads to it, then remove resident serving alternatives. |
| Full fitting residency — M06 | Scoped refill/control checks pass. Complete public-generation census, text readiness and automatic service integration remain open. | Finish finite preload/refill for documents and every index/directory role, including retained versions. Below the aggregate bound, rare reads stay hot and serving reads issue no storage fetches. Writes, growth, shrink and budget changes preserve this rule without stranded collection capacity. |
| Final qualification and promotion — M07 | No production completion or promotion is claimed. | The five workload classes and repository/release checks pass on one integrated source, including standalone/replicated operation, security/expiry, recovery, backup, audit/history, maintenance and joined shutdown. Promote that qualified source and record cache accounting, RSS, swap and latency separately. |

These gates refine M01–M07 without narrowing the complete feature-preserving
redesign. A diagnostic probe, byte-only response owner, parser-only meta input,
prepared facade or test-only selected publisher cannot satisfy a later gate.

The complete ownership gate includes native leaf/density/cache/reclamation work,
the original fixed-u64 update, protected point backing and statistics spool,
the final schema validator, and retained historical sources. Publication must
preserve text ranking, schema and uniqueness semantics. Refill must run on
startup, mutations, released pressure, budget changes and joined shutdown;
storage-byte warming or PrimaryAndStructured completion cannot declare full
residency. These obligations remain binding throughout the ordered gates.

The remaining schema work now has a finite source inventory with 17 concrete
production joins. It distinguishes fixed platform/thread backing from schema-sized
compiler work. Finish the original default-meta pattern constructors and their
lazy matcher caches, actual meta validation and owned diagnostics, the supported
user compiler branches and per-validation scratch. Then replace both ordinary
production meta/build calls and the raw validator/weak cache with their retained
owners. Prepared references and BTree annotation collectors have reviewed source
and integrity evidence; runtime is pending. Their supported partial graphs cannot
stand in for this complete production frontend.

Native FST backing is now joined in a reviewed, unqualified successor. Its shared
prefix bound is conservative and must be used consistently by estimator and
consumer; it does not prove fitting cache residency. Qualify its actual
registry, stack, transitions, original errors and published dependency selection.
Complete entry/record growth, analyzers, fast-field/store/meta finalization and
canonical parsing before claiming the whole writer or enabling text publication.

The 30-image schema helper preserves the existing suites and adds the reviewed
reference/legacy cases: AP 1,852, Query 124, focused 97 in each of four profiles
and native referencing 143. The newer 137-image pattern successor needs a new
source-derived inventory and qualification helper; do not run the old selection
as evidence for its additional cases. Both successors remain unqualified. Preserve
the passing URI/meta checkpoint before applying them.

The actual external Tantivy harness now resolves its genuine development
dependencies and preserves all 144 original production identities, the reviewed
same-version FST path transition and the original feature union. Its 241-package
lock is qualified as a dependency selection; no native runtime result is implied.
The separate FST, Columnar and SSTable native selections still need exact harness
resolution and runtime qualification. The fast-field source has passed independent
whole-image/mode, 941 saved/original dependency and 99 published-member checks;
its 15 actual backing layouts remain an unqualified component.

Runtime qualification currently needs sustained build space. The last ownership
test compile exhausted disk and even evidence-log flushing failed. The source
guard was reaped, and an independent post-run check confirms all 3,032 pins remain
unchanged. Preserve that interrupted result and the passing normal library check;
do not count it as a test pass or retry a large build while free space is unstable.

### Recorded integration history

Earlier source-specific checkpoints and their original failures are preserved in
[the qualification history](disk-backed-cache-progress-20261003.md#additional-integration-history-preserved-on-2026-10-04).
The current checkpoint above and the evidence ledger determine current status;
historical passes do not activate a production path. Open obligations below
remain binding until their stated gates pass.

### Immediate integration gates

These are ordered prerequisites, not completion claims. Keep source-pinned
component results separate from service activation.

The source-retirement and archive-cancellation repairs have scoped passing
evidence. Preserve their deterministic checks in final qualification: hold the
actual opening lock while closing captured/historical sources; retry only that
known contention; retain genuine finish failures; require immediate bootstrap
close after snapshot installation; validate exact Archived resource inventories;
and derive child generation ceilings from the actual validated parent page.
Actual create/replace/schema rebuilds have isolated component passes; the
archived-schema test must assert the existing sealed-definition rejection.
Referenced collection catalogs, metadata-only generations and deferred query
opening pass the isolated integration selection. Same-attempt index resource
release and the per-Database source-work census pass their focused checks.
Finite refill now passes full-fit/cancellation/source-failure and pressure cases.
The pressure correction retains the exact typed DocumentSource retention
diagnostic. An entered refusal becomes Pressure only when the original owned
resource ledger identifies actual capacity refusal. A retained refill pause
keeps the original source, peak grant and diagnostic in its registered owner;
resume must restore that exact owned reader. The older retire-and-retry path
requires positive cleanup before replacement. Public ResourceExhausted codes,
native failures and callback failures alone are never capacity provenance.
Released headroom then permits primary/structured refill; the actual retained
Session's refusal/checkpoint races now pass. Actual installed-reader cohort authorization is a separate service
activation gate; fixture sources alone do not establish that right. The
next graph gates are the complete structured/unique/text catalog producer,
independent whole-graph verification, one atomic final publisher, and
query/lifecycle activation against its captured source.

1. **Requalify the coherent snapshot protocol and backend bridge on final source.**
   The integrated protocol already compiles and has scoped passing evidence.
   Preserve original source/cleanup errors and final-owner funding; recheck
   affected constructor allocations, current-root slices, foreign/stale
   identities and cancellation after the document/index cutover.
2. **Complete the protected encrypted-publication capacity guarantee.** Retain
   all segment, directory, proof, cache, source and diagnostic backing before
   Ready. Include conflicting-log deletion, one atomic final image and obsolete
   snapshot cleanup. Ordinary votes must preserve both resource and counter
   headroom while the allowance is parked.
3. **Finish operational qualification of canonical snapshot installation.**
   Actual encrypted installation and reopen now have a scoped passing check.
   Deny ordinary grants after Ready; verify install/reopen, higher votes,
   canceled waiters, partial failure and joined shutdown on this exact source.
4. **Remove the native atomic-image size bottleneck.** Preserve the canonical 65,536-operation / 96 MiB ordinary atomic-batch
   validity checks. The earlier frozen producer shared that ceiling; the isolated image producer/consumer has the recorded native and encrypted Store component passes. Larger snapshots need an admitted
   private candidate format and replay protocol whose one final durable root
   activates the whole image; intermediate chunks must stay invisible. Qualify
   crash/reopen, conflicting logs, retained sources and cleanup through that
   format. Current worst-height physical reservation is also conservative:
   12,600 operations promise about 18.65 GiB of native directory pages. The
   16-key batching improvement reduces actual writes, not that promise. Refine
   geometry only with a proven bound on intervening writer topology. These are
   open operational requirements, not acceptable permanent data-size caps.
   The constant-space image inventory now passes 100,000-row and >96 MiB
   component tests while preserving ordinary batch refusal. The canonical
   version5 segment writer/replay now passes large-image, torn-tail, injected
   failure and corruption tests; private chunks share one sequence and only
   the final ImageCommit can publish the image. The native Core consumer passes actual directory mutation, one final
   publication, preserved votes/old readers and mandatory grants denied after
   preparation as part of the full 596-test native suite. Actual native crash
   injection now passes its focused old-or-complete recovery gate. The wired canonical encrypted Store image spool passes the unchanged 65,539-operation release case; qualification on the final production join remains open. The real large operation fixture must also fit proven scratch
   and physical-publication reservations; final service activation remains open. The canonical follow-through
   uses one final writer acquisition from the actual current root, private
   bounded chunks under one sequence, one final commit and exact source capture.
   Include all framing in physical quotes and validate streamed logical digests
   without whole-value replay buffers. Old roots remain visible until final
   publication; every crash/reopen must select the old or complete new image.
5. **Finish and promote coherent document/index serving.**
   Activate M04/M05 together with full-fit decoded caching; verify all supported
   queries and retained snapshots through durable roots with empty resident
   document maps. The isolated primary adapter alone is insufficient.
   Complete the following dependency chain on one source cohort:
   - **Accepted graph construction:** actual Create/Replace/Schema Rebuild,
     a separately authorized fresh baseline/restore, and sparse Edit. Preserve
     exact scalar, array, missing/null, uniqueness and shared-field semantics.
     Bounded heap storage must work on the normal test and production stacks.
   - **Complete index catalog:** every declared structured, unique and text
     role has an actual producer and an independent semantic/physical proof.
     An encrypted text directory alone is insufficient: segment construction,
     row mapping, global ranking statistics, query scratch and analyzer lifetime
     all need accounting and parity evidence.
   - **Mandatory manifest join:** finish primary construction first; bind its
     exact end to the index span and mandatory catalog; write the successor
     Manifest at the reserved ordinal. Reject the old primary-only format.
     On one final captured source, account every allocated ordinal as Complete
     or Released, prove exact owning edges and retired physical absence, and
     authenticate shared old subtrees through their prior selected role paths.
     No optional catalog, fixture descriptor or Action reinterpretation may
     manufacture the complete publication capability.
   - **Protected query preparation:** register the original work owner before
     any fallible provider allocation; admit all encrypted point backing before
     starting work; borrow the selected captured source without forking it.
     Preparation, cancellation and retirement must retain their original errors.
   - **Service and cache activation:** connect the complete publisher and reader
     together, then remove resident serving maps. Finite preload/refill must
     retain all fitting documents and index pages and expose completion;
     shrink, released pressure and budget growth must trigger another pass.
6. **Finish residency and release evidence.** Run M06/M07 after the integrated
   cutover, including fitting datasets with rare reads, growth through the bound,
   scan resistance, refill, all operations and measured whole-process memory.

### M06 cache integration gates

- Route the actual selected primary metadata, pages and live/archive records
  through the aggregate cache. A completed finite warm pass must produce zero
  serving fetches for all fitting eligible entries; recheck authorization and
  key access on every hit.
- Carry explicit read intent through the real query bridge. Historical/range
  scans must not train demand frequency or evict hot entries under pressure.
  Passing a warm-cursor scan test alone does not prove query scan resistance.
- Remove every retired source membership even if other sources resize the
  cache directory concurrently. Destroy payloads and return provider credit
  outside cache locks. Pinned output tails remain charged until actual release.
- Register concrete query/warm work with the Database lifecycle. Failed reader
  acquisition must retain the exact entered child, and cleanup must operate on
  the original failure owner. No absent handle or dropped facade proves close.
- Production query/refill readers must borrow the actual protected captured
  source using separately pre-admitted point backing. An Active-only ordinary
  reader fixture cannot prove this capability; do not share the publication
  scratch opportunistically or bypass the installed cohort check.
- Wire budget growth, shrink and source-retirement wakes to finite refill.
  Preserve collection reservations within the same aggregate total. Validate
  allocation overlap during directory growth and restore all fitting entries
  after temporary pressure clears.
- Change the effective shared limit under the actual MemoryCore ledger lock.
  Lowering the limit must leave existing grants charged, deny unfit new growth
  and retire eligible cache entries under pressure; it cannot refund live memory
  by relabeling it. Increasing the limit must publish a real relief event after
  the ledger change. Reconcile collection preferences against that same limit.
  Fixed slot/work inventories require separately admitted backing to grow.
- Drive finite warm passes from accepted generation publication and real
  aggregate headroom relief. Capture capacity before the actual refusal and
  retain the same attempt's source, cursor and peak grant while waiting, so an
  external release racing waiter creation is observed and its own cleanup
  cannot create a retry loop. Census availability has a separate real event.
  Complete and Pressure wait for a relevant change; timer polling and synthetic
  publication signals do not satisfy this gate. A changed accepted generation
  requires positive old-work retirement and a pass over the exact successor.
- Fund analyzer dictionaries and their initialization peak before loading or
  fingerprinting embedded pages. Every tokenizer clone must retain its original
  runtime credit. A shared slot must cover any surviving weak/control backing,
  avoid an owning cycle through MemoryCore, and retain initialization failures
  in the original work census. Query token planning and index production must
  use the same admitted runtime and profile before text serving is activated.
- Share unchanged pages/payloads across sources only with the actual accepted
  producer's unchanged-graph proof. Equal descriptors in a newly captured source
  cannot hide a missing/corrupt current graph. Add all index roles to the same
  residency proof before enabling service disk serving.

### M03 admission boundaries that must be active together

The capacity guarantee applies before **each replica accepts its local durable
obligation**. A follower may receive an entry already committed by the leader;
refusing that RPC before local acceptance must remain retryable. Admission in
`StateMachine::apply` is too late, and a fallible `LogStore::append` alone does
not cover recovery or snapshot installation.

The actor must admit before mutating its accepted log or membership. A capacity
error from the later storage callback would fence an already accepted operation;
it is not a clean refusal. The guarantee must cover each supported backend,
including the Authority state machine that does not own Engine SourceRoots.
Use explicit backend capabilities, with no assumption that every group is an
Engine database. A byte/shape envelope alone is neither a capacity reservation
nor proof of the actor's actual predecessor.

- Leader proposals and internal joint/uniform membership steps need an owned
  ticket tied to the actual actor predecessor and successor shape before entry
  acceptance. A caller-side sample of membership is insufficient.
- Incoming append RPCs must acquire and transfer the same concrete capacity
  before invoking OpenRaft. Existing HTTP503/transport-unreachable backoff can
  express preacceptance refusal; it must not report a false conflict or success.
  Worker custody must outlive canceled HTTP/client waiters, and raw Raft handles
  must not provide an unguarded supported route.
- Startup must install required snapshot and accepted-suffix capacity before
  `StateMachine::open` can restore/apply it, including uncommitted membership
  entries that might later become committed. Waiting until `Raft::new` is too
  late for the earlier restoration path.
- Snapshot ingress must stage and admit its actual successor before the final
  chunk can trigger installation. Catalog/key-shape growth must likewise own
  its overlap before the relevant producer changes the readable shape.

These boundaries must be promoted together. The isolated cohort now has actual
constructor/receiver funding, source preparation, ordinary actor/provider
acceptance, and tracked Application/Custody snapshot bodies. Focused local
startup and covered-handoff checks pass. The actual snapshot
install/reopen scenario now passes with canonical target receiver ingress.
Covered actor installation and cleanup also pass denial of new mandatory
installed grants after Ready; the Engine governor, physical promises, and all
other ingress paths remain separate qualification requirements. The mandatory vendor snapshot corridor, concrete storage ABI and shared native
producer are now composed in isolation. The unconditional unbound refusal has
been replaced by actual preparation, exact store/context checks and a bound
native Ready witness. Conflict, final image, source capture and cleanup must
pass the actual install/reopen and failure selections together before promotion.

Local preacceptance is the boundary for each replica, not an all-member quorum
requirement. A lagging replica can refuse new local obligations until it has
capacity while the existing Raft quorum continues. Once a replica accepts the
obligation, later apply must use its owned capacity; cancellation of a client or
RPC waiter must not release it. Recovery must cover accepted uncommitted entries
as well as committed ones, because a later heartbeat may commit the former
without another append.

Promotion must install the real current/next source cohort and reusable encrypted
workspace during database construction, before initial restore or replay. Source
preparation must consume those owned assignments.
The first public escape of a Generation or snapshot must fund its historical
ownership before returning it; aliases share that same funded source. Internal
apply/validation borrowers keep their exact predecessor without a new public
acquisition. Return a publication assignment only after actual retirement or
completed history transfer. Prove several real encrypted publications while an
old snapshot stays readable and ordinary bytes/slots are saturated. This slice
is a prerequisite for the complete ingress guarantee above, not its substitute.

The cohort owns the actual current/next metadata cells, proof backing and prepared
point buffers, as well as native readers and report/census rights. Funding only
a pin or recording a byte quote cannot authorize a publication. Before a current
source first escapes, admit the concrete replacement lane that its historical
retention would otherwise consume. Share funded ownership across aliases and
return it only after actual retirement. A clean capacity refusal must cancel only
provisional history work and leave the current source readable and retryable;
unknown cleanup retains both the original failure and the actual owner. Accepted
suffixes retain their obligations across canceled request waiters.

### M03 promotion gates

The isolated cohort contains the ordinary actor provider, explicit Engine,
Authority and Custody roles, fixed startup ownership and the canonical native
snapshot corridor. The current production-status section and evidence ledger
record its exact passing and failing selections. Historical component passes do
not establish successful service installation or promotion.

Use these finite, ordered exit gates for the current M03 integration:

| Gate | Required result before promotion |
| --- | --- |
| Ordinary actor acceptance | Real leader/follower/init/membership paths acquire capacity for the assigned IDs before mutation. Rerun all three original startup scenarios and explicit refusal/retry tests without changing their limits. |
| Shutdown and refusal | Enrollment serializes with sealing; callbacks run outside owner locks. After a known refusal that never entered publication, return slot capacity only after transferring the original diagnostic to a separately funded owner. Unknown append/flush/cleanup outcomes retain their actual owners. |
| Exact snapshot preparation | Retain the actual backend, replacement tables, final writes and canonical gate across preparation and publication. Do not accept a replacement backend at publication. Preserve per-schema maxima even when the aggregate byte bound does not grow. |
| Snapshot actor progress | An owned, Send restore object crosses the worker/actor boundary. Higher-term votes remain durable while snapshot selection is held; defer conflicting work without blocking the actor on its own preparation gate. Include the actual pre-install conflicting-log deletion in the same prepared authority and certificate; moving it after installation creates an unsafe crash window. Cancellation retains the prepared body until positive retirement. |
| Native publication allowance | Admit one node-bound allowance before Ready for all conflicting-log deletion chunks and final namespace replacement. It must coexist with durable votes, cover actual old/new row inventory plus encryption/native workspace, and transfer already funded rights into each current-root transaction without fresh ordinary admission. Inventory actual deduplicated encrypted operations, including old-row deletion; retain exact store/node and key identity. Conflict chunks may commit independently, but final application/custody namespace replacement remains one atomic native publication even when staging is streamed. Capture its exact selected native source using already funded backing while that final commit still owns the writer; keep the returned source through backend publication after releasing the writer. Do not recapture a newer root after votes or cleanup commits. Inventory post-publication cleanup as well, or transfer it to an actual separately admitted maintenance owner before acknowledgement; a crash-safe marker alone is not an owner. Preserve native sequence/file-ID headroom while ordinary votes progress. Holding today's WriteTransaction across the handoff fails this gate because it monopolizes the shared writer. Deny ordinary memory/physical grants after Ready and verify completion, partial-write failure/reopen and exact retirement. |
| Complete overlap accounting | Fund the actual gate/registry through final retirement and account prepared backend, candidate, writes and diagnostics at their overlapping lifetimes. Passing source-slot tests alone does not cover these allocations. |
| Integrated promotion | Compile and test the composed production constructors, all ingress paths, recovery and shutdown; then apply the verified source to the live checkout and rerun affected operational cases. Component-only or isolated-copy evidence cannot close this gate. |

All M03 entry points must connect the following owners without obtaining a
replacement mandatory grant after acceptance; qualify them together on the
source that will be promoted:

1. **Constructor adoption:** all three Engine construction paths consume the
   actual constructor envelope, returned point backing and returned workspace.
   Fresh bootstrap, durable bootstrap, snapshot restore and the accepted suffix
   must supply their real seed before restoration or replay starts.
2. **Protected prior-control planning:** the same reusable source assignment
   covers prior cursor, initialization and retirement rows as well as the
   successor selection. Charge actual decoded DTOs, serialization and retained
   prepared writes at their overlapping lifetimes. A selected-source quote
   alone does not cover this earlier control work.
3. **Actor and snapshot custody:** the actual actor predecessor and assigned
   entry IDs select an owned Ready token or a retryable Pending result before
   accepted-log or membership mutation. Snapshots use their actual prepared
   selection. No pending operation may block the actor from delivering the
   apply acknowledgement needed to free its capacity.

Complete these gates before claiming source-cohort production activation.
Snapshot preparation owns the canonical control gate used by maintenance and
bootstrap writers across worker, actor and install handoff. Cancellation must
explicitly close the actual staged resources, queued source reader and point
workspace; Drop cannot certify retirement. Keep the restore obligation counted
through actual reservation destruction. A cleanup panic retains its original
payload in funded custody. Published source ownership transfers to the current
Generation; an unknown publication cannot become a clean cancellation.

For a closed application snapshot, revoke plaintext access at its existing
boundary. The final custody-only publication must then use an explicit authority
for that exact staged custody inventory. A paired publication that rechecks an
already sealed application fails after acceptance; a blanket key-check bypass
or delayed revocation is not an acceptable repair. Cover both successful close
and custody revocation before final publication.

The snapshot progress gate also covers indirect worker reads (replication and
external GetSnapshot). A prepared body must not queue its own cancel/install
behind a read blocked on its held gate. Pending source capacity needs a concrete
wake path, including with periodic ticks disabled. Native write workspace and
physical precommit promises for conflict truncation and snapshot publication
must be obtained before acceptance; a source-byte quote or a bounded batch
count does not supply those guarantees.

Single-domain and cohort checks validate reusable components; they do not
alone meet these gates. Capacity growth must perform provider callbacks without
holding its lane/cleanup mutexes, and an accepted capacity token must keep a
real drain obligation until both append and flush have successfully returned.
The actor slot and its concrete provider allocation need independent constructor
funding, released only after both allocations actually retire. An unknown or failed flush must
retain the actual token and original failure in an owner visible to shutdown;
cancellation or dropping a wrapper cannot stand in for completed retirement.
Even a capacity request that fits existing byte maxima must preserve its
per-schema high-water shapes for later combined operations. Preacceptance sizing
must not advance the exact published replay seed. Source-specific refusal
checks do not prove that native write scratch, physical promises, application
candidates and responses are already funded; retain those as separate
preacceptance obligations. M04 disk document serving, M05 disk indexes and M06 total
residency/accounting remain required after the ownership integration.

The **M05 retained-log qualification** is separate from the M03 actor boundary.
The production per-entry map and full header collection are already removed;
only scalar retained endpoints remain resident. Validate full entries against
the exact captured immutable source at startup. Append publication
and capture must exclude intervening writers through the actual native writer
owner; that prerequisite now passes its focused checks. Thereafter bounded
protocol lookup may read authenticated scalar IDs from that validated source.
Truncate, overwrite and snapshot transitions must preserve or replace this proof
explicitly. The current protocol ID representation may remain during the M03
integration checkpoint, with M05 explicitly open. It is not a supported fallback
or a completed bounded-memory design. Do not make the remaining retained-log qualification
a prerequisite for testing the actor's actual preacceptance capacity boundary.

### Document, index and cache cutover gates

The next work advances three coordinated lanes. Their shared durable collection
identity must bind the primary root, structured/unique roots, text generation,
counts and semantic byte totals to the exact accepted source. No lane is a
separate serving mode, and none may activate with a resident-map fallback.

| Gate | Concrete exit condition |
| --- | --- |
| Trusted mutation inventory | Actual reducers produce the accepted journal for ordinary writes, staged finalization, archive placement and collection/schema changes. It covers inserts, replacements, deletes, archival and multi-ID/multi-collection batches. A caller-supplied changed-ID set or whole-map diff cannot grant publication authority. |
| General primary editing | Bounded insertion, split, deletion, empty-root and collapse operations feed one private evolving tree. Intermediate staged pages have explicit retirement ownership; large edit inventories use admitted ordered storage. Publish only the final roots through both ordinary `CompletionLoan::publish_source` and other accepted publication paths. |
| Exact index ownership | Close the actual accepted producer's ordinal interval. Mark every new live object once through its exact owning edge; reject unmarked, duplicated or foreign objects. Released tombstones stay unowned. Shared old subtrees retain their original ownership and require exact selected-source graph proof. Branch separator references are borrowed and must equal their child's minimum. The collection Manifest requires the complete index catalog. |
| Every index kind | Structured presence/postings, unique tuples and text storage use durable roots and bounded builders/readers. Query access is lending and fallible. All index roots commit with document roots, and all existing query and analyzer behavior passes on the exact selected source. |
| Runtime state and operations | Remove all-document live/archive maps from production reducers, validation, counts, leases and serving. Preserve semantic snapshot records; restore builds fresh local pages and never exports local page IDs. Cover genesis, bootstrap, replay, snapshots, rejection and idempotent replay before removing test-only activation gates. |
| Full-fit decoded residency | Add actual cache membership, exact version identity, pressure eviction, reservations and finite warm/refill progress to the charged document pool. Fund retained query owners and their per-database registry; retain original read/cleanup failures through canceled waiters. After warm-up, every fitting record and index page remains hot, including rarely read data. |
| Coherent activation | One source-pinned service run uses empty resident document maps, durable indexes and the total cache budget below and above the bound. It passes security, pagination, atomicity, restart and snapshot tests before live promotion. |

Logical index order cannot use native HMAC key order. Preserve exact decimal,
string and tuple ordering, including legal keys longer than a primary document
ID or one page, with admitted external key backing and bounded comparison work.
Text indexes must retain the term, frequency, position and document statistics
needed for existing analyzers and ranking without a resident all-ID directory.

The canonical native atomic-image extension is a shared prerequisite for final
root inventories that exceed one existing atomic batch. Implement private
candidate publication once and use it for both large snapshots and large
application/index publications. Keep intermediate chunks invisible and retain
all original source and physical ownership until the one final root is durable.

## Unresolved qualification obligations

These remain release gates even when related component reruns pass:

- **Physical enrollment:** exact same-inode/EOF allocated-block mismatches occurred
  during large encrypted publication and expiry/reopen. Unchanged reruns pass, but
  the cause and a qualified recovery are not established. Preserve original
  custody and strict closed-owner enrollment checks; do not infer a repair from
  a later pass.
- **Admission before acceptance:** selected-source cells were requested too late
  in serving expiry/backup, archive publication and backup cancellation. Fund their
  actual successor, capture and diagnostic owners before the local obligation.
  Preserve the recorded deficits and original response/failure identities.
- **Replica/recovery:** original invalid constructor budgets stay negative cases;
  separately derived positive fixtures do not count as same-budget repairs.
  Recovery physical-acquisition failures and later unmarked leader-barrier
  timeouts still need exact diagnosis/final-source qualification. Deadlines and
  vote durability remain unchanged.
- **Lease and metadata cutover:** selected query metadata must retain definitions,
  validators and bounded source rights without resident ID/membership/text roots.
  The original-owner selected lease page worker passes its ten selected/legacy checks with
  exact point/scan DTO reads, header-only lookahead, final authorization/expiry
  rechecks and finite callback-safe lease removal. Its explicit selected backing
  retains immutable metadata credit without a resident ID directory. The full
  117-test Query suite also passes explicit rejection of resident APIs for
  selected metadata. This still
  needs the actual complete metadata/source publisher, independently funded
  archive metadata and removal of resident open/refresh/select paths.
  Compiled schema validators currently escape as raw Arcs through a global
  weak cache. Metadata preparation must transfer an actual prospectively
  funded validator owner before dropping the accepted resident Generation;
  retaining an uncharged validator clone is not a memory-accounting solution.
  The existing schema input limits alone do not establish compiler or retained
  allocation bounds, including reference expansion, regex work and weak tails.
  The isolated closed native owner serializes compilation/meta-validation and
  each validator's calls without exposing a raw native validator. Its three
  runtime/parity/concurrency-poison tests pass. The acyclic owner repair now
  passes all 1,713 native cases, including the unchanged Weak-only recursive-drop
  probe, actual compiler-created auxiliary sharing and clone/error lifetime fixtures. All 239 native
  regex tests pass with a source-derived parser-scratch quote; that quote does
  not establish the full compiler or regex-engine bound. Compilation workspace,
  repeated auxiliary reference trees, containers, regex construction/retention
  and validation/error workspace each need source-derived prospective funding.
  Snapshot leases currently share resident ID trees and select/size rows from
  resident maps. Replace the entire page-selection path with bounded headers and
  exact same-snapshot live/archive loans; replacing only ID enumeration is
  insufficient. Perform disk work and provider callbacks outside the lease
  registry lock, then preserve current authorization, TTL, term and epoch checks.
- **Total memory:** candidate bodies, history/audit/staging, query/aggregate/decimal
  work, native text parser/writer/finalizer allocations, and error/diagnostic tails
  must all have bounded original ownership. Native cache accounting alone cannot
  establish a whole-process bound. Qualify protocol term metadata, ingress and
  response bytes as well as already-streaming retained-log lookup.
- **Final source:** repeat affected operational/security/restart checks after the
  document/index cutover, including the previously passing 100,000-row recovery
  and 4,200-command permanent-custody cases. Synthetic/component evidence is not
  a production RSS, swap, latency or full-residency workload.

The [2026-10-02 history](disk-backed-cache-progress-20261002.md),
[2026-10-03 history](disk-backed-cache-progress-20261003.md), and
[evidence ledger](evidence/disk-backed-cache-20260930/README.md) preserve exact
previous checkpoints, failures, pins and commands. Reorganizing those records
closes no obligation.

## Goals and completion criteria

Recording or reorganizing the plan closes no goal. Each criterion below requires
evidence from the actual final implementation at the stated scope.

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
- Make the configured cache capacity usable across its native and decoded
  layers. Internal per-group or per-tier ceilings must be explicit configured
  constraints, or reconcile with the total so they do not evict a fitting
  database merely because one collection or index holds most of the bytes.
  Unused collection reservations must not strand capacity needed for full fit.
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
   Include an uneven distribution with one large collection/index and many
   small ones, proving that independent internal ceilings do not leave data
   cold while the complete eligible set fits the declared configuration.
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

C01 and C02 provide the foundations. Build C03 on admitted durable lookup,
integrate C04 and C05 together, then complete C06 and final C07 qualification.
The [implementation design and allocation inventory](disk-backed-storage-design.md)
records memory ownership and the durable application transition; the
[compaction follow-up](disk-compaction-followup.md) retains its separate physical
reclamation requirements. All supported callers move to canonical first-release
APIs and formats with strict old-format rejection and no compatibility fallback.

Disk-size reduction is a separate objective: compact encoding, compression and
effective reclamation may reduce storage use, but are not implied by eviction.
Do not claim a universal cache hit rate or a reduction in on-disk database size.
