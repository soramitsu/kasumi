# Disk-backed storage with full residency below the memory bound

Status: **active; all seven implementation goals remain open**. Established
2026-09-30 from the user's proposal and clarification; current status consolidated
2026-10-04. These goals extend G02 and its query, snapshot and resource-admission
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
| Native lookup/publication | Earlier pinned selections pass 598 native tests and actual 100,000-row / >96 MiB images. The contraction correction passes all 191 NodeDisk tests and the original large byte-bound Store image. The original 65,539-operation Store rerun, with its unchanged 8 MiB staging cache, is currently pending on the unchanged v1 baseline. | Remaining operational reproduction, final installed workloads and sustained reclamation. The filesystem cause is unproven. |
| Documents and writes | Protected current/old sources, accepted primary edits, mandatory structured catalogs and an actual indexed Edit commit/selected receipt have scoped passes. Primary command staging and fixed point backing are allocated before candidate construction. | Complete candidate/journal/index/verification ownership before local Raft acceptance, all ingress/recovery paths, full index graph proof and activation. |
| Query and text | All 120 Query tests (including the schema streaming preflight and native flush-group geometry) and the earlier 11 encrypted Engine ordered/catalog/query checks pass. The expanded original-history baseline passes with a real Stats branch, independent physical statistics and graph checks. All 12 original-source journal ownership checks pass. Accepted-row/component and complete LiveTerms semantics, mixed/empty group retirement, and actual selected metadata/ID headers pass their encrypted checks. | Sparse edits, repeated disk merge execution, native allocation admission and final atomic all-role publication remain open. Complete lease-page replacement and release of resident generation ownership remain pending. These component proofs do not grant publication authority or activate serving. |
| Cache and refill | Large-cache sampling/churn, same-Core reclamation and collection protection have focused passes. All 58 latest refill/worker/child checks pass, now including the finite selected-lease Session phase and mutation races. Three closed Generation-handle and six actual control/weak-tail accounting tests pass. Structured traversal verifies a zero-new-read second pass. | Finish text traversal, the funded census of all retained public generations, all-role completion, automatic service startup/shutdown and final accounting/workload qualification. PrimaryAndStructured cannot claim whole-database residency. |
| Operations and consensus | Snapshot install/reopen, source-retirement, audit cancellation and selected recovery repairs have scoped evidence. Reviewed canonical OpenRaft inventory passes 251 library tests and 18 verifier regressions. | Engine-wide admission before acceptance, unresolved operational cases, final feature/platform/release checks on one promoted source. |

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
| **M01: Repair current failures** — C05, C06, C07 | Preserve the metadata-slot repair and finish startup-source, election/membership and capture/restore repairs; preserve original failures and real cleanup. Keep independent M02/M03 implementation moving when it supplies a named repair. | Each valid scenario reaches its intended assertion on the integrated source. Preserve invalid configurations as negative cases; derive separate positive fixtures from canonical constructor costs and explicit workload capacity. Do not mask defects with changed caps, deadlines, assertions or row counts, accept unknown outcomes as success, or release old roots prematurely. Final operational selection passes, including exact reopen. |
| **M02: Reusable encrypted reads** — C01, C05, C06; supports C02 | Route earlier control planning, selected capture and installed terminal scans through their actual operation-owned point backing. Finish constructor/retirement custody and the exact read-owner handoff. | Real encrypted reads reuse bounded backing without mandatory per-record reservations; snapshot, table, provider, authentication and current expiry checks remain exact. Two distinct cleanup failures retain both originals. Verify the large capture path separately from fixture setup. This does not yet prove postcommit capacity. |
| **M03: Protected publication capacity** — C01, C05, C06 | Activate real current/next source rights and reusable workspace; fund escaped historical sources before return. Bind complete successor capacity to local leader/follower acceptance, recovered accepted suffixes, membership/catalog changes and snapshot installation. | After accepted admission, saturating ordinary capacity cannot introduce a new mandatory source/planner/capture refusal. Several writes progress while old snapshots stay readable and charged. Refusal happens before local acceptance; canceled waiters cannot release accepted capacity. Recovery and all ingress paths use the same owned guarantee. |
| **M04: Authoritative disk documents** — C03, C04, C05, C06 | Wire primary construction, edits, deletes and recovery into actual ordered publication. Switch document queries to exact durable roots and activate full-fit document caching. Remove the resident all-document serving alternative. | The real service performs point reads, scans, CAS, batches, idempotent replay, retained-version reads and restart with documents larger in total than RAM. Fitting new/updated/rarely read documents stay resident after warm-up. Document publication and all associated metadata are atomic. Coordinate the cutover with M05 so existing index features remain available. |
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

The current integration checkpoint has five specific completion gates:

- **Entered-planner cleanup:** keep the original error, Cell and credit after
  positive source close and point return. A transient Cell lock conflict must
  remain retryable without replaying retirement, and an active wake callback
  cannot authorize completed custody. Count waiter registration before cloning
  a Waker, and keep it counted through replacement/destruction callbacks. Test
  contention, concurrent registration, delayed callbacks and original panics.
  Qualify the supported serialized async drain and diagnostic-observer race: a
  temporary retained result must become complete on a real retry after normal
  callback return; a caught original panic remains retained.
- **Published-capture cleanup:** the original expiry scenario already committed
  its durable publication, then failed to capture a selected reader. Join only
  the exact returned capture error to positively retired point backing and the
  registered reader. Retain its response, forbid acknowledgment, and require the
  original reopen assertions. Earlier planner refusal proof cannot cover this
  later failure.
- **Native schema memory:** fund the actual private node controls, compiler and
  final vectors, sorting workspace, locations/URIs and supported validator boxes.
  Quote input vector capacity independently of length. Actual allocator tests
  must cover spare capacity; complete compiler admission stays open until every
  remaining term is funded.
- **Text counter ownership:** qualify the single original native write transaction
  and fixed-u64 update, preserving absent-zero insertion, overflow, rollback,
  pinned readers and exact failure identity. This removes duplicate reads; it
  does not satisfy native writer funding before Raft acceptance.
- **Selected text refill:** traverse all ten actual catalog roles, canonical
  component directories and every file chunk through the original selected
  source. Qualify repeated hot reads, corrupt tails, expiry, cancellation and
  pressure/refill. Byte residency alone leaves native parsing, semantic proof
  and the text completion gate open.

These gates extend the prepared sparse-text/catalog, early-expiry, QueryMemory
planner and draft-credit batch. The latest successor retains 2,052 source/config
pins. Its scoped results now include all five selected text-warming cases, the
actual async callback test (four cases), original cancellation and checkpoint
checks, all seven standing scratch-backing cases, all 124 Query tests, 141 native
reference tests and 1,727 native schema tests. Original setup/compile/accounting
failures and exact corrections remain in the evidence ledger. These passes
qualify the tested components; they do not activate production serving.

The service expiry scenario still fails. The earlier 2,049-pin run observed an
ordinal-2 sink failure with no preparation remaining. The expanded 2,052-pin
run instead observes an ordinal-1 action error after successful publication,
with a positively closed failed-capture cell. The existing binder-only receipt
cannot cover a later selection-validation failure. Add only a proof tied to the
actual validation's normal returned error, exact cell, positive native close
and original point-bank return; panic, foreign errors and unknown native
outcomes must remain retained. Preserve both observed failures and the original
shutdown/reopen assertions.

The unchanged eight ordered-index and two sparse-text checks are running on
successor v2. The original 65,539-operation Store case still runs on frozen v1
(2,036 pins) with its original 8 MiB staging cache. Neither checkout is promoted
to production. Recovery checkpoints preserve both sources and the 29 external
native inputs; source-specific runner logs establish qualification. No performance
conclusion about the intended large-cache deployment follows from the
zero-native-cache component fixtures.

Reusable scratch backing now passes its scoped runtime checks. Both transaction
creation and maintenance roll consume the original leases; only positive
physical file retirement returns a lease to its slot. The prospective-byte test
also distinguishes an adopted file's reusable lease from its two ordinary setup
leases, which retire on actual close. Engine counters do not yet activate this
bank. Next, qualify the actual native maintenance codec buffers, then complete
leaf/directory/cache/reclamation workspace and the owner-bound fixed-u64 write.
The actual Engine budget headroom and admission before acceptance remain
required; neither prerequisite alone closes M03 or authorizes publication.

The next concrete deliverables, in dependency order, are:

| Deliverable | Required proof before proceeding |
| --- | --- |
| Integrate the qualified statistics spool | The direct prepared stream now passes all seven regressions, including unchanged multi-chunk 2/1/0/2 rounds, file identity, exact original/aggregate credits and saturated slots. All nine registered-spool custody tests pass. Connect this preparation to the actual command before acceptance; other native index allocations remain an independent gate. |
| Join every index role to one durable source | The complete structured/unique/text catalog, exact component origins, semantic graph and released-object census authorize one final publication. Sparse edits and repeated merges use that same proof. |
| Install bounded metadata and lease pages | The recursive owner repair and all 1,718 native schema tests now pass. Derive the remaining compiler/validator/validation-work bounds and transfer the original validator and archive metadata credit. The closed serialized owner prevents concurrent calls from growing hidden regex pools; parser scratch and literal classification pass all 240 native regex tests. Exact snapshot pages preserve authorization, expiry and original cleanup. Selected metadata refuses resident-only APIs. |
| Complete the full-fit refill proof | All 58 integrated refill checks now pass, including the lease phase and mutation revision. Add text traversal and the complete historical-generation census. Closed Generation handles and their prospective control/weak-tail credit pass nine checks in isolation; selected metadata funding remains separate. Current-generation filling and native current/pinned completion alone cannot declare complete historical residency. |
| Activate the production path | Connect startup, writes, reads, leases, every replica's preacceptance funding and joined shutdown; remove resident serving alternatives together. |
| Qualify one final source | Run below-bound, crossing-bound and refill workloads plus feature, operational and release checks. Only these results can close C01–C07/M01–M07. |

### Recorded integration history

The following records preserve earlier source-specific results. The current
checkpoint above and the evidence ledger determine the latest status; historical
passes do not promote an isolated component into production.

The complete-catalog fixture now passes all three cases on 1,991 unchanged source/config pins: positive semantic replay, missing-LiveTerms rejection and original failed-join custody. Every original catalog/census assertion and the normal stack limit are preserved; the actual component heap is prospectively funded. The joined index owner remains Unverified until native allocation admission and production publication are qualified.

The original native schema probe established a real ownership defect: compiling
`{"$ref":"#","unevaluatedProperties":false}` leaves one original pending
properties cell strongly owned after the validator is dropped. The original runtime and
parity cases passed, but this retirement case failed on unchanged source.
The reviewed acyclic repair and immutable shared auxiliary payloads now pass
the full 1,709-test native library suite, including the unchanged failing probe,
actual compiler-created payload sharing and clone/error lifetime cases.
The remaining metadata goal requires the actual allocation model; shared
payloads do not bound repeated context-dependent compiler work.
All 239 native regex tests also pass, including actual parser scratch versus
its prospective layout quote. This closes the demonstrated cycle defect for
the qualified source, while complete native admission remains open. The same
cohort also contains native writer flush-group parity, exact borrowed sparse
text inputs, command-wide text-update detection and distinct original removal
and unchanged-projection capabilities. These are implementation steps, not
selected publication authority.

The latest combined qualification passed on 2,007 unchanged source/config pins:
1,709 native schema tests, 120 Query tests, three accepted-text Edit checks,
54 refill checks, four selected-lease checks and eight source-cohort checks.
The `source_registry_` filter matched no tests and supplies no evidence. All
18 external schema and four external regex test inputs remained unchanged.

The selected-lease census has a finite UUID cursor, exact manager/source
identity, original retention credit and mutation revisions. Its Session phase
now passes its qualification in isolation. Public Generation
ownership now uses closed handles there, with separately reviewed prospective
control and weak-tail credit. The remaining historical-generation census must
carry original metadata/validator/control credit through the last owner; a
permanently strong registry or relabelled history credit cannot close that gate.

The preceding integration checkpoint was applied only in the isolated 2,015-file
cohort and remains partially qualified. It adds the selected-lease Session phase,
sparse text framing, structural schema-planning prerequisites and the narrow
same-file physical contraction reconciliation. Its exit gates are concrete:

- The six unchanged text tests that failed with `text directory still has live
  aliases` must pass after synchronous native compression, together with the
  actual LZ4 writer geometry/semantic checks. The preceding complete text run
  passed 59/65; no failed cleanup is accepted as a positive join.
- All NodeDisk tests must pass, including the original negative enrollment
  drift case and both observed contraction geometries. Reproduce the affected
  operational workloads before closing physical enrollment; unit fixtures
  cannot establish the filesystem cause or production recovery.
- The finite lease Session must finish current and leased primary/structured
  traversal plus the same native source union, and reject mutation races.
  Text and arbitrary public historical generations must remain explicitly
  pending until their real traversal and funded census are installed.
- Qualify structural planning against the actual native compiler/reference
  implementation, including recursive presence-only references and original
  errors. This prerequisite does not yet admit the complete compiler graph.

The first validation of this cohort passed all 120 Query tests, then stopped
at a Store cursor borrow type error before Engine tests ran. The one-call
borrow correction is being validated without changing its safety predicates.
The Store correction passes all 191 NodeDisk tests and the unchanged original
large encrypted byte-image case (786.66s). The original operation-count check is queued behind the full text suite.
The Engine expiry/reopen check currently fails earlier at retained ordinary
completion cleanup; diagnose its original owner before retrying physical reopen.
Engine compilation then
found two missing test error conversions and two calls to a private Session
helper; their narrow corrections are reviewed, with Engine execution pending.
The new native structural checks pass in all 1,713 schema tests. The standalone
reference library has one failing bundled-metadata ownership fixture (136/137).
The reviewed closed Generation-handle migration, sparse physical graph checks
and main schema operation cursor are now applied to the isolated 2,020-file
cohort. Engine test compilation found two remaining mechanical substitutions;
no new Engine pass is inferred. Native main-schedule/classifier qualification
passes all 1,715 schema and 240 regex tests on that exact source. The legacy
handle constructor cannot stand in for funded selected metadata, weak-control
tails or a complete history census.

The 2,023-pin cohort combines
the narrow compile/reference/reentry corrections, prospectively funded Generation
control and weak tails using the existing allocator allowance, and sparse Edit
physical-statistics verification from the original accepted snapshot. All 137
native reference tests pass. Its Engine selection passes 79/80: all control,
handle, refill, Session and accepted Edit checks pass; one document corruption
fixture incorrectly classifies restored version zero as corrupt. The reviewed
test-only repair preserves every corruption assertion using an invalid upper
boundary and adds valid zero-revision loans. The next 2,026-pin cohort includes
that repair, actual schema-cache scheduling and shared sparse/Baseline component
comparison. All 1,718 native schema and eight document/revision checks pass;
the complete original text suite now passes all 65 tests in 5,834.71s. The following Store operation-count case started but has no terminal result; its runner is absent and the case requires a new run. The original expiry scenario
currently fails at retained cleanup before reopen and remains a required repair. These pieces do not yet authorize final index publication, selected
metadata construction, or production full-residency completion. The subsequent
2,036-pin cohort installs the funded Generation registry/Session and native
structural executor; 140 reference and 1,722 native schema tests pass. After a narrow test-helper return conversion, the Engine selection passes
98/100, including all six registered-generation Session cases. Two preexisting
empty-database fixtures stop at missing audit placement before refill enters;
the explicit fixture setup repair is prepared. Both ordered verification cases pass (1,453.62s). The original expiry case still
fails at post-publication capture/action cleanup; its exact witness is recorded
below. All 2,036 source/config pins match at the runner exit.

The next reviewable completion gates are:

| Work | Required next result |
| --- | --- |
| Operational cleanup | The unchanged expiry witness shows sink success followed by an action/capture error: Cell closed with no views, loans or native failure, but the exact failed owner still blocks completion. Add positive post-publication capture retirement and exact original action-error custody; preserve the failed response and no acknowledgment. Qualify early refusal and entered-planner retirement separately. Finish the original large Store operation-count case and exact shutdown/reopen. |
| Historical residency | Qualify the reviewed registry/Session integration over current, leased and registered historical generations, including last-strong-owner retirement, same-source native pages, mutation races and zero-read repeat traversal. Keep public-generation and text completion pending until the actual selected metadata constructor and text traversal use funded owners. |
| Native schema ownership | Qualify the reviewed structural executor on actual resolver transitions, then install the real QueryMemory-funded driver. Schedule exhaustion remains incomplete: URI/pointer, regex, vocabulary, registry, context, compiler output and validation/error work need prospective original credits before complete admission. |
| Sparse text publication | Qualify the actual ordered primary + carry/replace/delete/insert + complete catalog/Manifest replay. Retain the original pending primary draft across typed errors and panics. Move its credit into preaccepted workspace and fund native writer/parser/counter work before production publication; the distinct test-only unverified result supplies no publication authority. |
| Production activation | Install the completed document/index/metadata owners, finite all-role refill and every replica's preacceptance capacity together; then remove resident alternatives and run the final workload matrix. |

All five rows are open. Reviewed or passing test-only prerequisites are not
production completion. The detailed source hashes and original failures remain
in the evidence ledger; future progress must name which gate it closes.

Qualification also retains a concrete performance gate: the original eight-document
text group-merge case finished within a 5,834.71-second passing 65-test
unoptimized run. One-second stack samples observe statistics replay,
immutable index replacement/retirement and encrypted native writes. This does
not establish a deadlock or a filesystem cause. The original fixture explicitly
sets persistent and scratch native cache bytes to zero; this is not a measurement
of the intended large-cache production mode. Identify repeated work from source before changing it; preserve its data,
assertions, configured budgets and durability. Component correctness alone
cannot close C07.

The immediate critical path is now explicit:

1. Finish the preaccepted current/old-source staging owners and exact private
   text descendants; no ordinary allocation fallback may enter accepted work.
2. Complete text graph verification and physical statistics/merge parity, then
   join documents and every index role in the same final durable publication.
   Preserve the now-passing original-history split/statistics checks and
   selected ordered pagination in both directions, with exact prefix, range
   and continuation semantics. Baseline accepted-row/native-component and
   LiveTerms semantic proof now passes both encrypted qualification checks;
   sparse edits, logical merges and native allocation admission remain gates.
3. Activate durable document/index serving and the Database-owned finite refill
   session together, including actual shutdown join and budget/publication wakes.
4. Remove the resident serving alternatives and prove full residency below the
   bound, controlled eviction above it, and complete refill after shrink/growth.
   A document-and-structured-index pass must report text still pending until
   actual text traversal finishes and the existing native directory/value-page
   warmer proves completion for the same current/pinned source set. An
   unrelated source's refused cache offer must not prevent a fitting source
   from completing its finite pass. Retained snapshot generations need their own
   closed census and original retention credit; a raw Generation Arc or a
   current-only traversal cannot certify their complete residency.
5. Promote one coherent source and run its repository, operational and release
   gates. Earlier component passes remain evidence for their exact source only.

The current code gates are narrower than those five release milestones:

- **Accepted source owners:** repeated preaccepted old-source loans now pass
  under full ordinary byte pressure, including exact sealing and panic custody.
  Prepared Ordered staging is integrated for testing. Initial baseline capture
  now binds the actual newly selected source into its preallocated reader in a
  passing protected fixture. That fixture publishes an indexed baseline, then
  proves and aborts a prepared indexed edit. A subsequent actual indexed Edit
  commits and consumes its exact selected receipt in a passing integrated
  fixture. The command factory now owns its primary metadata, page/frontier,
  collection and captured-source workspace before candidate construction.
  Its input is already a committed command: this does not establish capacity
  before durable local Raft acceptance. Candidate/journal/index allocations
  and every replica acceptance/recovery corridor remain M03 requirements. The
  actual sparse primary draft must enter the operation owner before fallible
  index work; its distinct draft credit also still needs to move from accepted
  edit_collection execution into the original preaccepted workspace. Keeping a
  draft on failure does not prove that this credit was admitted before acceptance.
- **Pressure and refill:** all selected document-pool tests now pass, including
  callbacks that reenter during credit release. The constructor fixtures account
  for its three actual fixed owners; former insufficient slot caps remain
  negative tests. Budget reconciliation and finite refill are integrated for
  testing. Actual same-Core mandatory admission reclaim now passes 41 selected checks,
  including original-request retry, active-loan retention and reentrant relief.
  The finite victim-sampling and optional frequency-priority changes now pass
  an actual 1,024-entry reclamation/refill check in the integrated 27-test batch.
  Churn lookup now passes with every directory bucket previously occupied;
  misses use the maximum actual insertion displacement rather than scanning all
  tombstones. Collection protection uses its sorted table for lookup. The
  concurrent source-retirement and scan-history checks also pass. The async
  worker retains its original future, source session and diagnostics in the
  Database census through cancellation and shutdown. It passes its cancellation, failure and background
  completion checks in a 54-test coherent selection. Actual source-work census
  availability needs its own refill event: freeing a slot while retained reports
  keep grants charged must still resume Pressure. Relief racing checkpoint
  capture must not introduce a self-wake loop. A primary-only pass cannot
  declare full Database warm-up complete.
  Census capacity and byte capacity are separate events. The actual worker
  census-wake checks now pass, including released slots whose retained report
  aliases keep their bytes charged. The actual parented Session now passes the
  byte-relief/checkpoint race: release before checkpoint resumes its retained
  attempt, while unchanged pressure idles without an own-cleanup retry loop.
  The same source, cursor, diagnostic and grant survive the wait; one-slot
  full-fit and joined shutdown pass. These are isolated component results;
  production activation and complete index/native residency remain open.
  The retained reader continuation is now applied in isolation. It pauses only
  with its own original failure and a restorable reader/manifest, keeps its peak
  charged, and cannot accept a failure from another source. Its three new
  fixtures pass alongside both bounded staged-text-cursor checks. Joined
  retained worker steps now pass all three checks, including release before
  waiting, unchanged owner identity, original failure retention and abandoned
  pause cleanup. The parent/child census now passes its actual one-slot,
  foreign-scope, original-failure and callback-reentry checks. Complete
  Session wait integration passes in the latest 30-test refill selection. The original
  refill operation grant becomes Resident after census publication, before
  source work, preserving all bytes while releasing the operation slot.
  The RSS sampler repair is applied in isolation: the sampler publishes
  observations, while the owning async waiter delivers callbacks. Its focused
  checks have passed in the active batch, including a callback dropping the
  last MemoryCore without self-join. Actual final-owner join is preserved;
  the complete batch passes 55/55 with all 1,807 source/config pins unchanged.
- **Text baseline:** preserve the accepted physical segments, captured deletion
  generation, row identities and scoring statistics. The borrowed snapshot
  interface now passes the unchanged old-snapshot/late-merge regression. Captured
  raw file controls survive removal of their directory paths. Bounded encrypted physical import now passes three actual fixtures,
  preserving deletion masks, row identity and original partial-failure custody.
  Retained-control accounting, complete physical statistics/readback and
  all-role publication are still required. A native merged component can be
  larger than the memory bound: preserving its bytes does not qualify a bounded
  cold read. The canonical serving representation must use bounded components,
  persisted physical term/statistics data and a live term-to-component directory.
  Logical merge groups must retire deleted statistics under an explicit shared
  policy; deleted-only terms still count toward prefix/fuzzy expansion limits.
  Baseline preserves the original physical groups. Clean Rebuild must establish
  an explicit shared initial-group rule or reproduce the pinned native writer
  flush groups: a single initial group is not generally equivalent for later
  deletions/merges even when initial live scores agree.
  The earlier 110-test Query selection passed finite exact-score
  comparisons of one-document components across three analyzers and all search
  modes. The full producer now builds the additional disk term/group roles;
  those roots remain unverified until complete graph closure. The shared
  deterministic merge selector passes native-reference threshold and tie tests;
  actual disk group mutation/statistic retirement is still required. Original-history
  population, sparse edits, general limits and merge-boundary parity remain
  acceptance gates. Original failures remain recorded.
  The actual empty-group retirement editor now passes with a real statistics
  branch; mixed groups preserve original physical statistics, while removal of
  whole groups deletes their exclusive terms and keeps shared terms. Sparse
  carry additionally needs authenticated component creation context: an old
  immutable segment embeds its original epoch/counts and cannot be opened by
  substituting the successor catalog context. Bind its exact prior graph,
  definition/profile and still-live row to the new catalog without weakening
  validation. Qualify repeated merge rounds, not only one successful round.
  The resident reference now completes explicit committed merge rounds until
  no candidates remain. Its 160,000-row test executes two rounds, checks every
  live row and preserves the old searcher, within the passing 117-test Query
  suite. This is an explicit first-release scheduling rule. Disk group planning
  and mutation must use the same barriers; it does not assert equivalence to
  the old timing-dependent background schedule. The bounded disk coordinator
  now passes an actual eight-group merge, a subsequent no-candidate round and
  final graph/released-object census. The multi-chunk spool reuse test exposes
  a 124,608-byte ledger increase; preserving the original owner/file identity
  is insufficient until that accounting/lifetime failure is resolved.
- **Text allocation evidence:** the actual synchronous writer/finalizer test
  now passes four finite payloads with cross-thread frees observed. Its largest
  requested allocation peak is 20,228,003 bytes. The original overcommitted
  128 MiB fixture reservation remains a negative case; the positive case uses the
  existing producer's 32 MiB work allowance. This finite matrix does not qualify
  arbitrary documents, asynchronous merges or process RSS. Pinned Tantivy's
  writer memory parameter sizes an initial table; it is not a hard allocation
  bound. Source-derived transient/finalizer admission remains a separate gate.
  An allocation-free Japanese lattice preflight has been reviewed against the
  original admitted dictionary and pinned tokenizer sources. It passes three native checks and the complete Query selection; it bounds
  only a fresh normal-mode system lattice. The original
  runtime must supply that bound before tokenization; token output, retained
  analyzer scratch, writer growth, finalization and parser peaks still require
  their own admission. A helper or finite allocation sample cannot certify the
  combined production path.

The integrated 27-test batch establishes the first result and the import/cache
portions below. The next acceptance results must use the actual owned paths:

1. A real protected indexed Edit commits and consumes its exact selected receipt,
   returning the original funded successor baseline for the next command.
2. The canonical text baseline serves bounded live components with original
   physical statistics and deleted-only term expansion. Its encrypted statistics
   stream must verify fully before publication. Live term postings bound candidate
   selection; deterministic logical merge groups preserve the chosen resident
   reference semantics without requiring whole merged-file reads.
3. The registered service worker owns finite primary and index/native warm
   passes through publication/budget wakes and joined shutdown. Only a complete
   catalog-minted all-role pass can expose full warm-up completion; source,
   capacity, cancellation or retained-cleanup outcomes remain distinguishable.

Passing those component checks enables the production join; it does not close
it. The join must remove test-only gates, replace the resident document/index
adapters, preadmit all mandatory work on every role, and exercise the same paths
through startup, writes, reads and shutdown. Text writer/finalizer and retained
physical-file accounting remain explicit prerequisites. Do not promote a
partially switched serving path or combine unrelated test cohorts as a pass.

These gates keep the large-cache contract unchanged: retain fitting data,
reclaim only for a real byte/RSS capacity need, and refill completely when the
eligible dataset fits again. Slot contention or stale sampling is not an
eviction trigger. C01–C07 stay open until their production exit gates pass.

The resident text reference now has two passing regressions across mixed
deletions, wholly empty segments, the default eight-segment merge boundary and
24 further updates. Old snapshots retain exact score bits. These results define
the required behavior; they do not qualify disk text parity. A baseline must
preserve existing physical text statistics, including mixed-deletion segments.
An explicit schema rebuild can use its existing fresh-live-row semantics.
Treating both as a rebuild from live rows would change ranking at cutover.

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
   validity checks. The earlier frozen producer shared that ceiling; the new
   isolated image producer/consumer is now being qualified separately. Larger snapshots need an admitted
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
   injection now passes its focused old-or-complete recovery gate. The wired
   canonical encrypted Store image spool is still under integrated qualification. The real large operation fixture must also fit proven scratch
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
