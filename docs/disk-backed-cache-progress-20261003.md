# Disk-backed cache qualification history — 2026-10-03

This preserves the detailed status and qualification narrative removed from the
active goal list during consolidation. Statements are scoped to their recorded
source and date. It is history, not a claim that production activation is complete.
Use [the active goals](disk-backed-cache-goals.md) for current work and the
[evidence ledger](evidence/disk-backed-cache-20260930/README.md) for exact runs.

## Current production status

All C01–C07 goals remain **open**. The native key directory is disk-backed.
Production document maps and structured/text indexes are still resident, so the
complete document/index cache cutover is not active. The large cache must keep
all eligible data resident while its fully accounted footprint fits.

Implementation and validation are currently in an isolated integration cohort;
those changes have **not been promoted to the live checkout**. Component passes
from different source cohorts do not combine into a release qualification.

- **Native foundation:** the latest complete native selection passes all 598
  tests on 1,671 stable pins. It includes actual 100,000-row and 100 MiB atomic
  images, retained snapshots, votes, reopen and first-read full residency.
  A subsequent focused selection passes actual log/directory/root fault
  injection with old-or-complete crash recovery and cross-chunk key rejection.
- **Encrypted snapshot publication:** the canonical Store bridge now feeds the
  same single-final-commit image protocol. The actual snapshot installation and
  encrypted reopen check passes. The large byte-count case fails during commit
  on an exact physical-enrollment mismatch; the same inode and EOF have fewer
  allocated blocks than the prior observation. Original custody is retained.
  The unchanged byte case passes its close-trace rerun, leaving the original
  mismatch unexplained. Earlier operation-count runs were interrupted during
  slow per-row staging. Both unchanged large encrypted workloads now pass
  together on 422 stable Store dependency pins, including the 65,539-operation
  image with the original 8 MiB staging cache. The passing rerun does not erase
  the original allocation mismatch or its failure/recovery acceptance gate.
- **Document/index construction:** accepted primary editing, referenced catalogs,
  metadata-only generations, bounded index point editing and same-attempt
  resource release have scoped passes. The complete accepted index producer,
  exact ownership proof and mandatory all-role catalog are still required.
  The combined accepted-draft/index join, encrypted text-file import and
  prospective query preparation are applied only in the integration cohort.
  The earlier selection passed 55 of 56 Engine checks; its text-tree abort-tag
  failure is now repaired. The subsequent coherent selection passes all 50
  selected checks (Engine 34, Query 11, Store 5), covering mandatory collection
  joins, selected index baselines, sparse edits, old-graph retirement, text
  production, original protected-source loans and charged analyzer initialization.
  The unchanged large branch/Released proof also passes. Paired retirement
  records now pass their codec, corruption, unknown-append and paired-cleanup
  checks. The final-publication fixture initially retained the pre-catalog count;
  after correcting that count, its unchanged unknown-outcome/reopen assertions
  pass. These component results do not qualify production serving.
- **Query/cache ownership:** Database-local source-work accounting, exact owned
  source preparation and cache-headroom release events pass focused checks.
  All four finite-refill cases now pass, including fitting data, cancellation,
  original failure retention and pressure followed by complete refill. The
  narrow Pressure result preserves the original typed refusal before native
  acquisition. The shared matching-term interface and bounded-score experiment pass all
  105 Query unit tests;
  the earlier OwnedBytes selection passes all 15 unit tests on its pinned source. The real analyzer allocation check measures
  278,508 bytes of peak requested heap against a 52,988,594-byte total admitted
  envelope, including 47,524,744 embedded bytes. This is allocator evidence,
  not a process RSS measurement or a text writer/finalizer peak qualification.
- **Known concurrency repairs:** scoped checks now pass both the source-close
  contention repair and the separate publication/audit lock-order repair.
  Their original failures and exact evidence remain recorded.

The next production dependencies are complete disk index graphs, ordinary query
loans over protected captured sources, and event-driven finite preload/refill.
Text admission must include the actual writer/finalizer peak and any analyzer
dictionary that outlives a query or builder. A transient operation allowance
cannot cover a process-lifetime Japanese dictionary. Disk text metadata must
distinguish live candidates from retained deleted segments used by the existing
scoring semantics; row identity and segment identity are separate exact integers.
Repeated updates/deletes must cross the pinned resident Tantivy merge thresholds
in ranking-parity tests. An indefinitely retained inactive-segment statistic can
diverge when the existing merge policy removes deleted physical documents; a
silent live-only statistic is not an acceptable substitute. Define and qualify
the corresponding disk text compaction/statistics policy before activation.
The shared analyzer must also remain hot between queries while the complete
accounted footprint fits. A weak registry alone does not provide that residency:
retain an explicitly charged idle owner outside the governor's ownership cycle,
and retire it only for real byte pressure, a configured aggregate RSS bound,
invalidation or shutdown. Slot contention and a failed RSS sample alone must
not evict fitting data. Verify both idle
reuse and final allocation release, including weak control blocks and escaped
reader/error handles. The first integrated idle-owner selection exposed five
failures: stale RSS-sample age prevented retention of an already-funded runtime.
The correction now passes all five unchanged tests and an explicit stale-sample
regression in a 112-test integrated selection. Fresh admission remains strict.
Same-owner budget resize, active-byte retention after shrink, publication wakes
and prepared private-source reads pass in that selection. Finite Database refill
and actual service startup/shutdown integration remain open.
Only after those join the atomic publisher can serving and reducers remove the
resident maps. All operational, security, accounting and final release gates
remain required. The 42 changed and 11 added OpenRaft files have now been reviewed
and the isolated canonical inventory deliberately advanced to 611 files. The
actual 251-test library selection, 18 verifier regressions and exact dependency
integrity check pass; the latter covers 960 stable file pins. This closes that
inventory mismatch on the isolated source only. Full feature/platform and
integrated release qualification remain open. The [evidence ledger](evidence/disk-backed-cache-20260930/README.md)
retains source pins, artifacts, commands, original failures and scoped results.

| Area | Implemented and verified scope | Still required |
| --- | --- | --- |
| Native storage | Public Core uses the segmented log, immutable disk directory and shared bounded page/value cache. Its resident per-key tree is removed. The latest isolated native source passes all 598 unit tests, including fitting-data retention, pressure/refill, large atomic images, mandatory pre-effect admission, optional post-effect cache refusal, snapshots, compaction and failure/reopen. Earlier live and integration evidence remains separately scoped in the ledger. | Final installed workload/release qualification; bounded maintenance progress and physical space reclamation under sustained work. |
| Cache accounting | Aggregate native cache credit includes payloads, metadata, idle credit and retained reader pins. A real installed-governor fixture retains 16,513 rows and 91 pages with 128 slots and no backing reads on repeated passes. Pressure value and directory reads now use their admitted output directly without redundant temporary payload buffers. A fitting multilevel directory retains every page with no repeated backend reads. | Decoded document/index cache integration, collection reservations, all data-sized application allocations, validated deployment defaults and whole-process measurements. |
| Application reads and indexes | Queries use a snapshot-scoped lending source; owned outputs retain admission. The production source adapter still borrows resident document maps, and structured/text indexes remain resident. | Authoritative disk documents and all index kinds, bounded builders/editors and query work, identical results and security both below and above the bound. |
| Atomic publication | The ordinary command owner binds raw bytes/digest and retains the actual response, context and guard. Production completion keeps actual source preparation/selection through outer Raft finish and pairs installation on all three construction paths. Focused ownership/publication checks pass; canonical production report inspection preserves originals. | Integrate primary publication, all edit kinds, initial/recovered baselines and source serving. Current primary/COW graph publishers are test-only; full operational qualification remains open. |
| Source and memory ownership | Exact selected-source proofs, actual source registries, completion constructor quotes and real allocation-tail tests have focused evidence. Closed internal validation/apply paths now use one exact prior Generation; only actual uninitialized construction permits an absent prior. Registered/native funding components also have recorded coverage. | Production integration of complete source funding and encrypted loans; capacity before accepted work; complete candidate, query, error and diagnostic ownership. |
| Operations and release | Encrypted source reads and selected restart/restore checks have recorded passes. Earlier failures retain a per-case ledger; scratch pressure, staged capacity and audit cancellation now pass their integrated checks. Metadata restore passes within its unchanged limits. Full replica recovery passes under an explicit valid constructor/workload budget; the original invalid total is retained as a negative case. Expiry/reopen passes its latest run, while its earlier physical mismatch remains unexplained. The unchanged large capture/restore now passes its focused deadline gate. | Full standalone/replicated, backup/restore, archive/audit, shutdown and security qualification on final disk-serving source. Known failures and final-source qualification remain open; both formerly interrupted permanent-custody cases have scoped passing evidence. |

The production residency blockers are visible directly in
[`CollectionState`](../crates/kasumi-types/src/lib.rs),
[`GenerationDocumentSource`](../crates/kasumi-engine/src/document_source.rs) and
[`QueryIndexes`](../crates/kasumi-query/src/lib.rs). By contrast, native
[`Core`](../crates/kasumi-kv/src/core.rs) already opens `DiskState`; replacing its
old resident key map is no longer pending implementation. This distinction does
not close C02's operational and qualification requirements.

Initial generated policy assigns a 1 GiB persistent per-group cache ceiling and
512 MiB per scratch table under aggregate installed admission. These are explicit
large policy settings, **not validated production defaults**. Per-group ceilings
must never be counted as independently available capacity.

## Qualification history and remaining gaps

- The canonical snapshot install/reopen and positive actor cases now pass after
  receiving through the actual target owner and observing the retained log
  scalar without reacquiring the held control gate. Their pair and gate checks
  remain intact. Actor installation/cleanup passes with mandatory installed
  grants denied after Ready. A later combined decoded-cache cohort exposed
  immediate bootstrap-source retirement failure. The actual original owner
  identified opening-lock contention; the precise repair and the separate
  physical-identity lock-order correction now have scoped passing evidence.
  Preserve both regressions during final qualification and promotion.
  Engine-wide governor denial, physical promises, large atomic images, and the
  final-source operational selection also remain open.
  Prepared-child cancellation/wait and the original fourteen physical-owner
  fixture failures also pass their unchanged assertions. The earlier failures
  remain in the evidence ledger.

- Restore cleanup ordering, the earlier header rejection and the four bundle
  setup failures have focused passing evidence. The latest integrated selection
  also passes both actual encrypted scratch pressure cases, staged-capacity
  branch retirement and both audit cancellation/panic cases. The native arena
  header is now constructor-owned, eliminating its late post-sync grant.
- Metadata restore now passes its intended `QuotaExceeded` assertion and the
  unchanged recoverable-image assertion under 32 slots/64 MiB. The repair reuses
  actual decoded views through full semantic validation; the other verifier
  still decodes its image once. All three selected verifier regressions pass,
  including wrong supplied state, semantic substitution, cancellation and
  corrupted footer. The original allocation failures and exact lease inventories
  remain recorded; this focused result does not qualify all restore paths.
- The earlier source/ownership selection passed 113/114 Engine, 24/24 Raft and
  16/17 Store tests. The Engine unwind repair and its exact-payload regression
  now pass in the 865-file selection. The Store final assertion now checks that
  a positively retired native registration is absent after dropping the combined
  diagnostic; that Store test now passes. Three new Raft planning tests pass.
  All four older synthetic fault fixtures now have an explicit installed physical
  owner for the planner and pass their original crash/failure assertions.
- The expiry case now passes Complete-close and fresh reopen. The earlier
  physical allocation mismatch remains unexplained; a later pass alone does
  not establish its repair. Local source-startup capacity and the separate
  archive/backup late grants still require M03.
- Replica membership and full close progress, but isolated first reopen fails
  the 528-byte SourceRoots registry grant. Actual charges are 265,194,343 bytes
  against a 454,059,462-byte limit, plus 67,108,864 required cache headroom and
  134,217,728 ordinary protection: the requested total exceeds the cap by
  12,462,001 bytes. Slots and sampled RSS are not the limiting condition. This
  occurs before selected-record planning; the separately applied actual-root
  plan cannot explain or close this failure. The fixture's 384 MiB base is fully
  consumed by independent audit, maintenance, ordinary-protection and cache-work
  floors, leaving no constructor overhead. The former ordinary-protection
  admission predicate also omitted existing source/cache obligations. Its applied
  correction now checks the complete proposed protection and independent cache
  floor atomically before mutation. This invalid budget is retained as a negative
  case; the positive fixture derives from canonical constructor quotes plus
  explicit workload capacity. A corrected fixture is not a same-cap repair.
  The positive scenario now passes every replica reopen with exact state/membership
  comparison (25.86 s test, 1,542 unchanged pins); the actual invalid-budget
  installation/rollback case also passes. A separate older eight-slot audit
  fixture is likewise invalid under its combined nine-slot obligations. Both its
  exact refusal case and separately derived positive fixture now pass; the latter
  preserves four actual resident slots while ordinary work is saturated. A
  combined traced run also timed out earlier during election;
  retain that separate result. Vote durability and deadlines remain unchanged.
- The unchanged large restore case (512 terminal rows, 256-chunk manifests,
  60,000 ms verification deadline) now completes source snapshot capture. Public
  restore framing and decode remain separately measured. Table reuse and exact
  batch-retirement ownership pass 36/36 scratch tests, but subsequent unchanged
  restore runs expired after 20 and 29 of 64 terminal batches. The diagnostic
  sample locates repeated full 64 KiB decryptions for native header/page reads.
  The private 4 KiB native layout now passes all 62 selected spool/table/claim
  tests and the original restore: all 64 batches finish and verification completes
  in 34,842 ms. Exact pre-effect quotes, retained ownership, authentication,
  original record counts and the deadline remain enforced. Earlier runs
  and differing host contention remain in the ledger; system swap and one-time
  process samples are not whole-workload RSS/swap qualification.
- The broader selected-primary filter also ran the serving-expiry/proof case.
  It fails during the initial backup checkpoint, before the intended expiry
  assertion, retaining an apply failure at log 4 with applied position 3.
  The later retained-report observation identifies a late source-cell grant:
  9,216 bytes requested at 433,968,186 charged, with a 588,277,281-byte cap
  plus 67,108,864 cache headroom and 134,217,728 ordinary protection. The
  exact sink failure is `ResourceExhausted`; the actual response remains
  retained. This is another M03 preacceptance-funding case, before expiry.
- Archive publication fails its mandatory 8 KiB selected-source cell admission:
  charged work plus required cache headroom exceeds the unchanged cap by
  38,191,738 bytes. Slots and RSS are healthy. The separate backup cancellation
  case has a 45,726,037-byte deficit with additional ordinary protection. These
  are distinct measurements of late mandatory capacity acquisition; neither the
  cache read optimization nor a completion-owner shell fixes availability.
- The broader recovery route has both a retained physical-acquisition failure
  and later leader-barrier timeouts without a physical-failure marker. Existing
  evidence does not establish the exact failing reopen/checkpoint or a repair.
  Do not substitute a later partial pass or change deadlines to close this gate.
- Candidate bodies, growing application history/audit/staging state, remaining
  query/aggregate/decimal work, opaque text analyzer/index allocations, enclosing
  error shells and diagnostic collection tails are not all admitted or bounded.
  A native byte-cache bound does not establish a whole-process bound.
- The original 100,000-row retirement recovery case now passes on 1,528 unchanged
  source/config pins (820.97 s test / 822.88 s runner). The gate-stable coverage
  repair preserves row authentication, key validation, complete candidate checks
  and rejection of the uncommitted tail. Earlier interrupted runs remain in the
  ledger. The other interrupted `permanent_custody_exceeds_former_count_and_snapshot_ceilings_and_reopens`
  case now passes in 351.71 s (358.24 s runner, 1,560 unchanged pins). It first
  failed setup because its synthetic node lacked the actual physical owner
  required by the control planner. The fixture now shares that owner with scratch
  under its original 256 MiB/4,096-slot provider. The 4,200-command workload,
  snapshot limits, replay and exact crash-reopen checks are unchanged. These
  synthetic fault-backend tests are not production RSS/performance workloads;
  their affected paths still require final-source qualification.
- Kasumi's per-entry retained-log map and full header collection are now
  replaced with a streaming authenticated fold and scalar retained endpoints;
  focused startup/corruption/range tests now pass. Limited reads pass their
  64-entry/48 MiB prefix tests, including large legal records. This does not by
  itself bound Raft memory. OpenRaft's retained term-boundary list can grow with
  term churn. A finite vendor change now coalesces committed ranges, bounds active
  entry/reply batches and preserves cancellation-safe snapshot handoff. Its nine
  new actual worker/actor tests and 14 existing custody/snapshot/shutdown checks
  pass on their recorded source. Non-apply ingress and opaque response bytes still
  need admission. Preserve exact log continuity and protocol matching while bounding
  those remaining owners; silently truncating the protocol list is invalid.
- Current primary/COW, aggregate decoded-document pool, retained-source worker
  and registered protected-source components include test-only paths. Their
  source-pinned successes are prerequisites, not production activation.

The [detailed implementation history](disk-backed-cache-progress-20261002.md)
preserves all previous checkpoints, failures and qualifications. Its dates and
source selections control the scope of each claim; historical statements that
work was pending are not current status. Open obligations recorded there remain
requirements until qualified evidence closes them. The
[evidence ledger](evidence/disk-backed-cache-20260930/README.md) retains exact
commands, source pins, measurements and rejected interpretations.

## Additional integration history preserved on 2026-10-04

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


## Component history consolidated into the 2078-pin phase on 2026-10-04

This preserves the previous source-specific checkpoint verbatim. Current status is in the goals and evidence ledger.

These gates extend the prepared sparse-text/catalog, early-expiry, QueryMemory
planner and draft-credit batch. The latest completed selections share the exact
corrected v6 cohort, with 2,070 unchanged source/config pins. They pass 254
standard/263 generic-snapshot OpenRaft tests, five journal and 19 accepted-producer
tests, the original expiry/reopen/shutdown scenario, four warming and 125 broader
native checks, 1,741 schema and 124 Query tests. Each runner and its dependency
inventory checks exit 0; their selected-pin hashes are identical. Earlier scoped text-warming,
async callback, cancellation, checkpoint, standing scratch and reference tests
remain recorded on their exact predecessor sources in the evidence ledger.

**The original service expiry/reopen/shutdown scenario now passes** on corrected
v6, with every original assertion unchanged. Actual writer abort/disposal/access
retirement handles precommit expiry, and graceful Raft stop now consumes the
original applied responses before the core exits. The earlier sink, capture and
unconsumed-response failures remain in the evidence ledger. A completed drain
alone still cannot erase a reported error or authorize discarding retained
ownership; the passing scenario requires the real error-free shutdown and exact
reopen results. This closes that reproduction, not all M01 or M03 obligations.

The v5 repair now passes 13 retained-native, 21 paired-domain Store, nine
Raft completion and 18 Engine cleanup tests. Its original service failure is
resolved by the v6 native stop repair described above. The
reviewed v6 cohort adds actual retained leaf traversal/planning backing and
canonical schema type/logical/acyclic-reference payload ownership. All 1,739
schema and 124 Query tests pass; unsupported compiler graphs and final Validator
handoff still report incomplete. The seven leaf-workspace tests and 125 broader
directory/compaction tests passed after two test-only compile corrections.
Review also corrected two ordinary leaf scratch quotes without changing budgets
or canonical algorithms. The constructor-owned ordinary journal grant passes all
five actual reducer, allocation/drop, drain, unwind and authorizer-bound tests.
The graceful shutdown repair now passes all 254 standard and 263 generic-snapshot
native library tests on the corrected source. The same 2,070-pin cohort passes
all 19 accepted-producer checks and the unchanged Engine service scenario; its
runner exits 0 with all pins unchanged. Four retained-warming tests, 125 broader
native checks, 1,741 schema tests and 124 Query tests also pass on that source.
These are scoped advances in M03, not evidence
that whole-operation admission or disk serving is complete.

The unchanged eight ordered-index checks passed on successor v2. Both sparse-text
checks failed with `selected protected primary source unavailable`. Their fixture
used an ordinary predecessor with the protected successor API; repair the fixture
to construct the actual protected cohort, bind its prepared baseline capture and
read through the prepared current source. Preserve the complete original rows,
budgets, semantics and positive retirement assertions. All 2,052 source/config
pins remained unchanged. The original 65,539-operation Store case
still runs on frozen v1
(2,036 pins) with its original 8 MiB staging cache. Neither checkout is promoted
to production. Recovery checkpoints preserve both sources and the 29 external
native inputs; source-specific runner logs establish qualification. No performance
conclusion about the intended large-cache deployment follows from the
zero-native-cache component fixtures.

The next 2,074-pin v6 phase applies reviewed density planning, reclamation
traversal, schema properties/array payloads and the protected sparse fixture.
Its page/grant constructor lifetime correction is included. Native qualification
has exposed preparation refusals under unchanged 3-MiB budgets and one new
max-key fixture using an incompatible tiny segment. Resolve the actual geometry
and fixture setup without weakening workloads or raising memory budgets.
The three schema compile errors are corrected. The next run passes 1,746 of
1,747 schema tests and all 124 Query tests; the remaining negative fixture
assumes a held-child funding boundary absent from the canonical fused-array
schedule. Preserve that schedule and check the real final payload instead.
The actual native trace identifies an unreachable 2-MiB torn-tail search quote
inside the prepared maintenance owner. Remove only that term, retain general
recovery funding, and verify real damaged-prefix refusal. The separate max-key
fixture needs the normal writer; preserve its 8-MiB budget and full workload.
These narrow corrections require runtime qualification before sparse execution.
The earlier 2,070-pin passes do not qualify the new changes.

Reusable scratch backing now passes its scoped runtime checks. Both transaction
creation and maintenance roll consume the original leases; only positive
physical file retirement returns a lease to its slot. The prospective-byte test
also distinguishes an adopted file's reusable lease from its two ordinary setup
leases, which retire on actual close. Engine counters do not yet activate this
bank. The actual native maintenance codec buffers now pass all five focused
cases, including sparse leaf evacuation and density packing with old snapshots
under both zero and large cache settings. Retained directory buffers and the
seven leaf-workspace cases also pass their scoped checks. Complete the actual
density planning, post-publication warming, cache/reclamation workspace and
owner-bound fixed-u64 write, then install these owners through the real Engine
admission path before acceptance. The warming successor passes its four focused checks on corrected v6; density
and reclamation still require qualification after the measured quote repair.
The actual Engine budget headroom and admission before acceptance remain
required; neither prerequisite alone closes M03 or authorizes publication.

The predecessor v3 (2,056 pins) qualified actual maintenance codec buffers,
capture-validation retirement after successful binding, and the canonical
schema pending/keyword input owner. All 605 native tests passed, including the
original 100,000-row and over-96-MiB publication/reopen cases, as did 124 Query
and 1,732 schema tests. Its helper retains a nonzero selection-count outcome:
18 intended Engine tests passed there, and the omitted nineteenth passed in a
separate exact run on the same source. The initial test-only compile error and
the selection mistake remain preserved, together with their corrections.

The qualified v4 changes add actual retained directory mutation buffers,
canonical boolean payload/final-node ownership, and the production accepted
owner's inventory shared with physical graph inputs. They do not yet select
disk document/index roots for serving. The v5 expiry repair now retains the actual
native transaction across abort and records its disposal separately, preserving
an abort error even if later cleanup panics. Its scoped passes alone do not close production admission; the later v6 service
shutdown reproduction passes as recorded above.


## Checkpoint history consolidated after Decoder16 qualification — 2026-10-04

The following exact checkpoint text was replaced by the active, scoped results.
Original UTF-8 fragment SHA-256: `be0b1cc89120f81d9e8733056be1919c70f8151003f721390cc1e48da73d53a4`. Earlier passing and failed
source cohorts remain historical evidence; none activates production serving.

### Current integration checkpoint

The integration checkpoint has five specific completion gates. A component
pass below closes only its stated test scope; production milestones remain
open until their exit gates pass on the active service path:

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
  later failure. Also retire the original writer explicitly when a concrete
  access check fails before commit. Preserve its abort result separately from
  disposal and both access-guard outcomes; neither an unknown abort nor a
  destructor panic proves completed cleanup.
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

The last fully completed selection was corrected v6 with 2,070 unchanged
source/config pins: 254 standard and 263 generic OpenRaft tests; five journal,
19 accepted-producer and the original service expiry/reopen/shutdown checks;
four warming, 125 broader native, 1,741 schema and 124 Query checks all passed.
This closes the original service reproduction while M01/M03 remain open.

The following 2,074-pin phase exposed six real 3-MiB maintenance-preparation
refusals, one incompatible maximum-key fixture and an array test that assumed
a nonexistent funding boundary. The actual allocation trace identifies a
2-MiB torn-tail reservation unreachable from prepared-identity replay. Reviewed
fixes preserve the general recovery allowance, original memory budgets, rows,
error/panic identities and all semantic assertions. Original failures remain
in the evidence ledger.

The active 2,078-pin phase contains those narrow fixes, canonical size-validator
payload accounting, and authenticated constructor command-shape observation.
Its full 1,751-test schema suite and all 124 Query tests pass, including the
corrected array test; that runner exits 0 with every source pin unchanged.
All 151 selected native maintenance/directory/reclamation checks also pass,
including the seven original failures and new durable-corruption case, with
all pins unchanged. The 12 retained-command constructor checks and four paired Store callback
checks also pass with unchanged pins. Engine compilation exposed two older
fixture sites missing the new explicit protected-mode bool; the narrow test-only
correction is applied. Both protected-capture cases now pass, but the original
sparse selection aborts on a stack overflow in native scratch-table creation.
The first admitted disk Box passes four allocation/lifetime cases and both
protected-capture cases on the combined 2,080-pin source, but its sparse run
still aborts. That crash reaches `DiskState::assemble`: Core's closure frame fell
from 874,144 to 513,296 bytes, while create/assemble still occupy 370,960 and
186,800 bytes. The reviewed successor moves the actual fixed traversal state
behind an admitted owner and retains its complete charge through deallocation.
Its full 653-case native suite passes with no ignored/filtered cases and all
2,080 pins unchanged; both protected-capture cases also pass. The original
sparse workload completes without a stack abort on the default stack, but both
cases fail at a document-source retention capacity refusal. Constructor stack
repair is verified at that scope; the complete sparse gate remains open. An
unchanged rerun uses the existing admission trace to identify the exact refusal
and ownership dependency. The prior combined-source 651-case pass remains recorded.
The command summary is quotation data: complete decoded
Command ownership and incoming acceptance capacity remain open. Complete
schema compilation still reports incomplete until its remaining payload,
resource, diagnostic and final-handoff terms are owned.

The numeric-owner successor passes all 1,756 AP schema tests, all 124 Query
tests and six focused tests in each of the non-AP and independently enabled
Serde-AP configurations. Every one of its 2,078 source/config pins remains
unchanged. Large-number arithmetic scratch and complete compiler ownership
remain open; these passes establish the supported private payload owners only.

Protected sparse-text fixture repair now uses the actual prepared cohort;
its two original workloads still require a successful runtime result. The unchanged
65,539-operation Store debug test stopped during the explicit interruption;
process inspection confirms it no longer runs. Its original partial log is
retained. The release-profile run keeps the original rows, 8-MiB staging cache,
assertions and mandatory-grant denial. It completes with one failure during
native publication preparation, before commit diagnostics/readback. The retained
original cause still needs observation and repair. None of these isolated sources is
promoted to production.
Exact source hashes, failed originals, recovery archives and test selections
are recorded in the [evidence ledger](evidence/disk-backed-cache-20260930/README.md).

For the remaining implementation, completion means a finite set of connected
production capabilities: (1) owned read/write/compiler capacity before acceptance,
(2) one atomic primary/index producer and its durable selected reader,
(3) complete full-fit residency and finite refill, and (4) final feature/workload
qualification. Additional diagnostics and test fixtures are evidence for these
capabilities, not new goals or substitutes for them. Integrate a reviewed change
only after its affected checks pass; keep failed originals available for exact
reproduction.

The next concrete deliverables, in dependency order, are:

The immediate implementation slice is finite: qualify the native constructor
stack repair; preserve the qualified retained reclamation candidate/capture ownership;
complete typed Command decoding and remaining schema payload ownership; then
join those actual owners to the accepted primary/index producer. The sparse
2-case selection and protected-capture 2-case selection are the constructor
repair gate. Native reclamation's seven new failure/pin/retirement cases and
existing 151-case selection pass together. Automatic compaction residency now
has an actual retained-owner implementation with a complete 658/658 native
pass, including five new denial, full-compaction, refill, error/panic and
foreign-owner checks, with all 2,082 pins unchanged. Owner-bound fixed-counter/writer admission
remains the next native implementation. The schema fixture correction now
passes all 1,763 AP tests and eight focused checks in each alternate numeric
profile, with all 2,082 pins unchanged. It preserves the exact original unknown
Draft7 annotation case and strict incomplete ownership assertions; both original
failures remain recorded. Legacy dependency-array ownership and the typed
Command decoder are reviewed successors under combined-source qualification.
The array selection first exposes a test-helper type mismatch before runtime
totals. The decoder compiles its complete DTO inventory and production libraries,
then exposes two new Entry test literals missing the canonical initialization
field. Repair those fixtures while preserving their original assertions.
None of these gates
permits larger stacks, relaxed budgets or a production residency claim.



## Refined remaining implementation and preserved failures — 2026-10-04

The active goal continues to require the complete fitting database resident in
a large configured cache, with capacity eviction only above the bound and
finite full refill after shrink or budget growth. Durable writes precede
publication in both regimes. No production goal is complete yet.

The remaining deliverables stay connected: complete actual preacceptance owners;
one durable document/structured/unique/text publication and selected reader;
service full-fit startup/mutation/refill/shutdown; final workloads and release
checks on one promoted source. Isolated fixture fixes and new diagnostics do
not create additional completion goals. Current source-specific failures and
exact successors are recorded in the evidence ledger under “Original
integration failures and owned successors”: decoder denied-unknown/scope
fixtures, schema original-wrapper/early-executor fixtures, independent native
reader refund, and ENOSPC before the Store preparation observation. The
original Store preparation refusal and sparse journal capacity refusal remain
unresolved. Qualify the actual encrypted counter consumer, positively dispose
retired text construction buffers, complete the ordinary response bank and
compiler graph handoff, then join these owners to the production publisher.

## Completed owner scopes and remaining integration gates — 2026-10-04

The current goals now name four connected deliverables: complete preaccepted
ownership, atomic all-role disk serving, full residency below the aggregate
bound, and final operational qualification. All C01–C07 remain open.

The final schema graph successor passes 1,779 AP schema tests, Query124 and
24 tests in each alternate profile on 2,101 unchanged pins. Its supported
validator/diagnostic owners retain original compiler credit and retire backing
before credit. Nonempty default meta-validation, Value clones/object not,
source/Registry, other private variants and runtime funding are still required.
DependentRequired's prior frontier correction passes 1,773 AP and18+18 focused
checks; Query124 passed on the same production code. Both original failures
remain in the ledger. Decoder depth/map correction passes11+11 on2,086 pins
without changing canonical Data errors, locations or recursion semantics.

Fixed-u64 native checks pass7/7. The encrypted consumer compiles after two
narrow type fixes; its new destructor custom-error fixture still finds one
allocation. The unchanged real encrypted long-run and Engine checks remain
active. Positive text construction retirement's first selection stops on private
test access; the original sparse workloads have not yet passed. Response byte
custody passes7/7 plus Raft publication19/19 and normal Engine/Authority library
checks. Three canonical-type fixture corrections are under the remaining
Engine/Authority/service qualification. These components are isolated and do
not authorize production acceptance or disk-serving activation.

A distinct actual full Rebuild text producer is frozen for review. It must close
statistics, live-term membership and all roles through the original accepted
input, Manifest and final source census before native/metadata admission and
atomic publication. Complete service refill must then include every retained
public generation and index role, with no capacity eviction below the bound.
The original Store preparation observation retry remains active with its
original workload. Verified removal of obsolete unlinked task object outputs
recovers space without cleaning the warm Cargo lane or unrelated data.


## Integrated writer and exact remaining reservation — 2026-10-04

The refined goal remains complete residency below the aggregate memory bound,
capacity eviction above it, and finite full refill after shrink or budget growth.
The native key directory is already disk-backed. Production document maps,
resident index graphs, all-role publication and selected serving still prevent
C01–C07 from closing. Five exit gates now connect the remaining work: repair
original failures; own all preaccepted work; publish documents and every index
atomically; activate full-fit service residency; qualify the final source.

The funded compiler entry passes AP1,801, Query124 and46+46 focused cases,
with2,142 unchanged source/config pins and all Cargo invocations fenced. The
response bank passes Engine9, Types1, Raft constructor7 and response7, with
2,090 unchanged pins. Its original first-membership fixture failure is preserved;
the correction applies that same fact before the later application. These
scopes do not close default meta/runtime/frontend ownership or all responses.

NativeFinal35 integrates the reviewed serialized writer, original scratch
retirement and held-state facades into the final Decoder/Response source. Its
exact native10 and encrypted Store2 checks pass on2,094 unchanged pins. The
complete qualified source and reviewed inputs are archived in
`target/disk-backed-cache/source-checkpoints/native-final-image-qualified-successor-2094-v1`.
The original65,539-operation encrypted release finish/replay gate is still
pending. Scoped native checks and the earlier admission probe cannot replace it.

The unchanged original sparse caller trace finishes0pass/1fail565.77s;
runner671.97s exit1 with2,081 unchanged pins. The refused reservation is the
component proof's second Session:33,554,560 requested bytes,230,199,416
charged,329,238,878 limit,67,108,864 protected cache bytes,52 source slots,
100 live slots and a free slot. Cache pressure is false. The repair binds that
component to the actual preaccepted Edit credit and reuses its physical Session
after producer/import and positive retirement return. The two original
workloads and all caps/assertions remain binding.

MetaInput13 is reviewed and applied only to the schema successor for runtime
qualification, including explicit preserve_order. It owns the exact19 embedded
input decodes, partial prefixes, original native errors and final controls.
Default meta runtime and production compiler admission remain separate work.
Target response capacity is integrated into the writer/decoder successor; its
affected checks remain pending. No source is promoted and no production goal
is marked complete.

## Remaining integration gates — 2026-10-05

The target-response selection passes Engine response 10/10, Types 1/1 and
Raft constructor/response 7/7 each. Exact target machine/resolution is 17/18:
the unchanged exact-prefix reopen test fails during Builder setup, requesting
20,552 bytes for an encrypted scratch segment when all 32 original provider
slots are occupied. Its 64 MiB byte ceiling is not exhausted. The next run
uses the existing real lease trace; no cap or prefix assertion is changed.

The recorded target checkpoint contains 2,094 unchanged source/config pins.
Its source archive is 7,574,871 bytes, SHA-256
`cf4020cc0f606e9070d7ce6a4aa13e46c4575f64e62c151f063c4ba483a1052a`;
reviewed inputs are 73,910,518 bytes, SHA-256
`b0ada3c5102c1ac537dc1ab542c2ef345838a138bed7aa27dbe0b3e61dee53ec`.
It is a failure checkpoint, not a qualified production implementation.

Combined meta-input/value-keyword qualification passes Query 124/124 but
exposes two schema fixtures needing exact corrections: canonical and funded
validators use different base URIs, and the historical partial const fixture
now reaches the newly supported native compilation branch. AP is 1,812 pass /
two fail, with 57 pass / two fail in each of four alternate profiles. The
runner exits 1 with all 2,146 selected pins unchanged. These results do not close the schema frontend.

The sparse Session qualification currently exposes one new panic fixture
tuple mismatch. Actual retirement drops expected, comparison, journal, then
kernel; comparison refund unwinds after expected has retired. The reviewed
test-only correction retains original panic-pointer, charge and physical
Session retirement checks. The original sparse selection has no terminal totals: the original full-semantics
case aborts on the default stack in `DiskState::compact_inner` during structured
index writes. Static frames in the matching crash/binary already sum to
2,053,728 bytes before other runtime frames. The reviewed five-file receiver
keeps one typed intermediate role in the existing funded box and separates
transitions; it and the fixture correction are now applied for qualification
with unchanged budgets, default stack and original sparse assertions.

The preaccepted canonical effects successor is now applied to the integrated
writer cohort for qualification. Its six reviewed images and 521 exact
dependencies retain all four original durable writes before acceptance and
bind them to the actual verified root without new allocations. Native task
Cell/undelivered-Join changes and the complete Tokio inventory are applied.
The initial run stops before compilation at a stale README support-file record;
an exact inventory-only repair is applied and qualification is rerunning. Source notification/drain,
default-meta/frontend ownership, all-role publication, production query
cutover and full-fit service refill remain open.

The canonical effects run finishes one pass / four protected setup failures;
the exact-prefix target case remains one failure. Its recorded checkpoint
contains 2,095 unchanged pins, source SHA-256
`5d32f8ab495410cb160f11ccf04a9ba6112c2aeaa3623e48c6bbe0cd46140b26`
and input SHA-256
`05f1c75c339286249e51b9b30adcc37535f781ff7bef31878b7b713b6dc7408f`.
The existing same-owner retained apply diagnostic is now observed only on
fixture failure; the original result and custody remain unchanged.

The target lease trace identifies all 32 real owners: 15 durable node leases,
nine first-importer construction leases, seven first-table initialization leases
and one transaction file. No predecessor can positively retire before the next
file reservation. The reviewed test correction uses the existing canonical
temporary importer scope while retaining the original durable node budget and
all prefix assertions; it is not an aggregate production-memory proof.

Equal-base-URI and genuinely unsupported-enum fixture corrections are composed
with the original funded options clone and applied to the schema cohort. The
next exact gates are AP 1,822, Query 124 and 67 focused checks in all four
profiles. Actual cold hash/default-meta/frontend ownership remains open.

## Verified successors and remaining production work — 2026-10-05

The options successor now passes AP 1,822/1,822, Query 124/124 and all 67
focused checks in each of four feature profiles. The runner finishes in
2,788.22 seconds with exit 0 and 2,149/2,149 source/config pins unchanged.
Its cold hash and fresh default-options successor also qualifies: AP
1,826/1,826 (6.82 seconds), Query 124/124 (3.93 seconds), and 71/71 in all
four profiles (0.38/0.38/0.47/0.47 seconds). The final runner exits 0 after
141.06 seconds with 2,168/2,168 pins unchanged. Original upstream hash
selections pass 34 library, five map, one no-panic, three no-RNG and three
compile-time-RNG cases. Two earlier selection helpers incorrectly expected
five tests in mutually exclusive three-test feature branches; their failures
are retained. Only the inventories were corrected, with no native assertion,
algorithm, capacity or feature semantics changed.

Protected baseline, four-role effects, coupled capture and metadata now pass
all eight actual Engine checks (63.31 seconds) on 2,654 unchanged pins. The
exact response tail is prepared by the fixture for every protected command,
before ordered preparation, and its original capacity owner survives through
the operation. The earlier publish-only fixture still lacked that tail in
`prepare`; its seven setup failures are preserved. Target machine/resolution
passes all 18 cases (4.21 seconds), including exact-prefix reopen. The canonical
temporary importer scope retains the durable node's original 64 MiB/32 slots,
8 MiB table and all original prefix assertions. Engine response checks pass
10/10 (5.76 seconds). This fixture repair does not prove aggregate admission
for production ingress.

Native task checks pass 7/7. Original Tokio abort, panic, task-ID and join-set
selections pass 8/7/17/19. The join-set harness enables its required `test-util`
feature; its original source and assertions remain unchanged. Its initial
helper mistakenly required an upstream test gated on `tokio_unstable`; the
corrected stable inventory has exactly 19 tests. Canonical caller-owned drain
registration, independent Waker cancellation and actual caller funding still
precede production source retirement. Native data completion must remain
separate from notification metadata disposal.

Sparse role preparation passes all 11 focused checks (1,133.72 seconds) with
the default stack and unchanged limits. Both original sparse cases start,
then the first aborts with stack overflow in the later text-edit
`PrimaryStage::perform` path, before terminal totals. The runner exits 101
after 2,299.71 seconds with all 2,081 pins unchanged. The matching crash and
binary identify the actual large preparation state copied through catch and
return frames; the earlier boxed role orchestration frame is now 240 bytes.
The next repair retains that original edit state in a prospectively funded
box. Both original sparse workloads remain required.

The unchanged encrypted Store 65,539-operation release image/replay test now
passes **1/1 in 1,279.25s**, runner **1,425.37s, exit 0**, on
`/tmp/kasumi-source-cohort-store-release-v1`, an immutable copy with all 3,060
source files verified and **2,654/2,654** matching qualification pins. Its
original workload and assertions remain intact. The snapshot inventory hash is
`9d0cb4691d624b98f7ff9bd4a11b5c023c188e477039568def9ecb078c04dfbe`.
The earlier generic 105,955,471,360-byte promise failure remains evidence.
This closes the original large image reproduction; production preacceptance
ownership and final joined-source qualification remain open.

The reviewed URI and fresh native meta-Registry owners are now joined in the
isolated schema cohort, preserving the original embedded schemas and native
builder. Their actual allocation, refusal and cleanup checks and the affected
original native suite still require runtime qualification. The boxed text-edit
receiver and bounded native document constructor are also joined in the Engine
cohort with the previously qualified retirement, Session and role fixes. Every
other newer image is preserved. Both original sparse workloads retain their
original limits, rows, assertions and default stack; they still need a terminal
pass. Neither join activates the production frontend or all-role publisher.

The refined sequence is to finish these original failure gates, close actual
native/schema/response ownership before acceptance, publish all document and
index roles atomically, activate disk queries and complete finite service
residency, then run the five final workload classes on one promoted source.
The complete fitting database must stay resident, including rare data,
indexes, metadata and retained versions; growth alone causes capacity eviction,
and shrink or budget growth triggers finite complete refill. All C01–C07 and
M01–M07 remain open. No implementation source has been promoted to the live
checkout.


## Source-scoped prerequisite history preserved during goal refinement — 2026-10-05

This section preserves the earlier goal document's exact prerequisite narrative.
Its stages describe the source and evidence available at each checkpoint; the
current goals and latest verified successors take precedence for present status.
Every remaining ownership/capacity obligation is still binding. Earlier failures
are not discarded when a later repair passes, and no component pass activates
production serving.

The final schema graph owner passes **1,779 AP schema tests, all 124 Query
tests and 24 focused tests in each non-AP and independently enabled Serde-AP
profile**, with all 2,101 source/config pins unchanged. It retains the original
compiler credits through validator, diagnostic and concurrent last-owner
retirement. This closes the supported private graph handoff scope. Value
clone/object `not` also passes **1,784 AP schema tests, all 124 Query tests and
29 focused tests in each alternate profile** on 2,136 unchanged pins. The actual
Source clone owner now passes **1,789 AP schema tests, all 124 Query tests and
34 focused tests in each alternate profile** on 2,138 unchanged pins, using the
cohort build identity guard. Nonempty default meta-validation,
fresh Registry construction, process-global hash runtime, remaining private
compiler variants and production integration still precede complete compiler
admission. The actual retained Registry clone also passes **1,795 AP schema
tests, all 124 Query tests and 40 focused tests in each alternate profile** on
2,141 unchanged pins with the build identity guard. Its exclusive original
Registry loan and private clone/control backing remain charged through final
physical retirement. The funded entry receiver now passes **1,801 AP schema
tests, all 124 Query tests and 46 focused tests in each alternate profile** on
2,142 unchanged pins. It borrows the same funded Registry, Source and original
resolver/options into the unchanged compiler. Default meta runtime, fresh
Registry/hash construction and the production frontend remain incomplete.

The typed Command decoder passes **11 ownership/depth/map checks in each JSON
Map profile** on 2,086 unchanged pins. The canonical unknown-field Data error,
error location and recursion limits are preserved. Its prior constructor12,
Store4, journal5, accepted-producer19 and original expiry/reopen/shutdown passes
remain source-scoped. Shared candidate payloads and complete response admission
still require actual preacceptance receivers.

Native maintenance residency passes **658/658 tests** on its source. The fixed
traversal owner eliminates the constructor stack abort, but both original sparse
text workloads still fail capacity admission. The earlier trace identifies a
9,476,672-byte journal request with 252,819,440 bytes charged, a 329,238,878-byte
limit and 67,108,864 bytes of cache headroom. Positive retirement of completed
text construction work passes all seven component checks after correcting two
private test-access errors. Both unchanged sparse cases still fail with the
original document-source retention error. The subsequent exact caller trace
locates a **33,554,560-byte** second Session reservation in
`primary_stage_index_text_component_proof.rs:133`, with 230,199,416 bytes
charged against the same 329,238,878-byte limit and 67,108,864-byte cache
reserve. A free ledger slot remains; cache pressure is false. Reuse the actual
preaccepted Edit Session only after producer/import and positive retirement
return, retaining its original credit and frame invariant. Qualify both
unchanged sparse workloads with their original limits.

The earlier original **65,539-operation Store release workload failed during native
publication preparation**, before commit/readback. Its original rows, ordinary
65,536-operation refusal, two image chunks, 8 MiB staging cache and denial of
new mandatory memory after Ready remain intact. The first failure-only
observation exits with ENOSPC before the preparation diagnostic. The unchanged
retry completes with native CapacityDenied at pre-effect preparation; every
commit/capture/cleanup/disposal entry remains NotEntered. A genuine inventory
probe now preserves the backend's original **StorageFull**: the current generic
bound promises **105,955,471,360 bytes**, including file framing and tails,
against about 5.1 GB available. The tighter serialized image owner must hold its
actual writer through authenticated effective-edit preflight and capture; the
generic parked bound remains unchanged. The integrated serialized owner now
passes **native 10/10 and encrypted Store 2/2** on 2,094 unchanged pins. Its
original state, raw panic/error and held-writer cleanup remain owned through
retirement. The exact 65,539-operation encrypted release workload now passes
unchanged through commit, capture, replay and disposal: **1/1 in 1,279.25s**,
runner **1,425.37s, exit 0**, with **2,654/2,654** matching pins. The immutable
snapshot contains 3,060 source/configuration files. This closes the original
image reproduction; production preacceptance ownership and final integrated
qualification remain open. The interrupted debug run still has no terminal
result, and the diagnostic probe alone does not count as that pass.

The corrected fixed-u64 native selection passes **7/7** actual update/close
checks. The real encrypted Store long-run passes its original 2,500 unique updates,
cache-on/off, split, roll and maintenance requirements. The additional destructor
fixture first exposes one **64-byte** allocation in its native mutex receiver.
Replacing that test receiver with an inline mutex preserves its original custom
error and zero-allocation assertions. The focused **Store 2/2 and Engine 2/2**
checks now pass with exact same-table memory-relief reentry. Earlier missing-API
compile errors came from stale metadata in the shared Cargo target; subsequent
commands serialize Cargo and refresh changed package roots without changing
source bytes or discarding the warm target. These scoped passes do not yet fund
a complete writer before Raft acceptance.

Modern dependentRequired ownership passes **1,773 AP checks and 18 checks in
each alternate profile** on 2,099 unchanged pins before the final graph
successor. Original helper/projection and early-refusal failures are preserved;
the correction observes each real constructor frontier rather than assuming an
executor exists before construction.

The response byte owner passes **7/7** ownership checks and **19/19** Raft
publication checks, and normal Engine/Authority libraries compile. Its corrected
fixtures pass **Engine24, Authority8 and the original expiry/reopen/shutdown
scenario** on 2,087 unchanged pins. The fixtures use explicit borrowed byte
copies or canonical response construction; their original assertions remain.
The ordinary accepted-response bank and typed audit/recovery buffers now pass
**Engine 9/9, Types 1/1, Raft constructor 7/7 and response ownership 7/7**
in the fenced v14 cohort on 2,090 unchanged pins.
Their failed-buffer proof observes the same original ledger slot, identity and
byte charge after separately completed Store retirement; aggregate totals remain
exact. The original wider selection failed because its fixture had not applied
the first membership fact. Applying that exact original first entry before the
later application preserves the assertions and passes all seven constructor
cases. Native notification/cleanup, remaining response families, shared
candidate descendants and durable suffix reconciliation remain open.
Earlier private-constructor/import compile failures and the original aggregate
baseline failure remain recorded. Final return notification progress, remaining
response families, shared candidate descendants and durable slot reconciliation
remain open.
