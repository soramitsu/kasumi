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
custody passes 7/7 plus Raft publication19/19 and normal Engine/Authority library
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

## Detailed prerequisite history consolidated after initial native qualification — 2026-10-05

The following exact checkpoint narrative was moved out of the active goal sequence.
It preserves earlier source-scoped failures, repairs and obligations; current
status and executable exits are in `disk-backed-cache-goals.md`. Statements that
an intermediate source was unqualified describe that historical checkpoint.

The remaining schema work now has a finite source inventory with 17 concrete
production joins. It distinguishes fixed platform/thread backing from schema-sized
compiler work. Finish the original default-meta pattern constructors and their
lazy matcher caches, actual meta validation and owned diagnostics, the supported
user compiler branches and per-validation scratch. Then replace both ordinary
production meta/build calls and the raw validator/weak cache with their retained
owners. Prepared references and BTree annotation collectors have scoped source
and runtime evidence. Their supported partial graphs cannot
stand in for this complete production frontend.

Native FST backing is now joined in a reviewed, unqualified successor. Its shared
prefix bound is conservative and must be used consistently by estimator and
consumer; it does not prove fitting cache residency. Qualify its actual
registry, stack, transitions, original errors and published dependency selection.
Complete entry/record growth, analyzers, fast-field/store/meta finalization and
canonical parsing before claiming the whole writer or enabling text publication.

The 30-image schema helper preserves the existing suites and adds the reviewed
reference/legacy cases: AP 1,852, Query 124, focused 97 in each of four profiles
and native referencing 143. The newer 139-image pattern/HIR successor uses its
own source-derived inventory and qualification helper; the old selection cannot
qualify its additional cases. It has exact source, mode, patch and
16-package vendor checks, including an independent HIR ownership review. Its
original qualification failures and later passing correction follow. After two exact compiler-interface repairs,
the normal Engine/Query check passes with all 2,254 pins unchanged; the original
compiler failures remain preserved. The new AP harness genuinely resolves its
302 original identities with only the two reviewed same-version path transitions;
its source-derived runtime gate is AP 1,868, focus 113×4, Query 124 and native
referencing 143. Its first test build fails an integer-versus-pointer identity
interface in an existing BigProperties owner test: 30.95s, exit 101, with all
2,254 pins unchanged. The exact test-only correction compares the same backing
addresses directly; it changes no owner assertion or runtime inventory. The
failed source is archived before applying that correction. The passing URI/meta source and exact native
harness inputs are preserved in the verified 2,612-member checkpoint before
applying this successor.

The corrected test build reaches the actual joined inventory: 1,864 of 1,868
library tests pass, while four owner fixtures fail; Query passes 124/124.
The original provider-refusal boundaries, completed-node custody, canonical
annotation base URI and original child-process error need precise diagnosis.
The four focused profiles finish with 110/113, 110/113, 111/113 and 111/113
passing respectively. The native referencing suite stops at a stale test call
to `Resolved::draft`; use the original consumed `into_inner` result to preserve
the draft assertion without adding a production accessor. The terminal runner
is 1,590.45s, exit 101, with all 2,254 source pins unchanged. A separate exact
meta-child run preserves the original frontier assertion failure in 17.02s.
These results do not qualify the joined schema source or close the frontend.

The precise six-image fixture correction now qualifies the joined source:
AP 1,868/1,868, Query 124/124, focused 113/113 in all four profiles and native
referencing 143/143. Runner 167.59s, exit 0, all 2,254 source pins and 4,368
exact inputs unchanged. Completed native nodes and real pre-transfer refusal
boundaries are both tested on the original schemas/capacities; canonical base
URI and original result handoff assertions remain exact. This closes the finite
fixture/runtime gate, while default-meta Pattern/regex, complete compiler
funding, retained validator/cache owners and production frontend remain open.

The actual external Tantivy harness now resolves its genuine development
dependencies and preserves all 144 original production identities, the reviewed
same-version FST path transition and the original feature union. Its 241-package
lock is qualified as a dependency selection; no native runtime result is implied.
The separate FST, Columnar, SSTable and Stacker native selections still need exact harness
resolution and runtime qualification. The fast-field source has passed independent
whole-image/mode, 941 saved/original dependency and 99 published-member checks;
its 15 actual backing layouts remain an unqualified component.

The earlier ownership-test compile exhausted disk and even evidence-log flushing
failed. Its source guard was reaped; an independent post-run check confirms all
3,032 pins unchanged. Build space later recovered to approximately 70 GiB, with
no Kasumi build running at inspection. The next attempt passes the ordered-effects
normal library check but fails test compilation in 68.27s with all 3,033 pins
unchanged. Preserve both distinct failures; neither establishes runtime behavior.
The corrected retry uses the existing warm target and unchanged test selection.
It reaches all 121 selected tests: 111 pass and ten Custody cases fail; runner
319.68s, exit 1, with all 3,033 pins unchanged. The ten ordered-publication tests
pass on that source. The precise test-only observation/provider-unit correction
now passes all 34 selected Custody and original observer-consumer checks in
42.10s, exit 0, with all 3,033 pins unchanged. Strict whole-lifetime observations
remain strict; the separate retirement interval records original outside backing
and cannot claim a complete allocation census. The earlier failed source and
both failed compile/space attempts remain preserved. Final joined qualification
is still required.


The tighter FST/row successor has a reviewed finite source bound using actual
compiled trie-node degrees and the same Session credit through fixed admission,
census and dynamic admission. It also includes the prepared row buffers in the
native memory report. Exact source, package membership and patch application
checks pass; a new test's obsolete call arity has a separate frozen correction.
Runtime, fitting-dictionary admission, remaining tokenizer/store/parser work and
whole-source readiness remain open. This refinement cannot change the large-cache
full-residency requirement or justify an arbitrary dataset cap.

The retained ordered query-metadata handoff now has independent whole-source
review: eight images, 3,130 exact dependencies and six additive tests. It carries
the actual unique committed baseline, both original metadata credits and prior
capture through success and original binding failures; it exposes no serving or
next-apply authority. Qualify its successful retirement and stage/binding failures,
then add direct tests for actual Retained, cleanup error, raw unwind and guarded
Drop retaining both ledgers. Only after those gates pass can this handoff support
the production serialized apply receiver. Shared-generation funding, inherited
native destruction and all-role admission remain separate open dependencies.

The first runtime attempt passes four of the six new metadata tests. Both early
failure fixtures keep an issued response buffer alive while awaiting shutdown;
the real cohort correctly waits for its outstanding credit. Preserve the
3,034-pin stalled source and native process sample, and record the controlled
interruption separately from a completed test failure. The minimal correction
must release each actual response before waiting, without altering drain flags,
budgets, original errors, raw panic identity or metadata-credit assertions.
The precise response-lifetime correction now passes all six new metadata and
ten original ordered tests: runner 286.84s, exit 0, all 3,034 pins unchanged.
Strict dependency selection and the normal Engine check also pass. The passing
source is archived before the direct retirement successor. The subsequent
four retirement tests, six metadata, five selected-cleanup and ten ordered
checks preserve the exact 25-case inventory. A passing handoff needs
the production apply receiver, complete accepted graph and all-role publisher.

That direct retirement selection reaches 24/25: all four new retirement,
six metadata and ten ordered cases pass, with four of five original selected
cleanup cases passing. The remaining canonical predecessor fixture returns a
retained Raft apply failure. Runner 328.42s, exit 1, all 3,035 pins unchanged;
the exact failed source is archived. The borrowed original report identifies
the actual missing Entry response slot before sink entry. The narrow correction
prepares the actual Entry and holds its capacity through publication, without
clearing original failure custody, synthesizing a response or changing the
budget. The unchanged selection now passes 25/25 in 268.36s, exit 0, with all
3,035 pins unchanged. Both failed and passing source views remain archived.

The prepared FAST/FST successor is now applied to the isolated cohort against
that passing source. Actual locked selection verifies all 18 packages and the
three exact same-version Columnar/SSTable/Stacker path changes; all other lock
rows remain unchanged. Normal Engine compilation exposes E0369: original
Stacker `Addr` lacks equality for the new same-held-table identity assertion.
Runner 9.71s, exit 101, all 3,141 pins unchanged. Preserve that failed source;
the exact scalar identity interface now makes normal Engine compilation pass.
The affected Session selection initially reached 4/5 because its added refusal
fixture expected no Index, although Session retains the actual original Index.
The narrow fixture correction now verifies that same retained owner through
both refusals. Normal Engine compilation and all five tests pass: runner
93.07s, exit 0, all 3,141 pins unchanged. The complete passing source is archived;
the earlier 342.50s, 4/5 failure and its source remain recoverable.
The narrow native test import and SSTable constructor corrections now make all
five original supported-profile library/integration/doctest suites pass. Tantivy
passes 1,066 library cases with five original ignores, plus 52 doctests with one
original ignore; SSTable passes 40 library and two integration cases in both
profiles. The full qualified source is archived separately from the preserved
compile failures. The Store helper splice is restored to its exact qualified
predecessor, and the 34-image Store successor is applied in isolation. Its actual
19-package selection and normal Engine compilation now pass. All six native
Store cases, the full Tantivy suite and both LZ4 library profiles pass; the actual
Engine allocator matrix also passes. Its admission fixture still needs the
installed-baseline census correction. LZ4's two no-frame doctest failures also
occur on unmodified published source and remain recorded separately. Whole-writer
ownership, all-role publication and production activation remain open.

### 2026-10-06 constructive ownership checkpoint

The repaired isolated source passes the exact genuine genesis/index9, policy2,
original Engine35 and backend6 selections. Its separate three mutex parity,
nonblocking and poison/raw-payload cases also pass:55 runtime cases in total.
The two funded production fields use inline mutex controls, removing the
observed128-byte hidden allocation without changing the original census.
The earlier runtime gap and original-helper compile failures remain archived.
The complete passing source is preserved before the next join.

The following canonical collection-map and funded validator/query-constructor
join fails normal Engine compilation: its new native Validator initializer
omits auxiliary_owners. Full3,707 source inputs and the terminal compile failure
are preserved before repair. No runtime pass is claimed for that join. The
updated [goals](disk-backed-cache-goals.md#next-executable-exits) put the exact
joined constructor/runtime checks before native copy ownership, atomic all-role
publication, disk serving and the final full-residency workload matrix. All
C01–C07 and M01–M07 remain open; the production checkout is unpromoted.

### 2026-10-06 joined constructor and lifetime qualification

The canonical map/query successor now passes normal Engine compilation after
preserving the actual iterator interface and annotating the original refill
fixture's exact map input type. Its full Query selection passes136 unit,
five integration and three compile-fail ownership cases. The original consumer
selection passes57 distinct cases: genesis/index9, policy2, Engine35, backend6,
mutex3 and map2. All three native Known-root allocation cases and the ownership
compile-fail case also pass against the exact original schema dependency graph.
Complete passing sources and the intervening failed compile, fixture and graph
checks are archived separately.

The subsequent external per-field copy and original-diagnostic ownership join
passes normal Engine compilation and all35 original Engine cases. Its three
new lifetime cases fail during scratch-table setup with StorageFull before
their lifetime assertions run. The exact38-case result remains failed; backend6
did not run in that helper because it stopped at the failure; a separate exact
backend6 run now passes. The native library reaches1,122 pass, two new analyzer
fixture failures and five original ignores. Both new failures concern the
state expected before the actual clone: the returned/raw case receives success
instead of its second funding refusal, and the English case observes no held
String charge. Full3,708 source inputs and both terminal failures are preserved
before correction. Retain original budgets, assertions and raw payload identity,
then rerun the complete selection. Original native profiles on the corrected
source and the restored full schema suites remain required runtime gates.
Atomic all-role publication, production disk serving, finite full-fit refill
and the final below/above-bound workload matrix remain open.

The exact fixture correction now passes all38 Engine and6 backend cases;
all original35 Engine assertions and the64KiB/native-zero diagnostic allowance
are preserved. Actual retained-token warmups make Tantivy pass1,124 with five
original ignores; its documentation passes52 with one original ignore. The
strict result parser initially stops at an original Stacker identity split by
concurrent expected-panic output despite Cargo47/47 success. Its helper-only
correction preserves the exact identity/status/totals checks, and both original
Stacker profiles now pass47+3; both Columnar profiles pass188+1. The full3,708
qualified source is archived with4,301 verified member hashes/modes before the
schema reunion. The archive records1,698 passed case invocations across these
original repeated profiles, plus six original ignores; that is not a count of
distinct tests or production acceptance.

The restored schema join adds the missing authored compiler modules and six
owning support forks without changing dependency versions. Its actual4,036
source inputs and25 native packages verify. Normal Engine compilation now passes,
as do AP1,881, all four original focused123 profiles, referencing143 and the
original ownership compile-fail case:2,517 case invocations including repeated
profiles. The complete qualified source and actual compiling harness are archived
with5,536 verified member hashes/modes. The source
audit confirms production refill/public-generation bindings remain test-only,
selected text serving still lacks its verified disk backend, and native cache
ceilings need a genuine aggregate-capacity handoff. C01–C07/M01–M07 remain open.


### 2026-10-06 current ownership join and refined completion gates

The next actual join combines borrowed genesis construction and known index
ownership on the restored schema source. Its complete4,040-input source retains
all25 native packages and passes source/inverse verification. Normal Engine
compilation fails with12 errors: duplicate/private inline-publication mutex
module declarations and generic inference at connected callers. The54.71s
runner exits101 with all3,468 selected inputs unchanged. Its complete failed
source, unrun exact consumer harness and qualified ancestor are preserved in
4,098 verified archive members before repair. This failed join is not promoted.

The next runtime gate is normal compilation followed by the exact69 connected
consumer and144 Query selections. Their result parser must preserve original
compile-fail identities and strict handling of interleaved panic output. In
parallel, complete funded canonical default-meta compilation, Japanese metadata,
dictionary and stream constructors, and actual canonical backend dispatch with
retained failure custody. Then join primary/structured/unique/text publication
under one genuine durable receipt; activate version-aware production disk reads,
public retained-generation accounting and finite refill. Final acceptance proves
complete residency below the aggregate bound, pressure eviction above it and
restoration after shrink or budget growth, including an uneven large collection.
C01–C07/M01–M07 remain open until that final source passes operational/release
checks and the measured five-workload matrix.


Removing only the duplicated private module declaration makes normal Engine
compilation pass17.95s/exit0/all3,468 source pins. The unchanged joined Query
selection separately passes all144 cases including three exact compile-fail
ownership checks (50.68s). The complete connected consumer attempt stops before
runtime on seven old test-constructor type/field errors,132.39s/exit101/all3,468
pins. Its4,040-input source and exact compiler/harness output are preserved in
4,085 verified archive members/modes. A two-image mechanical correction installs
the actual inline mutex and production-equivalent initial lifecycle fields;
all original assertion bodies, test identities and capacities stay unchanged.
The69 consumer/144 Query joined rerun is active. Prepared tokenizer Registry and
standard-meta Pattern constructors are assembled separately on that exact source
for independent review and original native qualification; they are not activated.


The repaired Engine target runs59 cases:55 pass and four bootstrap cases fail
(37.07s runtime;104.80s runner/exit101/all3,468 pins). The failures concern
persisted authenticated identity and exact error/cancellation/release accounting;
none is converted to success by weakening assertions. The full4,040-input failed
source and actual harness/runtime are archived in4,089 verified members/modes.
Types4 separately passes10.86s and backend6 passes61.39s on that source. The
independently reviewed prepared Registry/standard-meta Pattern join adds15 images,
three new leaves, producing4,043 inputs with all25 native packages verified. It
is applied under the full failed-source guard; normal compilation and original
native profiles remain active qualification gates. Production publication,
selected text reads, all retained-generation residency and final workload
acceptance are still open.


### 2026-10-06 actual constructor and bootstrap qualification

The 4,043-input Registry/standard-meta join passes normal Engine compilation.
The first schema attempt stops on two test call-site reference-depth errors;
its complete failed source and actual compiling harness are preserved. The
original Tantivy attempt then runs 1,126 passes/two historical fixture failures
and five original ignores: the frozen helper had removed write permission from
original mutable format fixtures. Restoring exactly their original modes, with
no source, assertion, profile or parser change, passes 1,128 library cases/five
original ignores and 52 documentation cases/one original ignore. The qualified
source and harness are archived in 5,057 verified members and modes. Unchanged
Stacker and Columnar profiles retain their separate original scoped passes.

The next six-image source repairs authenticated genesis digest custody, audit
quiescence in four native bootstrap witnesses, and exactly the two schema test
reference-depth calls. Normal Engine compilation passes in 46.94s with all
3,471 selected pins unchanged. The exact Engine60 target runs 57 passes/three
failures: the new isolated registry pair fixture tries to open an unused scratch
directory within its original 64 KiB/native-zero allowance; cancellation leaves
an older owned report alias alive after borrowed drain; and the positive startup
case reaches maintenance-headroom refusal. Other previously failing native
release/failure cases now pass. The complete consumer failure source and actual
harness/runtime are archived in 4,834 verified members/modes before repair.
The remaining Types/backend/Query selections were not run by that failed helper.

The corrected native schema target compiles and runs exactly 1,885 AP cases:
1,884 pass and the new standard-meta parent fails. Its cold 2019-09 child reports
Incomplete(Regex) where the original graph-frontier assertion requires
Incomplete(NativeCompilation). The paid constructor branch currently misses
actual Operation::Pattern scheduling. This is a real admission boundary to
implement, not an assertion to relax. The focused four profiles, referencing
and documentation selections remain unrun on this failed source. The full
4,043-input failure and exact source/runtime/harness are being preserved.

A consuming SnapshotWorkReport drain successor and narrower same-allowance
actual Registry pair/alias witness are source-frozen for qualification. The
registry witness does not qualify production Session::prepare_registries or
EncryptedDirectory capacity. Startup headroom needs exact ledger attribution:
its current 384 MiB is also an existing explicitly invalid maintenance budget,
whose negative refusal must remain intact. Native Japanese Metadata, Bigint and
lexical-float components are source-frozen; the actual JSON-number/ModelInfo and
application Japanese consumer handoff is still incomplete and unqualified.
All C01–C07 and M01–M07 remain open. No isolated application source is promoted,
staged, committed or release-qualified.


### 2026-10-06 current exact handoffs and preserved failures (actual114–128)

The consuming native report drain, isolated real Registry pair/alias fixture,
actual Pattern operation branch and failure-only maintenance ledger observation
join in six images on the exact 4,043-input source. Normal compilation passes
9.32s/all3,471 pins. Engine60 runs59 passes/one startup-headroom failure,
132.48s runner. The exact actual ledger confirms the old384MiB total cannot
cover existing physical/audit owners plus proposed protection/cache floors.
The Pattern branch advances beyond Regex refusal but initially constructs twice;
the resulting original native input-capacity failure is preserved, together
with the full source/runtime/harness, in4,838 verified archive members/modes.

The next five-image source uses the previously specified supported positive
workload plan only for the new startup witness and constructs actual Pattern
once. Legacy384/default callers and the independent128MiB workload/fixed owners/
all original floors remain. Normal compilation passes46.21s. Engine60 again
runs59 passes/one failure,72.04s runner: startup now passes admission, but
consensus metadata publication loses the paid generation owner. The original
funded-genesis assertion fails; do not replace it with legacy adoption. Both
original invalid-budget/refusal cases pass2/2 in2.05s. Types4 and backend6 pass.
The first Query helper stops before runtime because the new recipe case was
named from its filename instead of the actual text_kernel::runtime module.
A helper-only one-identity correction retains all original144 cases/parser/
features/source bytes; the exact Query145 union passes24.89s/all3,471 pins.

The exact AP1,885 target still runs1,884 passes/one meta parent failure. A
subsequent test-message-only observation keeps every production leaf, run,
assertion and limit unchanged. The exact cold parent diagnostic identifies
PlanningFailureKind::Capacity, with native validation/resolver/vocabulary/raw
errors absent. Its entries1,024/depth512/transitions32,768 are constructor
execution bounds, not a byte allowance; locate the actual refusal site without
raising them. Focused four profiles/referencing/documentation remain unrun on
that failing source. The complete earlier4,043-input source and actual outputs,
passing Query/negative cases and preserved helper defect are archived in4,891
verified members/modes before applying that observation.

The real paid metadata successor is being implemented as a scoped apply-time
producer. Prospective funding before native cloning does not prove funding
before local Raft acceptance; the canonical backend/standing permit connection
remains a separate required gate. Japanese native JSON f64 and ModelInfo
components are source-frozen and independently reviewed, with a new test-input
extraction defect preserved for correction. Cold shared controls, clone/stream/
Registry consumer, original numeric profiles and old-backing debit retirement
are still required. All C01–C07/M01–M07 remain open; no application source is
promoted, staged, committed or release-qualified.


### 2026-10-06 exact metadata and native directory boundary (actual129–140)

The diagnostic-only capacity observation locates Main(Capacity): locations1,024
at literal entrylimit1,024, activeframes7/depthlimit512, aliases157/pending7/
placeholders3/seen15, nodecredits1,073. Actual131 exact cold parent fails37.55s,
all3,471 pins unchanged. The full4,043-input source/runtime is archived before
the next change in4,796 verified members/modes, SHAc6a72b1db0c1db4ee7404374e10f42a9059fddf9a58d72afe4d6b2c9547e88d5.

Actual133 joins the real eight-image paid empty-metadata producer and three
cfgtest-only native census images, including two new source leaves. Its complete
carrier has4,045 inputs; normal134 PASS61.55s/all3,473 pins. Actual135 Engine63
runs62 passes/one original startup funded-genesis assertion failure,156.81s.
All three new metadata allocator/actual backend/returned-and-raw refusal cases
pass. Actual startup still loses paid provenance in another path; trace the
real replacement/source installation rather than add a flag or relax the test.
The producer is an apply-time gate; it cannot prove admission before local Raft
acceptance. No production API or cache serving is activated by these cases.

Actual136's exact cold parent fails49.33s/all3,473 unchanged pins. The original
compiler successfully constructs the SAME owned schema/options/base and reports
1,060 completed locations/163 aliases/zero pending/zero placeholders/seen15;
the prepared fixed directory stops at1,024 entries. This is borrowed diagnostic
observation, not adoption/funding of the ordinary compiled graph. Preserve the
ordinary fixed-capacity refusal contracts,512depth/32,768transition limits and
complete semantic/funding tests when implementing bounded prepared directory
work. No blanket limit increase closes the issue.

Actual137 numeric qualification stops before compilation because the exact
original locked serde_stacker dependency is absent locally. Actual138 fenced
locked fetch succeeds without source/lock changes. Helper2 changes only the
fresh runtime path; original46-package lock,186source pins, all original tests/
profiles/parser/assertions remain. Actual139 original default tests process
passes, then the strict parser rejects an original inline stdout prefix from
regression::issue845::test. Preserve the actual helper/raw failure and add only
a narrow observed original stdout adapter before the unchanged strict parser;
no numeric suite PASS is claimed yet. Computed32 numeric fixtures and cold five
closed native dictionary controls have finite source reviews, but remain
unapplied and do not qualify the actual owning Japanese stream/Registry bridge,
old-backing debit retirement or production full-fit residency.

Failure140 preserves the complete current4,045-input source and actual134–138
outputs/consumer/schema/numeric helpers in5,250 verified members/modes, SHAf20e852dfcb9cfc5fac173cb9f46b0b215de9441192c119dc655aaae54c72c12. Numeric139's then-active runtime is excluded and
must receive its own preserved terminal evidence. All C01–C07/M01–M07 remain
OPEN. No source promotion/stage/commit/push or release qualification.


### 2026-10-06 companion qualification and exact numeric output adapter (actual142–146)

Actual142 wrapper stops before Cargo on its own wrong manifest key; preserve
that wrapper/raw outcome. Helper/source are unchanged. Wrapper2 uses the actual
artifact_files key. Actual143 passes exact Types4/backend6/Query145,112.43s
runner/all3,473 unchanged pins on current493/full4,045. Engine135 remains
62pass/one startup provenance failure. The actual terminal source installer
at state.rs932 publishes a legacy generation before consensus metadata. The
repair must fund and retain real DurableRows catalog/binding descendants,
preserve original revision0/source identity and continue those same owners
through metadata. A flag setter or source=None successor cannot certify this.

Numeric139 raw baseline default process passes but output parsing fails on
original regression::issue845::test's two exact Debug values. A source-only
helper3 authoring attempt preserves its permission failure in the immutable
copy. Helper4 creates its new artifact root with write permission and changes
only fresh runtime4, the narrow exact source-derived stdout adapter and required
baseline/selected payload equality. All186 sources, original46lock, tests, flags,
feature selections and strict parser AST remain exact. Good/changed-payload/
unknown/orphan/duplicate/missing-terminal synthetic checks pass. Manifest
82e1cf7cbb1b3aac02f23767f883fbe3adc832489e63866a6d749e81e1920991,
helper3f76d8b921304f3c83c649d157b98945dbb2f60ac1ebd097f3d506fb0e7a5518.
Actual146 starts the unchanged four full numeric profiles; no result claimed
until its terminal evidence is checked. All C/M goals OPEN; no promotion.


### 2026-10-06 bounded meta directory qualifies; independent new gates retained (actual147–153)

Failure147 preserves current493/full4,045 plus original numeric default raw
process/parser and new test-import failures, together with qualified current
Types4/backend6/Query145,4,712 verified members/modes, SHA38bb5e1ba36317e0cdadfa349f211e2fddf81a6ab6d16adfc86576e5112a2cd6.
Exact Memo5 rebases to current2ced/full4,045 in fiveimages, oldcurrent native
source/full before inverses/privateGit/25inventory/484lock verified. Actual148
applies only in isolated root. Actual150 original normal Engine PASS29.86s.
Actual151 complete original AP1,887 (previous1,885 plus2additive memo controls),
focused123 in all4 original profiles, native referencing143 and original
ownership doctest1 PASS217.00s/all3,473 unchangedpins,2,523 caseinvocations.
Completed-key eviction retains every real NativeInput and original grant,
never grows backing/recyclesidentities/evicts authoritative aliases or pending
controls. Original State::finish/full test bodies and all1,024/512/32,768
limits stay exact. This resolves the observed directory frontier; canonical
NativeCompilation/runtime/Ready and production ownership remain incomplete.

Separately, actual149 explicitly broadens to --all-features --lib and fails
2existing fixture-caller errors,88.54s/all3,473 unchangedpins: Engine test-utils
does not forward Raft's same existing test-utils feature. Normal150 remains a
separate pass, not a substitute for this failed gate. A narrow1manifest-image
feature forward is source-frozen9c79b3a0..., keeps every dependency/version/
lock/default production path exact, and still needs actual all-feature check.

Catalog9/one new privateSourceSlot preserves genuine paid Gen/source aliases
and metadata captures in source review, but independent review finds a moved
replacements double-drop in its legacy continuation. The raw e177 and root
7bffd composition remain source-only/unapplied. Correct that exact drop and
seal consume-once per-role constructor capabilities before qualification;
shared alias loan is not authority for unbounded fresh source construction.

Numeric6 fixes only explicit alloc format/ToString test imports with whole
body inverse/all assertions preserved. Actual152 again passes entire original
default baseline tests/docs, then newserde tests compile; standalone lexical
target exposes E0502 in prepared Bigint try_reserve_exact argument. Original
reserve/quote/limits remain; compute identical count-minus-len in a stack local
before mutably borrowing. Source-frozen successor7 and new numeric helper
require actual full four-profile qualification. All original failures retained.
Qualified153 preserves current2ced complete4,045 source and actual149–151
helper/full native runtime in4,822 verified members/modes, SHA6eef6311b02db36edcee1f933ca5501a48e694cb7c3e413367a04fb64ddd98b7.
Its then-active numeric152 runtime is excluded and must be preserved separately.
All C01–C07/M01–M07 OPEN; no application sourcepromotion/stage/commit/release.


### 2026-10-06 corrected catalog installed; numeric failure retained (actual154–159)

Numeric154 preserves the full unapplied6/full4,050 carrier and actual152/H5
runtime in4,286 verified members/modes, SHA331e6b771e284323e2bea0d3a2875fd3a905041f57982cf388906d9477005e32.
Borrow7 precomputes the identical count-minus-len before the actual mutable
reserve, retaining original layout/funding/order/algorithms. Actual155 H6 passes
entire default baseline and selected tests/docs, then entire original
float-roundtrip baseline tests/docs; selected float-roundtrip compilation
fails E0282/E0283 in the new empty-limb assertion because Value numeric PartialEq
makes [] ambiguous. No full four-profile pass. Failure156 preserves complete
unapplied7/full4,050, H6/raw runtime in4,308 verified members/modes,
SHAd71343893080a59c50ac00065c76076830fb4ce8eb1e6b0c7869b53632f6b20c.
Source-only8 adds the actual &[Limb] type to that same equality assertion;
all production bytes/original46lock/rosters/features/assertions/limits exact.
H7 MF ea30faac71a0d545330a51ad4fbac1f1a90610b116a17e4c66c14741c7769820,
186physical pins, preserves strict parser/original inline stdout comparison.

Cataloge177→move2→permits3→headOrder4 finite review5 PASS. Raw e177/rootv1
retain double-drop and v3/rootv2 retain early loan retirement; all remain
unapplied historical sources. Final private role/layout permits are consumed
once before actual Arc creation; four temporary heads now die before their
source/control/original loan. Successful actual pre-serving ApplyOwner binding
retains the genuine generation pointer/revision0 and real metadata source
aliases, with no source=None or paid flag adoption. Generic transient catalog
workspace, general admission and production Ready remain unqualified.

Rootv3 combines final9 effective catalog images and the existing one-line
Engine test-utils→Raft test-utils feature, preserving all current2ced vendor
memo/diagnostic/census leaves and original25inventory/484lock. Manifest
59555de86bea63858d51303333a03377b2d938adc42f9113db30117b7a162059,
patch2b693e6ab81aed9d15ff8aee34f559a7ee52f5808e93a5cf57a647957ca7b5c0,
10images/one new catalog_source.rs,full4,046. Guard153 fullsource verified
before actual157 isolated apply. Normal158 PASS95.81s/all3,474 checkpins.
All-feature library159 pending; previous149failure remains binding. Exact
H9 current source roster Engine66+Types4+backend6=76 and Query145, MF
17678dd47444ebe27b67e25ee16f2b2592ba188add7fde7cc6e7a30dbcd622a9,
preserves all earlier73+145 identities/flags/assertions/strictparser and adds
three actual source/control, catalog installation and role-permit cases.
Startup runtime pending; no substitute assertion or scoped pass claim.

Aggregate policy5/full4,045/13images has finite independent review2 PASS:
actual installed MemoryCore roles borrow available same-ledger aggregate
capacity, exact unused grant trimming preserves used+rollback, pinned native
backing remains charged through shrink, Resident requires real aggregate
headroom, and generic None/zero/configuration guards remain unchanged. Two
meaningful actual roles/encrypted NodeStore shrink/grow tests still require
rooted runtime. Japanese owning5485/reborrow2 and canonical ingress1869 have
finite reviews but remain source-only. Japanese Box/Registry/production Session,
canonical repeated typed failure delivery/native cleanup and full default-meta
runtime remain executable dependencies. All C01–C07/M01–M07 OPEN; no source
promotion/stage/commit/push/PR or release claim.


Actual159 separate cargo check --locked --offline -p kasumi-engine --all-features --lib PASS47.54s/all3,474 unchangedpins on5955/full4,046. This repairs the actual149 missing fixture forwarding failure; normal158 remains a separate original gate. Actual160 starts exact H9 Engine66+Types4+backend6/Query145; runtime pending. No startup/allrole/production/fullfit claim or goal closure.


Actual160 H9 ends148.99s/exit101/all3,474 unchangedpins during Engine66 libtest compilation: unchanged staged_terminal_tests544 still constructs Option<Arc<Source>> rather than SourceSlot, and line714 original Arc::ptr_eq now receives borrowed Source. No selected case executes. Normal158 and allfeature159 remain separate passes. Require narrow genuine source fixture construction and same native Arc identity inspection, preserving original assertions. Fullfailed5955/source4,046 archived161 before any successor application; numeric162 H7 starts unchanged four-profile qualification separately, runtime pending. All C/M OPEN, no promotion.


Failure161 full4,046 corrected-catalog cohort preserved in4,104 verified members/modes, SHA11226ff28ac63e9503346f053e885c96c42771dd8156ca9873178c42eec8d635. Independent fixture2 review PASS confirms cfg(test) constructor moves the identical original nativeArc with loan=None/no allocation or paid adoption, and ptr_eq compares that same actual native allocation. Original test bodies invert exactly after two interface spellings. Source MF7c0d7a77a9138dc591f23134bd9258e3e2fea223058fa3131e56b5b8a3bd0384, independent review470d35a47d1d45624163363b936143dd716a541cd7b6ded6eb2bf45ed19136c3. H10 source-only exact prior76+Query145/helperentirebytes unchanged, MFeec2b1693bea221fdfb5f6aa5fee9843aed5ead48ae511638aa60aab9060f0a9. Actualrootstill5955 while numeric162 fence active; no fixture runtime claim. Aggregate13 unchangedpatch forwarded separately onto fixture2 in source-only2a6b4d8b1fd11e9fbb6db3bcfd62a973b8db9c6346d840487d7c1a2f441f60f7/full4,046; requires originalstartup qualification before actualapplication. Numeric162 selectedfloat-roundtrip compile/tests nowPASS; docs and remaining profiles pending. No C/M closure.


### 2026-10-06 full original numeric matrix passes; startup selection retries (actual162–165)

Actual162 H7 allfour originalbaseline+selected complete serdeJSON/lexical numeric profiles PASS1,298.15s/all3,474 outerrootpins unchanged. Default/float-roundtrip/arbitrary-precision/combined each retain fullnative library,8 declaredintegrationtargets and docs. Original46lock/packageandresolve graphs are exact after only ownroot/macOSpath normalization; original identities/statuses/rawshouldpanic/compilefail/ignore reasons and exactissue845 stdout remain. Baseline970pass/4originalignore, selected1,028pass/4identicalignore acrossprofiles: caseinvocations, notdistinctcases. No test/row/cap/deadline/limit/assertion weakening. Source8 onlyadds actualLimb type tosame newassertion on numeric7 borrowrepair/import6; productionnumeric code is the exactselected source.

Qualified165 preserves complete unapplied8/full4,050, H7/native186 and allraw fourprofile runtime in4,358 verifiedmembers/modes, SHA28df039c7bdc0539c8597fbdf0f95df464bb7fd9ddeddb218fd03f59f30deb80. This is standalone componentqualification; actual productionJapanese/Session/numeric credit and oldbackingretirement stillopen. Guard161 fullfailed4,046 then permits actual163 two cfgtestoriginalSourceSlot fixture spelling repairs. Actualroot now7c0/full4,046; allproductionbytes remain same5955 and native25/original484lock unchanged. Actual164 H10 reruns exactEngine66+Types4+backend6 and Query145, unchangedhelperentirebyte/parser/flags/features/rosters. Originalpaidbootstrap provenance/revision0/durableimage assertions retained, runtime pending.

Canonical typedfailure/inflight successor5447 issourceonly on exactowned ingress4 ancestry, actualinline sameowner failureframe observers and oneprequoted cachedclosed-snapshot issue ratherthanfreshErrorImpl perrepeat. It stillneeds independentreview/explicitfeature1+fixture2 forwarding/realrooteddispatch andclose qualification; no M03 completion. Aggregate13 staysunapplied2a6b until originalstartup qualifies. All C/M OPEN, no promotion/stage/commit/push/PR.


### 2026-10-06 startup reaches original revision check (actual164/166–167)

Actual164 H10 Engine66 terminal64PASS/2FAIL,226.17s/all3,474 unchangedpins,46.68s runtime. Five metadata/catalog witnesses pass; originalfreshstartup preserves genuine fundedgenesis, then fails next originalrevision0 at bootstrap_existing_tests582: observed1. Actual localRaft startup applies membership/election Blank through genericMetadata whose logindex advancesgeneration. Require sealed exactsource/replay-prefix initializationauthority and originaljoint barrier, preserving realapplied/membership cursors and every genericMetadata test. No revisionreset/adoptedcandidate/flag or changedexpectation; snapshots/firstNormal close authority. Original serializeddurableimage assertion remainsunreached.

New realcatalogsource installation witness failssetup withretained registered StorageOwnerId0: catalog.kv path is outsideconfigured persistentroot. Correct thatactualpath using samepersistentroot/config/1GiBrole/budget/inputs/assertions; no capacityincrease. Fullfailedcurrent7c0/source4,046 archived166 beforeany successor in4,104 verifiedmembers/modes, SHAe40e84f6a8ff42891ff280ed4014d38fd84955085d0091d450da6c113d66fb73. Actual167 exactTypes4/backend6/Query145 startsseparatelyoncurrent7c0; noEnginePASS claim.

Typed2 finiteindependent review4a9be02d7b6b0873cf96e8284a44752da7be15dd9647aa387fd5fc66ba677f17 PASS sourceonly; actualoccupiedframe/nativeownership/inflight/non-freshmarker behavior stillneeds rootedruntime/canonicalcaller join. PaidNativeContext runtime22/current2ced/full4,047 frozen0346716743e3b14e7ae91b732df23b01e040bbce3541b46341c581e6c2037d71 consumesactualpaidSyntax/sharedreport/cyclememo/uniquetable hooks, closedRegex/Unique/acyclicAllOf/scalar scope. Ref/AP/generalfrontend/defaultMeta remainopen, noNativeReadyclaim. JapaneseBox/Session precursor12/full4,054 frozenf3373f41aa05930425ddc43664cfccfc94cd82ff81a4801850e37dfb4d25669d actualnativeBoxdeallocation beforedata/C, sameSession loans/realregistry/perfield/writer/escapedaliases witnesses. ItsfirststdMutex lockgap iscorrectedinSourceLock3, butfinite reviewfinds guardauto-Sync unsound forSend-only rawT; narrow nonSend/nonSync guardsuccessor pending. Preservebothsourcefailures; noReadyclaim. Allnewprimitives sourceonlyuntilactualqualification, all C/M OPEN, no promotion.


### 2026-10-06 original companion selection passes; startup correction applied (actual167–170)

Actual167 exact Types4/backend6/Query145 PASS111.64s/all3,474 unchanged source pins on7c0/full4,046. Its complete raw results and prior actual164 Engine64PASS/2FAIL are preserved before the next mutation in checkpoint168:4,121 verified archive members/modes, SHA3dd54b190467a32137a8a7fbfdcb1ac7e2cedda7665ef4865e07a942e639ec3d. No Engine PASS or whole-cache claim follows from those companions.

Initialization3 and the single configured catalog path correction have finite independent source review PASS26a9cb/reportadd1af. Root composition415aee4db712614f12eb73aa00ed42d726fbb18dbf93f31ed45e4522d2b4642c/full4,046/fourimages preserves exact original tests, budget, role configuration and native25/484lock. Actual169 applies after checkpoint168 guard. The current native BackendStorageHandle dereferences through its closed BackendRef to the actual TenantEngine override; it has no intervening default trait implementation. The genuine stack-borrowed consume-once initialization prefix preserves logical revision-zero/genesis and original joint publication; first Normal or installed snapshot permanently ends this authority. Normal170 and H11 exact Engine66+Types4+backend8=78 plus unchanged Query145 remain runtime gates. No changed revision expectation, paid adoption, source substitution or increased allowance.

Preferred Japanese Box2→inlineLock3→guard4 has finite independent review24587/report6871f PASS, including the original mutex-allocation and guard auto-trait repairs. Numeric6/7/8 is being forwarded unchanged onto that chain for current-source integration; genuine Session/static page, numeric credit and old-backing retirement remain open. Paid native Context22 has finite independent reviewc93b4dd/report60491dc PASS; scoped native runtime/rooted producer qualification remains required, with references/AP/general meta/full-fit explicitly open. All C01–C07/M01–M07 OPEN.


Actual170 original normal Engine check FAIL64.32s/exit101/all3,474 on415a/full4,046: StateMachine uses actual StorageHandle<TenantStorageSet>, so machine.domains.serving() is not an API; snapshot_seed150 misses the new monotonic application_entered field. No runtime executes. Full failed source171 preserved in4,098 verified members/modes, SHA9faee932f16de4a5a3d449d4d09055f13847dc6b1acc495d65a4501c3880f0c2, including unexecuted H11. Exact successor90104681d192558252c924235dfc60a031576b672688fd642e81fe42f98c818e/full4,046/twoimages binds the borrowed same applicationArc and closes the actual snapshot-seed prefix. Original tests, grants, caps and semantic assertions stay exact. Rooted compilation and exact unchanged78+Query145 H12 remain pending. Aggregate13 current-forwardb8e1 is still unapplied until this actual startup gate passes.


Actual172 narrow interface9010 applied after failed171 guard; normal173 FAIL19.09s/all3,474 only missing anyhow::Context on new Engine Option.context calls657/659. Fullfailed9010 preserved175 in4,100 verifiedmembers/modes, SHA7cd718ae5d0b0fd108551d27ae24ed46a38c633d3680ccad20e545ae881fe24d. Actual176 applies single local anonymous Context import747a0753738ee1628ddae7b4422708af72281f826290a4c6b2bc710dfdcdc502/full4,046 after that guard. Independent finite9010 review25f283/report7749cc and single-import review08c0a80/report5e440 PASS; all whole inverses and old assertions/caps retained. Actual177 normal cargo check --locked --offline -p kasumi-engine PASS12.43s/all3,474. Actual178 H13 exact78+Query145 starts on747a; old Engine66+Types4+backend6 untouched, only two actual native prefix tests added. Runtime pending; no actual startup/production/fullfit PASS yet.

Executable integration priority: preserve these original repaired startup assertions, then root-qualify Aggregate13 native/encrypted-role shrink/growth on exactcurrent747a. Its effective13image current-forward6435e89ba59de20a177fe7cf37e09b27f24e8b9c22294068526f589aadc3e37a keeps samead1f12 patch/full4,046; generic fixed/zero guards and charged pins unchanged. Combine reviewed Japanese final3/numeric6–8 and Context current3 onto one complete source before further runtime claims. The actual canonical SDK firstCollection producer is a separate finite ownership dependency and must be compiled/run before any claim of preaccepted or general-body capacity. Public document/index serving, genuine all-public/leased/registered generation census and complete text refill still precede whole-fitting-dataset qualification. All C/M remain OPEN.


Actual178 H13 Engine66 executes65PASS/1FAIL,137.30s/all3,474 unchangedpins/43.22s runtime. Original fresh-local startup nowpasses all original funded-genesis, revision0 and exact serialized durable-image equality assertions; all original Metadata and five other metadata/catalog source/permit cases pass. Remaining new actualpaidcatalogfixture reaches next exact production guard: application/custody catalogs require pairedstorageowner, whilefixture supplied oneTenantStore. Correct through genuine same-budget paired fixture and real install_storage_domains path, not bypassing the guard or changing assertions. Actual179 exact Types4/backend8/Query145 starts separately on current747a/full4,046; two nativeprefixcases included. Full failedsource/raw178 and companionresults willbe preserved before anypairedfixture mutation. All C/M OPEN; repairedoriginalstartup is scopedprogress, not productionactivation/fullfit.


Actual179 Types4/backend8 PASS, including both actual native initialization-prefix cases. Query library raw summary137PASS/0FAIL but original search.rs eprintln diagnostics742/895 interleave in mergedstdout/stderr with two actual result identities. Strict helper correctly captures135/137 and refuses fullqualification; no testfunctional failure or accepted fallback to summary counts. Full current747a and actual177–179 raw evidence preserved180 in4,111 verifiedmembers/modes, SHA73e5efe061d80ba714bf6e68c73eeb12fe98666bcb2ac42c0ca3d73984f846d5.

H14 root helper33b28884b72e52a82b5550e7e2b4275b21979b553eab39435b36642165b6af18 preserves exact78+145 selections/features/flags and strict parser AST. Only native process stdout/stderr now go to separate complete raw files; no changed threadcount, testcase, resultnormalization or inferredstatus. Independent capture-only review65c298/report922fb PASS, including original fencedargv and exact two sourcecapture inverses. Actual181 genuine paired fixture727c applied after180guard; independent review2fc94/report4e4eec PASS. Actual182 H14 Engine66=65PASS/1FAIL76.13s/all3,474. Remaining same fixture reaches next actualaudit-placement guard: standaloneapplication purpose requires caller-selected placement; existing fixturehelper intentionally installs onlyLocalFixture/NodeControl and silentlyreturns for this purpose. Correct actual explicit FilesystemAuditArchive/install_tenant_audit_archive path while retaining the original standalonepurpose/pairedguard/budget/assertions. Originalfreshstartup remainsPASS. Actual183 repeats complete unchangedQuery145 on current727c using separate rawstreams; qualification pending.

One source-only executable union736deaf2b7839aca76c24e17263dce8585f256dd24f8c1eaeb7c16939dfd4d14 combines exactJapanese39/Context20Rust/Aggregate13 oncurrent747a/full4,065/72images/19new. Independent finite combined review5c7f506/report24ef3ec PASS: all owningRust afterimages exactly reviewedcomponents; only actual README/inventory joins, whole opposinginverses and prior currentMemo/census/catalog/init retained. Source roster269 old complete testintervals,62 additive sourcefunctions plus2 compilefailblocks, no guessed runtimecounts. Pairedfixture sourceforward selectedc181 sourceonly. ProductionQuery original-credit owner, AP/reference/generalmeta/nativeReadypayment and fullpublicgeneration/textcache activation remain dependencies. All C/M OPEN.


Actual183 complete originalQuery145 PASS21.41s/all3,474 on727c/full4,046 with H14 exact strict parser and separate complete raw stdout/stderr. Actual182 failedcatalogfixture and actual183 PASS/raw/metadata source are preserved184 in4,124 verified members/modes, SHA80db3f034089e76b59bc3312fc1339fd0bbdc163e1886151285b0f118dddcb77 before mutation. Explicit samepurpose/samepaired application audit fixture27542c8cd93b0dc6c11e31b0508851efec3a92aee1fe1c9667cb01c3ce0b8d7c/full4,046/oneimage has finite independentreviewe8134d/reportbbecc1 PASS, exact whole test setup inverse, unchanged assertions/bounds/tenant/role/access. It uses actual FilesystemAuditArchive and installed original app archive API, with no audithelper/guard/purpose bypass. Actual185 applies after184guard. H15 entirehelperbytes and78+145 rosters/parser/features/flags/rawcapture exactH14, MF230eed9fc5e20bcf8381860d8d0882418b9795e6c811e0bb614f0bf274d13417; actual186 fullselection runtime pending. No originalnormalrerun for test-only file; normal177 separate productiongate remains applicable through identical productionbytes. All C/M OPEN.


## Detailed ownership and integration gates preserved during goal refinement — 2026-10-06

The following is the complete previous detailed goal/checkpoint text. Its ownership, admission, failure, security and release obligations remain binding. Attempt status is historical; the current goals and latest evidence below determine which checks have actually passed. No criterion is closed by moving this text.

## Current production status

**C01–C07 remain open.** The native key directory is disk-backed, but production
still uses resident document maps and structured/text indexes. Application changes are being
implemented and tested in isolated integration cohorts; they have not been
promoted to the live checkout. No combination of component passes closes
a production goal.

The remaining critical path has four executable exits, in order:

1. **Qualify the joined owners and actual startup.** The current isolated
   catalog composition has 4,046 complete source inputs and passes the original
   normal Engine check (actual158, 3,474 unchanged check pins). It preserves the
   genuine paid generation through actual disk catalog installation and metadata
   capture. Private consume-once role/layout permits and head-before-source
   retirement correct the two independently found ownership gaps. The earlier
   Engine63 result remains 62 passes/one original funded-genesis startup failure;
   the successor must pass that same provenance, revision0 and durable-image
   assertion, plus all three new actual catalog cases. Its exact selection is
   Engine66/Types4/backend6 and Query145. Actual160 stops during libtest
   compilation on two unchanged staged-terminal fixture calls to the old source
   API; no case executes. The reviewed correction is applied in actual163;
   its native Arc identity assertions remain unchanged. Actual164 executes
   Engine66:64 passes/two failures. Genuine paid genesis is preserved, but
   the next original revision0 assertion observes 1 after native initialization
   membership/election metadata. Keep logical genesis unchanged through that
   real prefix while still durably publishing applied/membership cursors; retain
   ordinary Metadata semantics and close initialization authority at snapshots
   or the first Normal entry. The new catalog fixture also opens outside its
   configured persistent root; correct that actual path with unchanged budget,
   capabilities and assertions. Five other metadata/catalog witnesses pass.
   The original durable-image equality has not yet been reached. Exact companion
   Types4/backend6/Query145 passes actual167 on the same complete source.
   Its complete source and raw results are preserved in checkpoint168 before
   applying the initialization/path correction. Actual169 applies that reviewed
   four-image correction; normal170 exposes two integration errors: wrong
   storage accessor and a missed snapshot-seed prefix initializer. Preserve the
   complete failed source in171. The two-image interface correction passes
   Raft compilation; actual173 then exposes a missing Engine trait import,
   preserved in175. Its one-line correction passes the original normal Engine
   check in177. Actual178 executes Engine66:65 pass/one new fixture failure. The original
   funded-genesis, revision0 and exact durable-image equality now all pass.
   Correct the new catalog fixture to use the real paired application/custody
   owner; preserve the production guard, all assertions and unchanged bounds.
   Actual179 passes Types4/backend8, including both native prefix cases.
   Query library reports137 passes, but stderr/stdout interleaving corrupts two
   result identities and the strict harness correctly refuses qualification.
   Preserve that raw failure; H14 captures separate raw streams with identical
   parser, flags and original selections. Paired fixture181 reaches the next
   explicit audit-placement guard in182: use caller-selected actual placement
   for its standalone application purpose, without changing the guard or budget.
   Actual183 complete Query145 passes on the separated streams. The explicit
   audit fixture is reviewed and applied in185; actual186 reruns the full
   original78+Query145 selection before further cache integration. Two additive native replay-prefix cases make the successor
   selection Engine66/Types4/backend8 (78) plus unchanged Query145.
   The separate broader all-feature library check passes actual159 with the
   existing fixture feature forwarded; preserve original149 failure. Apply-time metadata and pre-serving catalog
   ownership do not prove admission before local Raft acceptance.
   Preserve the bounded completed-location memo's AP1,887, focused123 in all
   four original profiles, referencing143 and ownership doctest (2,523 case
   invocations on current2ced/full4,045). Original fixed-capacity refusal and
   1,024 entries/512 depth/32,768 transitions remain. Complete the canonical
   default-meta validator/runtime and actual prospective owning application
   caller; NativeCompilation still deliberately stops short of Ready.
   Original and changed numeric code now pass all four complete profiles
   (actual162): default, float-roundtrip, arbitrary precision and their combined
   profile, including the entire library, eight integration targets and docs.
   Preserve the original 46-package lock, package/resolve graph, all identities,
   assertions, ignore reasons and raw output markers. This qualifies the numeric
   component; its genuine production caller and backing retirement remain open.
   Japanese owning lattice/clone/stream
   has a finite source review; actual Box, Registry and production Session
   connection and backing retirement remain required. The canonical owned
   backend checkpoint is also source-only: finish allocation-free repeated
   failure delivery, dispatch, close and genuine native cleanup.
2. **Publish and serve every role together.** Connect accepted document,
   structured, unique and text changes to one durable receipt, then switch
   snapshot-aware production reads to those selected disk roots. Prove failure,
   cancellation and recovery preserve the old or complete new selection.
3. **Finish complete-fit residency.** Expose finite warm-up/refill completion for
   documents, every index role, native pages and retained versions. A fitting
   dataset stays fully resident, including an uneven large collection; shrinking
   or raising the budget restores full residency. The current refill executor
   and public-generation registry binding are test-only, selected text queries
   still reject an absent verified disk backend, and installed native roles
   still need runtime qualification of aggregate borrowing. The reviewed 13-image policy binds real installed MemoryCore
   adapters to the same total ledger while preserving generic fixed/zero guards
   and charged pinned tails. Qualify its two actual role/encrypted-store
   shrink/grow cases, then finish genuine serving/registry and all-role refill
   before claiming full-fit completion.
4. **Qualify the final source.** Run the original operational/release checks and
   all five workload classes below and above the bound. Measure reads, accounting,
   RSS/swap and latency before closing any C or M goal.

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
| **M01: Repair current failures** — C05, C06, C07 | Qualify the applied genuine catalog-owner correction against the original startup failure (previous Engine63:62 pass/1 fail). Normal158 passes on full4,046; actual167 Types4/backend6/Query145 passes. The reviewed initialization/path correction is applied in169; require original Engine66 plus Types4/backend8 and Query145 on that successor. The separate all-feature library159 now passes. Preserve revision0, funded provenance and exact durable-image assertions. Preserve the bounded memo correction: exact AP1,887/focused123×4/ref143/doc1 pass with original fixed/refusal contracts and all limits retained. Complete canonical default-meta validator/runtime and genuine prospective application ownership; the NativeCompilation frontier remains incomplete. The existing Engine fixture feature now forwards to Raft in the isolated candidate; qualify the separately observed all-feature compile gate. Preserve failed sources and original limits. Preserve the qualified complete four-profile numeric component through the real production caller join; finish actual Japanese Box/Registry/Session consumers and old-backing retirement. Apply-time metadata funding is separate from the canonical preaccepted backend/standing guarantee. Corrected receiver5 and both original sparse scenarios pass in release/default stack. Corrected fresh Registry passes AP 1836, Query 124, focused 81 in all four profiles and native referencing 141, with every source pin unchanged. Preserve their earlier failures, ENOSPC trace and exact corrections through final integration. The unchanged large Store image, protected setup8, target reopen18, encrypted2,500-counter workload and focused close/reentry checks also have scoped passes. | Each original scenario reaches its intended assertion on the final integrated source. Keep source-derived fixture units and concrete owner capacity boundaries; retain invalid configurations as negative cases. Final operational selection passes, including exact reopen. Do not change caps, deadlines, row counts or ownership assertions to mask failures; do not accept unknown outcomes or prematurely release old roots. |
| **M02: Reusable encrypted reads** — C01, C05, C06; supports C02 | Route earlier control planning, selected capture and installed terminal scans through their actual operation-owned point backing. Finish constructor/retirement custody and the exact read-owner handoff. | Real encrypted reads reuse bounded backing without mandatory per-record reservations; snapshot, table, provider, authentication and current expiry checks remain exact. Two distinct cleanup failures retain both originals. Verify the large capture path separately from fixture setup. This does not yet prove postcommit capacity. |
| **M03: Protected publication capacity** — C01, C05, C06 | Activate real current/next source rights and reusable workspace; fund escaped historical sources before return. Replace production legacy generation references and plain validator references with actual payload and Weak-tail funding owners. Bind complete successor capacity to local leader/follower acceptance, recovered accepted suffixes, membership/catalog changes and snapshot installation. | After accepted admission, saturating ordinary capacity cannot introduce a new mandatory source/planner/capture refusal. Several writes progress while old snapshots stay readable and charged. Copied metadata-bank retirement cannot certify shared payload retirement or authorize the next apply. Refusal happens before local acceptance; canceled waiters cannot release accepted capacity. Recovery and all ingress paths use the same owned guarantee. |
| **M04: Authoritative disk documents** — C03, C04, C05, C06 | Preserve the isolated normal Engine compilation of the actual primary tree and projection modules and genuine fixture-only gates. Install and retain the actual committed baseline and bound query metadata in the production apply lane; preserve the prior and accepted candidate through publication, capture failure and exact recovery resolution. Wire primary construction, edits, deletes and recovery into actual ordered publication. Switch document queries to exact durable roots and activate full-fit document caching. Remove the resident all-document serving alternative. | Normal compilation and real factory/standing-owner callers pass before claiming production integration. The real service performs point reads, scans, CAS, batches, idempotent replay, retained-version reads and restart with documents larger in total than RAM. Fitting new/updated/rarely read documents stay resident after warm-up. Document publication and all associated metadata are atomic. Coordinate the cutover with M05 so existing index features remain available. |
| **M05: Disk indexes and growing metadata** — C01, C03, C04, C05, C06 | Persist structured/unique/text indexes and bound their build/edit/query work. Replace remaining data-sized resident history, archive references and active staging. Preserve the implemented scalar retained-log endpoints and streaming header fold; qualify their exact immutable-source proof through append, truncate and snapshot transitions. Finish bounds for protocol-owned term metadata, requested entry batches and opaque response bytes; retain the exact active window needed for consensus. Keep already-disk-backed receipts/terminal rows on their canonical paths. | All supported filters, ordering, projections, aggregates, pagination and text analyzers/ranking agree below and above the bound. Documents and index roots commit together; schema/uniqueness behavior is preserved. Startup, log/header traversal and builders do not materialize a full data-sized map/vector. |
| **M06: Complete residency and accounting** — C01, C03, C05, C07 | Integrate one total budget across native and decoded caches, query/output work, protected sources, retained versions and bounded collection reservations. Bind every genuinely published public/leased/registered generation to the census. Activate the finite production refill worker and complete selected text warming. Let one large collection or native role use available aggregate capacity; installed per-database limits cannot strand a fitting dataset cold. Expose finite preload/refill completion and budget-change behavior. Develop this alongside M04/M05. | A complete fitting dataset has zero serving document/index/directory fetches and no capacity eviction after warm-up, including after writes. Growth through the bound evicts gradually; cold scans preserve the hot set; deletion/budget growth refills everything that fits. Actual live and weak/pinned tails stay charged until release. RSS/swap are measured separately from cache accounting. |
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
| Schema frontend | CaptureInfo AP passes all 1,873 original/additive cases after restoring the exact original relative fixture; retry runner 30.86s, exit 0, all 2,358 pins stable. Query 124, focused 118 in each of four profiles and native referencing 143 pass. Original default matcher passes library 206, integration 60 and doctests 459 with two original ignores. Its one no-std library failure and 40 integration compile errors reproduce on the exact unmodified published baseline with the original 42-row graph. Failed runs and complete passing Capture source are archived. | Preserve the qualified forward-NFA repair described below, then finish Pattern/default-meta compiler/runtime, user compiler branches, retained validator owners and production frontend. Preserve original matcher failures separately; a baseline reproduction does not make a failed gate pass. Resolver/Analyzer maps, reverse NFA, meta-engine pools and platform/thread backing remain open. |
| Reopen and typed responses | Target passes all 18 machine/resolution checks, including exact-prefix reopen, using the canonical separate temporary importer scope. The durable node retains its original 64 MiB / 32-slot provider, 8 MiB table limits and exact-prefix assertions. Engine response 10/10, Types 1/1 and Raft constructor/response 7/7 each pass. Earlier slot exhaustion and the physical lease trace remain recorded. | Qualify the reviewed actual Custody bank, both admission providers, authenticated pending-tail recovery and pre-write response consumers. Finish its enrolled source drain and actor terminal paths, then complete aggregate production admission. A fixture’s separate importer scope does not prove the whole process budget. |
| Native task retirement | Seven actual native task checks pass. Original upstream abort, panic, task-ID and join-set suites pass 8/7/17/19 respectively; the final join-set harness enables its required `test-util` feature without changing upstream source. The actual joined caller-owned drain and controls now pass their scoped selection. The complete 121-test source-pinned retry has 111 passes and ten Custody allocation/accounting failures; the exact failed source is preserved. The precise observation/provider-unit correction now passes all 34 selected Custody and original observer-consumer checks, with all 3,033 pins unchanged. All ten ordered-publication checks pass on that same source, without qualifying the failed Custody selections. | Qualify independent original Waker registration/cancellation, admitted notification/cleanup joins, actual inline controls and diagnostic tails. Verify the actual selected control features. Native data completion must remain distinct from notification metadata retirement. A connected Custody source must positively retire the actual A data owner and retain separately charged B notification, Frame, caller and diagnostic tails; a completed join or callback cannot certify their physical deallocation. |
| Atomic baseline and metadata | All eight actual protected baseline/effects/coupled-capture/metadata checks pass on 2,654 unchanged pins. The fixture now prepares the exact response tail for every protected command and retains its actual capacity owner through the operation. Target passes 18/18 and response-bank checks pass 10/10. Earlier publish-only and missing-tail failures remain recorded. | Integrate the complete accepted primary, structured, unique and text producer into one atomic publication. Replace ordinary empty publication effects with that verified all-role producer. Pending text evidence remains a refusal; test fixture admission does not close production ingress. |
| Retained metadata and selected-source cleanup | The corrected selection passes all 25 cases: four direct retirement, six metadata handoff, five original selected cleanup and ten ordered publication tests. Runner exit 0 in 268.36s; all 3,035 pins match. The missing response was traced through the borrowed original report to a fixture that bypassed actual Entry preparation. Its correction holds the real preaccepted capacity through publication; budgets and assertions remain unchanged. | Preserve the result through native writer integration, then close the actual production entry and retirement paths. The original interrupted response wait, 24/25 failure and exact retained diagnostic failure remain recoverable; these fixture corrections do not establish production all-role ownership. |
| Prepared FAST/FST integration | Actual locked selection verifies all 18 native packages and the three same-version path transitions. Normal Engine compilation and all five affected Session tests pass; runner exit 0 in 93.07s, all 3,141 pins unchanged. Original supported profiles now pass: FST 131/119, Columnar 185×2, Stacker 35×2, SSTable 40 library + two integration cases in each profile, and Tantivy 1,066 with five original ignores. Their original doctests pass, including Tantivy 52 with one original ignore. The refusal test retains the same original Index through both denials. Full passing source and earlier compile/fixture failures are preserved. | Preserve these results through the connected Store and writer changes. Original nightly, benchmark and example gates remain separate. Whole-writer admission, all-role publication and production activation remain open. |
| Prepared Store record owner | All nine connected Store cases pass on the isolated successor. Actual selection verifies all 19 native packages; normal Engine compilation passes. All six native Store cases, Tantivy's full 1,072-case library/52-doctest selection, LZ4 library profiles 23/20 and its ten default doctests pass. The unchanged Engine allocator matrix passes all six 4,097-record scenarios with zero observed allocations during armed record/flush/close. The corrected admission/retry fixture proves zero additional operation-owned reservations while preserving the exact installed metadata baseline and all original refusal/backing/credit checks. All 3,158 pins match; both the original failure and complete passing source are archived. | Preserve this finite synchronous no-store/None/small-LZ4 result through actual writer entry and finalization. LZ4's two no-frame doctest failures reproduce on unmodified published source and remain recorded separately. Complete writer admission and universal full-fit acceptance remain open. |
| Initial native allocation owner | The isolated actual term table and two first arena pages retain their original partial/error owners under the same writer credit. Original Tantivy passes 1,076 cases with five original ignores and 52 doctests with one original ignore. Stacker passes 38 cases in each original profile. Normal Engine compilation and all eight connected Engine cases pass: initial denial, five original Session reuse/retirement cases and both Store consumers. Runner 135.81s, exit 0, all 3,159 pins unchanged; complete passing source is archived. | Preserve the same consumed prequoted pool and original writer credit through later term/postings growth and remaining constructors. Entry-vector and initial term-buffer qualification are recorded below. An initial bank does not fund every later native allocation. |
| Document-entry vector owner | The original 1,000-opstamp Vec and its doubling are admitted before counters or Store mutation, consuming each prepaid byte once under the same writer credit. Tantivy passes 1,080 cases with five original ignores and 52 doctests with one original ignore; all nine connected Engine consumers and normal compilation pass. Both runners exit 0 with 3,160 unchanged pins. Complete passing source is archived. | Preserve original errors, backing and credit through later per-field constructors and token/table/arena growth. This finite change does not establish whole-writer or serving readiness. |
| Initial term-buffer owner | The original 20-byte term buffer is the seventh measured initial layout and moves with the original context/opstamp backing. Tantivy passes 1,081 cases with five original ignores and 52 doctests with one original ignore. Normal Engine compilation and the same nine connected consumers pass; runners exit 0 with 3,160 unchanged pins. | Preserve this ownership through the qualified field constructors and complete later term/token/table/arena growth, analyzers and finalization under the same admitted credit. |
| Per-field posting-writer constructors | Actual field-vector capacity and all six concrete posting-writer Box layouts use the same consumed credit. Original/additive Tantivy passes 1,083 cases with five original ignores and 52 doctests with one original ignore. Normal Engine compilation and ten connected consumers pass; runners exit 0 with 3,160 unchanged pins. Complete 3,675-input source is archived. | Finish dynamic term/table/arena/recorder growth and remaining analyzer/FAST/fieldnorm/finalizer constructors. Preserve the original caller-funded immutable Schema and all shared/control/Weak obligations. |
| Forward-NFA schema constructor | The allocator repair passes the strict original case, full AP 1,878, Query 124, focused 123 in each of four profiles and referencing 143; runner 422.55s, all 2,360 pins stable. The narrow native test borrow-scope correction then passes default matcher library 208, integration 60 and doctests 459 with two original ignores. The original no-std profile still has one library failure and 40 integration compile errors. Both patched UTF-8 library profiles pass 149 and default documentation passes 48. The unmodified published package passes both 147-case library profiles and default documentation 48, but reproduces exactly the same fourteen no-std documentation failures, with 34 passes. Complete 2,815-input source, actual profiles and baseline comparison are archived. | Preserve these exact results and failing original profiles through the final source join; finish complete compiler/default-meta/runtime and retained validator ownership. Baseline reproduction classifies an existing failure and does not turn a failed gate into a pass. The fixed grammar owner cannot certify the whole frontend. |
| Normal primary compilation | The actual primary tree, projection and bound-metadata receiver compile normally in the isolated successor. Required owner dependencies are available in production; genuine fixtures retain explicit test gates. Actual 19-package selection passes with original inline-control features. Normal Engine check passes in 14.80s; all original 25 metadata/retirement/publication consumers pass in the separate 421.76s runner. Both exit 0 with 3,159 unchanged pins; complete passing source and earlier failures are archived. | Install the serialized unique committed baseline and bound metadata and connect the actual factory to the complete all-role publisher. Replace legacy public generation/validator references with genuine payload and Weak-tail owners. Normal compilation and these tests do not activate serving or establish shared payload funding. |
| Prior metadata-bank retirement | The exact field-current successor passes normal Engine compilation in 46.82s and all 25 original affected consumers plus three bank-retirement cases in 127.75s. Runner 283.19s, exit 0, all 3,160 pins stable. Full 3,675-input source is archived. Original refusal, raw-panic payload and credit custody survive while retained snapshots and Weak references remain readable. | Preserve this result through the owned bridge and standing installation. Returning copied-bank capacity does not fund shared Generation/validator payloads, prove their retirement or authorize the next apply. |
| Owned-command primary bridge | The concrete repair passes normal Engine compilation, all original/bank 28 consumers, all three owned-command cases, caught-unwind custody and all four original backend gate tests. Runner 274.55s, exit 0, all 3,161 pins stable; complete 3,676-input source is archived. Earlier compilation, error-box, lazy condition-variable allocation and lost unwind-safety failures remain preserved. The exact original tests and assertions are unchanged. | Preserve this result on the combined source. Qualify actual standing metadata, paired Engine control/Weak and retained accepted ingress. Finish genuine Generation/validator payload funding and the accepted all-role publisher; a concrete control owner or copied-bank retirement cannot certify payload retirement or full residency. |
| Standing metadata and Engine controls | The caller owns the paid strong metadata bank; Engine has only a paired paid Weak, and the inert roots seed moves out before metadata binding. The joined source includes closed EngineRef/EngineWeak control owners and retained backend guards. The one-import fixture correction preserves every observation, test body and limit. On the joined 3,681-input source, normal compilation, original28+3+1, joined Engine19 and all backend6 pass. The complete qualified source and original profiles are archived with 3,799 verified members. Earlier compilation and harness-selection failures remain archived as failures. | Pass these actual callers, then connect the real Database startup, cancellation and shutdown custody with positive populated-bank retirement outside startup locks. Preserve the existing ApplicationSourceCustody prohibition on Generation retention. The ordinary legacy Engine and Generation payloads remain separately unqualified. |
| Dynamic native growth and JSON paths | Exact arena/hash/term/recorder and prepared JSON path/name/position owners compose with the bridge, bank and Engine controls on one 3,681-input source. Native/raw witnesses preserve original payload, old backing and entered state; all nineteen native packages, original lock and modes verify. Connected Session consumers pass. Original Tantivy library passes1,091 with five original ignores and documentation52 with one original ignore. Stacker passes44 in each original default and compare_hash_only+ahash profile. The profile assertion correction changes no selected features or tests. | Preserve these joined original profiles and actual Session consumers through final integration. Complete JSON finalization, analyzers/Japanese, FAST/fieldnorm, remaining constructors and diagnostics under the same preaccepted owner. Successful finite growth cannot certify complete supported-input fit. |
| Retained accepted Engine ingress | The joined source moves the original preheld paired Engine permit into an external command frame before decoder/provider work, retaining it through success, returned refusal and raw unwind. Its corrected private authority references borrow that same closed owner, preserving original pointer/roots/scope/bootstrap assertions. All three added actual ingress cases pass within the joined 27-case selection; that entire selection remains failed because of its separately recorded Session/startup failures. | Qualify the retained standing factory on the explicit successor, then activate the real leader/follower/recovery/backend callers. Fund actual outer backend control/Weak tails and payloads before acceptance; no fresh Arc or permit after acceptance can stand in for that guarantee. |
| Database lifecycle and prepared JSON finalization | Both coherent real-group startup cases pass2/2 with original cleanup deadlines/assertions. The complete source is archived; baseline SDK setup takes about17seconds and remains a performance concern. The explicit factory/native FAST/canonical JSON/Backend join passes normal compilation and all33 Engine/backend6 after a checked allocation-test type correction. Its3,685-input source is archived with3,700 verified members. The Unicode/recovery successor passes normal compilation and all three actual shared recovery cases: no saved snapshot, snapshot plus newer applied entries, and rejection of a changed live durable floor. Its3,687-input source is archived with3,701 verified members. | Default all-targets compilation, actual construction/Weak2 and original key-revocation1 now pass. Original killed-process and history now pass after preparing response buffers above the actual reconstruction floor, preserving durable custody and the pending-write cutoff. Three range checks, original TLS replication/peer security and affected control/Weak/key checks pass. The repaired default workspace all-targets compilation passes. Preserve the complete prerequisite source through the native join. Qualify original native profiles on the joined source. Preserve failures, source-derived Session debit, actual cleanup and exact constructor rejection. Activate actual shared payload ownership and the all-role publisher. Retire physically freed stream Box charges under the same original credit; verify repeated fitting inputs and retained buffer replacements. |

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

1. **Finish M02/M03 ownership:** preserve qualified FAST/FST, Store, initial,
   entry, term-buffer and field-constructor owners. Finish dynamic native growth,
   analyzers/finalizers and complete schema compiler/runtime ownership. Preserve the
   qualified prior-bank retirement, repair and qualify the external owned-command
   bridge, then install the standing
   baseline with funded Engine, generation, validator and Weak tails. Every
   accepted/unapplied entry keeps its concrete workspace and response through
   cancellation, recovery and positive retirement.
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

The retained standing factory and paid backend component pass all33 affected
Engine and6 backend cases. Actual shared snapshot-free and snapshot-tail recovery
now pass, with the original live-floor mismatch still rejected. Finish these
four connected exits in order:

1. The canonical Database/Raft workspace passes default all-targets
   compilation, including server and benchmark consumers. Also check the normal
   Engine package separately: workspace feature unification must not hide a
   production dependency on test-utils. Both actual
   construction/control/Weak checks and original key revocation pass. The real
   killed-process and history tests now pass after constructor response buffers
   are prepared above the actual authenticated snapshot/bootstrap reconstruction
   floor. The separate durable floor and original pending-write cutoff remain
   unchanged; all three pending/bootstrap/snapshot range checks pass. Original
   TLS replication and peer security pass with the same storage/admission budgets
   and explicit fixed role for their non-Engine fixture backends. Affected
   control/Weak2 and original key revocation1 also pass on the repair. Preserve
   this complete prerequisite source, including its passing repaired default
   workspace all-targets compile, through the native memory join. Other feature profiles remain unqualified.
2. Preserve the closed lexical stream receipt and retained String replacement
   owners. The actual sustained stream and raw String replacement cases pass;
   the earlier selection passed34/35 Engine and6/6 backend cases, with its
   original English analyzer failure preserved. The repaired selection now
   passes35/35 Engine and6/6 backend cases. Connect paid real analyzer
   construction, registry lookup and per-field
   copies, including English and Japanese, without using an unfunded clone or
   granting a fresh allowance after acceptance. Return Box capacity only after
   physical destruction; charge both old and new String backing during growth.
   Preserve every original assertion. Both original Stacker profiles pass47
   library and3 compile-fail cases; both Columnar profiles pass188 library and
   their original documentation case. The repaired complete Tantivy library now
   passes1,114 cases with5 original ignores; documentation passes52 with1
   original ignore. This includes the actual29,417-word English vocabulary and
   all eight previously failing error-wrapping, pure-quote and per-record Store
   cases. Both failed and qualified source are preserved, including the unchanged
   original English Session case on the repaired selection.
   Qualify the actual external per-field copy bank and pair its returned native
   diagnostic with the same original credit for its entire lifetime, including
   deliberate forgetting. A formatted wrapper cannot stand in for the original
   diagnostic or an admitted wrapper allocation. Registry/constructor and Japanese funding remain
   required before production admission can claim complete native ownership.
3. Finish constructive Generation, index and validator payload ownership, then
   connect actual owned accepted apply to the unique standing metadata bank.
   The native empty-root constructor, canonical inline policy actions and typed
   empty-genesis producer now share one isolated source with the English/Store
   repairs. The repaired source now passes normal Engine compilation, all nine
   actual genesis/index cases, both inline-action cases, and all35 original
   Engine plus6 backend cases. The exact allocator census passes without
   changing its byte/count/grant assertions: the two production mutexes use
   inline controls with the original poison and nonblocking recovery behavior.
   The earlier128-byte allocation gap and three test-interface compile errors
   remain preserved. All three actual mutex parity/panic checks now pass,
   bringing this prerequisite selection to55 passing runtime cases. Its complete
   source is archived. The next collection-map and funded query-constructor join
   failed normal Engine compilation because its native validator omitted an
   ownership field; that full failed source is preserved. A direct native
   empty/boolean root removes the unrelated full-graph owner and lazy mutex,
   retaining the original allocation assertions. Its normal joined Engine check
   now passes after correcting the collection iterator's Clone interface and
   publication cursor type. All four map/policy checks pass separately. The
   joined Query selection passes all136 unit cases, five integration cases and
   three compile-fail ownership cases, including all ten new constructor and
   retained-credit checks. The original Engine libtest build then exposed two
   unchanged refill Default inference ambiguities; its complete failed source is
   preserved. Their exact original map input types are now annotated, and the
   unchanged selection now passes57 distinct cases: genuine genesis/index9,
   policy2, original Engine35, backend6, mutex3 and map2. The complete prerequisite
   source and the unchanged passing Query144 selection are archived together.
   All three native known-root allocation cases and their ownership compile-fail
   case also pass against the exact original resolved schema graph. The first
   harness stop was a preserved macOS path-normalization error before tests; its
   corrected graph comparison preserves every package, version and feature.
   The original full native schema profiles remain a separate required gate before
   adding another production producer. Extend the same prospective ownership to
   supported collection/document changes and compiler/runtime allocations.
   A source-reviewed empty producer cannot qualify decoded or nonempty payloads.
   Move the original prior into its external transition receiver before graph
   work; block new loans through retained failure or cancellation. A successor
   requires the same durable receipt and genuinely funded Generation and
   validator payloads. Leaked validation diagnostics must retain their original
   payload credit. Copied metadata retirement alone cannot authorize publication.
4. Join primary, structured, unique and text producers to one atomic durable
   publication, then activate canonical serving and finite service refill.
   Qualify every workload below and above the bound on that final source.

Each gate needs its own concrete runtime evidence; a source review or component
pass cannot substitute for the production serving connection. All C01–C07 and
M01–M07 remain open.

The immediate acceptance sequence is concrete:

- Preserve the passing normal Engine compile, complete Query selection and
  compile-fail documentation for the joined map/validator/query constructor.
  The restored authored schema branch now passes normal Engine compilation,
  AP1,881, all four original focused123 profiles, referencing143 and the original
  ownership compile-fail case. Preserve its qualified4,036-input source. The
  later4,040-input borrowed genesis/index join passes normal Engine compilation
  and Query144 after its two-line duplicate-module correction. Seven stale
  test-constructor errors are separately preserved and mechanically corrected;
  Engine59 initially ran 55 passes/four bootstrap failures. Current Engine63
  runs 62 passes/one original funded-genesis startup failure; all three actual
  paid metadata witnesses pass. Current Types4/backend6/Query145 also pass with all3,473 unchanged pins;
  both earlier original invalid-budget cases pass.
  The bounded completed memo now passes exact AP1,887/focused123×4/ref143/doc1
  (2,523 invocations) on4,045 inputs/all3,473 pins. Its original fixed/refusal
  contracts and depth/transition limits remain. Preserve the separately observed
  all-feature fixture-forwarding failure; qualify the narrow feature correction
  and complete the still-incomplete canonical default-meta validator/runtime.
  Qualify genuine startup provenance and all schema profiles; apply-time funding
  does not close preacceptance admission. Rerun the
  genuine genesis census against the joined types; a prior layout total cannot
  certify a changed representation. Original schema regression passes do not
  close the funded canonical default-meta path, which still reports incomplete.
- Join the per-field native copy and diagnostic owners. A returned, forgotten or
  panicking diagnostic must keep the same original allowance charged until its
  actual backing and control tails are destroyed. Preserve the complete original
  native and Engine selections, alongside the new ownership witnesses. This join
  passes normal Engine compilation and all38 Engine plus6 backend cases after
  correcting the three diagnostic fixtures' unused scratch setup. The original
  64KiB/native-zero limits and all assertions remain unchanged. Correcting two
  analyzer warmups to retain actual populated tokens makes the complete Tantivy
  library pass1,124 with5 original ignores; documentation passes52 with1 original
  ignore. Both preceding failed sources are preserved. The strict helper's
  interleaved-output stop is also preserved; its parser-only correction now
  passes both original Stacker profiles47+3 and both Columnar profiles188+1.
  The complete3,708-input qualified source is archived before the restored schema
  join. The later prepared Registry native join also passes its exact original
  selections and four new constructor cases; its Engine/Query consumers and the
  canonical compiler/runtime successors remain open until their actual joined
  checks pass.
- Connect actual accepted payloads and standing metadata to one durable receipt
  covering primary, structured, unique and text roles. Exercise failure and
  cancellation before activation, then activate snapshot-aware disk serving and
  bounded refill.
- On that final joined source, verify full residency after finite warm-up below
  the bound, pressure-driven eviction above it, and restoration after shrink or
  budget growth. Include retained versions, all index roles and native pages in
  the census; complete the original recovery and release checks before closing a
  production goal.

The startup fixture uses real SDK entries and their original publication
receipts. Its original setup scope is restored, with every gate/retirement
deadline unchanged; its measured17-second baseline is not a latency claim.
Passing cleanup does not establish real Engine crash/reopen recovery. The
shared floor cases now verify coherent durable application/log/response state
before constructor acceptance and replay; preserve that result through the
canonical caller cutover and verify actual documents, receipts and policy.
Preserve exact mismatch rejection; do not clear persisted response floors or
invent a snapshot merely to make startup pass.

Keep the active goal at the complete redesign scope. The next work is ordered
by these finite exits; finish a failed prerequisite before enlarging its source
cohort or repeating unrelated checks.

| Order | Concrete work | Exit evidence |
| --- | --- | --- |
| 1 | Preserve qualified Store, initial context, document-entry, term-buffer and field constructors; complete dynamic native growth and the remaining constructors. | Original native test identities, constructor error/panic/backing checks and connected Engine consumers pass. Consume each prepaid byte once under the same writer credit. Keep options, budgets and default stack unchanged; preserve retirement 25/25 and the joined schema evidence. |
| 2 | Finish actual native text entry, analyzer, parser, finalizer and diagnostic ownership; qualify canonical caller-owned source draining and the connected Custody source. | Every remaining allocation has a concrete preaccepted owner, and original native suites and installed Engine/replica consumers pass. Preserve original errors/panic payloads and backing through refusal. Separate data retirement from physical control/notification/Frame/diagnostic retirement. Conservative finite Store or MRU estimates cannot certify universal full-fit admission. |
| 3 | Preserve the qualified forward-NFA repair and prior-bank retirement; qualify the repaired owned bridge, then finish schema compilation and accepted primary/structured/unique/text ownership and one durable all-role publisher. | Forward-NFA AP 1,878/focus 123×4/Query 124/referencing 143 pass on its archived source, including every preserved original identity. Preserve the qualified default matcher and exact published reproduction of all fourteen no-std UTF-8 documentation failures without changing selected package surfaces. Keep all original no-std failures visible. Preserve the joined normal/28+3+1/Engine19/backend6 and original native profiles. Qualify retained ingress, actual Database lifecycle and prepared JSON finalization on their explicit joined successor. Install the real baseline without an Engine-owned route back to its owned command or guard. Complete shared payload/Weak funding, compiler/default-meta/runtime allocation inventory and one accepted journal/semantic graph/selected generation before replacing ordinary empty publication effects. |
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
| Ownership before acceptance — M02/M03 | The 147-image native source joins ordinary Snapshot B disposal, last-caller/held-Weak metadata and the preinstallation race correction with posting/position/term-info/FST and canonical/Custody ownership. Exact source, mode and 15-package vendor checks pass. The ordered-effects bridge is applied in the isolated candidate and its normal library check passes. Test compilation exposes four stale fixture/accessor interfaces; their narrow correction uses the actual preinstalled Snapshot caller and preserves the failed result. The unchanged 121-test retry is terminal: 111 passes, ten Custody failures and all 3,033 pins unchanged. The precise test-only Custody correction then passes all 34 selected checks with all 3,033 pins unchanged; the original 121-test failure remains archived. The reviewed 139-image schema translation/expression/HIR successor is applied separately; full frontend ownership remains open. | Own the complete native writer/FST/tokenizer/parser, schema frontend, candidate/index journal and every typed response before leader, follower or recovered entry acceptance. Qualify original task installation, DATA/B disposal and the separate Frame/caller/diagnostic/Weak census. Accepted work must not encounter a new mandatory capacity refusal. |
| One atomic publication — M04/M05 | Production still has an empty application-write publisher and resident document/index serving. Its apply lane retains a selected receipt but lacks the actual closed committed baseline and bound query metadata needed by the primary factory. The isolated candidate now carries the reviewed preaccepted ordered-effects bank into the real CompletionLoan publisher and passes all ten ordered-publication checks. Production activation remains open. | The real accepted primary and every structured, unique and text role produce one canonical durable receipt and exact selected generation. Retain the unique committed baseline, bound query metadata and prior failure/retirement tails in the serialized apply lane. Connect fresh, snapshot, point, query, pagination and history reads to it, then remove resident serving alternatives. |
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

The remaining ownership work has three concrete dependency groups. Dynamic native
text growth, tokenizers/analyzers, finalizers, canonical parsing and diagnostics
must use the same preaccepted owner through successful completion, refusal and
retirement. The initial table/arena and finite Store gates now pass; they cannot
certify allocations outside their actual profiles or universal full-fit admission.

Schema translation, expression, HIR and paid-frontier ownership pass their
original joined selection. CaptureInfo is applied in isolation. Its original
default matcher library passes 206 cases, integration passes 60 and doctests
pass 459 with two original ignores. The original no-std profile has one library
failure and 40 integration compile errors; both reproduce against exact unmodified
published source with the original feature and dependency graph. A narrow
qualified Result spelling repair resolves
the separate AP interface error. Restoring the exact original relative fixture
then passes all 1,873 AP tests; all four focused profiles, Query and referencing
also pass. Both the failed fixture run and complete passing source are archived.
The repaired forward-NFA successor passes its original preadmission allocator
check and complete schema selection. Both UTF-8 library profiles and default
documentation pass; preserve and independently reproduce the fourteen no-std
documentation failures. Qualify the repaired matcher on its exact original
profiles before advancing the compiler.
Complete Pattern/default-meta NFA and runtime construction, supported
user compiler branches, per-validation scratch and retained validator/weak-cache
owners before replacing ordinary production compilation. Keep fixed platform
backing separate from schema-sized work and preserve original partial/error
custody throughout.

Normal Engine compilation passes with the actual primary tree and projection
modules in the isolated source. Required production owner dependencies are
available normally, while genuine fixtures retain explicit test gates. The
original 90-error source, incremental compiler failure and subsequent narrow
interface failures remain preserved. The original 25 metadata, retirement and
publication consumers now pass; preserve that checkpoint through later native owners.
Install the unique committed baseline and bound query metadata in the serialized
apply lane. The actual factory, complete accepted index graph, one durable
publisher and exact selected-reader handoff must share that owner. Ordinary
empty effects and pending text refusal remain until the real all-role producer
is ready. A compiled capability alone does not activate document serving.

The source audit makes the shared funding dependency concrete:
`GenerationRef::legacy_resident` supplies neither payload control nor registry
ownership, while selected metadata clones validator references and funds only
its copied strings, maps and index controls. Replace those production constructor
paths with genuine retained payload/validator owners. Preserve live public
snapshots and their charged Weak tails while later writes proceed; dropping one
reference or returning the copied bank cannot prove those referents deallocated.

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

### 2026-10-06 original startup/catalog qualification and combined native integration (actual186–195)

Actual186 H15 full original Engine66+Types4+backend8/Query145 PASS116.37s,
all3,474 outer pins unchanged (223 case invocations). Genuine funded genesis,
revision0 and exact serialized durable bootstrap image all pass, as do actual
paired catalog installation, explicit same-purpose audit placement and both
native initialization-prefix cases. Qualified187 preserves full4,046 in4,130
verified members/modes, SHA0db8e5098d0b33bdda278c3655752d66efea42fce8c270ff37fd1d9d64397466.
This is prerequisite qualification, not production cutover or full residency.

Actual188 applies independently reviewed unionaaeaa:72images/19new,
full4,065, native25/original484lock unchanged. Actual189 original normal Engine
check FAIL14.95s/all3,493 due to Lindera SchemaIndex projected Deserialize
blanket overlap and unresolved native ArchivedHashMap hasher. Full failure190
preserved4,824 members/modes, SHA2f2ceddb9c8f929a8e219013169e43f6157edae6f25b7aebf8e2c55ecf9779b7.
Independent585 repairc508/report4d68 PASS retains exact original archived
Option<HashMap> type/resolver/geometry using a local field adapter and concrete
native hasher; no format, test or bound changes. Actual193 applies its3images.

Actual191 complete KV libtest compiles and lists successfully, then exits1
at11.72s/all3,493 before any test execution: root helper guessed cache::tests
rather than actual cache::pool_tests for the new aggregate case. Full listing,
failed helper and complete unchanged source are preserved192 in4,833 verified
members/modes, SHAb46760012c8ddb1307bc23baf8a582aa9683246889cfecfcba3f577b254728d6.
Correct source-derived literal on the successor; retain the full unfiltered
namespace, strict original parser, commands and separate raw streams. No KV
functional failure or runtime PASS follows from a successful listing.

Actual194 original normal Engine check FAIL36.84s/all3,493 on585/full4,065.
The rkyv correction compiles. Original anyhow FrameFailure conversion at
primary_stage_index_text_edit_roots187/195 requires Sync, while the genuine
Japanese dictionary retains Box<dyn Any+Send> panic custody. Correct through a
closed owner retaining the same Send-only raw payload; do not unsafely expose
it as Sync or replace/drop the original failure. Integrated H16 runtime has
not executed. Failure195 preserves the complete source/raw/unexecutedH16 before
any successor. All C01–C07/M01–M07 remain open, no source promotion or release.

Failure195 archive verified4875 members/modes, SHA17baa740ec8732adee760a9bc8bf1f5a2625e62e27ded2cf0a66f6b9505b3443.

### 2026-10-06 complete native KV and integrated normal build pass (actual196–200)

Actual196 unfiltered nativeKV library677 PASS617.86s/all3,493 source pins
unchanged on585/full4,065. Every literal listed identity receives an exact
original strict result; zero ignored/failed. Additive aggregate-role pressure
shrink/grow passes along with original96MiB image,100,000-row publication and
reopen,65,539-operation sparse image and prepared maintenance refusal cases.
H2 changes only the actual pool_tests selector/fresh runtime and three585 source
pins; original191 failed helper/listing remains preserved192. Qualified197
contains full4,065 and4,896 verified members/modes, SHA5cda63c334ef0697cff2b6f3aed084d5d5937f179e7a83121c13ab45f925d9c9.

SourceLockb3f3 finite review28c5/report8ea4 PASS, whole4,064 other source
leaves and complete original test modules unchanged. Both naturally Send-only
Japanese construction receivers stay inside private inline selected parking_lot
controls; only bool presence is shared, payload borrows/take require exclusive
mutable access. No unsafe Sync payload, heap/control grant, changed raw failure
or new allowance. Actual198 applies one Session image after197 guard. Original
normal Engine199 PASS27.86s/all3,493. Actual200 H16SourceLock full244 original
plus additive consumers starts on exactb3f3/full4,065; no runtime result yet.
First13 remains source-only reviewed narrow-forward26a36139, H18 exact257
selectors, no production/preacceptance/fullfit claim. All C/M open.

### 2026-10-06 integrated Session fixture type correction (actual200–203)

Actual200 exact244 selection FAIL136.73s/exit101/all3,493 during Engine libtest
compilation; no selected case executes. New production Japanese Session case
uses original arena15_000_000 inferredu64 by Session::allocate, then enter
requiresusize. Failure201 preserves full4,065 and4,935 verifiedmembers/modes,
SHAe011d1638207921d15c430a32c2833f9825dbe22b6393a194eba0da8d6af7e72.
NativeKV196 complete677 and original normalEngine199 remain separate scoped
passes. Exact ecb737 correction has independent revieweb3b/reporte272 PASS:
checked usize::try_from(arena)? at that same cfgtest call, same literal and
all assertions/caps/inputs. Whole file inverse and4,064 other source leaves
byte/mode exact; production bytes unchanged, so no redundant normal rerun.
Actual202 applies after201 guard; H16-v3 entire helper bytes9039 unchanged,
all244 literal names/flags/parser/capture exact. Actual203 fullretry runs on
ecb737/full4,065; no runtime PASS yet. Schema H17 whole source guards forward
this one fixture pin while all700 compiling native leaves and original302
graph/AP1893/focused123x4/ref143/doc1 remain exact. All C/M open.


### 2026-10-06 integrated runtime failures and aggregate correction (actual203–210)

Actual203 Engine69 reaches all original and additive assertions: 68PASS/1FAIL,
107.89s/exit101/all3,493. Genuine production Japanese Session, SourceLock and
all original66 pass. Installed native aggregate shrink fails its unchanged
main.evictions assertion: resize_retention(0) clears lookup aliases before the
counted-victim loop. Actual205 Query lib154 reaches153PASS/1FAIL,
41.92s/exit101/all3,493; unchanged same-Work zero assertion sees transient4108
after mutable-token refusal. Do not reset the tracker or alter the assertion;
known native backing must be disposed before its original debit is retired.
Types206 full4PASS7.99s and backend207 full8PASS44.04s remain separate passes.
No complete244PASS or production activation follows.

Guard208 preserves currentecb/full4,065 and all runtime raw streams, including
Engine203/Query205 failures and Types206/backend207 passes, in4,960 verified
members/modes, SHA133c1ef3fc3dcb27760b6a0b3b0f7f990c5c0c7e92227ee6936a463ce94df980.
Actual209 applies reviewed34ff8b aggregate zero-target accounting then045819
empty-control fixture. Only actual aliases removed by aggregate zero-target
pressure increment evictions; explicit clear semantics, targets, caps and
pinned-backing charges remain. The unchanged final used==0 assertion now follows
positive pin release and disposal of the empty pool control. Actual210 runs the
complete source-derived cache:: subtree with original strict parser and separate
streams; it is a focused scope, not another full677 claim. Native/consumer/schema
helper forwards retain exact original flags, assertions, rosters and graphs.
All C01–C07/M01–M07 remain open; live changes are goals/progress only.


### 2026-10-06 repaired aggregate qualification and native schema fixture failure (actual210–216)

Actual210 lists101 actual cache-filter identities, then the root helper's
prefix-only predicate rejects legitimate page_cache/publication_cache names;
7.56s/exit1/all3,493, no testcase executes. Frozen successor changes only that
predicate/labels, retaining the same Cargo substring filter, strict parser,
separate streams and whole source guards. Actual211 all101PASS17.96s/all3,493
on045; exact original aggregate and new zero-target/pin/empty-control witness
pass. Actual212 Engine69PASS90.15s/all3,493, including installed encrypted-role
aggregate shrink/growth/rewarm and original66. Qualified214 captures full4,065,
4,926 members/modes, SHAba82f96ce2a163c3ecd89869397a5c853d1b0b5cfb04adbb85a928c7a1b9213c.
These passes do not activate production disk documents/indexes or whole residency.

Actual213 original schema AP metadata/package/resolve graph PASS, then stops
before any testcase at native libtest compilation: syntax_runtime_tests raw
panic_any Box<OriginalError> owns non-Send Rc<Ledger>. 44.70s/exit1/all3,493;
700 actual native/compiler leaves and all original flags/rosters remain exact.
Guard215 captures full4,065 and4,939 members/modes, SHAc17460cbc4134a9f04f5d4d26a590769754715f5ecdb52e378250c717f4dc205.
A narrow private test-only same-Arc ledger with safe mutex observations is in
review; original test bodies/patterns/debit/raw pointer/caps and production bytes
remain unchanged. Japanese successful-scope correction is also under finite
review: dispose known native sentence backing before returning its original
transient debit; returned/raw consumers preserve original partial ownership.
Actual216 original default mmap Lindera baseline/selected scopes runs current045
separately; no runtime claim yet. All seven criteria and milestones remain open.


### 2026-10-06 current correction integration and normal build (actual217–221)

Guard217 preserves original216 tokenizer failure/published source/helper174lock,
original213 schema fixture failure and fullcurrent045:5,160 verifiedmembers/modes,
SHAf7ad147b701076e91409bf4661ebf63b09d0b3e16cb5e05134ceec7f5bcf9240.
Actual218 Stacker original49lib+4docs each required default/compare_hash_only+ahash
profile PASS68.29s/all3,493, exact statuses/graphs/caps. These native source bytes
remain unchanged through the subsequent correction chain.

IndependentJapanese661 review76e824/report035996, syntax525e reviewc7051/report89cc6
and exactjoin75805 reviewe1255/reportb83ae allPASS; rootverifiesartifact hashes/modes.
Actual219 applies045→661 fourimages→75805 twoimages, full4,065/native25 verified
at both steps. Successful lexical scope disposes completed native lattice before
same-group debit retirement; entered/mutable and returned/raw failures remain
entered with original owners. Test-only sameArc ledger observations preserve
all original native syntax bodies/limits/raw pointers; no production fixture change.
Actual220 normalEngine PASS64.81s/all3,493 withwhole4,065 before/after guard.
Actual221 exact248 consumers runs current75805: original244 plus four sourced
Japanese scope cases; strict parser/capture/flags/assertions unchanged. No runtime
result or production activation is claimed yet. Original upstream Lindera
resources25 restored from exact published commit b805dbe17cdd71b9aec319d604dfea96933744b4
into reviewed helper candidates; original fixture test remains intact. All C/M open.


### 2026-10-06 final original analyzer alias accounting witness (actual221–223)

Actual221 full248 attempt stops370.22s/exit101/all3,493 on final originalQuery
library count:157PASS/1FAIL of158. Engine69/Types4/backend8PASS on same758;
the prior transient4108 assertion and allfour newscope casesPASS. Original
registry finalstrongcount now sees8/1: ordinary=alias.get(...) remains live
past existing drop(fields,alias,manager,dictionary,work). Exact trace is original1
plus ordinary frame1/native tokenizer1/five dictionary controls5. Current native
ownership is correctly retained while that actual alias lives. Explicit actual
drop(ordinary) before unchanged final disposal/count1 is a cfgtest witness repair,
not a provider reset, premature refund or Ready promotion. Oneimage6de full4,065
has independent2ac5/report9542 PASS; every production byte/input/cap/assertion
unchanged. Root runtime remains required before treating the full consumer gate
as passed. Guard222 captures full4,065/5,261 verifiedmembers/modes,
SHAbfc97a12c76db33ddeaf6a8a41090ddb391d390f48539620362dd975c1ba0746.
Actual223 current758 originalnativeSchema700/AP1893/focused123x4/ref143/doc1
runs separately; do not mutate active source before its terminal. First source
remains unapplied, all C01–C07/M01–M07 open, no live code promotion or release.


### 2026-10-06 original schema and corrected Query qualification (actual223–226)

Actual223 whole current758 Schema native700/AP1893+focused123 eachfourprofiles+
referencing143+ownershipdoc1 PASS310.28s/all3,493 (2,529 caseinvocations). Exact
original302 graph/locks/manifests/features/fixtures and originalassertions/caps
remain. This qualifies component compiler/runtime cases, not general production
schema/reference/defaultmeta full-fit activation. SyntaxcfgtestSend correction
has no production byte changes. Actual224 applies positive ordinary alias
fixture6de onecfgtestimage aftercompleteguard222; full4,065/native25 exact.
Actual225 correctedQuery167 PASS69.02s/all3,493 (lib158+other9), including unchanged
original registrycase/transient0/finalcount1 and allfour newscope cases.
Core81 PASS221 remains on identical production; no invented one-command248PASS.
Native schema700 and original Stackerscopes are byte unchanged through6de.
Actual226 originalLindera completebaseline/selected defaultmmap with all25 same
upstream fixtures runs current6de; no runtime result yet. First17/H22 source
currentforward is independentlyreviewed (all261selectors unchanged), still
unapplied/unqualified. All C01–C07/M01–M07 open; livechanges goals/progress only.


### 2026-10-06 complete Tantivy and original Lindera roster observation (actual226–228)

Actual226 restoredfixtures Lindera original83 librarycasesPASS ondefaultmmap,
with exactoriginal174 graph and sameversionSerdeedge. Selectedlib actual108
lists successfully, thenstrict23additions roster rejects two genuine earlier
native lattice witnesses: normal_lattice_bound_covers_dense_matches_unknowns_and_reused_sentence_slots
and normal_lattice_quote_arithmetic_refuses_overflow. 24.23s/exit1/all3,493;
no selectedcase executes. Freeze exact25 additions with source/wholebody/module
provenance; retain every original test/status/cap, separate rawstreams and flags.
Guard228 preserves current6de/full4,065 in6,430 verifiedmembers/modes,
SHA3894f74b75f57cfd9a049476d4e9b7707056999b3ed66f1b123f85725b3b43b7,
including qualifiedQuery225/Schema223, oldcorepasses, failed226/list/helper/fixtures.
Actual227 complete originalTantivy native1133lib(1128PASS/5originalignore)+53docs
(52PASS/1originalignore) PASS102.41s/all3,493 current6de, exactoriginalgraphs,
locks/support42/body/flags/status identities. Scope hook nativechanges reach
all originalbehavior tests. First17/H22 sourceforward finite peer review7e1a/reportd2d9
PASS; all261selectors and4,122 other sourceleaves exact, stillunapplied/runtimepending.
No productionactivation/fullfit/release or C/M closure follows.


### 2026-10-06 original Lindera compile-only identity and preserved source (actual229–230)

Actual229 on current6de/full4,065 preserves all original174 graph/lock/default
mmap features and the exact same-version Serde source edge. Original83 and
selected108 library tests PASS; both original and selected dictionary-builder
5-case selections PASS. Original documentation execution exits0 with1PASS and
1 originalignore, but the strict helper rejects the original no_run doc result
`src/loader/metadata.rs - loader::metadata::MetadataLoader (line 14) - compile`
against its unsuffixed list identity. The outer run ends101.75s/exit1/all3,493;
selected documentation has not run. This is a helper identity failure, not a
passing complete-native claim. A source-derived exact compile-only mapping is
required; broad suffix stripping, status/count fallback and test changes remain
excluded. Guard230 preserves current6de/full4,065 with4,414 verified members
and modes, SHA35039d1742cfada87465f02d5ec440e7a8becc43177b4ee3196cd002ca2bcb30,
including complete Tantivy227/raw Lindera229/H9/finite reviews and the verified
inherited228 checkpoint. First17/H22 artifact hashes and all100 after images,
4,023 dependencies and58 new-source absences are verified. First SDK candidate
remains unapplied; all C01–C07/M01–M07 remain open.


### 2026-10-06 complete native gate and first SDK normal integration (actual231–238)

Actual233 H10 complete original Lindera defaultmmap/174 graph PASS97.39s/all3,493:
baseline83 and selected108 library cases; both5 dictionary-builder cases;
baseline/selected docs1PASS+1 sameoriginalignore. Exact source no_run line14
and ignore line69 mapping keeps strict parser/status/provenance. Peer c35fe0/report
afdc14 PASS root-artifact-verified; no source/cap/body/profile changes. Actual231
applies reviewed First17 genuine100images/58new/full4,123/native26 after guard230
and actual233 terminal. Original484 graph has sole same-version imbl7.0.1 source/
checksum transition. Actual232 normalEngine fails97.19s/exit101/all3,536 with one
E0599: StateMachineBackend trait not in scope at typed initialization dispatch
owned_ingress.rs144. Guard235 full4,123/4,561 verifiedmembers/modes preserves the
failed normalsource/raw/H22 plus successful Lindera233/H10, SHA752e57f278101834
dad1bbd59b5f423c5f1ed1960f18b642dffa9b55a3bd4b02. Actual236 applies one anonymous
trait import18 (MF21afeba4/patchfc5e94), allother4,122/native26/484 unchanged.
H23 all261 selectors/casebodies/helper literalbytes remain H22 exact; peer
a73d07/report64d780 PASS/root-artifact-verified. Actual237 normalEngine now
PASS15.54s/all3,536 and whole4,123 before/after pins. Actual238 full261 SDK/consumer
roster runs on that exact source; no runtime result claimed yet. The actual
baseline/standing seed, preacceptance allowance handoff and normal worker/refill
module prerequisites are source-only work. Config census also keeps C01 open:
large shared residency must not be silently capped by current512MiB default
reservation total or installed small per-store limits. All C/M remain open;
no live source promotion or disk-serving/full-fit claim.


### 2026-10-06 actual SDK pass and complete Engine roster failures (actual239–246)

Guard239 preserves First18/full4,123/4,573 verifiedmembers/modes and compile238
scopes, SHAc6359d6aa1bf6ab905ea13363fe934a38d547d67e967a27ffbf52faab9c40034.
Actual240 applies First19 exactly two source-scope repairs: private completion
Action renamed at3 tokens and SDK GenerationRef imported. MFcdca605e/H24
7c3be2ad, wholehelper/all261selectors and original testcasebody literals exact;
peer da79e65/report7ee046 PASS/rootverified. Normal241 PASS6.06s/all3,536, full
4,123 before/after guard. Actual242 Engine82 exactnamespace reaches76PASS/6FAIL,
273.74s/exit101/all3,536. Real SDK firstcollection and5 constructive First tests
PASS; two backend terminal zero checks see7,309,680 totalbytes while their live
NodeAdmission still owns original bookkeeping. Proper observation must require
resident0, unchanged source-derived bookkeeping, total==bookkeeping and exact
paidgrant slot retirement; a zero total would falsely refund the live governor.
The aggregate case and three standing helpers fail actual key-access checks.
Their current-thread fixtures have long synchronous work with no scheduling
boundaries, starving real renewal. Source constants are MAX_KEY_LEASE60s, renewal
20s, provider5s; earlier informal30s inference is incorrect, no constants change.
Selected types/backend/Query do not run after this Enginefailure. Guard243
preserves full4,123/4,581 members/modes and actual242 raw/H24, SHAac9d86019aa98e6f
1e3cb3ac80cf0d2241cb9bc9dc22bfb89f6b6b18fff9086e. Four cfgtest image corrections
are source-only: ledger observation1 a2168; standing two shared bounded helpers
b051; aggregate cooperation1 2765. Original phases/step64/writes32/warm256/rows/
limits/TTL/runtimeworkers/expiry checks stay fixed. These repairs do not claim
that any one synchronous native phase is below the lease lifetime. Phase timing
keeps that gate observable in the next run.

Native imbl H1 preserves published52/132lock and selected54/exact3new cases,
all current4,123 guard inputs. Actual244 stops2.77s/all3,536 beforemetadata because
original proptest-derive is uncached offline; no tests run. Actual245 fetches the
exact original132 locked dependencies2.69s/all3,536, all immutable artifact/source
bytes/modes unchanged. Actual246 same frozen helper/fullsource runs the original
default+productionserde+allfeatures library/docs profiles on fresh runtimev2.
Default library122original and125selectedPASS; complete profiles remain running.
This standalone132 graph does not substitute production484 SDK qualification.
All C01–C07/M01–M07 remain open; only goals/progress changed in the live checkout.


### 2026-10-06 complete persistent-collection qualification and corrected joint run (actual246–249)

Actual246 complete original imbl7.0.1 default/Serde/all-features library and
documentation qualification PASS926.23s/all3,536 unchanged source pins. Default
and Serde each preserve122 original library cases and125 selected cases;
all-features preserves132 original and135 selected cases. Both phases preserve
120 docs in default/Serde and125 docs with all-features, all original statuses
exact. The three added native allocation cases pass in every profile. Original
132 standalone graph and production484 remain distinct; this component result
does not establish SDK or whole-cache completion. Recoverable supplement247
references the verified failed-First19 full-source guard243 and archives242
verified helper/runtime/outer members, SHAa1224d6805341a9fc157969dd483d8fb4145815ce
3434c70819a716b7add9014.

Current20 disjoint four cfgtest image union26ee1706/patch2849fa97 preserves full
4,123 source/native26/production484. Independent union/H26 review9b4d6175/report
5acbb7ef PASS/root-artifact-verified; whole H24 helper/261 selectors literal,
exactly two ledger observations and one aggregate scheduling case body change,
standing shared helper checkpoints only. Original bookkeeping is retained,
expected resident zero and exact one-grant retirement are required. Actual248
applies only these four reviewed images after native246 terminal and guard243;
all4,119 other leaves/modes are unchanged. Actual249 uses H26 afc0352b, whole
qualifier59e5b034 and fresh runtime-root-v4 for Engine82+Types4+backend8+Query167.
The complete261 run is in progress; no passing result is claimed. Normal
production bytes remain241-qualified. C01–C07/M01–M07 stay open; no live source
promotion, disk-serving activation or full-residency claim.


### 2026-10-06 corrected joint consumers and normal worker compilation (actual249–252)

Actual249 H26 complete261 PASS419.00s/all3,536: Engine82(75.88s), Types4,
backend8 and all167 Query callers preserve every selected identity/status. The
genuine SDK First and all six earlier failed fixtures pass. Cooperative setup
keeps the original workloads,60s key lease/20s renewal/5s provider checks and
runtime worker counts; aggregate original256-step warming records a longest
rewarm step7.03322s without extending the lease. Ledger terminal checks require
resident0 plus unchanged exact governor bookkeeping and one real grant retirement.
Guard250 preserves completeCurrent20/full4,123 in4,370 verifiedmembers/modes,
SHA873a3e53f6c7ca892a8b3e2351aead1701a129102ef3e867520469a1f02dacf2;
failed242/source243 and native247 supplements stay referenced and intact.

Normal7→Current20 literalforward fb9ac3b1/patchee66782f applies251 only seven
reviewed images, all4,116 other leaves/native26/484 unchanged. OriginalNormal7
peer12b97 plus forwardpeer949bae03/reportefdb4b53 are root-artifact-verified.
Actual252 normalEngine PASS118.62s/all3,536 with complete4,123 source guard before
and after. This makes real per-Database source work, finite refill/inline child,
selected lease refill controls and actual normal source methods compile; it
does not install a committed baseline, start automatic warming, serve selected
documents/indexes or remove resident query alternatives. Test compilation already
included these same guarded bodies before this cfg-only promotion.

Budget caller audit4e61439a is preserved as Current20-residency-budget-audit-20261006.md:
None512MiB currently capsallcharges; Some remains an explicit totalcap. Temporary
native workspace shares the Resident category with permanent owners, and sampled
RSS plus all reservedbytes overlaps live materialized backing. No cap-only repair
is applied. C01/M06 require constructor-proven transient roles/positive transfer,
one simultaneous workspace total, usable scaled aggregate default and an actual
materialized allocation union. NextcompleteFirst seed uses the existing original
payload through owned authority, effects/metadata and nativecurrent/point/stage/
frontier/verifier/capture constructors. Selected query seam4e282 source-only retains
original QueryMemory/rejections/reports and unchanged5s worker wait; actual public
failure/output handoff remains open. All C01–C07/M01–M07 remain open; no live source
promotion or completion claim.


### 2026-10-06 normal selected-query seam and preserved focused failure (actual253–256)

Actual253 applies the two reviewed selected-query seam images4e282f9e/patch
216a5157 onto Normal7→Current20; all4,121 dependencies/native26/production484
stay exact. Actual254 normalEngine PASS8.48s/all3,536, with full4,123 source
bytes/modes guarded before and after. The real helper uses the original
QueryMemory, scope/registration, cancellation and unchanged5s timeout. Rejected
plans and the same original source failure reports remain typed owners; this
is not public serving activation.

Strict17 helperv2 d87cf637/qualifier22d7a1f6 retains the original H26 Engine
profile, features, runtime-thread defaults and capture/parser pipeline. Finite
peer59f8a411/reportbf1f0b1c verifies full4,123 source/body/module/attribute-line
identity and rejects zero-case package selection. Actual255 terminal104.07s,
exit101/all3,536 unchanged:16PASS/1FAIL. All5 actual primary source cases and
11 other original cases pass. Restore identity validation fails at
state.rs3605: TestDiskMemory reserve_installed encounters live32/max32, native
request28,936/charged33,056, before the expected snapshot-validation path.
This is not fixed by relaxing the original cap or discarding a reservation.
Guard256 archives full4,123 source and4,191 verifiedmembers/modes,
SHA7cae108c1190fcb727b67399fdd7ae7495ef038a1ba5c5d3e4757fc4935c12af,
including strict17 helper/rawrun, both source carriers and peer; it references
qualifiedCurrent20 guard250. No mutation follows until that failed source is
recoverable.

Prepaid encrypted point carrier264c0689/patch83a041d9 and its finite
peer60c19e12/report2658a7bc are source-only. The actual inline constructor keeps
its fixed lender and partial native backing before callbacks and retains raw
failures until positive disposal. All60 original bodies plus5 real new Store
cases are preserved; closed Engine loan runtime remains pending. Root native
registered-source/First bank carrier3ef9484a/patch9c1dceec likewise remains
source-only:11 images,4,112 exact dependencies/full4,123, owning parses and
private forward/reverse replay pass. It quotes metadata and native owning
layouts before allocating, using original fixed First subcapacity through
actual capabilities. Those components must join the closed complete First SDK
publisher before a compiling or runtime claim. Ordinary succession,
preacceptance replicas, public query consumer, census/full-fit refill and final
release gates remain open. C01–C07/M01–M07 all remain open.


### 2026-10-06 actual native prepaid constructors and encrypted-point qualification (actual257–264)

Native disjoint union257 is19 images/one new/full4,124 on exact Seams2+Normal7,
MF89ed4c65/patch94716977; its Engine BankFirst image remains pending the closed
First SDK join. Root verifies both finite component reviews and exact physical
forward/reverse composition. Actual258 normalStore FAILED133.54s/all3,537:
E0599 revealed the omitted real NodeDatabase prepaid point forward. Guard260
preserves full4,124/4,190 verifiedmembers/modes,
SHA98c947399125f294f8d6df8d34cd0d7d18656f1c7bf27eaef45efac064b07a2e.

One-image forwarding successor636fdb13/patch916021dd applied261, all4,123
other inputs unchanged. It uses the original accepted Direct/Registered
owner dispatch and exact FnOnce funder/result; no cap, ownership or assertion
relaxation. Actual262 normalStore PASS6.43s/all3,537/full4,124 before/after.
Strict Store19 helper263 compiled successfully but rejected the actual23-case
namespace: four original nested constructorVisit cases were missing from the
author selection. Prior helper, compiled list and raw refusal remain intact;
there was no test run or source correction from this discovery.

Source-derived reachable Store23 helper264 SHA828a4620b466c09f2c9162b82257ed2c4004
f93bb6de13f80303f207e047ecfd preserves original14 direct plus4 nested
constructorVisit bodies and the5 new actual prepaid cases. Actual264 PASS10.03s,
all3,537 unchanged/full4,124 bytes+modes guarded at both captures:23PASS,
0FAIL/0IGNORE, original default features/profile/runtime threads. Real fixed
funding, native partial before second callback, original returned/raw errors,
positive disposal, prepaid growth refusal and current key expiry all pass.
This is native Store constructor qualification; no closed Engine First,
committed baseline, automatic refill, public serving or process memory claim.
Restore original32-slot failure remains open, with a concrete same-cap native
maintenance-bank repair in progress. C01–C07/M01–M07 stay open.


### 2026-10-06 coherent First publication seed and preserved compilation failures (actual265–272)

Cohesive First40 dc80d32f/patchb5f3ee7f parent636f applies265:40 Engine
images/new2/full4,126, all4,086 dependencies/native26/484 unchanged. Root verifies
all physical bytes/modes/aux, actual private reverse and forward. Finite positive
review3226601f/report72bdfe8e verifies the same original First payload bank,
complete actual graph/verifier→four-write receipt→unique metadata→existing
Standing route, original22 complete changed-source cases and H27/H28.
No raw/opaque final-disposal, preacceptance, general-producer or serving gate
closes from that finite review.

Actual266 normalEngine FAILED32.79s/all3,539:2E0308, original_parts declared the
old Reservation while holding StageCredit; require_roots returned the native
Error type through an anyhow signature. Guard267 preserves full4,126 and4,410
verifiedmembers/modes SHA7677b28ed18eeed322835eee651fc6227229bcad54dbf1c796478
03b62fc1061; the actual normal command helpers are preserved beside that archive
under their own linked manifest. Exact typed2 successor638c8505/patch03ebfac7
applies268, all4,124 other leaves unchanged. Guard269 refused a stale carrier
hash before Cargo (0.05s/all3,539); corrected helper270 binds exactly638c and
preserves269. Actual270 normalEngine PASS15.69s/all3,539/full4,126 before/after.

H28 f15c13ff keeps H27 helper2a4ebdf3 literal and all263 selected identities:
original261 plus genuine SDK baseline/shutdown and rooted four-buffer witnesses.
Root verifies169 immutable helper artifacts. Actual271 first Engine84 compiled
list FAILED90.46s/all3,539 before any runtime cases:11 errors comprise the wrong
fixture provider import, seven original StageCredit grant-observation calls
missing their forwarding method, two new SDK private owner accesses and one
Effects drain visibility mismatch. Original assertions and production private
interfaces remain binding. Guard272 preserves complete4,126 source/H28/rawlist
in4,331 verifiedmembers/modes,
SHA0d86e7c0f634d6b3f18e2a48b1629ff01b00c21f098d4f6d960c9f91c82534a4.
Normal270 remains a pass; new SDK/runtime and complete263 remain unrun.

Native maintenance-bank13 and selected-query handoff6 are not applied. The
former preserves originalrestore64MiB/32 and ordinary denied grants2–8, quoting
one original grant for eight distinct real native owners;3 new native disposal
witnesses still need runtime. The latter retains original input/output grant
and failure tails, but finite review found a moved !Unpin drain guard after
unsafe polling; a stable pinned-stack correction is required before application.
Its actual Database cancellation anchor remains open. All C01–C07/M01–M07
remain open; source promotion and final release/workload gates are pending.


### 2026-10-06 corrected First test bindings and exact consumer rerun (actual273–274 pending)

Exact cfg/test-only successor05d4246e/patch321e3f39 applies273: five images,
full4,126, all4,121 other inputs/native26/484 unchanged. Root verifies physical
bytes/modes and private reverse/forward replay. The actual held StageCredit,
paired SourceRoots/existing Standing and original drain are exposed only to
fixtures; all production bytes and original assertions/caps remain unchanged.
The new SDK witness drops its own observation alias before actual shutdown.
Finite peer23931c11/reportf782b424 independently verifies the same source,
complete original test prefixes and exact helper H29.

Root verifies all177 immutable H29 artifacts and43 peer artifacts. Its literal
263-case roster and qualification helper preserve the original261 selections
and two actual First witnesses; immutable check passes with Cargo0. Actual274
is running on this same source with3,539 outer Rust/config pins. No runtime
pass, final-source promotion, full residency or serving claim is made yet.
The corrected native Bank13/query handoff union remains source-only.
C01–C07/M01–M07 remain open.


### 2026-10-06 actual First fixture provider correction (actual274–277 pending)

Actual274 FAILED49.14s/all3,539 unchanged: one E0432 remained in the new
Effects witness before any test ran. The author/finite reviewer had resolved
LocalKeyProvider to Engine test_utils incorrectly; its actual existing owner is
Store test_utils. This compiler finding supersedes that narrow source claim.
Guard275 preserves complete4,126/H29/rawlist in4,384 verifiedmembers/modes,
SHA7c34e5b233c7ca219c78a125d04cfdc7c860f3552b667a88a679d4a443d4d170.

One cfgtest import successor61375fcf/patch ef71f1fa applies276; inverse token
replacement recovers the entire prior file and all4,125 other leaves are exact.
No input, assertion, configured bound or production byte changes. Literal
H30 helper2a4ebdf3/roster6208be05 retains all263 selections and updates only
source provenance and the additive witness body. Immutable Cargo0 PASS.
Actual277 is running in a fresh directory; runtime results remain pending.
Bank13 and the corrected stable-pinned/original-quote query handoff have finite
peer reviews, but their executable union/runtime and actual public Database
cleanup anchor remain pending. C01–C07/M01–M07 remain open.


### 2026-10-06 real SDK First publication/shutdown pass and fixture setup correction (actual277–281 pending)

Actual277 Engine84 reaches runtime:83PASS/1FAIL in49.43s, outer130.06s, all3,539
source/config pins unchanged. The genuine SDK verified baseline/same metadata/
Standing/shutdown witness passes, as do all82 original Engine selections.
The one failure is new Effects setup before Node construction: defaultNone was
passed to isolated_disk_admission_config, whose explicit payload precondition
is incompatible. Types4/backend8/Query167 are unrun in this failed roster.
Guard278 preserves complete4,126/H30/rawlist/run in4,384 verifiedmembers/modes,
SHA4dfa27ba916748d6fe9b50f267743544de53c6bfad53d0ae201aa15653797215.

Exact cfgtest successor78d4ce37/patch30c89f6b applies280: only that setup now
uses AdmissionConfig::default() directly under the same fixed1GiB capacity and
resident0. This is the same normal resolved128MiB total, including all owners
and bookkeeping, with no separate payload/metadata allowance added. Every
assertion/input/native-cache setting/thread/slot limit and other source byte
is unchanged. H31 cbd93a52 keeps the entire helper2a4ebdf3 and literal263
selection objects; rosterffb7f973 refreshes one additive body/provenance.
Immutable Cargo0 PASS; actual281 full263 is running. Its corrected Effects
witness has passed in the ongoing Engine run; no full terminal claim yet.
C01–C07/M01–M07 remain open.


### 2026-10-06 qualified complete First consumer roster (actual281 / guard282)

Actual281 PASS145.41s/all3,539 unchanged and full4,126 before/after: all263
selected original/additive invocations pass, with0FAIL/0IGNORE. Totals are
Engine84, Types4, backend8, Query158lib+4output+1textallocation+4 ownership
compile-fail docs. Runtime Engine45.90s. Root verifies exact terminal identities,
all package totals and14 actual list/run calls; terminal SHA38095ec38a61b19f3b
2e40bb9f99fe2599952860f2929264588b4961d0542c9c. Both real SDK durable
four-role receipt/same unique metadata/Standing/shutdown and distinct native
four-buffer/same original4 ledger slots witnesses pass under current78d4.

Guard282 preserves complete4,126/H31/all raw list/run captures and actual command
helpers in4,420 verified archive members/modes, SHA41daa6871f08107ac062dde4a7e
437c82d70141f81eb3c1a5a74b3e891226566. Earlier failed guards remain immutable.
This qualifies the narrow empty collection with known simple schema; it does
not activate general mutations, public selected serving, preacceptance funding,
automatic complete refill, allocator union or deployment-scale full residency.
C01–C07/M01–M07 remain open.


### 2026-10-06 joined maintenance-bank and query handoff compilation (actual283–285 pending)

Literal reviewed union19 e435b2e6/patch1dd03d00 applies283 on exact qualified
actual28078d4: full4,128/new2/4,109 exact dependencies/native26/484 unchanged.
All13 native bank and6 Query afterimages are identical to their reviewed
components; no semantic merge. Root verifies bytes/modes/aux and actual private
reverse/forward. Independent union peer0712f606/report936de329 verifies167
complete old bodies and10 actual additions, real pin/quote ownership and strict
helper source/AST/flags. Root verifies all72 peer artifacts and reads its report.

Actual284 normalEngine PASS26.75s/all3,541/full4,128 before/after. Root verifies
all15 final helper4 artifacts/MF9254bbb6/helper82c4a986 and immutable Cargo0 PASS.
Actual285 is running exact original17 +7 Query handoff Engine cases and native
Bank3 +five original constructor grant2–8 denial cases. The restore fixture
retains64MiB/32, genuine distinct native buffers and all old assertions.
No public Database cancellation anchor, general publication, default cache
accounting or full-fit gate closes. C01–C07/M01–M07 remain open.


### 2026-10-06 restore constructor remains open; native bank qualified (actual285–287)

Actual285 fails in139.80s with all3,541 source/config pins unchanged. The exact
24-case Engine roster reaches runtime:23PASS/1FAIL in22.11s. All seven new
query handoff cases and sixteen other original cases pass. The original restore
case still fails before its validation assertion at64MiB/32 live reservations,
with the same28,936-byte request (33,056 charged) and32 live reservations.
The scalar bank does not reach snapshot receipt Builder → EncryptedTable::new
→ ScratchTable initialization/ordinary publication. This is an implementation
failure; no original cap, handle lifetime or assertion is relaxed.

Guard286 preserves the full4,128-source failed cohort, helpers and raw captures
in4,325 verified archive members/modes. SHAffd2e0b2697838b4f3957fb666f48339
b5181c92cb2e343454cbdbcd1f570656. The earlier qualified First guard282 remains
recoverable independently.

Actual287 separately qualifies all eight native cases on the unchanged source:
PASS16.31s/all3,541, Bank3 plus five literal original grant2–8 denial cases,
8PASS/0FAIL/0IGNORE. Root verifies the terminal's exact identities, totals,
full4,128 provenance and two list/run calls. The private query kernel and native
bank prerequisites now have runtime evidence; public Database cleanup, generic
restore construction, ordinary publication and full residency remain open.
C01–C07/M01–M07 remain open.


### 2026-10-06 status detail retained during execution-goal refinement

The following historical/scoped status text is retained as evidence. The concise
goal summary supersedes its ordering; none of these component passes closes a
production acceptance criterion.

## Current production status

**C01–C07 and M01–M07 remain open.** Production still serves documents and
structured/text indexes from resident structures. The reviewed implementation
is being integrated in an isolated source cohort; it has not been promoted to
the live checkout. Component passes do not establish a process memory bound or
activate disk serving.

The original startup/catalog prerequisite passes all 223 selected cases,
including funded genesis, revision0 and the exact durable bootstrap image.
The isolated integration now has 4,128 pinned source inputs. Its native KV
foundation passes the complete 677-case library; the focused cache
selection passes all 101 cases. Earlier aggregate Engine qualification passes
all 69 selected cases, including borrowing across encrypted stores and
rewarming after shrink/growth. Original memory caps and assertions remain.

The combined Japanese cleanup and schema fixture corrections are reviewed and
applied to the isolated source. The normal Engine build passes. Engine69,
Types4 and backend8 pass on unchanged production bytes; corrected Query225
passes all 167 selected cases. Native schema223 passes all 2,529 case
invocations across its original profiles and ownership doc test. The original
allocation suite passes both required feature profiles. The complete original
Tantivy library and documentation suites also pass,
preserving their original ignored cases. Lindera’s complete original and selected library, dictionary-builder and
documentation suites pass with all original statuses, features and limits.
The persistent collection library also passes complete original and selected
library/documentation suites in its default, Serde and all-features profiles;
its standalone dependency graph does not substitute for SDK qualification.

Earlier failures remain in recoverable full-source checkpoints and raw logs:
an uncounted zero-target eviction, a retained 4,108-byte Japanese transient
debit, a non-Send test panic ledger, missing upstream tokenizer fixtures, and
an ordinary analyzer still alive at a fixture's final ownership assertion.
Corrections preserve original inputs, limits and assertions. These scoped
passes do not establish production activation or the final process memory bound.

The canonical first-collection SDK producer is applied to the isolated source.
Its normal build and the genuine SDK first-collection creation case pass.
The complete 261-case roster passes on the corrected isolated source:
Engine82, Types4, backend8 and Query167. The earlier 76-pass/six-failure Engine
run remains archived. Four reviewed fixture images correct those failures. Two terminal
checks measure resident bytes separately from live governor bookkeeping and
also require the exact bookkeeping and grant-retirement totals. Cooperative
setup lets real key-renewal tasks run between the original bounded steps. These
corrections preserve configured bounds, lease lifetimes, expiry checks and
runtime worker counts. The actual finite source/refill worker now compiles in
the normal Engine build; automatic refill and production disk serving are
still awaiting the committed baseline. Its
admission occurs after local Raft acceptance, before cloning the candidate.
Preacceptance admission, ordinary mutation publication, selected document/index
serving, full allocation census and finite automatic refill remain open.

The selected primary-query worker also compiles in the normal Engine build and
uses the existing query reservation, cancellation and five-second deadline.
Its five actual source cases and eleven other original cases pass in the
focused 17-case run. One restore-validation case fails at its test provider's
32-live-reservation limit before reaching the intended validation assertion.
That run and its complete source are preserved; the reservation lifetime still
needs runtime qualification. A native maintenance bank now funds its eight
distinct buffers through one original grant, while preserving the original
constructor denial cases. The bank and corrected pinned query handoff compile in the normal Engine
build. The 24-case Engine run passes 23 cases, including all seven new handoff
cases, but restore still reaches the original 32-reservation limit. The banked
scalar path does not cover the generic receipt-table constructor used by
restore. Its actual constructor and publication workspace must be repaired.
The separate eight-case native run passes under the unchanged limits, including
all five original constructor denial cases. The public query handoff must retain rejected
plans and original native failure reports through positive cleanup before
cutover.

The real prepaid encrypted-point constructors compile in normal Store and pass
all 23 selected cases: 18 original encrypted-read and constructor-custody
scenarios plus five new prepaid failure/retirement cases. The closed Engine
publisher must still prove those same loans through its actual committed
baseline and Standing owner. This component result does not establish full
residency or production disk serving.

The complete empty first-collection baseline now joins verified disk
publication, captured metadata and the existing standing owner under the same
original fixed budget. Its normal Engine build passes. The first test build
exposed fixture binding errors; recoverable failed sources remain preserved.
The real SDK publication/shutdown witness and all 82 original Engine consumers
now pass. The additive four-buffer effects witness's setup used an incompatible
fixture planner; it now uses the normal default under the same fixed capacity,
without an additional allowance. The complete 263-case roster (the original
261 plus two real SDK/native witnesses) now passes on that corrected source:
Engine84, Types4, backend8 and Query167, including four ownership compile-fail
documentation checks.
This corridor covers an empty collection with
a known simple schema; general mutations and index/schema producers remain
open.

### 2026-10-06 exact restore allocation trace and ordinary publication bank (actual288–296 pending)

Actual288 applies one opt-in test-utils denial-stack observer, fe748e08/full4,128,
without changing any grant, input, cap or assertion. Actual289 repeats the exact
original restore case: FAILED79.70s/all3,541; runtime2.82s. The actual call stack
corrects the earlier inferred allocation label: the28,936-byte request is
SnapshotPins::capture inside prepare_reusable_cache_publication, reached by
ordinary native commit during generic EncryptedTable initialization. It is not
the scalar MaintenanceLeaf warming directory constructor. Guard290 preserves
the full4,128 failed source/raw trace in4,286 verified members/modes,
SHA8514573c374ee4af8468f61c5e8e3094ca4d547df7e0a77b558f9e210886c3cf.

Root Bank11 prospectively sums the five real values/replay/directory/capture/
proof requests plus concrete native bank Arc, loan Boxes and construction
shells before allocation. The actual Direct ScratchTable selects this ownership
mode before its original setup; the same durable commit/proof/rollback body
runs. Ordinary native constructors and old denial cases stay available and
unchanged. The original64MiB/32 restore cap and old handles are preserved.

Actual291 applies31061fbd/full4,129 with private reverse/forward verified.
Actual292 fails12.14s/all3,542 at KV libtest with missing original writer-gate
lease binding and sibling Core visibility (E0425/E0624), before runtime.
Guard293 preserves complete4,129/raw/helper in4,307 verified members/modes,
SHAb9d0a03d66d47c70ac678f25ac6ae95b94393c01314fa73781dd9aab2fbf572c.
Bindings2 successor937e1be1/patch8a9028ae applies294: restore the original
writer-gate binding and actual sibling visibility only.

Actual295 native11 PASS16.65s/all3,542. All three new actual System allocation/
five distinct backing/returned-and-raw partial/refusal witnesses, Bank3 and
five unchanged original grant2–8 denial cases pass,11PASS/0FAIL/0IGNORE. Root
verifies all exact identities, totals and both list/run calls. Actual296 runs
Engine26: original17, Query handoff7 and both real First SDK/native witnesses,
including the unchanged restore case. Its result is pending. No cache milestone
closes. C01–C07/M01–M07 remain open.

### 2026-10-06 publication repair advances restore to its next actual read owner (actual296–299)

Actual296 Engine26 FAILED191.44s/all3,542/full4,129 unchanged. Runtime37.11s:
25PASS/1FAIL, including both real First SDK/native witnesses, all Query7 and
sixteen other original cases. Restore passes the earlier namespace publication
then fails a20,728-byte request (24,848 charged) at32 live reservations during
the actual receipt read. Guard297 preserves complete4,129/raw/helper in4,296
verified members/modes, SHA66e0be25a915d7baf545a32abaee46b295530aa67a6bac
14fcbe7f67a76751d4. The unchanged64MiB/32 cap/old handles/assertions remain.

Actual298 repeats the exact original1 with the existing opt-in trace only:
FAILED5.79s/all3,542, runtime3.07s. Exact native stack is Builder.push →
EncryptedTable.get → ReadTransaction.open_table → Snapshot.table_exists →
DirectoryReader.get → PageBuffer::new. Supplement299 preserves this raw trace
and helpers against the exact full-source guard297. A passing publication bank
does not close read ownership. Root is consolidating the genuine persistent
constructor controls; no early snapshot drop, cache disable or larger slot
limit is used.

Independent Bank11/bindings2 peer f94bbdb8/report4032cb0b is finite source PASS:
full physical parents, both Git inverses,13 parses,77 literal old functions and
three real native additions, exact five component/control/Box quote and field
retirement, unchanged durable effect tail. Root verifies both peer artifacts
and reads the report. Runtime confirms the finite native witnesses but not
complete restore. Generic opaque provider tails remain separately open.

Aggregate-budget carrier d32706f2 remains frozen: root finds that ordinary
Operation→Resident retain erased still-live refill workspace. Exact successor
6b60054f keeps the remaining component conservative, releasing only actual
byte shrink while preserving the operation slot transition. Its new witness
keeps the same32KiB cap and requires the previous28KiB request to refuse;
proven optional native cache retention remains separate. Helper2a191f241 has
exact Engine54/KV155 source selections and immutable Cargo0 verification.
Neither budget carrier is applied or runtime-qualified yet.
C01–C07/M01–M07 remain open.

### 2026-10-06 genuine receipt constructor ownership (actual300–305; qualification pending)

Root freezes ControlBank8 (683d684f/patch63f6a026) over exact937e1be1.
The genuine generic encrypted ScratchTable constructor funds the same original
Shared, DiskState, RootOwner, DirectoryArena and SnapshotPins requests with one
installed grant before their native allocations. Exact BankArc, concrete loan
Boxes and backend Arc are also quoted. Private Shared aliases retire their Arc
control before payload funding; failed opening retains paired backend custody.
The original64MiB/32-slot restore inputs, held snapshots and assertions stay
unchanged. Disk format and original constructor/effect branches remain exact.

Actual300 applies full4,130 after independent private inverse/forward. The
initial outer helper rejected an unsupported `store` scope before Cargo; the
normal Engine scope is used thereafter. Actual301 normal Store check fails
9.12s/all3,543 at four E0308 bindings: three real source/publication/u64 owners
still used raw Shared Arc. Guard302 preserves complete4,130/raw/author/apply
in4,159 verified members/modes, SHAbc3eece4de100ac4393bfe47f270362e0565917f66
b543802e965a003ae788a6. No failed source is overwritten without preservation.

Bindings3 (33efebe7/patch16608bb8) replaces precisely those three private
fields with the same closed SharedRef. Actual303 applies with complete physical
inverse/forward; actual304 normal Store check PASS22.25s/all3,543 unchanged.
Actual305 strict original Engine26 is in progress; no runtime pass is claimed.

Independent peer6c4d4788/report224771e4 verifies full4,130, original source
inverses,11 parses,62 old literal functions, original fixed-request expression,
all native inventories and complete Shared alias census. It identifies a generic
backend destructor tail: automatic Loan field drop can release funding while a
last opaque destructor panics. Disposal successor37269f4b/patcha38501ea manually
retains that loan until raw Arc destruction returns and adds three real System
allocation/refusal/partial-constructor/escaped-registry witnesses. It remains
source-only, unapplied and unqualified pending the current Engine run.

Canonical document prerequisite76af1d90/one-field correctionf8d5c965 and native
audit Single COW49424101 are source-only. Ordinary paid publication, public
query/cancellation/error custody, preacceptance, complete residency census and
final workload/release gates remain open. C01–C07/M01–M07 remain open.

### 2026-10-06 original restore reaches its intended assertion (actual305–308)

Actual305 strict Engine26 PASS216.74s/all3,543 unchanged/full4,130. All26
literal selected identities pass,0FAIL/0IGNORE and exactly two list/run Cargo
calls. The original restored_identity_metadata_is_validated_before_bootstrap_
persistence now reaches its intended validation assertion at unchanged64MiB/
32-live slots with old handles held. Root independently verifies roster/totals/
source and terminalSHAc2e9e5ce2614cc7574c6a7b6f919ff88e85c368141100dad76a2faf
1926505e8. This closes this concrete restore refusal, not production activation.

Actual306 applies disposal37269f4b (backend manual alias and native3); actual307
applies0914a3e6/patchb611eb91: final SharedRef manually retains a same-bank alias
through the complete real Shared/DiskState/backend payload, releasing only after
all original destructors return. An opaque last backend destructor can occur in
DiskState after CoreBackend itself has retired, so protecting only that wrapper
was insufficient. Both real inline alias layouts/allowances join the prospective
original quote; caps/handles/effects/test bodies remain unchanged. Actual308
strict native14 (old8, publication3, constructor3) is in progress. No pass is
claimed before exact runtime totals. C01–C07/M01–M07 remain open.

### 2026-10-06 preserve original native constructor interface (actual308–311)

Actual308 strict native14 fails7.46s/all3,543 before runtime: the unchanged
CoreDiskBox original test calls its original six-argument private assemble
entrance, while the new bank had replaced it with seven arguments/new owner
type. Guard309 preserves complete4,130/raw/helpers in4,149 verified members/
modes, SHAa4416d3ea337135c4fff4a4190bf995ac0d84006a2b15d79c2f0522269a18eab.
Successor19621df7/patch ec562c16 restores the exact original entrance and four
ordinary API call bodies, forwarding to the one owned native assembly body;
no old test changes, format fallback or second writer. Actual310 applies1/full
4,130 with actual inverse/forward. Actual311 strict original8+publication3+
constructor3 is in progress. C01–C07/M01–M07 remain open.

### 2026-10-06 scope the constructor observer to original error transport (actual311–317)

Actual311 native14 fails12.31s/all3,543/runtime13PASS1FAIL: all original8,
publication3, constructor positive controls/escaped registry and original
refusal pass. The new every-check witness incorrectly expected only direct
CoreError::OwnerFailed at ordinal5; CheckedGroup intentionally carries the
same source in KindOther Io. Guard312 preserves full4,130/raw/helpers in4,146
members/modes, SHA9f6fd6a9d71ecc57c4c9a9b102b72aec7793b4a15b1cd56095dcd50a
165faab2. Scoped successor3ae67a05/patch e2e7d358 keeps every original ordinal,
raw-pointer/refund/allocation assertion and all original production/tests.
It explicitly checks the exact IO OwnerFailed source/Other kind and ends the
finite constructor backing census at the original returned failure callback,
as the existing observer already does for original raw payloads. Opaque native
IO diagnostic heap, transfer credit and final-provider custody stay open;
this is not a generic error allocation proof.

Actual313 applies1/full4,130. Actual314 fails7.74s/all3,543/runtime13PASS1FAIL:
the new case reaches ordinal28, where original Root::publish returns
UnknownCommit after entering successor writes. Guard315 preserves complete
4,130/raw/helpers in4,147 verified members/modes, SHAdbf4dc906cd6de9929e76a9e
554c203104b1ff9394aebda255ad82242f49b518. Successor c1aacb1f/patch54772b20
preserves that actual original uncertainty route, still requiring exact
OwnerFailed source/Other kind; no arbitrary error is accepted. Actual316
applies the one new-test arm only; production/old tests/caps/handles remain
literal. Actual317 strict native14 is in progress.

Root verifies finite peers244c4330/report55709707 and1b3fc8da/report844f4fc9,
including physical artifacts and scoped final-tail/error-boundary findings.
A full real Core final opaque backend-destructor probe is frozen source-only;
it requires the same grant to stay charged and exact preallocated raw payload
to remain identifiable after that uncertain tail. Public Database cancellation
registration correction eb7b4123/strict38, canonical document joint bbe5e749,
and aggregate policy/retention join remain source-only/unactivated. All C/M
goals remain open.

### 2026-10-06 all finite constructor witnesses pass (actual317–321)

Actual317 native14 fails4.80s/all3,543/runtime13PASS1FAIL: the new raw sweep
reaches owner-check12, inside original backend namespace-lock custody. Its
wrong clean-close assumption misses actual CoreOpenFailure retaining original
Panicked and the poisoned backend's entered/retained close. Guard318 preserves
full4,130/raw/helpers in4,146 verified members/modes, SHAf3a516689bdc7c981be562
67abb60d20b2fba51a1546335f8659a3f7d59e45ac. Retained-negative source8 stays
source-only; inspection replaces its private field access with a canonical
borrowed original-close result getter in preferred sibling9.

Actual319 applies63f89825/patch17274cd3 (2images/full4,130). Its new retained
branch requires exact original raw pointer, entered/retained/Other close,
one same original bank quote still charged, no refund/no token deallocation
before and after discarded report, and actual execution of this negative
branch. All other ordinals and positive allocation/disposal/refusal assertions
remain; all production native effects and original test functions stay exact.
Opaque IO diagnostic allocation/transfer and final-provider tails remain open.

Actual320 native14 PASS7.77s/all3,543/full4,130 unchanged: original8,
publication3 and constructor3 all pass,0FAIL/0IGNORE,exact two list/run calls.
Root verifies exact identities/totals/MF and terminalSHA16913e8de11f1bd827bfa48
d4617e8dddddede744e3487b597c2d010e1d3a591. The constructor's positive actual
System allocation/control/escaped-registry/refusal and every returned/raw
callback case now has finite runtime evidence; the negative original unproved
native owner stays charged. This does not close generic diagnostics or any C/M
goal. Actual321 reruns unchanged original18 plus prepaid5 Store consumers on
this same physical source; result pending.

Full real Core final backend-destructor source probe929d7856 and policy/helper
e9902e27/b48de5a9 are source-only. Before Cargo, root finds probe's trait impl
missing five mandatory native publication methods; source correction with the
actual native delegates is pending. The finite Git/parse peers do not establish
Rust trait type correctness. Canonical document/public query/accepted capacity/
large residency and final workload/release gates remain open.

### 2026-10-06 encrypted consumers preserved and complete backend probe compiled (actual321–326)

Actual321 Store23 PASS32.18s/all3,543/full4,130 unchanged. All18 original plus5
prepaid cases pass,0FAIL/0IGNORE/exact two list/run calls. Root verifies full
source identity/roster/totals and terminalSHA8f49fe7c68db1f578020ce93d354f5157
5b6f0ab95b741227aeb0667cf8dc87e. No complete full-fit/public-cutover claim.

Before actual probe activation, source inspection corrects its five missing
required publication methods with same original native delegates. Actual322
applies9d6c56ee/full4,131; actual323 native15 fails3.51s/all3,544 before runtime:
18E0433 from an absent std::io import in the new nested probe module. Guard324
preserves complete4,131/raw/helper in4,150 verified members/modes, SHA54f4bbc7
2c346a75345e10186217a833eb599951c1ddd0112087ec3db6c80399. Literal one-import
successor1f6a38fd/patch1bc8c6ff keeps all22 actual trait delegates, the original
full-Core raw-pointer/no-refund witness and all old tests/production bytes.
Actual325 applies1/full4,131 with actual inverse/forward. Actual326 strict
native15 is in progress. Policy and canonical document/public query joins,
actual preacceptance, materialized allocation union, finite all-role refill
and final5 workloads/release gates remain open; all C/M goals remain open.

### 2026-10-06 complete Core negative tail passes; namespace failure retained (actual326–328)

Actual326 listed successfully but the helper expected the new test under the
wrong module name; it exited1 before any runtime run,7.32s/all3,544/full4,131.
Guard327 preserves complete source/carrier/helper and raw outer result in
4,147 verified members/modes, SHA6e60d55b7d2fd50b4910a0e46b87df094c8ed551f
400e4a608a0bfff2847c7b4. Successor helper328 corrects only the literal module
identity to control_drop_tests, preserving all15 expected cases and flags.
No source correction or assertion/cap change occurs between326 and328.

Actual328 native15 PASS1.69s/all3,544/full4,131 unchanged: original8,
publication3, constructor3 and the complete Core final opaque backend-drop
negative case all pass,0FAIL/0IGNORE/exact two list/run calls. Root independently
verifies every actual list/result identity and totals, sourceMF1f6a38fd and
terminalSHA2e6cf8627e2e72d0142f3a4032e6bd8156598a138c143bdbd6430450ad758ff4.
The last case requires the same original grant/no refund and exact original
preallocated raw payload across the actual Shared/Disk/backend teardown.
Generic diagnostic heap/transfer and final-provider positive retirement remain
open. Policy7 is the next physical join; Document44/VersionMap/public query,
preacceptance, all-role finite refill, materialized allocation union, final
five workloads and release gates remain open. No C/M goal closes.

Complete raw-log supplement: source-checkpoints/native-failed-runtime-supplement-v331/complete-native-failed-runtime.tar.gz, SHAffbc0f906d7878b17358cdcca8a918679c7740974dd81774345434295703cca2, 35 verified leaves/modes. This supplements the immutable full-source guards309/312/315/318/324/327 with all preserved complete native14 attempts1–4 and native15 attempts1–2 stdout/stderr/command leaves and native helpers; original source failures remain recorded. No source mutation or goal closure.

### 2026-10-06 aggregate budget physical join and next caller checkpoint (actual329–331)

Root independently verifies all policy7 source/auxiliary hashes/modes and exact
parent1f6a38fd. Actual329 applies8423776f/patch8a7cd82a,14images/full4,132 with
private and actual Git inverses/forwards; command exits0. Outer source-monitor
reports expected changed13 existing files (the14th is the new policy tests),
so this mutation envelope exits1 as designed; it is not a runtime test failure.
The default total now follows validated low-water capacity, with a separate
bounded aggregate workspace component. Explicit totals remain exact. Ordinary
retention/handoff keeps all unproved live workspace charged; only actual byte
shrink or disposal releases it. Actual330 strict Engine54/KV155 is running.

The complete failed native raw-log supplement331 is preserved separately.
Canonical Document44+VersionMap preferred compiler carrier355965a4/full4,137
is source-only; root verifies all carrier leaves/modes and private Git inverse.
Normal compiler feedback and original consumer qualification remain required;
no paid Generation, ordinary mutation, public-query activation, materialized
allocation union or full-fit claim is made. All C01–C07/M01–M07 remain open.

### 2026-10-06 intentional default policy test migration, complete failure guard and VersionMap join (actual330–335)

Actual330 exits101 after594.54s/all3,545/full4,132 unchanged. Engine54 has
53PASS/1FAIL/0IGNORE; the sole failure is the original None-default expectation
of256MiB total on fixed2GiB host, versus the required new896MiB low-water total.
All six new workspace cases and original16,513-row/128-slot native cache case
pass; the latter preserves two zero-fetch scans, original64MiB cache and exact
cardinality/reservation/warm-up assertions. KV155 is not executed after the
Engine failure. This does not count as a209-case pass.

Guard332 preserves complete4,132 source, original carrier, all helper artifacts
and complete list/run stdout/stderr/command data in4,214 verified archive
members/modes, SHAacc2908b1b204f289a15408e8f48da9244c2fe4456d0735ac56da6331
ed745fe. The old failing expectation and production source remain recoverable.

Root and finite peer verify70800a4d/patchdede1b2e default-fixture8: sole cfgtest
change derives None total from existing validated1GiB*7/8, and adds exact old
workspace256MiB assertion. Original2GiB host, explicit16MiB total/workspace,
headroom4MiB/4 and64MiB/64, reserve/refund and all other original assertions
stay exact. This intentional default-contract migration is distinct from
raising an explicitly configured cap or weakening a negative test. Actual333
applies1/full4,132; production code is byte unchanged from330. Strict209helper9
preserves all names/flags/parser and honestly changes this one body hash.

Actual335 applies VersionMap3 e8faedfc/unchanged23patchbf5015b2/full4,133, with
all immutable leaves/modes/private and actual Git inverses/forwards verified.
Receipt version paths use canonical sortedVec with bounded256-row paid-builder
layout and allocation-free insertion; ordinary conversions preserve wire
ordering/duplicate behavior but confer no paid provenance. Seven affected
normal targets and Types2 runtime qualification remain required. Canonical
Document44 early compiler joins next; peer inspection identifies an archived
Arc identity helper mismatch before activation, and its narrow source-only
correction is pending. Production/public query/preacceptance/all-role refill/
materialized union/final workloads and release gates remain open. No C/M closes.

### 2026-10-06 canonical document compiler feedback preserved (actual336–341)

Actual336 applies corrected Doc44 abc72017/patch6e1b5076/full4,137 with exact
current VersionMap3/default8 parent, complete immutable source/modes and actual
Git inverse/forward. It restores original archived Arc identity before Cargo.
Actual337 normalEngine fails4.57s/all3,550 unchanged: native imbl's crate-level
unsafe-code deny rejects two new manually controlled retirement blocks. Guard338
preserves full4,137/source/helper/complete raw compiler streams in4,263 verified
members/modes, SHA0291b422572060a4d612781365362f072083cfd0d86e0aa74a993715
ba0bb689. No runtime/paid Generation/SDK mutation claim.

Actual339 applies3cea7eb1/patch1d854a2a,three images/full4,137: function-scoped
unsafe allowances and explicit once-only ownership safety comments preserve the
same native payload-before-loan expressions; crate-wide deny stays exact.
The original qualified server Arc path is restored inside its canonical wrapper;
only the genuinely changed imbl inventory row is updated. Finite independent
Doc peer6334cf4c/report701993c5 verifies whole current source/inverses/merges and
closed null/bool unsplit-leaf/Weak custody; runtime remains root.

Actual340 normalEngine fails40.17s/all3,550/full4,137 unchanged: oneE0599,
DocumentMap lacks the original range::<_,str> used by document_source.rs124.
Native imbl and Types now compile through their owning boundary, but Engine
normal compilation is not yet successful. Guard341 is preserving full source,
current helper and complete raw streams before the range correction. Next is
an allocation-free borrowed range adapter with original bounds/reverse behavior,
then normal affected callers, Types/Engine/native document owner cases and
original server JSON. All C/M gates remain open; no production activation.

### 2026-10-06 normal Engine join passes; new range test compile boundary retained (actual341–345)

Guard341 completes full4,137/helper/complete compiler raw in4,167 verified
members/modes, SHA15e30abcf3ea2979526ff5e75955f5a2f15712445365ef5d2bc2a61d
f50f4536. Actual342 applies2aa13847/patch0c8dd055,4images/full4,137 with genuine
native inventory, original GenericOrdMap range<R,Q>/Comparable borrowing,
Legacy RangedIter and allocation-free paid row-slice bounds. Old consumers and
assertions remain; two new range parity scenarios cover441 Unicode bound pairs,
forward/reverse/alternating/empty/inverted/equal/excluded/clone-cursor semantics.

Actual343 normalEngine PASS35.03s/all3,550/full4,137 unchanged, exactly one
original fenced normal --lib/default check. Root independently verifies command,
manifest/full count and terminalSHA6bca7b4b816a15961cdf1e9b10f8f6f6e5e2211d
30741d0b2bca8274c8ae7dad. Native/Types/query/Engine compile together;817 existing
Engine warnings mean the release lint gate remains open. This is not a paid
Generation, SDK ordinary mutation or full-residency activation.

Actual344 Owner10 fails9.71s/all3,550/full4,137 unchanged at Types libtest list,
before any runtime: three errors only in one new range test. Custom Key needs
Comparable's actual Equivalent<String> supertrait, and its local cmp::Ordering
shadows the atomic SeqCst assertion. Guard345 is preserving complete source,
helper and all raw streams before correction. Keep the custom comparator and
all original/new boundary/assertion geometry; fix the owning trait reexport,
borrowed equivalence impl and fully qualified atomic ordering. Seven affected
normal callers, owner10, native3 profiles and original server JSON still need
qualification. Corrected query Anchor20/strict41 is source-only on this real
current Doc/budget/VersionMap parent; public serving/transport remain uncut.
All C01–C07/M01–M07 remain open.

### 2026-10-06 custom range fixture inference preserved (actual345–348)

Guard345 completes full4,137/helper/complete raw in4,172 verified members/modes,
SHAba61f77864e98c802152cb3c8afbdf0b334ba0d19c44e91a086dd664544c4435.
Actual346 applies fixture13 b7ccb9c3/patchde30d49a,three images/full4,137:
actual Equivalent reexport, exact borrowed Key equivalence, and fully qualified
atomic ordering. Production range algorithm, bounds and assertions are unchanged.

Actual347 Owner10 fails8.80s/all3,550/full4,137 unchanged in its first Types
libtest list, before runtime. TwoE0283 identify the new custom-comparator call's
ambiguous RangeBounds key type. The next correction specifies that borrowed Key
type; it changes no range semantics or limits. Guard348 preserves complete source,
helper and all compiler streams in4,171 verified members/modes,
SHA2f6ae432859d60e79a52ea1cd05a4b00a53034fd82687a1e913092b6988ca227.
Normal Engine343 remains a scoped compiler pass; Owner10 and the affected caller
gates remain open. No production activation or C/M completion is claimed.

### 2026-10-06 document owners/callers pass; owning native target remains open (actual349–355)

Actual349 applies fixture14 96d09b91/patchbe3a2edd,2images/full4,137: solely
the new custom-comparator test specifies its borrowed Key type; native inventory
and production algorithm remain literal. Actual350 Owner10 PASS174.95s/all3,550
unchanged: Types6/Engine2/privacy2,6 list/run calls,10PASS/0FAIL/0IGNORE. Root
verifies terminalSHAa613ac7f066f7a6b710281bddd31f344b2b1b39cc432bc2558113653d22d606d.
Actual351 normal7/VersionMap2 PASS492.16s/all3,550/full4,137 unchanged: all seven
affected real normal targets, including capacity bin's required network feature,
plus exact Types2 list/run;9calls. TerminalSHA9e1c0a486c5a2e82502afe1bb933ade63b1b9cd6f24fdaef39b588b47d57f13c.
These qualify the narrow constructors/interfaces, not paid ordinary publication.

Actual352 native3 profiles/server1 fails1.22s/all3,550 unchanged before any
native/server runtime: imbl is excluded from the workspace, so Cargo refuses
its dev-dependency tests through -p. No actual484 owning-native pass occurred.
Guard353 preserves full4,137/helper/complete raw in4,170 verified members/modes,
SHAdb7bccb79a1d29f8f833635659efc44b6b2cb709899090b8d5b13f8de14bb310.
The correction must use genuine native workspace membership and explicitly
resolve/pin its changed lock graph; private Node/NODE_SIZE cases cannot be
replaced by consumer copies or the standalone132 graph.

Actual354 applies Anchor20 currentv4 071eae83/unchanged patch83b2358d on exact
fixture14,20images/9new/full4,146 with genuine actual Git inverse/forward and
whole source/modes. Actual355 strict41 H8 is running; no runtime pass yet.
Canonical Result/page ownership with retired-only operation-count release,
marker6, borrowed joint39 and the root encoded-Document6 constructor are
source-only successors under review. Encoded construction uses actual selected
native layout families and a preinstalled original owner, with no Value adoption;
its preserve_order thread-runtime and non-AP numeric profiles remain explicitly
unsupported until their constructive owners exist. Production dispatch/all-role
publication/full-residency and final release gates remain open. No C/M closes.


### 2026-10-06 query compiler corrections and encoded-document review (actual355–359)

Actual355 strict41 failed42.41s in the first Engine library compilation, before
runtime, with two interface errors: an unqualified QueryResponse and a child
wait observer whose visibility did not reach its parent. All3,559 tracked
source/config leaves and all4,146 carrier leaves stayed unchanged. Guard356
preserves complete source/helper/raw output in4,223 verified members/modes,
archiveSHA848fe1a820e47f5e5672a437368e8f53d030666480604ea867072f68bf400785.

Actual357 applies the exact two-file interface correction2105e8335e06dd7d9a11e144dfc8e03a1ced8479f74bdc2c296d8f6b3e503078;
private inverse/forward and all4,146 source leaves/modes are verified. Actual358
strict41 then fails149.19s at the first Engine libtest list, before runtime:
two include-file inner comments are invalid there, and a test helper attempts
a forbidden anyhow conversion of the closed ReadFailure. The normal library
compiled. Guard359 preserves complete source/helper/raw output in4,185 verified
members/modes, archiveSHAabd7d5c79291c99ebb05ee80092c47b87e3ffedcd3997f452b9ce8fc857f8c9a.
The repair must retain the exact source failure and actual query inputs under
a test-only closed receiver; ReadFailure remains non-Error in production.
Original cases, selections, limits and assertions remain binding.

The root encoded-document constructor is source-only. Independent review found
two real v1 gaps: malformed typed version numbers could enter native f64/lexical
work, and AP exponent/error scanning may normalize more bytes than the input
number token. V2 MF20a05cabe509003053d3a8313b8e3a6d543ae93f73b81c2694f7d087e855d732
adds an allocation-free exact current-writer envelope/u64 prefix gate and a
source-derived three-byte normalization allowance. Its six-image/full4,139
source, private inverse/forward and corrected review pass; actual compilation,
System allocation/custody tests and production joins remain required. The
preserve_order cold runtime and non-AP numeric profiles remain explicit open
construction obligations, not silent fallback paths.

Root independently verifies every artifact hash/mode in the corrected encoded
review82ecb7bb, paired-write review89bb9c24, marker review56a50399, selected-result
review55f59def and query-interface review2d806431. These are finite source reviews,
not runtime or activation results. Marker observations do not reduce RSS or
change admission equations. All C01–C07 and M01–M07 remain open.


### 2026-10-06 joined document/pair source and genuine native workspace (actual360–372)

Actual360 applies combined Result3 ddd12464,14images/3new/full4,149 on exact
Anchorinterface5. Actual361 strict49 fails79.99s before runtime: the newly
included selected-result fixture starts with an invalid inner comment. All3,562
source/config leaves unchanged. Guard362 preserves full4,149/helper/allraw in
4,215 verified members/modes, archiveSHA1a7dabf73e284d3b87924bb106f2170bbff480e122e9ec00dba50c4cf83637e2.
Actual363 applies solely that comment correction31d0dec5/patch e20d4d68. All72
quoted include calls are audited; no remaining included inner comments were found.
No test body, limit or assertion changed.

Root's Engine encoded adapter1 source review does not prove interfaces. Root
found its new fixture directly calling a Types-private downgrade. Preserved
carrier/review1; adapter2 uses the existing closed DocumentRef conversion and
public static downgrade, retaining the same original. Actual364 applies encoded
Engine2 MF1a09007bdd5cce24253bb02a95a4971f394fe25faf21c59d412a56d69035461e,
9images/2new/full4,151. Root verifies all source/modes and actual private Git
inverse/forward. Its five new Types/Engine cases leave19 affected old bodies
literal; the two old privacy examples move three lines with the added child
module and keep their original bodies. Actual365 applies paired-write current5
MF3691bd3ae4abf0927b774af132afe868894e00ce4125df4a614ccb97e2a2e605,
39images/1new/full4,152, preserving encoded and selected owners. It permits
borrowed main/receipt slices in one genuine durable transaction; the ordinary
producer is still unfinished.

Actual366 records locked offline metadata before membership:484 active packages,
15 workspace members, actual imbl excluded. Actual367 applies genuine imbl
membership precursor1172652e; original native dev dependencies/features/tests
are unchanged. Actual368 offline metadata resolves its real graph and writes
Cargo.lock, then fails on uncached triomphe0.1.16. Frozen actual failed state
868ee758e8240ed7f8dd46d861064624ebfd1e34da81ce8cb9014a420e2644bd
has full4,152. Cargo.lock has521 entries (37new); every existing version and
checksum is unchanged. Only imbl/archery add dependency edges, with none removed;
other text changes disambiguate the existing itertools version. Guard369
preserves fullsource/carrier/before+aftermetadata/raw in4,168 verified members,
archiveSHA1dd4175643667a04a77380360a05ef3a63ab9710ec3ef1dd3cda14e96b273249.
Actual370 fetches the locked missing registry crate successfully without source
changes. Actual371 locked offline metadata passes, unchanged3,565 tracked leaves:
515 active packages,16 workspace members, genuine imbl library+all3bench targets.
All old484 active package IDs/versions/sources remain. Lock entries and active
metadata packages are distinct counts. This resolves the owning graph; no native
runtime qualification follows from metadata alone.

Actual372 Owner15 on exact868 graph is running. Both Types list/run pass with
exact9 names,9PASS/0FAIL/0IGNORE, including all3 encoded cases. Engine4 actual
System allocation/alias/Weak/native-error witnesses and the original privacy2
remain pending. The original strict49 query, paired Entry11+normal caller and
native3profile/ServerJSON gates are prepared against the same full4,152 source.
Census216 and concrete protobuf successors remain source-only. Actual production
publisher/selected dispatch/finite full residency/final release remain open.
No C01–C07 or M01–M07 closes.


### 2026-10-06 actual373–376: joined document and query runtime qualification

Actual372 reaches a real finite compiler-depth failure in the Engine's nested
Send/Sync containment chain after the nine Types cases pass. Guard373 preserves
full4,152 source, helper and raw output in4,185 verified members/modes;
archiveSHA d03d6d3e40a44febd9ff257ab0f07a9d9aa40ccf43dbeb045dc5ebd32b275309.
The independent trace review retains the complete stderr and long type. Actual374
applies solely an Engine recursion_limit=256 compiler attribute and explanatory
comments: MF b64cbf7ceb207e149c087d8181ed82b147c6effbce53d9fcc68bc6b6248ee162,
patch c15b0117963a8435d6214c36d475dc825be066647bb3b37a341f7745116b989f,
one existing image/full4,152. No runtime budget, assertion, workload, parser
limit or Send/Sync implementation changes.

Actual375 Owner15 passes256.95s,15PASS/0FAIL/0IGNORE,6 fenced list/run calls,
unchanged3,565 tracked and full4,152 source leaves. Types9, Engine4 and the
original compile-fail privacy2 all pass. The Engine System witnesses cover broad
and nested arbitrary JSON, Unicode/escaping/AP numbers, exact envelope/version
rejections, original allocation peaks and final strong/weak/error cleanup before
original credit release. TerminalSHA
 a6e7b1686330843aae5214f51e2ea6841db225ede5c196f10853a55a6b0585bf.
This is the normal owning profile; preserve_order cold runtime, other native
profiles and ordinary production producer activation remain open.

Actual376 combined selected49 passes93.89s,49PASS/0FAIL/0IGNORE,8 fenced list/run
calls, unchanged3,565 tracked/full4,152 source. Exact Engine37, KV8, Types2 and
Engine compile-fail2 original/additive identities pass, including the actual
Database cancellation anchor, retained result/page aliases, completed operation
release, original logical errors and extraction restrictions. TerminalSHA
0477365b79e5e64010a9121af6b803373c9520ba70796b30bbbabc4b3bae6c8b.
No production selected dispatch, protobuf/tonic activation, public full-residency
or whole-cache completion follows from these scoped checks. Paired Entry11 and
genuine native owning profiles are the next unchanged-source gates.
All C01–C07/M01–M07 remain open; no live implementation promotion or Git publish.


### 2026-10-06 actual377–384: paired Entry qualification and native profiles

Actual377 normal Engine check passes, but strict Entry11 stops at Raft libtest
compilation after115.36s: two old anonymous selected callback signatures still
use the former slice type; two new unwrap_err calls require Debug on the Ok
AppliedResponse. Source unchanged3,565/full4,152. Guard378 preserves4,176 verified
members/modes, archiveSHA
e99c7feae19ae48729b19d5e8c5154a7bb472693f1bc37a827ab3a651b84f78d.
Root freezes repair1 MF1ef398cce4a6b40914738ccdec231f435dacaed420f9cad2f100c9ba00399de8,
patch55e09530c5d3f7031eaa1b8b82b557656ee421d5f3f297e168e8dbd080d53c56,
2images/full4,152. It changes only the actual callback types outside old test
bodies and uses an equivalent Err/Ok match for the two new denial checks. No
Debug derive, production behavior, native inputs, cap or assertion relaxation.

Actual379 real owning imbl leaf3 passes in default, serde and all-features
profiles:9 actual runtime passes, no failures/ignores. Original graph, targets,
dev dependencies and bodies remain. Server original JSON1 subsequently fails
E0275 before runtime; entire attempt336.11s/source unchanged. Guard380 preserves
full4,152/helper/raw plus exact Server longtype in4,190 verified members/modes,
archiveSHA575c852012c3647e4f5d260c2571c06f6d62ff24dc37535013b8c3d25d8ac00c.
Independent Server trace44387a48 retains16 actual leaves and identifies94 concrete
containment steps plus29 Send/Sync obligations; compiler suggests recursion256,
with no infinitely expanding generic substitution shown. Root verifies every
review leaf hash/mode. Native ArcK leaf cases across profiles do not prove the
Engine's default ArcTK headers under triomphe; general native header kinds remain
an explicit final integration obligation.

Actual381 applies the exact fixture repair. Actual382 Entry11 plus normal Engine
passes54.15s,5 fenced commands,11PASS/0FAIL/0IGNORE, unchanged3,565/full4,152 source.
The exact original8 receipt cases and added3 real Entry cases all pass: borrowed
paired inputs authenticate one flattened effect stream, commit both slices and
custody atomically, preserve an actual old snapshot, reject changed second inputs
before planning, and leave the first slice/custody unpublished on validation
failure. TerminalSHA68aa75074852fc91b482d9032c321d88373675577ec9940977476bf39e32a40b.
This proves the native paired-write prerequisite, not the ordinary sparse producer.

Actual383 applies solely the matching Server recursion_limit256 compiler attribute
and comments, MF45f209d494d6de73d985126e7a2ba686fd5546651f43b71bd9c18011a427c8dc,
patch6621455a34428ddc22bdd36804d16643253c3556fb1e524966acde70da404388,
1image/full4,152. No runtime budget/parser/workload/Send implementation changes.
Actual384 retries only the affected Server original JSON1 on that exact source;
strict helper keeps original profiles/case bodies/parser/fence and is running.
Earlier native profile passes remain scoped to actual379. Whole cache, finite
residency, ordinary all-role publication, public transport and release gates open.
No C01–C07/M01–M07 closure, source promotion or Git publish.


### 2026-10-06 actual384–389: shared backing census and registry lifecycle

Actual384 original Server JSON1 passes248.61s with two fenced list/run calls,
1PASS/0FAIL/0IGNORE, unchanged3,565 tracked/full4,152 source leaves. The terminal
SHA is456cb4b7654e996f12f9fdeb52ad817c247559294d1d9045f913f8f7e660d771.
Its recorded selection is Server only; the terminal's broad status wording
does not create another native-profile rerun. The native9 passes remain
scoped to actual379.

Actual385 applies the23-image/full4,156 backing-census and First-registration
join, MF84db4c9c3de2a2af69718c781d62c98c4b0097361718783c444ee82c3f262b4b,
patch cda871d21e99e5b8e5f54c65983874342596e3810f57cbe3814dae14933d41d2.
Actual native cache markers identify original provider/slot/layout owners and
rehash backing; the materialization census is observational. It changes no
RSS subtraction, admission equation or full-residency claim. First registration
reserves its exact node quote in the original fixed bank before aliases and
activates before Current becomes visible.

Actual386 strict218 fails38.56s in normal Engine compilation before runtime: an
activation caller passes a borrowed Generation where the closed GenerationRef
is required. All3,569 tracked/full4,156 leaves stay unchanged. Guard387 preserves
the full source/carrier/helper/raw result in4,254 verified members/modes; archive
SHA b5b0d0eeddf65f2fb718872ce000e44a09b1d3703edeef521b01cc2cebdf1335,
checkpoint source-checkpoints/failed-first-registry-wrapper-interface-v387.

Root review also identifies a concrete Roots→registry node→FirstBaselineLease→
budget Core→FirstBaselineLoan→strong Roots cycle. Actual388 applies the nine-image
weak-credit successor, MF0a421e6d1a61ab43f5c9292449c72155ba8e5cbf35f638ea7a0b32df55548374,
patch40744a6e8e818f4f2a38606674a2803d6c89a7fb438cdc6aefc8b3318075be3d.
Its dedicated lease retains original PayloadCredit and a paid Weak source/provider
identity, with no strong Core/Roots back edge, new slot or raw adoption. Fallible
capacity checks precede aliases; Drop releases the actual mutex and Weak Core
control before the payload loan. A closed candidate_owner accessor repairs the
interface without changing candidate(). Private inverse/forward and all4,156
source hashes/modes pass; the outer source guard's exit1 records the intended
nine-image mutation, while the apply runner itself exits0.

Actual389 strict219 is running on this exact successor: Engine64/KV155, retaining
every original case body, cap, feature, filter and fenced list/run function. Its
new genuine last-Database-drop case uses native close and retained GenerationWeak,
without explicit Database shutdown or direct unlink. It requires positive roots
and payload retirement while the actual public weak control remains charged,
then final credit release after that weak control drops. Source review alone does
not qualify this lifecycle. The analogous nonempty cached-row bank cycle must be
removed constructively before the ordinary publisher is installed.

Goals now distinguish four production dependency joins: atomic ordinary
publication, selected serving/transport, complete finite residency and final
qualification. Full fit includes every eligible index/directory/version and
uneven collections; only capacity pressure permits eviction. All C01–C07 and
M01–M07 remain open. Existing unrelated live-checkout edits are preserved; this
work has not promoted the isolated redesign or published Git state.


### 2026-10-06 actual389–395: corrected native lifecycle qualification

Actual389 failed86.90s before runtime: a newly included test file used an inner
module comment where the include contract requires an ordinary comment. Guard390
preserves full4,156 source leaves and4,230 archive members/modes, archive SHA
c764f2efb230197ccee63811de3603b17fc91d8c4346e9402fb1892885e8775d.
Actual391 changes only that comment, MF
e848c3edff31bfcb648451c8c21d18b8a59fd661e8b37c234cf4fed237b9bb49;
all219 selected case bodies remain literal. Independent review resolves all73
quoted include targets and finds no invalid leading inner documentation.

Actual392 then fails510.35s with62 Engine passes and two new witness failures;
KV155 is not entered. The genuine16,513-row native full-fit case and aggregate
uneven-store/shrink/growth cases pass. The failed new cache witness expected the
three independently owned Node facade/startup/idle grants to remain after final
NodeAdmission Drop. They correctly retire. The failed new database witness
assumed Database facade Drop shuts down its independently delivered Raft runtime.
The established runtime API owns that shutdown; native close correctly refuses
while admitted runtime reads remain. Neither failure justifies raising capacity,
removing an assertion or claiming whole-cache completion. Guard393 preserves the
complete source, failed bodies and raw evidence in4,218 verified members/modes,
archive SHA aca8a488e5a11a292df8c26f1cead438a77937d85814fe6cf2564018ea3ed676.

Actual394 applies only the two new fixture corrections, MF
98383d6bd401e61e1160854eaee1d1d641c7432a3e3fc2dc6c705ad1ec249a44,
patch749614daff1035c32f53cfad103d39cb6ea94798d7cdf5fdaba80f79e745f467.
The native-cache witness observes the exact original slot/identity and charge,
checks that dead facade grants retire, and proves the cache grant remains until
its last CachedBytes alias drops. The database witness drops the facade, shuts
down the exact independently delivered runtime through its existing API, then
proves native payload/roots retirement while a public GenerationWeak still keeps
the original weak-control tail charged. Final Weak Drop refunds that same credit.
All217 other case bodies, caps and production source remain unchanged. Both old
failed bodies and fixture-contract proof are retained.

Actual395 focused2 passes52.75s,2PASS/0FAIL/0IGNORE, with two fenced list/run calls
and all3,569 tracked/full4,156 source leaves unchanged. Terminal
/tmp/kasumi-registry-native-fixture-focused-runtime-root-v1/TERMINAL.json SHA
783c2035c8930449585bb7d288c8e78074ead94d6918749e4f22ef436dd9c082.
Full219 and the stronger222 known-union selection require qualification on the
joined successor; this focused result does not claim those selections passed.
The goals now state the actual facade/runtime lifecycle and distinguish original
cache credit from grants whose real owners have already retired. Every C01–C07
and M01–M07 remains open; no isolated implementation has been promoted or Git
state published. Unrelated live-checkout source/API edits are preserved.


### 2026-10-06 actual396–402: selected native wire qualification and joined refill

Actual396 applies the direct Proto11 source to the corrected registry fixtures,
MF6af86116f65abcea480e8b143ff727b9d745f12659a590a4d4e722e6e02783be,
full4,161. Actual397 strict56 fails378.83s: Engine36PASS/6FAIL/0IGNORE in245.38s;
KV/Types/docs/Server are not entered. One new refusal fixture fails during Node
construction because its128KiB total budget cannot hold the memory sampler's
fixed160KiB startup allocation. Five original Database cases hit write/quorum
deadlines. All3,574 tracked/full4,161 source leaves remain unchanged. Guard398
preserves complete source/helper/raw logs and the root metadata draft, archive
SHA6f6a1f5947a590deae49e27053fed96eef25f680ce3132ee26e990549750b01e.

Actual399 changes only the new fixture's original(cap) helper: use the normal
existing64MiB total and apply the same intended cap through the actual
max_workspace_bytes setting. It preserves the original failed whole source and
an exact inverse substitution with the fixed startup/layout/API trace. MF
50124a444f35cdc1e6068c37d230c1f112c4b7d5cdbf69476a05fbfbf9c365b2,
patchba4d3e37fa112c9fca75db6b396fa7e615490b6a7c27b788608690e5b442469e.
Every54 runtime case body and both privacy compile-fail bodies remain literal;
no request payload, query cap, original deadline, test thread count or assertion
is relaxed. The inactive System observer review finds fixed TLS/atomic checks
and no leaked watch; it does not establish CPU attribution for the deadlines.

Actual400 strict56 passes726.15s,54 runtime+2 compile-fail checks,10 fenced Cargo
list/run calls; package totals Engine42/KV8/Types2/docs2/Server2, allPASS/0FAIL/
0IGNORE. All3,574 tracked/full4,161 source leaves remain unchanged. The five
previously failed original Database cases pass without deadline or body edits.
Terminal /tmp/kasumi-selected-protobuf-workspace-fixture-runtime-root-v1/TERMINAL.json
SHA52500d324349946f7d54610858c8503f9a891fcf78484c2e76a8792609b6adb0.
This qualifies the actual selected result/protobuf owners, native generated wire
parity and extraction privacy; public RPC/transport and whole-cache cutover are
still open.

Actual401 applies the five-image known-union diagnostic directly onto50124,
MF2e52158ab97d14244127383de9c788f9cc5aa87766e47fcfe676ae9ac6644d04,
patch536e743ddf9fc452234e69acc4d96523eee2140e0606eb4daa736192c38298a9.
After interruption Root physically revalidates all4,161 actual source hashes and
modes against this carrier; zero differences. Actual402 strict222 starts on this
exact source: Engine67/KV155. All corrected219 original bodies plus three scoped
known-union cases, original caps/features/parser/fence are retained. This record
is not a terminal result. Native pin epoch, physical RSS intersection, every
public/text origin and complete finite global refill remain open.

The genuine sparse producer now prospectively prepares query metadata from its
original document/receipt/publication bank. Source review verifies exact payload,
provider and paid Weak root equality, and prealias sparse registry attachment.
Root's actual owned-dispatcher draft retains Ready output before callbacks and
entered traversal on publisher None/Err/raw. These are source-only joins pending
normal compilation and actual SDK paired-write/selected-read qualification.
All C01–C07/M01–M07 stay open; no source promotion or Git publication.


### 2026-10-06 actual402–407: joined refill pass and genuine sparse compiler repair

Actual402 strict222 passes489.14s with four fenced list/run calls: Engine67
passes in370.81s and KV155 passes in12.04s; zero failures or ignored cases.
All3,574 tracked/full4,161 source leaves remain unchanged. The genuine16,513-row
native case retains its original64MiB/128-slot budget. Uneven aggregate sharing,
shrink/growth refill, retained historical structured data and both corrected
lifecycle witnesses pass. Terminal /tmp/kasumi-known-union-fit-runtime-root-v4/TERMINAL.json
SHA959b0bf9f10659c844a6be311fa4dbbf57b00328831ba2c5b15a0eacfb920255.
This is the finite known-union selection; complete native freshness after cleanup,
every public/text origin and the physical process-memory union remain open.

Actual403 applies the genuine40-image sparse producer, MF
77a6c2f05b9a5d86461141ac1789ce9790865336c7344c8bc0eadbc2c41faa23,
patch13df50c732189ca449896594cda891c0b9190260a2a3ddaa96dfe1f98a53371d,
full4,171. Actual404 normal Engine compile fails41.91s with65 errors: missing
Context imports, closed sibling access boundaries and Result/Option native
allocation geometry. Runtime is not entered. All3,584 tracked/full4,171 source
hashes and modes remain exact. Guard405 preserves the full failed source, raw
log, helpers and source-only retained-dispatcher draft in8,411 verified members/
modes; archive SHA34c05c494e81b980b29ec98588a272228fef9e2bf31bc6cdbdbdbfc2ff90a001,
checkpoint source-checkpoints/failed-genuine-sparse-compile-v405.

Actual406 applies only the six-image compiler repair, MF
e064a5c424ebe06e9b28dcd568d510a855352d231b5a6d3fbfc25f0fa4f7223e,
patchd823982bf67fd4550d83efd3d745a0eb8f5c8ccd0859db2b5eda0c34d0c6b731.
Three actual modules import Context; geometry converts allocated's Result at the
existing pure optional quote boundary and maps its typed error at funding.
Journal access stays inside state; typed baseline/prepared-reader borrows open
only to their actual crate siblings. No raw construction or adoption is added.
Bodies, features, caps and fixtures are unchanged; private inverse/forward and
all4,171 actual source hashes/modes pass. Actual407 normal locked/offline Engine
compile is running on this exact source; this record is not its terminal result.

The goals now record the222-case pass and exact next production dependency:
compile the genuine candidate and retained dispatcher, then qualify an actual
SDK paired write/selected read and canonical replay/refusal behavior. Complete
all supported command/index/replica producers before public cutover. The large
shared cache retains every eligible object below its fully accounted bound;
durable writes apply in either residency mode. All C01–C07/M01–M07 remain open.
Unrelated live source/API edits remain preserved; no implementation promotion
or Git publication has occurred.


### 2026-10-06 actual407–412: compiled publication join; SDK stack failure preserved

Actual407 genuine sparse candidate normal locked/offline Engine check passes
49.44s (Cargo48.50s), all3,584 tracked/full4,171 source hashes/modes exact.
Actual408 applies the five-image retained dispatcher directly on the compiler
repair, MF0c5e45bc9017f04d22c2940bf0670c4532113ceea491b4b02960ad66fd5a3564,
patch463727a80e24409627d3af3f85494409ecd170ae593f087e207af6e7e69a54eb.
Actual409 normal Engine check passes11.09s (Cargo10.60s), same source unchanged.
Ready output is installed before fallible metadata callbacks; entered inventory
stays in the external paid command frame on None/Err/raw. Native committed
selection and exact metadata/registry activation precede visibility. These
compilation passes do not establish SDK behavior or broad producer activation.

Actual410 adds one genuine two-write SDK witness and its include, MF
b67370bd8d8272dec953fef5b99499b63fba0528529f7fde5e5ab744d5940454,
patch98be85209151fc723971a164e86ca96acae1eaa43d00297b919afca9ed9c2e21,
full4,172. It checks actual durable receipt/primary selectors, empty resident
document maps and historical/current internal selected-query rows, with the
existing supported-startup fixture and default limits. The four selected prior
First/registry/query case bodies remain literal. This internal selected factory
does not claim public authorization, expiry, cursor or strict-audit activation.

Actual411 strict focused5 lists its exact five identities after normal test
compilation, then runtime aborts signal6 with a stack overflow in the unchanged
actual_selected_result_page_aliases_keep_same_grown_credit_and_release_only_completed_operation.
Runner311.22s; exit101; no complete runtime result or passed-case total exists.
All3,585 tracked/full4,172 source hashes/modes are unchanged. Guard412 preserves
complete failed source, both raw list/run streams, immutable runtime functions,
helpers and the unactivated observation dispatcher in8,376 verified members/
modes, archive SHA5d241594f644bb8bf2dd73653649e960c1032059be24a99f679b4eb3aa557c94,
checkpoint source-checkpoints/failed-sdk-sparse-paired-read-v412.

The next required repair traces the real retained command/backend/frame layouts
and removes oversized inline startup stack movement under the same prospectively
funded original owner. Increasing test stacks, relaxing assertions or raising
capacity would not qualify the production join. The new native post-cleanup
residency witness and native transport parts remain source-only until their
actual graph and runtime gates pass. Current selected source factories capture
GenerationRef plus exact SourceRoots without borrowing Standing; concurrent
paused-write serving and eventual public factory activation still need direct
qualification. Original fixed-bank retained tails also need physical accounting
and positive unused-headroom retirement before a global full-fit claim.
All C01–C07/M01–M07 remain open; no implementation promotion or Git publication.


### 2026-10-06 actual413–415: original paid dynamic ingress receiver

Actual413 applies the three-image production receiver repair, MF
16c0678b9ddf4438cef4679918b78e153cdffe89a232998782bd01ef647cabf4,
patch1be75656bab335dc09e44308bc5e56d294491849dc223864ccaa165a11fe07cc,
full4,172. Read-only actual411 LLDB confirms OwnedCommandPreparation104,496
bytes, Ingress104,504 and OwnedEngineBackend104,600. Immediate open/fixture
futures are2,944/8,528 bytes; they do not directly inline that whole backend.
The compiled constructor frames reserve210,208 bytes in backend install,
522,720 in OwnedEngineBackend::new and104,736 in Arc::new. Original disassembly
/tmp/kasumi-paid-receiver-old411-constructor-prologues.txt SHA
0fd53cad5717acb721f2f241dc0d6b85971e0b60c53938c6c9d5e83a2cb3aede.
These are source/layout observations; successful runtime repair is not inferred.

One concrete receiver allocation is now prospectively quoted in the same original
backend control. Box::new_uninit initializes only its small state flag during
startup; command installation precedes native callbacks. Ingress and Call move
the same pointer. Failed/raw command and credit remain together; only positively
empty receiver backing deallocates before the original control retires. No new
grant, stack increase, capacity change or deadline relaxation is introduced.
All prior owned-ingress case bodies stay literal. The actual System allocator
census now checks six concrete requests including the exact receiver Layout;
the old five-allocation case/source remains in the failed archive.

Actual414 normal Engine check passes49.65s (Cargo48.16s), all3,585 tracked/full
4,172 source hashes/modes exact. Actual415 strict10 is running: the complete
original failed SDK5 roster plus four unchanged backend/native custody cases
and the exact new six-allocation census. Both its runtime functions and strict
namespace/result parser remain literal; this is not a terminal runtime result.
All C01–C07/M01–M07 remain open. No source promotion or Git publication.


### 2026-10-06 actual415–417: stack repair qualified; sparse backend failure retained

Actual415 terminates257.02s with the full original SDK5 namespace: four
original SDK cases pass, including the former stack-overflow query case;
the added actual sparse document/receipt paired-read case fails with the
original service `UnknownOutcome: write task failed; resolve or retry with
the same idempotency key`. Runtime52.50s,4 passed/1 failed/0 ignored. No
sparse publication pass or exact failed mutation phase is inferred. The
helper stops before its second controls5 selection; it does not pass10.
All3,585 selected and full4,172 source hashes/modes remain exact.

Actual416 preserves the complete failed415 cohort and all raw/runtime/helper
inputs in8,380 verified members/modes, archiveSHA
f79a40aa40d8edb37b1d66ca790c44b84188e3e86481c2aa5fe725c0d7e1acbb,
checkpoint source-checkpoints/failed-paid-receiver-sparse-sdk-v416. Runner
136.45s,exit0; no source correction preceded this preservation.

Actual417 separately runs the literal original controls5 selection on the
same full4,172 source. All5 pass/0 fail/0 ignored; two actual fenced list/run
calls, runner7.96s. This verifies four original native/backend custody cases
and the exact six-allocation System census, including the original quoted
receiver backing and control retirement. TerminalSHAa6c16f9244f9ad3ea08f92260714557b6bc6f6885a2f13ce4c51bbb572f0125b.
It does not qualify the failed sparse SDK case or public cutover.

Goals now make the immediate gate the original retained sparse backend
failure, followed by actual paired commit/snapshot reads, canonical
replay/refusal, post-cleanup native residency and the real transport graph.
No increased stacks, capacity, deadlines or weakened assertions.
All C01–C07/M01–M07 remain open; no source promotion or Git publication.


### 2026-10-06 actual418–420: genuine retained original exposes resident counter assumptions

Actual418 adds only an SDK diagnostic include and a new fixture file, MF
9589224f61c77eaf69307c6217fddf229a7de68ee0753d082c28458536dbf67a,
patch2866295529af890f6da380eb68c751c8642789f4273f12abbf51779c5d4c9709,
full4,173. Every original SDK5 whole body remains literal. The diagnostic uses
the exact first SDK mutation and borrows the existing retained apply report
and BackendFailureRef.try_with_original. It returns the original SDK error
unchanged; it cannot drain, retry, reconstruct or refund the failed frame.
Actual419 normal Engine check passes12.45s (Cargo11.43),3,586 hashes exact.

Actual420 strict SDK6 lists all6 exact identities, then returns exit101 in
107.25s; runtime38.30s,4 pass/2 fail/0 ignore. The original SDK4 pass; both
paired sparse and additive first-write diagnostic fail. At ordinal2 the
actual retained backend borrows original `ordered output differs from actual
accepted counters`; inspected=true. Completion violation=Missing, action
returned, sink not entered, finish returned, cleanup refused Retained and
drain not entered. This establishes the first mutation and pre-sink failure,
not a successful sparse publication or cleanup. All3,586/full4,173 source
hashes/modes remain exact. Actual421 full failed-cohort preservation passes
163.00s,exit0: 8,382 verified archive members/modes, archiveSHA
ef6c2a2e1d26a263c88658ed9f8cee9e9280bf4440cee1ee97066a2bb4d7f10c. Checkpoint
source-checkpoints/failed-original-sparse-sdk-diagnostic-v421.

The counter verifier still compares physical output against resident map
lengths. Both prior-manifest and accepted-output joins need a typed sparse
counter owner bound to the genuine selected previous generation, actual
retained journal, roots and revision. Keep the independent expected/observed
verification unconditional and the resident-family checks intact. Do not
rebuild resident maps or skip verification based on an empty map/readiness flag.
All C01–C07/M01–M07 remain open; no implementation promotion or Git publication.


### 2026-10-06 actual422–424: canonical observation union and constructive counter repair

Actual422 applies the10-image observation/replay union directly over the
preserved SDK diagnostic source, MF2eb720afe9b3d179478212198d8ab1492fb5a302539e2172b043c3c3c291a242,
patch72a4d592c022a5ae692ef5d1b122d4ef06540d6fb8e7caeb3be8767026a27e05,
full4,174. It preserves unchanged receipt prefixes for replay, digest conflict
and pre-admission authorization/refusal, while admitted document/CAS/duplicate/
logical rejections receive permanent rejected rows. Its publication token
verifies the original exact prefix before the existing joint source publisher.
Actual423 normal Engine check passes69.58s (Cargo1m07),all3,587 hashes exact.
These semantics are compiled but their additive SDK cases are not runtime-qualified.

Actual424 applies only primary_projection.rs and primary_stage_ordered.rs,
MF5fbbe6e90770ed388d249f9271de4d289490aceec4bf795c343098c07632dc96,
patchcc2cbe81a37d50c32b631379e1df8181a0e50e7b86e94802f2a01a302abe8c0f,
full4,174. The closed counter family requires genuine previous/accepted sparse
origins, exact roots/revision/journal and exactly one collection without
archives. It independently replays every retained before/after row over old
count/bodybytes, validates candidate totals, and compares the full prior/output
Manifest Totals. Resident counter checks remain literal; expected==observed
is unconditional. No resident maps, raw scalar authority or lowered verifier
assertions are introduced. Normal compilation and SDK6 runtime remain pending.
All C01–C07/M01–M07 remain open; no implementation promotion or Git publication.


### 2026-10-06 actual425–429: original validator visibility correction

Actual425 normal Engine check fails15.30s/exit101 with exactlyE0624: the
new counter owner cannot call journal.require_state, whose existing visibility
is pub(super) in the DocumentJournal subtree. No runtime is claimed. All
3,587/full4,174 source hashes/modes remain exact. Guard426 passes14.52s/exit0,
preserving all4,174 source leaves and4,203 archive members/modes, archiveSHA
c65d835a1c57d1554edb729f1fa07748bcdc019d287d372d8014efa359a492b9,
checkpoint source-checkpoints/failed-sparse-counter-privacy-compile-v426.

Actual427 applies exactly one visibility token, pub(in crate::state), with the
validator body literal: MF7f9a77c41620053f8c45379ec42f007deffec5605b5f5d52b23c3451b0a12c90,
patchbf56a284eb673efa1c8d9e2fd5b91fc3a6ec14094cc3e666679366966c207790,
full4,174. This exposes borrowed validation to its actual state sibling; it
does not add a constructor or raw adoption API. Actual428 normal Engine check
passes16.77s (Cargo16.27),all3,587 hashes exact. Actual429 exact original SDK6
rerun is pending on this source; case bodies, names, filters, features, limits
and strict Cargo/source/result functions remain literal.

This finite counter family covers one collection without indexes or archives.
It does not activate public serving, other commands/indexes, replica capacity
or complete cache residency. All C01–C07/M01–M07 remain open. No source
promotion or Git publication.


### 2026-10-06 actual429–430: actual sparse SDK commits and retained selected snapshots pass

Actual429 strictSDK6 passes319.54s (runtime35.13s),6 pass/0 fail/0 ignore,
two exact fenced list/run calls on full4,174 source MF7f9a77c41620053f8c45379ec42f007deffec5605b5f5d52b23c3451b0a12c90.
All3,587 selected/source hashes remain exact. TerminalSHA21715ad21e7e8cea937bd90ab75714cf414014817e8a705046edb61dc9bb1c4f.
Every original SDK6 body, feature, filter, capacity and runtime parser/function
is unchanged. The formerly failing genuine sparse case commits document plus
permanent receipt, registers real sparse generations with empty resident document
maps, updates the same document again, and returns exact historical/current
internal selected-query rows under retained aliases. Original constructor,
metadata/registry and result-custody cases all pass. The additive first-write
original-error diagnostic succeeds without changing the SDK result.

This proves the finite one-collection/no-index/no-archive producer and actual
private selected reads. Public serving, all commands/indexes/audit growth,
replica preacceptance, global residency and process memory remain open.

Actual430 applies the literal four canonical semantic SDK cases on top of this
source, MF9fb8b46c5af6af37cf5954ff51928fe9cef69adb92990c46bf816242952c807e,
patch2b1c9fc1ca216808b211592b29cb8ed124087b4f501e30714b89c1195d8938a7,
full4,175/2images1new. Actual pin validation confirms every4,175 leaf hash/mode
including the semantic/paired/diagnostic includes. Normal check431 is pending;
SDK10 runtime remains pending. All C01–C07/M01–M07 remain open. No source
promotion or Git publication.


### 2026-10-06 actual431–433: canonical semantic SDK failures preserved

Actual431 normal Engine check passes23.54s (Cargo21.07),all3,588 source hashes
exact on full4,175 MF9fb8b46c5af6af37cf5954ff51928fe9cef69adb92990c46bf816242952c807e.
Actual432 exactSDK10 runtime fails132.48s/exit101 (runtime70.76s),6 pass/4 fail/
0 ignore. Every preceding SDK6 case passes; replay/conflict, CAS/duplicate
rejections, ordered-read denial and default-document-limit rejection fail.
Replay returns UnknownOutcome; denial and CAS compare actual UnknownOutcome
against their unchanged expected Forbidden/Conflict. The default-limit case
reports ResourceExhausted: document source retention budget exhausted. No
canonical semantic pass, precise failure phase or completed cleanup is inferred.
Actual source hashes/modes remain unchanged.

Actual433 preserves complete failed source, raw list/run streams, strict helper
and pending counter-negative source in8,391 verified members/modes,
archiveSHAa572a25e96d17a5f92c83c1f063e77bdcfdca72eb277c91a62825bc9a25d3010,
checkpoint source-checkpoints/failed-canonical-sparse-sdk10-v433. Runner82.59s,
exit0; full4,175. Next work borrows exact actual originals and resolves source
retention at owning constructors; assertions/budgets/deadlines remain unchanged.
Prepared concurrency/native/transport parts stay source-only until their actual
parents and runtime gates qualify. All C01–C07/M01–M07 remain open. No source
promotion or Git publication.


### 2026-10-06 actual434–436: additive canonical semantic diagnostics

Actual434 adds only the diagnostic include and four additive witnesses, MF
3c7d562a0a46c8dcc2e600f0a330a3bbed59a6e4b0f989659f09f68f71d6ca52,
patchc1be2c156a49f532e66fc23f90b5b7446f48db0456134a32500a83ed3708bec2,
full4,176. The original SDK10 whole bodies and default limits remain literal.
New witnesses use identical semantic assertions/workloads with wrappers that
borrow the actual existing retained apply report and return the exact original
factory/SDK/query/shutdown errors. They mark entrance/return steps without
retrying, adopting, draining or changing error classification.
Actual435 normal Engine check passes8.92s (Cargo8.43),all3,589 hashes exact.

Actual436 strictSDK14 is pending, with the existing test-only environment flag
KASUMI_TEST_SOURCE_GRANT_TRACE=1. That preexisting trace logs only rejected
DocumentSource requests, their actual caller/request/charges and protected
cache/ordinary floors. It changes no admission limits, assertions, deadlines or
Cargo features. Runtime/source/fence/parser functions and prior SDK10 case
bodies are literal. Complete source/physics claims still await actual results.
All C01–C07/M01–M07 remain open; no source promotion or Git publication.


### 2026-10-06 actual436–441: prior catalog cause and original history funding frontier

Actual436 SDK14 fails144.67s/exit101 (runtime70.03s),6 pass/8 fail/0 ignore,
full4,176 MF3c7d562a0a46c8dcc2e600f0a330a3bbed59a6e4b0f989659f09f68f71d6ca52.
Every preceding SDK6 body passes unchanged. Original replay, CAS and ordered-read
refusal diagnostics borrow the exact retained error: `referenced prior collection
counters differ`, ordinal3, before the output sink. Prior catalog verification
compares durable live counts with the sparse generation's deliberately empty
resident maps. These are genuine retained failures; cleanup is refused and no
completed drain or retirement is inferred.

The default-limit diagnostic reaches the actual mutation and returns the expected
ResourceExhausted `document exceeds byte limit`. Afterwards, before the selected
query entering marker, history retention fails. The existing opt-in trace identifies
PublicationCredit::prepare_history at application_source_capacity.rs236 as the
actual requester:95,206 bytes, actual charges524,333,851 or498,446,747, limit
607,813,494;64MiB cache/64 slots and128MiB ordinary/4 slots remain protected.
The source escape and actual same-core maintenance scope still need precise
qualification. Oversized decoder prospective funding is a separate finding,
not the observed caller. No bounds, deadlines or semantic assertions changed.

Actual437 preserves this complete failed source, strict helper, raw streams and
prepared prior-counter repair in8,419 verified members/modes, archiveSHA
e55fbe865d73a54cb6ce57a00f88f57d073daa61c97693df749f98c07915b5f3,
checkpoint source-checkpoints/failed-sparse-sdk14-original-semantic-source-trace-v437.
Runner61.63s/exit0; all3,589 selected hashes unchanged.

Actual438 applies the closed committed counter family, MF
39274a8c910bef3b1e556149c28066e9c179fc7b97e852c8dce3d2c008018dcd,
patch9da0e642cf1e327d8bf44efa0aba202a0d1d7e3dcaabb5bcc01a603b12974159,
full4,176/3 existing images. Its sparse proof requires the actual native sparse
producer, original governed payload/control, exact committed selected cell and
revision, complete document/body totals, and the existing finite single-collection/
no-archive constructor gate. Resident checks remain literal. Durable manifest
context/epoch/resource hashes, catalog mappings/inventory and aggregate selector
totals remain independent requirements. All original SDK14 bodies and bounds are
unchanged; no new allocation or fabricated readiness token.

Actual439 was an incorrect fence invocation, exit1 before any Cargo command or
source mutation. The raw invocation failure is retained. Actual440 supplies the
required isolated-root argument and normal Engine compilation passes12.74s
(Cargo12.38s),3,589/3,589 hashes exact. Actual441 strictSDK14 is pending on
full4,176 with the same opt-in source-grant trace and literal runtime execution.
The goals now name prior catalog verification and owning source-history funding
as concrete immediate gates. All C01–C07/M01–M07 remain open. No production
activation, source promotion or Git publication.


### 2026-10-06 actual441 terminal and public activation gates

Actual441 strictSDK14 fails254.55s/exit101 (runtime109.21s),11 pass/3 fail/
0 ignore. All3,589 selected hashes and full4,176 source leaves stay exact on
MF39274a8c910bef3b1e556149c28066e9c179fc7b97e852c8dce3d2c008018dcd.
Both originals and diagnostics for replay/conflict, CAS/duplicate rejection and
ordered-read authorization denial pass. The default-limit original/diagnostic
still fail at the actual95,206-byte history grant. A preceding SDK6 first-write
diagnostic also fails during fixture setup, before its mutation wrapper:
`selected publication failed after successful planner and prepared receipt:
storage owner failed: storage owner failed: storage owner failed`, followed by
UnknownOutcome deadline expiry. This raw result identifies neither its original
physical failure nor a repair. Original deadlines are unchanged. Later scoped
passes cannot erase that obligation.

The source-only public activation audit is saved under
source-audits/public-selected-activation-gates-v3, sealedMF
7a5b48fa0ac9812b47fc034da2ca3d7c83eebbe46ea9ead25046903c4be41da4.
Its verifier checks all4,339 leaves of the prepared transport/native source,
28 exact source files and eight integration gates; it invokes no Cargo and
does not claim this larger source is applied. Exact caller joins preserve
public auth/expiry/audit/cancel/release, coherent snapshots/transactions/history,
RPC/MCP ownership and SDK continuation. Selected text rejection, absent public
cursor issuance and public owning error transport are explicit unfinished
producers. Prepared transport stays immutable until the actual parent qualifies.
All C01–C07/M01–M07 remain open; no public activation or source promotion.


### 2026-10-06 actual442–445: failed cohort recovery and public escape tracing

Actual442 wrote the complete failed441 archive but its random-order gzip member
validation was excessively slow. Actual443 independently adopts that exact
written archive, reconstructs the identical original member roster, and checks
every member's bytes/mode in physical order without rewriting archive data.
It passes9.10s/exit0;4,176 source leaves,12,635 unique members/modes,
archiveSHAe2602cbcef130ec51ee55f709741e146f12fe3e2f2264fff0b23c3c10d4b3c54.
The redundant442 verifier is stopped only after443's complete positive proof;
its raw log records568.40s/exit-15 and all3,589 source hashes unchanged. This is
an interrupted verifier, not a failed Cargo test or completed442 qualification.
The original failed441 streams and all original sources remain recoverable.
New physical-order guard helper SHA19de38fad1c11fdcca99c169b6042ef0078a4a1303b62ee7525d30ce4d67a7ba
preserves every full-member byte/mode check and strengthens unique-name checking;
old helpers are untouched. Recovery helper SHA4e0edffa98cd7613c203dc3003f89a142c7e04fbf3137e0c5462ea4399059a77.

Actual444 applies only cfg(test) public escape/funding traces and track_caller
propagation, MF6a34d7afd76cb35200cacb9b7bb3950638b66dc8c5005350e0181f8798163b9c,
patchdb40b114b33b2365e7d16399d13eb0c05b5e591126f66a19bb8d78896d980ced,
full4,176/4 existing images. The opt-in trace follows the actual Engine::generation
escape to its original ticket and tests genuine same-MemoryCore synchronous audit
scope. reserve_document_source and every scope/limit/error remain unchanged.
Actual445 normal Engine check is pending. The next semantic SDK14 will run after
the finite unreachable-decoder prospective quote correction, with tracing kept
on that unchanged caller; no audit-scope substitution is proposed. All C/M goals
remain open and no source promotion or production activation is claimed.


### 2026-10-06 actual445–448: deterministic rejected-body capacity and native original diagnostics

Actual445 normal Engine check passes10.79s (Cargo9.98s),all3,589 hashes exact.
Actual446 applies the finite prospective quote correction, MF
613970a00721e094184d73924b8bce48274159fd0a71e7d7e9fc018560766031,
patch8a0f645178aa9d865eeac4b6322cee312aab26b4a9a01765577b3e7cb11d72f4,
full4,176/1 existing image. After preserving the actual prospective InputWire
allocation and canonical serialization, it uses the same plain Value encoded_len
predicate and actual prior max_document_bytes as the reducer. A too-large body
cannot reach encode_next, so its after-image decoder/wire/full Document geometry
is not reserved or published. Original receipt replay/digests, authorization,
read/CAS order, prior-reader capacity, batch limits and rejection/audit behavior
remain literal. No new grant, scope substitution, credit refund or cap increase.

Actual447 applies the diagnostic native erasure carrier, MF
1f7e6a0b15a38348410bfb5f47510cb3f08604b2f3b24b8e361573cebb48c747,
patch4cd08cba79906310b64978e71f66e04f928a439abf485635a009b0890bd68b89,
full4,176/2 existing images. Existing Store test-utils and unchanged KV debug
profile make opt-in KASUMI_TEST_NATIVE_PUBLICATION_ERASURE_TRACE=1 available.
Store borrows the actual original I/O error immediately before unchanged effect,
owner/funding/growth erasure; KV identifies exact direct image-owner refusals.
No branch, error classification, retry, deadline or feature is changed. Release
KV omits the trace. Current full SDK14 bodies/caps and executing helper functions
remain literal. Actual448 normal Engine compilation is pending; the next SDK14
will enable both existing public-source and added native-erasure trace flags.
The known physical-enrollment and prior fixture failure obligations remain open
regardless of that rerun's result. All C01–C07/M01–M07 remain open; no promotion.


### 2026-10-06 actual448–450: complete finite SDK14 semantic join passes

Actual448 normal Engine check passes24.46s (Cargo23.81s),3,589/3,589 selected
hashes exact. Actual449 exactSDK14 passes343.21s/exit0 (runtime132.41s),14 pass/
0 fail/0 ignore, two literal fenced list/run calls on full4,176
MF1f7e6a0b15a38348410bfb5f47510cb3f08604b2f3b24b8e361573cebb48c747.
TerminalSHA5e7d0c34c270b09e09b7b7eaa0d004c67772c6460bc5e6511122b0beb5014119. Every original body/cap/deadline,
feature and execution/parser function remains unchanged. Both trace flags are
explicit opt-in diagnostic context, without new scope or authority.

The finite genuine SDK publisher now passes paired document/receipt commits,
empty resident maps, retained historical/current selected queries, idempotent
replay/conflict observations, CAS/duplicate permanent rejection, ordered read
authorization denial and default document-size rejection. The size rejection
returns the exact expected ResourceExhausted/message, records its permanent row,
preserves the empty selected collection and completes selected reads/shutdown.
Unreachable decoder capacity was the corrected owning prospective obligation;
the actual95,206-byte public history ticket succeeds under ordinary funding.
Trace identifies service.materialization_access at service.rs1303 ->
Engine::generation -> retain_public_history, equal_core_audit_scope=false.
Audit protection was not substituted. Requested95,206 bytes are unchanged.

The preceding first-write fixture also passes this rerun. No native erasure
failure appears here; that does not identify or repair the original441 storage
failure or earlier physical enrollment failures. Their archived raw outcomes,
original deadlines and final-source obligations stay open.
Actual450 original Types9/Engine4 constructor/refusal plus privacy2 is pending
on this exact source. Counter negatives, paused-write concurrent readers, native
residency and transport successors are prepared source-only, not yet applied.
All C01–C07/M01–M07 remain open: finite one collection/no-index/no-archive/simple
schema is not broad production activation, all-history accounting or full-fit
serving. No live promotion or Git publication.


### 2026-10-06 actual450–454: original ownership checks and additive corruption/concurrency join

Actual450 exact original owning constructor/refusal/private-interface selection
passes47.97s/exit0: Types9 + Engine4 + two original compile-fail privacy cases,
full4,176 MF1f7e6a0b,all3,589 hashes exact. Every13 complete original case body,
original capacity/refusal/raw/weak-tail contract and both privacy source bodies
are literal. Actual451 original paid-receiver concrete six-allocation census and
same-pointer/custody controls also pass3.55s/exit0,5 pass/0 fail/0 ignore, two
literal fenced calls and all3,589 hashes exact on the same full source. These
scoped passes preserve the original SDK14 repair through its owning controls.

Actual452 applies actual constructor corruption witnesses, MF
a1e2930899efa490546067dbbb4699ee3f55c9e1e639d7d22bf23df07c901d4b,
patchba3f0825ba83d231c5b24c309ca4cf7b4649e42d9b36385d217f0c1b4b16431f,
full4,177/5images1new. Three real pre-installation faults alter actual header
count/body bytes or omit a real second journal effect while other outputs remain
unchanged. Whole original SDK14 bodies/caps and finite body guard stay literal.
Runtime must show original owned failure before publication, unchanged actual
Current/durable selector, retained original charge/permit and no invented drain.

Actual453 adds the actual paused-standing-write reader witness, MF
9f162964312d2abb6775128e6ce236482a00a4e58717fea97b4c77f0f3fce925,
patch27e17c369773d2236430661d49b97da6fccd834de1100a738177955fc77c6f63,
full4,178/3images1new. Original hook/body are literal. It pauses the real SDK
write after standing withdrawal and outside its bank lock, obtains a new private
selected plan from the actual committed generation, verifies old rows while the
write permit remains held, then new rows after real publication. This is not
public authorization/cursor/audit activation. Normal454 and combined exactSDK18
remain pending; one original14 prefix + corruption3 + concurrency1 selection
qualifies their joined source without weakening or omitting any earlier case.
All C01–C07/M01–M07 remain open. No live promotion or Git publication.


### 2026-10-06 actual454–455: joined corruption and paused-write SDK gate

Actual454 normal Engine check passes8.79s (Cargo8.25s),all3,591 hashes exact on
full4,178 MF9f162964312d2abb6775128e6ce236482a00a4e58717fea97b4c77f0f3fce925.
Actual455 combined exactSDK18 is pending, using both opt-in original source/native
trace flags. It retains every original SDK14 assertion/body/default bound plus
all three original real corruption witnesses and the same paused-write reader
body. Exact list/run, capture/parser/fence functions and features remain literal.
Original constructor/refusal/privacy terminalSHAbee047dca2a0858b2b1be3f8a217650a403054f7bcbc097911c8f096ac870c7b;
original receiver controls terminalSHA62c3010d3b7af3e197a0ce8d77a99f927c1fb42540f7c97082f6e8d091d4bc33.
All C01–C07/M01–M07 remain open. Native residency/transport/growing audit/tail
successors remain unapplied; no production activation or live/Git promotion.


### 2026-10-06 actual455 terminal: corruption refusals pass; concurrent phase unresolved

Actual455 combined exactSDK18 fails353.71s/exit101 (runtime152.43s),17 pass/
1 fail/0 ignore, full4,178 MF9f162964312d2abb6775128e6ce236482a00a4e58717fea97b4c77f0f3fce925;
all3,591 selected hashes remain exact. Every original SDK14 case passes again,
and all three actual count/body-byte/omitted-journal corruption cases pass their
unchanged fatal owner, durable selector, Current, retained charge and held-permit
assertions. No publication or cleanup success is fabricated for those failures.

The original paused-withdrawal/new-reader case fails with an unmarked anyhow
UnknownOutcome `write deadline exceeded; resolve or retry with the same idempotency
key`. Without phase markers this could precede the pause or concurrent factory;
no paused-reader success or consistency violation is inferred. Opt-in native
trace records check-owner-native-root on .tmppOyfns/persistent/node.kv,
InvalidData original Kind(InvalidData). Later .tmpHtFQmn reports NotFound; it is
not attributed to the same case/phase without evidence. Exact NodeDiskFile
checks include retained parent/leaf/descriptor identity, enrolled/local physical
counts and actual EOF versus accounted length; no failing branch is yet proved.

Actual456 complete failed source/helper/raw preservation is pending under the
physical-order guard. Next additions borrow the exact native branch and actual
concurrent operation phase while preserving all original18 bodies, assertions,
5-second concurrent waits, SDK deadlines and capacities. Native8ede/taild208,
growing audit and transport remain source-only and unapplied. All C01–C07/
M01–M07 remain open; no live promotion or production activation.


### 2026-10-06 actual456–457: concurrent failure preserved and original file checks traced

Actual456 full failed455 preservation passes7.17s/exit0:4,178 source leaves,
4,316 verified unique members/modes,archiveSHAee4ea6fe710281197acc54d1ecbf7dbcbcbdfaff769d953e85d4e8c8ef59f091.
The snapshot includes actual current source/carrier, strictSDK18 helper/raw streams
and the preceding successful SDK14/constructor/privacy/receiver helpers and raw
streams. Earlier failures stay independently preserved.

Actual457 applies one-file original native owner branch diagnostics, MF
b9953cdea8925ef77218117d0c538f8293b5d27c6bd89d3ef529df9018157b15,
patchd2c839abccac486a79890c98a2d4ac44b35f50528b3752027ea7ac11b991613f,
full4,178. The same opt-in test-utils trace borrows the original errors and already
observed parent/leaf/descriptor identity, enrollment/local numeric counts and EOF.
Original physical metadata call count, short-circuit order, enrollment/contraction
rules, error classification, fencing, budgets and deadlines remain unchanged.
Additive concurrent phase diagnostics are pending; they preserve every original18
body/cap and will add one actual normalized duplicate. No concurrent success,
precise failing owner branch, source repair or cleanup is inferred yet.
All C/M goals remain open; native/tail/growing audit/transport stay unapplied.


### 2026-10-06 actual458–460: unchanged concurrent case with additive phase diagnostics

Actual458 adds only the concurrent diagnostic include and one duplicate, MF
017c490813247073ddee1c48a396e6eba8c256abf805becf4400820bfcb8c858,
patch2bc4df1f1bb4a3e957406985de4a7789637172f6f3f9357d8c1e6883d369c184,
full4,179/2images1new. Reverse wrapper normalization reconstructs the complete
original concurrent body byte for byte. Original18 bodies, all5-second waits,
10-second pause fallback,90-second fixture write deadline and worker_threads=2
remain literal. Each wrapper calls the original once, logs exact entrance/return
and borrows the existing paid report on SDK error without changing classification,
source authority, native cleanup, sleeps or retry behavior. A fixture error before
DatabaseRef exists is logged as the original anyhow error; detailed native tracing
can then identify its actual owner branch.

Actual459 normal Engine check passes16.15s (Cargo15.34s),all3,592 selected hashes
exact on full4,179. Actual460 strictSDK19 is pending with both opt-in trace flags,
one literal list/run selection and current original18 prefix + diagnostic1. No
storage repair, successful paused reader or positive native retirement is inferred
from source-only diagnostics. Native residency, finite tail retirement, native
growing-audit foundation/Engine caller and transport packets remain unapplied.
All C01–C07/M01–M07 remain open; no live/source/Git promotion.


### 2026-10-06 actual460 terminal and actual461–464: concurrency passes; native witness applied

Actual460 strict SDK19 passes211.78s/exit0, runtime110.29s,19 pass/0 fail/0
ignore, all3,592 selected hashes exact on full4,179 MF017c490813247073ddee1c48a396e6eba8c256abf805becf4400820bfcb8c858.
TerminalSHA2704cf4debbb4dc092d252c1734ded6baf706373f493a86fa058cc3397b16722.
The original and normalized additive concurrent cases both reach old-selected
reads while the actual write is paused, new selected reads after real publication
and retained old-alias assertions. Original18 whole bodies, bounds, waits and
error identities are unchanged. This is a private selected-source consistency
result; it is not public authorization/cursor/transport activation. Earlier455
InvalidData and441 fixture timeout remain preserved and unexplained. No native
file repair is inferred from this passing rerun.

Actual461 applies the cleanup-current native residency witness, MF
c25a048639748ce451dbcdcc3301382326a478bff9e3b55a2a86761f8919cbf0,
patcha25eecd697ca622008992cb71cf56e4617966ba4253f58e256951189810b4dfc,
full4,180/14literal original images. The prospective owning witness checks the
actual memory owner, selected directory root, unique pinned root union, nonwrapping
structural/config version and completed warm state only after source/report
cleanup. The late check is pure locks/atomics/copies, without new reservation,
allocation, read, provider or callback. This covers the known native union, not
every public generation, text origin or process RSS. Actual462 normal Engine
check passes40.91s/exit0 (Cargo40.39s),all3,593 selected hashes exact.

Actual463 omitted the source-checker's scope argument and was refused before
Cargo or source mutation (ValueError: python3). Actual464 invokes the unchanged
strict current SDK19 helper with the required engine scope and both opt-in traces;
it is pending. Native223 follows sequentially. Finite tail v3 is source-only
MF5b9e72d9d453ac7fc2cab41651eaa8b4ba61170fdbaf15a6c3dd8e880a23fad2,
direct c25a/full4,181, SDK22 and original constructor/control/native helpers
independently preserve current bodies/profiles. Root runtime qualification remains
required before adoption. Growing audit and transport stay separate source-only
prerequisites. All C01–C07/M01–M07 remain open; no live or Git promotion.


### 2026-10-06 actual464–465 terminal: native witness test conversion failure preserved

Actual464 stops during the first SDK19 list build:86.35s/exit101, all3,593
selected hashes exact on full4,180 c25a. No test result is claimed. The added
native witness test at primary_generation_refill_session_tests.rs:560 uses
cache_warmup_status()? but its existing TestError implements From<anyhow::Error>,
not From<kasumi_kv::StorageError>. Normal Engine compilation passed because this
is a lib-test conversion. Original SDK bodies, waits, limits and production
behavior have not changed. A minimal explicit conversion is being prepared as a
separate source-pinned successor; no test assertion is weakened.

Actual465 complete failed-cohort preservation passes5.03s/exit0; full source,
current strict SDK19/native223 helpers and the earlier diagnostic19 passing raw
streams are physically preserved before any repair. Native runtime gates remain
pending. All C01–C07/M01–M07 remain open; no production activation or promotion.


### 2026-10-06 actual466–467: explicit test conversion applied, original SDK19 rerun

Failed464 archiveSHA bf02f7c04f2e629c832cb78d44f6883d1bee58a1d815391db92bed3e970c7c54,
full4,180/4,338 unique verified members/modes, remains recoverable.
Actual466 applies minimal test-only conversion MF90bfe1665194da7997bf33140f3ab6abd3cd49e70745a78ec0678e646256bd49,
patchcd5f493a2e7bc89a4342ed7139629b4f40fbed55802f30ccada28f0242d83c31,
full4,180/file1. The single expression now maps the original StorageError through
existing anyhow::Error into existing TestError. Exact inverse recovers the original
whole witness body; all assertions/caps/deadlines and other bodies remain literal.
Apply inner0/outer1 is the expected source mutation, selected3,592→3,593 matching
with exactly the test file changed. Actual467 strict SDK19 is pending on this source
with both original traces; native223 follows. Source-only tail review finds no
early W/scratch refund in the finite path: positive capture/source disposal and
all actual buffers dropping precede its typed same-bank witness; failures/retained
aliases keep the original funding. Root runtime still must verify that sequence.
All C01–C07/M01–M07 remain open; earlier physical failures stay independent.


### 2026-10-06 actual467–469: post-release writer completion isolated without deadline changes

Actual467 SDK19 fails259.57s/exit101, runtime142.45s,17 pass/2 fail/0 ignore,
all3,593 selected hashes exact on full4,180 MF90bfe1665194da7997bf33140f3ab6abd3cd49e70745a78ec0678e646256bd49.
The test conversion compiles. Both concurrent cases fail; diagnostic markers show
fixture, first put, old-generation capture, pause, old selected read and both explicit/
Drop release all return. The original five-second second-writer await returns
Elapsed(()), with no terminal report then. Later fixture removal causes a retained
writer to observe NotFound and UnknownOutcome; this is not evidence of the initial
completion delay's cause. Separate .tmpBaKTJO effect-before-fence InvalidData is
not associated with the concurrent case without matching original case identity.

Actual468 complete failed-source/helper/raw preservation passes6.52s/exit0:
full4,180/4,294 unique verified members,archiveSHAcd6065b450654d18097e1f5257a93b44e53b23334744ddf595a4c0a0e813031e.
Actual469 runs only the two unchanged concurrent bodies on the same actual source
as a diagnostic, under identical worker counts, original five-second waits and
native/source traces. It cannot replace the required failed full SDK19 join.
Read-only inspection is checking real publication cleanup against retained read
loans; no cause, source repair or timing relaxation is inferred. Native223 remains
a separate available gate. Tail/growth/transport stay source-only until joined
qualification; all C01–C07/M01–M07 remain open. No live or Git promotion.


### 2026-10-07 actual469–471: focused recurrence preserved; native gate stays independent

Actual469 unchanged concurrent2 fails35.66s/exit101,runtime32.56s,0 pass/2 fail/
0 ignore,all3,593 selected hashes exact. The diagnostic reaches old selected
read and both releases, then its original five-second writer await expires with
no terminal report. This recurs without the other17 SDK cases; a full-roster-only
load explanation is insufficient. No deadline, worker count or capacity is changed.
Later effect-before-fence InvalidData is not an established cause of that wait.

Actual470 complete failed469 preservation passes18.70s/exit0. Native223
actual471 starts independently on unchanged90bf with its original68 Engine and
155 KV cases plus the explicit conversion provenance; no concurrency claim is
substituted by that component gate. Borrowed publication-stage/effect-caller
markers and exact diagnostic fixture-path correlation are source-only next work.
All C01–C07/M01–M07 remain open; tail/growth/transport remain unapplied; no
production activation or live/Git promotion.


### 2026-10-07 actual471–472: original native refill stack abort preserved

Actual471 native223 stops in its Engine68 run23.59s/exit101, all3,593 selected
hashes exact on full4,18090bf. The original selected_native_refill_checkpoint_
binds_materialized_census_to_same_completed_source_pass overflows its stack and
aborts SIGABRT; no complete Engine68 or KV155 pass is claimed. The earlier original
222-case pass remains recorded separately. The new inline NativeResidencyShape
carries256 optional DirectoryRoots through native observation, Store work and
Engine async frames; layout/frame measurement and a compact constructive
representation are required. Original stack sizes/budgets remain unchanged.

Actual472 full failed-source/helper/raw preservation passes11.67s/exit0:
full4,180/4,298 unique members,archiveSHAf408ef544e82a86ad6df2f6d33f700d158ecf260131741eed0176cff61d708a9.
An actual unique-root union clock is being considered instead of large by-value
root copies; it must normalize the selected root, tolerate same-root reader churn,
fail closed on exhaustion and cover every actual pin mutation. This is a source
proposal, not a repair or native qualification result. Publication stage/effect
caller traces are frozen direct90bf; exact fixture-path correlation is pending.
All C01–C07/M01–M07 remain open; no live/source promotion or Git publication.


### 2026-10-07 actual473–475: exact writer stages and native effect caller correlated

Actual473 applies d36722512f348d4de753d7c16db9f9e69e2a5bd0655bfbfe4e6ef62cb8051063,
full4,180/3 leaves: opt-in actual writer stages after withdrawal, ordered
publication/capture retirement, binding, Current and outer cleanup; and exact
SegmentGroup.effect caller Location captured at method entry. Original physical
calls/order/fencing and all original SDK bodies remain unchanged.
Actual474 applies fixture correlation MF414b833784bafe2d8961cb5a473243eaa1e53149248901cdd266a2eba21ab8cb,
patchaa17cda5a8053a7be6e6bbc41c57398c763c0d396c4b4a3fee714772f996f39e,
full4,180/2 leaves. The existing fixture helper logs borrowed case/path/incarnation/
thread immediately after Installation and before CreateCollection; normalized
concurrent diagnostics use the same real helper. All19 complete case bodies
remain literal. Both applies inner0/outer1 have exactly their expected source
mutations. Actual475 checks Engine original test compilation; runtime stage
evidence is pending. Compact native witness repair is separately source-owned
on this parent. No wait/stack/budget change or source behavior repair is inferred.
All C01–C07/M01–M07 remain open; no live or Git promotion.


### 2026-10-07 actual475–476: original-test diagnostics compile

Actual475 Engine --tests check passes102.06s/exit0 (Cargo1m41s),all3,593 selected
hashes exact on full4,180 MF414b833784bafe2d8961cb5a473243eaa1e53149248901cdd266a2eba21ab8cb.
Actual476 focused original concurrent2 is pending on the same source, with
existing trace flags and exact original profiles/body/deadlines. Writer stages
and effect-caller diagnostics do not change publication ordering or error custody.
Failed469 archiveSHA f0b92bef55964ed6dd8bcd5b0206401ff87735eec6573019bb6e1446d5b23c79,
full4,180/4,294 unique members, is recoverable. A compact native union-clock
proposal covers actual selected/nonselected distinct root membership under the
existing pin mutex; copy-heavy witness/frame overflow remains unfixed until
Root original native gates pass. All goals remain open; no live/Git promotion.


### 2026-10-07 actual476 terminal: instrumented original concurrent2 passes without behavior repair

Actual476 focused concurrent2 passes161.05s/exit0 (Cargo2m20s/runtime20.13s),
2 pass/0 fail/0 ignore, all3,593 selected hashes exact on full4,180414b.
Both actual fixtures are correlated by borrowed path/incarnation markers. The
diagnostic writer returns through withdrawal, workspace, response/acceptance,
ordered operation/verification/inventory, actual source publication, capture
retirement/native close, backing disposal, metadata bind/transfer/installation,
registry activation, Current publication, producer/accepted cleanup and permit
drop. New selected read, old/new alias retirement and actual shutdown all return.
The original five-second await remains unchanged. The source adds only borrowed
stage/fixture/effect-caller diagnostics; this passing rerun identifies no repair
or cause for467/469 completion timeouts or earlier physical failures.

Compact native witness representation remains required for471's original stack
overflow. Next actual qualification is its original overflow case and complete
native/SDK joins, followed by finite W/scratch retirement and funded growing
audit/index/transport work. All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual477–480: compact exact native union clock adopted and native7 qualified

Actual477 adopts compact native membership revision MF7aa7a5797d3736580a3bbba3700e2b82b2034283aec99e265d5d00a93daa2a71,
patch9ea9e3a3021851a986d85eb752a9c06ed50fe88651b2c8ba5dd1849230a8ab9a,
full4,181/7 files. Every actual ordinary/protected/history slot replacement uses
the existing pin mutex; only distinct nonselected first/last membership advances
a nonwrapping Option revision. The actual Core selected root is synchronized at
capture and independently checked at final observation. Duplicate/current-reader
churn is ignored; exhaustion permanently removes optional witness eligibility
without fencing storage. No root hash, raw address, large captured root array,
new grant or heap backing supplies authority. All original SDK19 and237 pinned
native whole-body rows remain literal.

Actual478 exactclock7 passes12.27s/exit0,7/0/0,full4,181/all3,594 hashes exact.
Actual native sizeof shape=160,witness=168,Core observation=208. The standalone
leaf-field probe additionally measures Store observation232 and representative
async240 versus old24,800/24,808; this is not the complete Engine future stack.
Seven real pin/history/cleanup/exhaustion/layout tests pass. Original refill
overflow and complete native230/SDK19 qualification remain required.

Independent review finds Resident+absent witness can be transient: warm_status
samples actual shared cache capacity twice, so ordinary protected grant changes
or aggregate resize can mismatch AutoWarm/status. Actual479 therefore applies
MF a5a9cbd68b999cc28a3a7a055b0887fcc19b0e9e35ea7e43bca164a29d9429aa,
patch2b96c0e6a4943e306f667fd48364b050cf38b2872ed489b6c73825be3a6f3657,
full4,181/file1: use existing Waiting(Resident) and actual worker revisions,
retaining suppression of own generic capacity/refund wakes. Genuine failed
lifecycle WaitingTerminal is unchanged. Source-audited liveness is not yet an
Engine absent-witness scheduling pass; that additive case is being prepared.
Actual480 original overflow1 is pending on this transient-safe compact source.
All C01–C07/M01–M07 remain open; no live or Git promotion.


### 2026-10-07 actual480 terminal: original refill stack failure repaired under original profile

Actual480 original refill checkpoint passes140.19s/exit0 (runtime4.31s),
1 pass/0 fail/0 ignore,all3,594 selected hashes exact on full4,181 a5a9cbd68b999cc28a3a7a055b0887fcc19b0e9e35ea7e43bca164a29d9429aa.
TerminalSHA2bcfd6696e3213d7465f1877c231295420e0fc8fa0436a79e77c213bf0935de6.
The exact original body/profile/stack/capacity now runs with the compact native
witness. This repairs the scoped original overflow case; complete native230 and
SDK19 remain required. Current full4181 source hashes/modes were independently
revalidated before actual481 native230 started. Earlier concurrent/physical
failures remain unresolved; all C01–C07/M01–M07 remain open.


### 2026-10-07 actual481–484: full compact native230 passes; real absence recovery joins

Actual481 passes316.71s/exit0, all3,594 selected hashes exact on full4,181
MF a5a9cbd68b999cc28a3a7a055b0887fcc19b0e9e35ea7e43bca164a29d9429aa.
Engine68 passes300.99s and KV162 passes9.54s, with zero failures or ignored cases.
This preserves the original16,513-row full-fit, aggregate shrink/growth, snapshot
and lifecycle cases alongside all7 compact membership-clock cases.
TerminalSHA c7067df5bbb8463797d0b1ec5ad450a86bcb5a1a74920f85c833fe249f3966f9. The original471 stack overflow is repaired
under the unchanged test profile, stack and bounds. This component join does not
activate complete public/text residency or qualify whole-process memory.

Actual482 applies the additive same-node missing-witness test carrier0a5ca318
(full4,182); actual483 applies its recovery successor
a3d6603c114b6a3fcc14d44709efc28107176d16802c46a28433939bcbaeb886,
patch04d70f5860f20d8f2d9bc0432c5f60313fd03094af56a73ba6960ae95ff7e38a.
The two changed test leaves retain original case bodies and use two fixed
node-identity hook slots. The new case removes witness withdrawal, drives the
actual worker to Disabled at zero cache, observes the same pending waiter wake,
then restores precisely the installed original bound and requires witnessed
KnownUnionFit. Parsing/source review and immutable checks pass; actual484
parking2 runtime is pending. Each apply inner0/outer1 has only expected source
changes. Full SDK, finite workspace cleanup, growing metadata and production
cutover remain open. No live implementation/Git promotion; all C01–C07/M01–M07 open.


### 2026-10-07 actual484–486: preserve absence-test census supersession failure

Actual484 parking2 compiles and runs89.30s/exit101; one pass/one failure,
6.34s runtime, all3,595 selected hashes unchanged on full4,182 a3d6603c.
The actual native worker recovery case passes. The authored combined absence
case reaches `absent_resident` with `Pass::Superseded` after deliberately adding
a registered generation. Source inspection shows that registration invalidates
the retained registry census; the test must explicitly assert supersession and
checkpoint removal before beginning a fresh finite pass. Same-pointer fixture
publication does not itself invalidate retained_selection_unchanged. This is a
new test protocol correction, not permission to ignore arbitrary Superseded
results or weaken native-pending wait assertions.

Actual485 preserves and verifies all4,182 source leaves,4,270 archive members,
raw logs/helper/modes in4.65s. ArchiveSHA
6cd3aa92303147cd7dd888511a4146e4798baacf90054b3b36af56dd5e602d37.
No repair applied yet. Actual486 runs originalSDK19 on the unchanged a3d source
to qualify the compact production witness independently of the new authored
test protocol. All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual486–488: complete SDK19 on compact witness passes; census test corrected

Actual486 passes85.61s/exit0, all3,595 selected source hashes exact on
full4,182 a3d6603c. test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 1319 filtered out; finished in 83.10s
TerminalSHA 6ae2771813075f06ea9a85f74ebf3c269a4f14fcf59a886c078d4591135305bc. Both concurrent old/new reader cases pass
with unchanged original five-second await and budgets; canonical replay,
rejections, counters, same-bank ownership and shutdown cases also pass.
This does not diagnose the earlier intermittent completion/physical failures.

Actual487 applies only8 lines in the authored absence test, carrier
c18b7348361e40cab6af76af4d61e7cce2754a49c5a9aaa03898636dd0f69cda,
patchf25bc3f88bde27cd1343d8b5e4642415f0f3d6d3e6f60a8f363253a89b76042c.
The test now explicitly requires Superseded and no checkpoint after the actual
registry insertion, then the same Session's readiness for a fresh finite pass.
Missing-witness waiting assertions, recovery case and all earlier bodies remain
unchanged. The changed authored test body is explicitly repinned; inverse
insertion reconstructs its preserved failed source. Actual488 parking2 is
pending. No production behavior changed in487; all C01–C07/M01–M07 remain open.


### 2026-10-07 actual488–491: exact backtrace identifies publication lease-census invalidation

Actual488 parking2 fails41.58s/exit101,1 pass/1 fail,8.18s runtime, source
unchanged c18b/full4,182. Actual489 preserves complete source/raw/modes
in4.70s, archiveSHA d28b553f34d6f2db5ab188d4c6939f751739c3eb8c2618cc99e0f1bb5f9cc27f.
Actual490 same-source RUST_BACKTRACE=1 rerun fails9.52s/exit101,1/1,7.00s
runtime. Its exact backtrace identifies authored helper call line79, BEFORE
the deliberate registered-generation insertion. Actual491 preserves it in4.53s,
archiveSHA 436a80756832ab3684721866840ef50d2000962f127e811bb32d769558f846a3. Both archives verify4,182 source leaves.

The earlier pointer-only explanation was incomplete: TenantEngine publication
passes through LeaseManager::publish, which unconditionally calls refill_changed
before Current swap, including the same GenerationRef and empty lease set.
That actual lease revision invalidates retained_selection_unchanged. The new
test therefore needs an explicit publication/lease Superseded transition before
its separate registry signal stage, in addition to the valid later registry
Superseded assertion. Native waiting predicates remain strict; no production
change is indicated. The real worker recovery case passes in both runs.
All goals remain open; no live/Git promotion.


### 2026-10-07 actual492–494: exact lease transition exposed oversized authored test frame

Actual492 applies test-only f5070d6381f71589e314830a7b649b02ec2014a18b0935ec0fa32c08249f9104,
patch569cd81e20cf93e70b4b3e55065b527b680a1a8a3bc42afcd5f8919ef1712919,
one test leaf/full4,182. It asserts the real before/after lease revision and
Superseded/no-checkpoint/fresh-pass transition after same-pointer publication,
preserving the independent registered-generation transition. Actual493 compiles
but aborts43.02s/exit101 with a stack overflow in the combined authored absence
test before a terminal case result. No pass total is inferred from that run.
The extra inline Session::fill await states enlarged the test scaffold; the
original production refill/230-case qualification remains separately recorded.
An explicit test-future placement correction is pending; no stack/capacity
increase or production behavior change is authorized by this failure.
Actual494 preserves and verifies full4,182/4,272 members in4.57s, archiveSHA
b0e550f56e45a5f1b1119526cb84c81086a459daeecac4069aa286fc2c131901.
All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual495: compact native foundation normal Engine compilation passes

Actual495 normal cargo check --locked --offline -p kasumi-engine --lib passes
46.78s/exit0 (Cargo45.94s), all3,595 selected source hashes exact on f507
full4,182. This checks the ordinary production build of the compact native
witness and pending-witness wait behavior without cfg(test). The authored
combined test-frame placement correction is still pending; production SDK19
and native230 passes remain scoped prerequisites. All goals remain open.


### 2026-10-07 actual496–498: two authored transition futures boxed; source fence stops premature runner

Actual496 applies exactly two test expressions from f507 into
45fce382664d4f0ff04c62418d0717eac0502b6b6db9bc6ad71d6f4854147615,
patche6e1967d31a35e817bf4df8800bc37abb1a4c99ac382b83d44af01c71441902d,
full4,182/one file. Only the newly added direct transition fill futures now use
Box::pin; assertions/stages/deadlines/capacities and production remain unchanged.
The inverse reconstructs the preserved failed f507 test. Apply inner0/outer1
contains exactly the expected test leaf.
Root mistakenly dispatched actual497 before the apply tool session reached
terminal. The strict source guard rejected the old leaf before its first Cargo
call (0.35s/exit1); this is an orchestration failure, not a test outcome.
Before/after manifests and test leaves, both commands and source snapshots are
preserved in /tmp/kasumi-actual497-pre-cargo-source-fence-rejection-v1.
Actual498 starts only after actual496 terminal on the verified45fc source and
uses a distinct runtime directory. parking2 pending; all goals remain open.


### 2026-10-07 actual498–499: direct boxing did not remove authored test construction stack

Actual498 fails84.92s/exit101, SIGABRT stack overflow in the authored combined
absence test, with no terminal case total. All3,595 selected hashes unchanged
on45fc/full4,182. Direct Box::pin around the two new fill awaits is insufficient
to isolate construction temporaries from the enclosing test frame. A separate
boxed helper-frame correction remains required; no stack/cap override or claim
of a passing test is made. Actual499 preserves the complete failed source,
helper/raw logs and modes; archiveSHA cce0bb32aa9f3b6a4de09f1e79cd1a618db953f28b903892c233af941b83232a.
The original production native230, normal Engine and SDK19 gates already pass
on the compact production source. Independent finite workspace-retirement
qualification may proceed in isolation; the authored test failure remains open
until corrected and qualified before any production promotion.


### 2026-10-07 actual500–502: finite sparse temporary retirement adopted and normal Engine passes

Actual500 adopts the previously reviewed literal12-leaf retirement patch
6adf4cab2d7b63693508894a003b650bf240620229c04c0d7f6793d9223a3f3a on45fc,
carrier d38114346b216dd8afeac91dfbb73a05fce54a5a2a9b9312178208cb6143b422,
full4,183. Original bank and actual Current identity, positive ordered
capture/source/workspace disposal, producer scratch retirement and accepted
outer data cleanup all precede narrowing the same payload slot and bank ceiling.
Refused exact ledger joins restore the original ceiling; relief callbacks occur
outside locks. Retained payload/metadata/native/source/error/control tails stay
funded. All original SDK19 cases are retained; three added real SDK cases cover
positive same-slot reduction and returned/raw failures retaining full funding.
Actual500 inner0/outer1 shows only expected11 existing changed leaves plus1 new
test. Actual501 normal Engine --lib check passes23.79s/exit0 (Cargo22.72s),
all3,596 selected hashes exact. Actual502 SDK22 is pending on full4,183.
The independent authored native absence-test frame remains open and preserved;
its separately boxed helper correction will join after this runtime terminal.
All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 physical-enrollment obligation refined from source and preserved evidence

Independent read-only diagnosis /tmp/kasumi-physical-enrollment-readonly-diagnosis-v1.md
SHA54da960d91ceb13e826ad2605f2f630437e7452d06c9a134bc1cf1ef97c0800c;
full pins/labels /tmp/kasumi-physical-enrollment-readonly-diagnosis-v1.json
SHAb6fcfbe5fe7e2e16c4edce3838597d535b40da9edc12af96d8a8ee2563fbbd7e.
The narrow prepaid above-EOF contraction accounting repair is scoped-qualified:
NodeDisk191, original encrypted byte-image786.66s and expiry/reopen94.08s.
Exact original geometry hooks, live Budget synchronization and negative identity,
holes/growth/unsettled cases pass; current core/cursor/test source remains
literal to recorded selected pins. The goal no longer incorrectly groups those
as an entirely unfixed guard defect. No verified APFS trigger is claimed.
Opaque467/469 and earlier check-owner-native-root InvalidData remain independent
open gates; current check_owner does not compare allocated-block counts.
First-error caller/fixture/branch correlation is still required. This refinement
closes only the narrow historical accounting defect, not final-source recovery,
physical-failure acceptance, any production milestone or any C01–C07 goal.


### 2026-10-07 actual502–505: SDK22 failure preserved; separate test-frame correction adopted

Actual502 finishes508.55s/exit101: SDK22 has8 passes,14 failures,0 ignored
(runtime299.22s), all3,596 selected hashes exact on d381/full4,183. Failures
report completion deadlines/UnknownOutcome; none establishes a tail-credit
assertion failure. Source review found no new await or strong-reference cycle
in temporary retirement and observed matched retirement/permit entry/return
traces. These observations do not diagnose or repair the failures.
Read-only host observations show very high concurrent load (208.86 during the
run;379.52 afterward); a2s process sample captured active native baseline
construction. Host contention is not established as the cause, and deadlines,
capacity settings and original test concurrency remain unchanged.
Actual503 preserves all4,183 source files and4,248 members with modes in
/tmp/kasumi-actual502-sdk22-temporary-retirement-failed-fullsource-v1.
ArchiveSHA fcb581c8dc1be44effd59b743f05abf4c24e09d839078888b3e5e17f44faa616;
preservation39.99s/exit0 with unchanged selected source.
Actual504 applies test-only carrier38067fef14858b733f9e34b92185c4cecff39a053c02f6a67b937e87cdfa2a5a,
patch773f8931c4d1d20f035be267d32336ca251a205ff86587277e1d077a0d7b9193,
on literal d381. A separate non-inlined function constructs the boxed future
for the two authored Superseded assertions, preserving stage order, same
Session, deadlines, original budget and recovery behavior. Inverse/forward
verification passes; inner0/outer1 shows only the expected test file.
Actual505 runs the exact two absence/recovery cases; runtime pending.
Goals now order the remaining production blockers explicitly: completion and
retirement, indexed publication, complete command/replica producers, public
selected readers/census, all-index finite residency, then final workload and
release qualification. All C01–C07/M01–M07 remain open; no production promotion.


### 2026-10-07 actual505–510: native absence recovery passes; indexed/growing source integrated

Actual505 parking2 passes231.64s/exit0,2 passed/0 failed/0 ignored,
runtime25.64s, all3,596 selected hashes exact on3806/full4,183.
TerminalSHA 3b43dc7f8ac00f16116f722308354f96d43281d14cac031a38f7e33595eacf63.
Both actual native-witness absence wait and worker-driven recovery now pass;
the separate non-inlined boxed test helper resolves the authored construction
stack failure without changing the original stack, deadlines or capacity.
This closes that authored-test defect only; native232/final-source public
residency and all goal acceptance gates remain open.
Actual506 adopts combined c69c6a1f8a5fe38c20b172922c646a6c1a1f4efbc4364245b3eb6212998d26d0,
patch4304b8a11893061dd0e23fb418ca11c946ac221310b7c57ee50752852b6aaa25,
full4,193/45 leaves: literal structured index producer, native growing vector,
Engine audit growth, unique producer and exact unique header funding quote.
Each original packet and the combined result pass inverse/forward verification;
original tests/caps/profiles remain. Transport and multi-collection are excluded.
Actual507 normal Engine compilation fails8.66s/exit101 on two E0689 integer
inference errors in new native GrowingVectorGeometry::geometry. No runtime
claims follow. Actual508 preserves full4,193/4,250 archive members/modes,
archiveSHA bedfd6bceb7a97faa3c6f31f50a4b9a59e79868cd489cd311b2a67ee8f2fa4f1,
21.17s/exit0; selected3,606 hashes exact.
Actual509 applies ae174806d81bab6214460896ed8f92593151fea54a58919057526bc51952680e,
patch32190a0c916657591aa033a34e180a61a9ecb11c27509ea70d1a6ef3f25069b2:
only the two counters' initializers become0usize and the exact vendor source
fingerprint is updated. Inner0/outer1 contains the expected native leaf;
all original test bodies and capacities remain. Actual510 normal Engine check
is pending. All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual510–513: internal unique validator visibility corrected

Actual510 normal Engine compilation fails260.23s/exit101 on sole E0624:
the reduction parent calls validate_unique in its child module, where that
method was private. Native geometry/type checking progressed past actual507.
All3,606 selected source hashes remain exact on ae1748/full4,193.
Actual511 preserves full4,193 source and 4204 archive members/modes,
archiveSHA 2a1099910b462f4a9b0ea17e3ee962bed31f330422fbbbf0b0cee068ac174966,76.05s/exit0.
Actual512 applies0cfae9ae960ee6317f1f8710e757bec8fa96359980bc91ad868988883ee8a3d6,
patch27a4fe8286420c24bd44dce3353194d538d8c5512accec009c5b3b2d6669a35e,
parent ae1748/full4,193. Only validate_unique becomes pub(super), permitting
its actual parent-module caller without widening the external API; body,
original tests and budgets are unchanged. Verified inverse/forward passes;
inner0/outer1 shows the single expected Engine source leaf.
Actual513 normal Engine check is pending. All six original/additive native,
SDK and Query helper selections are forwarded unchanged to exact0cfa.
The actual502 source/log review isolates a secondary failure mechanism:
query-anchor fixture setup can drop its TempDir after an administer timeout
while its admitted child continues. Matching subsequent NotFound is teardown
induced; actual502 has no InvalidData. This does not identify the initial
delay. A narrow fixture cleanup/cancellation custody fix is being authored;
all earlier opaque InvalidData and initiating timeouts remain open.
All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual513–514: indexed/growing normal Engine passes; full native profiles running

Actual513 normal Engine --lib check passes104.03s/exit0 (Cargo1m42s),
all3,606 selected hashes exact on0cfa/full4,193. This qualifies compilation of
the joined structured/unique sparse producers and growing audit-header callers.
It does not establish runtime semantics, pressure behavior or production cutover.
Actual514 runs the published imbl original132-package graph against its exact
selected native source under default, production-serde and all-features complete
library/doctest profiles, retaining original cases and19 native additions.
Helper /tmp/kasumi-unique-validator-visibility-imbl-helper-v1,
MFe26c716b3074782f8aa9247552738999754ab9de34d8360b6c5224d441462e47,
qualifySHA72919268d2f3ad84922fd5475b2e4cc47a1c6b42a1a02037ee2e3e491fa13601.
Runtime pending; same sole warm target and original profiles/limits.
The query-anchor fixture cleanup draft is independently reviewed. Root found
an unpolled-future hole in the first draft: an async-fn body constructs its
retention guard only on first poll. Its successor will construct the guard
synchronously and add the actual admitted-child unpolled cancellation case;
the initial authored source remains preserved and has no runtime pass claim.
All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual514–516: native original profile catches a missing test trait import

Actual514 fails139.93s/exit1 with all3,606 actual selected hashes exact on0cfa.
The published original imbl default library passes122/0/0 in45.27s. The selected
native --list build then fails7 E0599 at the same cfg(test) header-leaf module:
GenericOrdMap::from_iter requires an explicit FromIterator import under the
unchanged upstream Cargo edition. No selected runtime or full-profile pass is
claimed; original profile/graph/manifest are not rewritten to bypass it.
Actual515 preserves full4,193 source plus complete original/selected helper,
raw native logs and4394 members/modes,41.14s/exit0;
archiveSHA 63f3165e92ad05e20b6c205ff6a444d91a58a82532152b15e2e059066e1daa3d.
Actual516 applies e93f41ff7a3a9bed5c524a5ea4a1fce811388ea15b3be46ab63fd95dcb111711,
patchceccf1f586b6e89b2c5f9ec502b970d574637016d283ec41c3fc7c4e7286662a,
parent0cfa/full4,193: only the explicit FromIterator test-module import and
exact vendor fingerprint. Every original/additive case body remains literal;
one inserted import line changes the later case source positions. Verified
inverse/forward passes, inner0/outer1 shows only the expected native leaf.
Production is unchanged since normal Engine513PASS; native runtime rerun pending.
All C01–C07/M01–M07 remain open; no live/Git promotion.


### 2026-10-07 actual517: original native profiles rerun after trait import repair

Actual517 runs /tmp/kasumi-native-header-test-iterator-imbl-helper-v1 on
exact e93/full4,193. HelperMFa6019921f020b4756fb660117789088e02555bf2ef09bcb9b0b7fc0d7a3f1bfe,
qualifySHA96a4d0cd7d30cce076d50d0eec88052037152579bac9cddf36e97bc251907fb8.
Original132 graph, all three complete library/doctest profiles, parser/runtime
functions and19 additive whole bodies remain literal; source-line positions
are repinned for the inserted trait import. Runtime pending, prior failures
preserved, all goals open.


### 2026-10-07 actual517–519: explicit native header-test input types

Actual517 fails160.70s/exit1 on unchanged actual e93/full4,193; original
default library passes122/0/0 in76.70s. Selected test compilation reaches four
E0277 at authored header-leaf FromIterator inputs: unsuffixed integers infer
i32, but the declared map requires u64. Original graph/profile/edition are
unchanged. Actual518 preserves fullsource, complete original/selected helper,
raw logs and4395 members/modes,66.29s/exit0;
archiveSHA 84337fb5d4cff1e3b71bc7263b8fda7a898591ce0f5e7979a18f8d58b031b66e.
Actual519 applies ff94bb059412ff47efe594b3178346f9d02d124489c0798a8bbce0271ae50882,
patchfd0a836b108d3bee5ff328a39129811538e8b69750323e52ef19de2a822cfefc,
parent e93/full4,193: four exact authored input expressions acquire intended
u64 suffixes, plus the vendor fingerprint. TEST_LITERAL_REPAIR.json records
every substitution. Numeric values, assertions, capacities, graph and profiles
are unchanged; four additive body pins must explicitly change, while original
published cases remain literal. Failed prior bodies remain preserved.
Verified inverse/forward passes, inner0/outer1 shows the expected native leaf.
A selected test compilation gate will precede the whole-profile rerun to expose
any remaining compile errors before repeating the baseline runtime. Production
is unchanged since normal Engine513PASS. All goals remain open.


### 2026-10-07 actual520–521: selected native test compilation passes

Actual520 compiles the exact selected native default library tests with
--no-run on ff94/full4,193. PASS30.18s/exit0 (Cargo26.08s), all3,606 selected
actual source hashes exact. Root's /tmp/kasumi-native-u64-selected-compile-root-v1.py
verifies the complete immutable helper and actual source before and after the
original fenced Cargo invocation. Runtime tests=0; this is only the compile gate.
Helper /tmp/kasumi-native-header-test-u64-imbl-helper-v1
MF58cf936eed842470d196ad41b3eaf13fcd730304cafff1b50763d65d97447493,
qualifySHA6123f67fffe1995cace0baba0f1f24cce7b124f51625e9e9ce2d444e05260bc2.
Actual521 now reruns all unchanged original native profiles on that exact source;
only the four explicitly recorded authored type-inference body pins differ.
No production behavior changes since normal Engine513PASS, no runtime completion
claim, all goals open.


### 2026-10-07 actual521–522: strict native listing exposes helper roster errors

Actual521 fails120.50s/exit1 before selected runtime; actual ff94/full4,193 and
all3,606 selected hashes remain unchanged. Original default library passes
122/0/0 in34.38s, and the selected library compiles and lists144 tests.
Strict set equality finds five expected header-test paths missing the actual
ord::map module and three existing prepared-leaf cases omitted from the helper.
This is a qualification-roster defect, not a new library/test change or a
selected runtime result. The helper successor must correct those five names,
include the three exact original leaf bodies and require all22 additions plus
the published baseline namespace. No case deletion, profile change or relaxed
set comparison is authorized by this correction.
Actual522 preserves full4,193 source, complete helper and raw runtime logs,
4398 members/modes,32.94s/exit0;
archiveSHA 8110b0f9145f21c857117773980e9deefab6dacc3bacf7ed41c98cee4ac67f0e.
Separately, Root's targeted follow-up review of the unadopted public-generation
census found a genuine late-failure invalidation gap, confirmed by independent
source review: Cell failure/native_retained can change after a visited COVERED
cell without public/registry/current/native witness invalidation. The original
e329 draft remains preserved and unpromoted. A checked availability clock and
monotone UNKNOWN publication ordering, plus an actual late-failure case, are
required before its full-residency checkpoint can be qualified. No observed
runtime false-Resident is claimed. All goals remain open.


### 2026-10-07 actual523–525: exact native empty-header ownership

Actual523 reaches the complete selected default native runtime:143 passes,
1 failure,0 ignored in17.83s; the original default122 pass in49.71s.
The failing authored copy case incorrectly assumes public Vector::ptr_eq
identifies inline-empty clones. Upstream documents that inline clones do not
share an allocation. Review also finds a production ownership defect: public
ptr_eq deliberately equates distinct empty Single chunks, so it cannot establish
which prepared owner may retire an empty header.
Actual524 preserves full4,193 source, complete helper and raw runtime logs,
4401 members/modes,30.58s/exit0;
archiveSHA 1fbc56d12b2472b3f151a40e904dbbf01543f764bad3d7fb1a21368303ecb427.
Actual525 applies5a8b249782d344e8a9408cd97bc519fd40ebc43615d4456c2ae983bbde45ef22,
patchac81a13f15a38bd3601e5350895f4155ecef5022b880422d8eb0129e8fdaf40e,
parentff94/full4,193. matches_header now compares the actual Single controls.
The authored source-preservation assertion distinguishes inline-empty value
preservation from exact heap-control preservation. A new regression gives two
independent empty headers their own original loans, rejects foreign retirement,
and proves each loan remains until its own final alias/control is retired.
No capacities, profiles, deadlines or published-original cases change. Verified
inverse/forward passes; the expected native leaf is the only selected change.
Actual526 runs the two exact changed/additive cases before all23 additions and
original default/serde/all-features complete library/doctest profiles. All five
new growing-vector cases passed inside failed523; that is not a full-profile pass.

The source-only public-census successor5dbe is independently reviewed and sealed
on5a8b, with SDK35/public3/native232 helpers. It incorporates the synchronous
fixture cleanup guard, supported genuine public origins, and checked invalidation
for late failure and covered retirement. The earlier e329 freshness gap remains
preserved. Multi-collection successor227a is sealed on5dbe with SDK36/Query180;
its new fixture keeps the shared cleanup guard through setup and final drains.
No M06 or multi runtime pass is claimed. All goals remain open; no live/Git promotion.


### 2026-10-07 actual526–527: native exact-header regression passes

Actual526 PASS79.08s/exit0; exact focused namespace2,2 passed/0 failed/0 ignored,
all3,606 actual selected hashes unchanged on5a8b/full4,193. The tests cover
source-preserving copy and two independently funded empty controls with a held
alias. Runtime /tmp/kasumi-native-small-header-focus2-runtime-root-v1/TERMINAL.json.
Actual527 is running the complete original132-package graph, default/production
serde/all-features library and doctest profiles plus23 native additions, using
/tmp/kasumi-native-small-header-identity-imbl-helper-v1,
MF40b0d33bbe840b6fa2d2281d0797191b6e59a5efe9fa1b22613ce58a573be14b,
qualifySHA82b468208624172e97b21f8fcd8a4f49e14e17b9aa1fe4afb47e80e4f142deb3.
The related native owner audit finds no analogous map/growing-vector defect:
prepared maps always carry a Some leaf and compare its actual SharedPointer;
the growing-vector owner already compares each actual control explicitly.
SDK36, Query180, public3 and native232 are now all prepared on coherent multi
source227a/full4,201. No combined compile/runtime pass or goal closure yet.


### 2026-10-07 source review before the combined indexed SDK run

Root's additional full-fit test exposes an inherited authored-test wait mistake
before runtime: the global query-anchor helper requires every Database QuerySlot
to be Empty. Structured, unique and multi tests call it for a released newer
result while intentionally retaining an older SelectedQueryResult/row, whose
original QueryLoan must keep its slot alive. Independent review confirms four
structured calls, one unique call and one multi call executed three times.
A distinct successor will wait for the specific released original charge while
asserting the older charge and anchor remain, then use the unchanged global
helper after the last old alias is dropped. Original SDK22 bodies, deadlines and
budgets stay unchanged. The new structured/unique fixture custody is also being
joined to the existing synchronous cleanup guard. No new runtime failure has
been observed and this does not explain actual502, which predates these cases.

Root source-only full-fit addition /tmp/kasumi-indexed-multicollection-fullfit-root-v1-work
MF4788a4efc078413f836a557e24963b3ab4dd979da85340bc5a4a2d7f69d403f0,
patch54689c90f2f9d934ae55e291402784dd73288716bbeab9e78158d9e6e1b603b2,
parent227a/full4,202,2leaves. It uses actual SDK-owned three-collection
String-unique/Number/Boolean metadata and parented refill, then compares native
loads/uncached_loads/evictions over selected indexed reads before and after an
atomic update/delete. Its post-update wait needs the same distinct correction;
initial serving waits correctly remain global. The old row/charge proves retained
output ownership, not a new read from every old generation. This is not public
cursor/text/transport, all-filesystem-I/O, RSS or universal full-residency proof.
Prior source remains immutable; no actual adoption or runtime pass is claimed.


### 2026-10-07 actual527–530: all native profiles pass; public/multi integration applied

Actual527 PASS1359.49s/exit0 on5a8b/full4,193, all3,606 selected actual source
hashes unchanged. Thirty fenced Cargo calls preserve the exact published
132-package dependency/feature graph and compare complete original/selected
namespaces and statuses. Default and production-serde libraries each pass145
(original122 plus23 additions); all-features library passes155 (original132
plus23). Complete original and selected doctests pass120/120/125 for the same
three profiles. Every target has0 failed and0 ignored. This qualifies the
native empty-control repair and growing audit-header support at this scope;
it does not qualify the later growing feed draft or production activation.
Terminal /tmp/kasumi-native-small-header-original-imbl-runtime-root-v1/TERMINAL.json,
SHA30c7b8b19d7b1718a2c329a7bef06a31f5c263a1beaf7eb4bfcdff617186ba08.

Actual528 applies reviewed public-census source5dbe on5a8b/full4,197,
14 leaves, verified inverse/forward,4.00s; inner0/outer1 is the ten expected
previously selected changes plus four added sources. Actual529 applies reviewed
multi-collection source227a on5dbe/full4,201,19 leaves, verified inverse/forward,
2.08s; inner0/outer1 is the fifteen expected previous changes plus four new
sources. The actual isolated source now contains the original cleanup guard,
supported public generation origins/late-availability invalidation and funded
multi-collection publication. No live source or Git promotion occurred.

Actual530 normal Engine --lib check is running on exact227a/full4,201 with
3,614 selected source/config files. The distinct authored indexed-test wait and
custody correction is being prepared before SDK36 runtime; production source
is independent of that correction. Query180, public3 and native232 are prepared
on227a and must follow any exact source successor before execution. Root's
additional indexed full-fit case remains separately unadopted. All goals open.


### 2026-10-07 actual530–533: initialize private public-origin state; correct indexed fixture waits

Actual530 normal Engine compilation fails179.15s/exit101 with all3,614 selected
hashes exact. The sole compiler error is E0063 at
application_source_private_current.rs310: its real private Cell constructor
omits the newly added public_origin field. Independent review confirms that
this private, preparing SourceReader must start UNSEEN, just like the ordinary
Cell constructor; it has not escaped as a public Generation. No public authority
is inferred from private construction. Both real Cell literal constructors
were inspected; unrelated startup/text Cell types are separate.
Actual531 preserves full4,201 source/raw evidence and4233 archive members/modes,
9.17s/exit0, archiveSHA06c0466376d211a5328c10b3c7cb0de861fce18a32fbec5fa3a6214a864de276.

Standalone one-line repair /tmp/kasumi-public-origin-private-current-init-root-v1-work
MFdf25100005ecd43bf7524cc3f19d63f3319d15efd1040613aa5ab857b90167c7,
patch3df47226db0c36d82ba3844495d7772b743e20bcf82300fad949a59b0bb32fa5.
The independently reviewed indexed-test correction is distinct source d217,
full4,202/5leaves. It keeps original SDK22 bodies and the global empty-anchor
helper literal; four new authored assertion cores are retained except explicit
intermediate exact-charge waits, and their fixture custody uses the synchronous
guard. Multi has one intermediate wait substitution. All final old-alias waits
remain global after final disposal; all original5s bounds and capacities remain.
Its exact proof is in CORRECTION_AND_CUSTODY_PROOF.json, SHAafb0426e4eaa285ab2d1f1238dfe7c01685055271c1acf398c7b32beed11bc64.

Actual532 applies literal combined source
/tmp/kasumi-public-origin-init-indexed-correction-root-v1-work,
MF660dd2a1bc427eb19896a4bc6a7828c960e432ad86796cd3dd2a1d86ff9a20b7,
patchc26285ebd3407b789f197e5f6e4f370af5342b38a83127f5034a4e484f802823,
direct227a/full4,202/6leaves. Verified inverse/forward,1.43s; inner0/outer1 shows
five expected previous leaves plus one new helper. Actual533 normal Engine
check now runs on660d with3,615 selected source/config files. Strict SDK36,
Query180, public3 and native232 helpers are being forwarded without roster,
profile or runtime changes. Runtime remains pending; all goals open.

The user reaffirms first-release canonical design and removal of old code.
Goals now explicitly require deletion of superseded resident implementations,
obsolete APIs and permanent compatibility paths after their canonical replacement
is integrated. The unqualified full-copy growing-feed draft is retained only as
source history: its O(retained feed) copying and original whole-bank retention
are structural release blockers. Canonical bounded disk headers/selected access
and exact retained ownership take priority over qualifying that interim design.
No live/Git promotion and no production feature loss are claimed.


### 2026-10-07 actual533–534: joined normal Engine passes; corrected SDK36 runs

Actual533 PASS79.80s/exit0 (Cargo1m18s), all3,615 selected source hashes exact on
660d/full4,202. This qualifies the private UNSEEN constructor repair and normal
compilation of the joined public census/multi-collection source. Actual534 now
runs strict SDK36 with the original names/profile/Cargo loops, corrected authored
waits/guards and original22 whole bodies. Helper
/tmp/kasumi-public-origin-init-indexed-correction-sdk36-helper-v1,
MF7906c71c25222aaee43b2fb6f113a6611906a0f69b682909d44cb558e42abd15,
qualifySHA79bcec4ff37652f5eead3a5e43b154d0c53df2175285d7ca8ed065a40e96d2da;
runtime /tmp/kasumi-public-origin-indexed-multicollection-sdk36-runtime-root-v1.
Runtime pending, original caps/deadlines unchanged, no goal closure.

All other helpers are forwarded to the same660d/full4,202: Query180
/tmp/kasumi-public-origin-init-indexed-query180-helper-v1 MFb7f28f45dec02d581c9ebacd28e6be9a31bb6345c69c3d3f5cb47a4e147ce788;
public3 /tmp/kasumi-public-origin-init-indexed-correction-public3-helper-v2
MF445b60cbb82ab23502e0bf9674fe1a57088760784e4ac3a19c169a2740cc4a2e;
native232 /tmp/kasumi-public-origin-init-indexed-correction-native232-helper-v1
MF94b73976c5bb7d0e25dbe7d4dafeb9f1764f3bb34f22dd6f98a714168e5853c9.
All original runtime bodies and profiles remain exact. Native/public verification
stdout carries an inherited4201 label, while actual source guards/pins are4202;
the label is not a runtime result. Every immutable verification passes, Cargo0.

Root's full-fit case is separately forwarded to660d with exactly one corrected
post-update wait. Source /tmp/kasumi-indexed-multicollection-fullfit-root-v2-work,
MFdec870368fbe599a656ab1ad60ed2b9f9a9179c37be4365d94c1418ce6182cc4,
patchc0bf4acfc40e7d8a0514bf4d3c938454c8dc0f88edca14eba505dda6f4b15fc5,
full4,203/2leaves; first-round and final-global waits stay literal. WAIT_CORRECTION_PROOF
records the exact change. Not yet adopted or run.

Canonical feed source work is authorized around a small authenticated FeedHead,
fixed commit/event descriptors and bounded full-after-image chunks, atomically
bound to selected primary/receipt publication. Same-snapshot direct sequence
paging and whole-commit trimming replace resident predecessor/commit maps and
whole earlier publication-bank retention. Shared cache/refill, snapshot export/
import, archived-history separation and pinned-version GC are required parts of
that integration. Existing snapshot kinds9/10 encode change headers/items; no
live engine.feed tables exist yet. No implementation or runtime claim is made.

### 2026-10-07 actual534–537: SDK test privacy repair

Actual534 fails during test compilation, before runtime: E0616 for direct access
to TenantEngine.application_sources and E0624 for ObjectId.write in the new
multi-collection assertion core. It takes 443.48s, exit101; all 3,615 selected
source hashes remain exact. Actual535 preserves all 4,202 source files and 4,268
archive members/modes plus the exact SDK helper and raw runtime directory.
Archive /tmp/kasumi-actual534-sdk36-private-test-failed-fullsource-v1,
SHA217aa9fd6edd25d7389290a6b0fc67f50c89c30baab746c164d291ee43476ecf;
preservation passes in 13.47s.

The one-leaf test repair uses the existing access-checked cache_refill_roots
method and constructs the fixed ObjectId wire key from its existing visible
fields. Production visibility, every assertion, all budgets/deadlines and the
36 complete test wrappers remain unchanged. Source
/tmp/kasumi-sdk36-test-privacy-root-v1-work,
MF1d78480d126a69af6b369411bc24293c3fc4c4bb901c3381fd2bbeb86014e81d,
patch43c179a64ff32f4d66e40c3d157912d92977495cba00a1ac3b91872206b5579d,
direct660d/full4,202. Actual536 applies with verified inverse/forward,
0.85s inner0/outer1 for the expected single test leaf. Actual537 now runs SDK36
on this source using /tmp/kasumi-sdk36-test-privacy-root-v1-helper,
MF5536e19e9f681f130b2fde904ffdf8f0e6cbbd21dc17b1805b8c307622785ae7,
qualifySHA584aed235c4b027966451dada88bd4cc14e927034cc3597e5353e1e3e7979b72.
Runtime /tmp/kasumi-sdk36-test-privacy-root-v1-runtime remains pending.

The first-release goal now has explicit deletion gates for obsolete document
and index maps, query/cursor dispatch, resident feeds and old format/configuration
paths. Selected cursor v3 has two independent source reviews; its tests and
canonical API/transport cutover remain pending. All production goals remain open.


### 2026-10-07 actual537–540: repeated query sealing self-wake

Actual537 compiled and listed all 36 SDK cases, then failed multiple runtime
cases with write-completion deadlines. It remained nonterminal with a sampled
Cleanup::poll → seal_query_anchor → QueryCleanupWake::notify → Frame::cleanup
loop. Root stopped only the verified owned test PID 84906 after over 14 minutes;
the wrapper finished exit101 in 1173.73s with all 3,615 selected hashes unchanged.
This is a failed/interrupted runtime, not an SDK qualification pass. Host load
was recorded but does not establish the cause of the first write deadlines.

Actual538 preserved all 4,202 source files, helper, raw runtime logs, process
samples and stop record before mutation (4,269 archive members/modes):
`/tmp/kasumi-actual537-sdk36-shutdown-spin-failed-fullsource-v1`, archive SHA256
`b69dbfc8c661cac68a38776bee9e248be6d61f1bf8d7575927c693b579d7485c`.
Preservation passed in 40.63s. Source review confirms repeated shutdown sealing
unconditionally schedules its own cleanup task even when no slot changed.

Actual539 applies the three-leaf repair from
`/tmp/kasumi-query-seal-wake-root-v1-work`, manifest
`bcdbf183e4a7eb57658123610c86b7151439447c974d6289003475ad249cf15c`, patch
`d47927da1af662f90fd1cd5d52b109f5de3776b2a86f5efaad5e2e7c23a60e4f`.
Sealing signals only a real sealed/abandoned transition. Loan return, slot
retirement and blocked restoration keep their existing independent signals.
The additive test observes the actual bound native wake, holds the original
result aliases and charge, and requires final retirement under the existing
five-second limit. Original SDK bodies, budgets and deadlines are unchanged.
Actual539 reports inner0/outer1 for exactly the three intended changed leaves;
actual540 is the focused regression, still pending at this entry.

The unchanged SDK36 helper is forwarded to the exact repaired source at
`/tmp/kasumi-query-seal-wake-sdk36-helper-v1`, manifest
`d33e0b86dc4a8818edffdfd3c62313807faa962bfd64222ec55a6497c6ca2a51`.
Its immutable verification passes; runtime remains pending. The cleanup fix
is not evidence that every earlier deadline is explained. All C01–C07 remain
open, including canonical feed/restore/query cutover and final workload gates.


### 2026-10-07 actual540–546: regression setup corrections

Actual540 compiled, then the new single regression passed its real wake-count
and retained-charge assertions but failed at revision 0 versus expected 2. Its
low-level setup had omitted the existing selected-service revision stamping step.
The run failed in 238.00s (runtime 9.19s); all 3,615 selected hashes were stable.
Actual541 preserved all 4,202 files and 4,263 archive members/modes at
`/tmp/kasumi-actual540-query-seal-test-revision-failed-fullsource-v1`, archive
`a8fc5795f95c1b21d5985bbc56f4bc8b860cf8bf2b0937b22c5e3fbef0f4cf6b`.

Actual542 applied the one-test correction from source
`/tmp/kasumi-query-seal-wake-root-v2-work`, manifest
`f9cdbdcc66c82d867e2e107ccdfc2946b831a1bae5849b1ee069f0a7ba19691d`.
Actual543 then failed compilation (E0616, private plan.source) in 30.40s before
runtime. Actual544 preserved that complete source and forwarded helper at
`/tmp/kasumi-actual543-query-seal-private-plan-failed-fullsource-v1`, archive
`30c5389757eb9284794b91d91bd29557172a0c1bd52b61bf72299a6a90811e59`.

Actual545 applies two test-only leaves from
`/tmp/kasumi-query-seal-wake-root-v3-work`, manifest
`4de6cc913123b27c33fa34a8b1ef7bdc9bb97f979dff0840f6e54c2a0f663653`, patch
`bedf79f5f4d503c0a2e7d5c1f1d6818badfe1adf59050462c9a293eee9ee2c9e`.
A cfg(test) accessor beside fixture_plan_charge returns the exact selected plan
revision without exposing production fields. The regression applies the same
revision setter as execute_selected_result_plan and keeps every assertion.
The production seal repair, all original cases and limits stay unchanged.
Actual546 is the focused regression on this source, pending at this entry.
The exact original SDK36 helper is forwarded to
`/tmp/kasumi-query-seal-wake-sdk36-helper-v3`, manifest
`98443124e7a148439f6ffa23d2064e7db4925026f50d97e9dbcb4bc9c7c85cea`;
its immutable verification passes, runtime pending.


Actual546 passed the real bound-native-wake regression: 1/1, runtime13.41s,
110.26s overall, all 3,615 selected hashes unchanged. This proves repeated-seal
idempotence and final-alias cleanup under the original five-second retirement
limit on the exact4de6 source. Actual547 now runs the original SDK36 profile;
it has already exposed a separate shutdown ordering error and remains a failed
qualification attempt pending its terminal result. No broader pass is inferred.

The first observed error in actual547 is the unchanged unpolled-cleanup test:
`drain Complete; background work result: ResourceExhausted: source consumers sealed`.
Shutdown seals application consumers before it joins an admitted ProposalWork;
that actual gated child still calls the public-history-funded generation read.
A source-only repair moves consumer sealing after positive proposal/backup
producer drains, retaining immediate public admission closure and both Retained
early returns. Independent review is recorded at
`/tmp/kasumi-producer-before-consumer-seal-readonly-review-v1.json`, SHA256
`6d81cd280a1cfe2cab02b2f20dc328b788726d114738e0af7f2119c1bec23fad`.
Other write deadlines are still unresolved. Early and later owned-process
samples are retained in the actual547 runtime directory.

### 2026-10-07: failed SDK36 shutdown/contention diagnosis and focused repairs

The original SDK36 actual547 run on `4de6cc913123b27c33fa34a8b1ef7bdc9bb97f979dff0840f6e54c2a0f663653` failed. Root stopped only its verified owned test process (PID5498) after prolonged contention; the runner exited101 after940.44s with all3615 selected files unchanged. Seven cases had reported failure; the interrupted run is not a complete case census or a pass. Three owned process samples and the exact stop record accompany the runtime. actual548 preserved all4202 source leaves plus the helper/runtime before source mutation.

The unpolled-cleanup case reported `source consumers sealed` while an admitted proposal still needed its source generation. actual549 applies the reviewed drain-order repair: seal public admission immediately, drain existing proposals and backups, then seal source consumers. Retained-producer exits remain before consumer sealing. Carrier `b0cf68b1dcaff30f4e5fbf5f168f075cab10e45894d3a45a14d02743f854f721`, patch `ac83e08fa8586a6106c0d5e3051ecc0a8f5e98c4d7b69fd9130e7a248ee333d5`, one production leaf.

The later samples show test allocator spin-lock contention even when no observer is active. actual550 applies a null-observer fast path with an Acquire load; armed entry/retirement use Release/AcqRel, and the active path still rechecks under the original lock. It changes only test instrumentation. Carrier `a19d2011db64cb384105ce381f1c639512b035fc39d7ac78146ed2121a355aec`, patch `ed1b272bf68ceae4396827bee1c0b0114e8f6345caa416253f049ef2bb23fd42`, direct shutdown repair,4202 leaves. Independent source review: `/tmp/kasumi-inactive-allocation-observer-feed-peer-review-v1.json`, SHA `d31449752bd8264d60cbe5b2ebd54ba7210907ab5587e735062d28b6730c9532`. This does not establish the cause of every deadline failure.

actual551 ran the unchanged six allocator/real-session cases together with the original unpolled-cleanup case and the repeated-seal/final-alias regression. No budgets, deadlines, concurrency settings or original assertions were relaxed. The original SDK36 helper was mechanically forwarded to this exact source: manifest `b3bbad875294fec97e97ac5d8e2c1ecf4cb7ac9082e7792e924362002c4202e2`, qualification script `e8a0d7e12edafd742900ed62e40a2eeddd482a50c906b579e0d0c24c0073cbb1`. Runtime remains pending. All C01–C07/M01–M07 remain open; final repository/release gates are not run or passed.


### 2026-10-07: exact SDK failures and ARM SHA-256 qualification

Actual551 finished with seven passes and one failure (145.46s overall, 17.12s runtime; all 3,615 selected hashes unchanged). Both shutdown regressions and the five direct allocator cases passed. The genuine Japanese Session test failed while preparing its dictionary under the original 32 MiB writer allowance. Source inspection found reconstruction/rebilling of an already paid dictionary; sharing the actual prepared dictionary remains implementation work. The limit is unchanged.

Actual552 reran the original SDK36 on source `a19d2011db64cb384105ce381f1c639512b035fc39d7ac78146ed2121a355aec`. Eight cases reported failures. Root stopped only the verified owned test process after prolonged execution; the runner exited 101 after 738.87s, all 3,615 selected hashes unchanged. This interrupted run is not a complete census. Its later 1,801-sample profile shows substantial software SHA-256 directory-page hashing; it does not prove the cause of every deadline. Actual553 preserved all 4,202 source files, helper, runtime, samples, stop record, and actual551 evidence at `/tmp/kasumi-actual552-sdk36-and551-text-session-failed-fullsource-v1`, archive SHA256 `0c52bb1ecdba5a21fc3aca5506cb30581501658d0570d3af34876848659c68a0`.

Actual554 was a runner invocation error: the Cargo-only fence rejected an apply command before mutation. Actual555 then applied the reviewed two-file ARM feature change, carrier `72c633a932226ff6df58b394f0c287ddd7f16a817403e7fd2a2c188139a29853`, patch `1a921ff9e8d4f6f30f4b39a822ffa94525a99b93055dd49d01231526ae69a6b8`. The pinned sha2 0.10.9 AArch64 dispatcher uses CPU detection and preserves its software fallback. Only the target-conditioned feature and sha2-asm 0.6.4 lock entry were added; no existing package version, digest algorithm, or validation was changed. Peer review: `/tmp/kasumi-arm-sha2-feed-peer-review-v1.json`, SHA256 `dd1ba9089bd8861f7f16f33b82fd0f1fc2bf9d0505cda91a2a75d2074d9a506d`.

Actual556 passed all nine original native digest/corruption cases (65.21s overall; 0.55s runtime), all 3,615 selected hashes unchanged. Actual557 is the unchanged SDK36 qualification on this source, pending at this entry. Its forwarded helper manifest is `be0c252278565c7b6ae6506db80cee2c276952da14b66bbf3cd23e5d6e9086fa`; qualify.py SHA256 `4ec776449df980d72eac87840a57ee85182c0470853db11b2b8e882813fd66e2`. No original budgets, deadlines, concurrency, or assertions were relaxed. No goal or production milestone closes on these component results.


## Historical checkpoint detail preserved during canonical goal refinement — 2026-10-07

The following is the prior goal-page checkpoint history, preserved verbatim. Its past-tense results apply only to their recorded sources. Current blockers and status are on the goal page; moving these details does not waive unresolved acceptance requirements.

The current qualified prerequisites are:

- Disk-backed native directory, snapshots and bounded page caching: the earlier
  complete 677-case KV library and 101-case cache selection pass. Native schema,
  analyzers, persistent collections and allocation profiles have their original
  scoped qualification recorded in the progress ledger.
- Empty first-collection publication: the real SDK commits the verified baseline
  and moves its captured metadata to the actual standing owner under the same
  original budget. The 263-case consumer roster passes, including both added
  SDK/native witnesses. This covers an empty collection with known simple schema.
- Encrypted point-read ownership: normal Store compilation and all 23 selected
  original/additive construction, failure and retirement cases pass.
- Query ownership: all 49 combined checks pass on the joined source, including
  the actual Database cancellation anchor, completed result/page aliases,
  logical errors and the original extraction restrictions. Production selected
  dispatch and transport still require activation.
- Native maintenance bank: all eight selected cases pass, including the five
  unchanged original constructor-denial cases.

The unchanged restore case now reaches its intended identity-validation assertion.
The latest 26-case Engine run has **26 passes and no failures**, including both
first-collection witnesses, all seven query handoff cases and every original
selected case. The repair consolidates the five real permanent receipt-table
constructor owners under one original grant, preserving the original 64 MiB
budget, 32-reservation limit and held snapshots. All 15 selected native
maintenance, publication and constructor cases pass, including actual
allocation/refusal, partial failures and the full Core's final backend
destructor retaining its original grant and panic payload. The encrypted
Store's 23 selected consumers pass on the preceding source. The joined document
constructor also passes all 15 checks, including measured native allocations,
final weak-reference cleanup and native-error retirement under the original
budget. These finite
checks do not establish generic diagnostic ownership or production activation.
The original Server JSON consumer also passes on the joined document source;
the joined aggregate budget, generation-registration and known-union refill
selection now passes all 222 cases. These scoped checks do not qualify every
public/text origin or the process-memory union.
The earlier failures remain preserved.

The next production joins are ordinary document/index publication, public
selected reads with cancellation custody, admission before every replica's
acceptance, and one aggregate residency/workspace budget. Complete finite
preload/refill and a materialized allocation union remain required before any
full-residency or process-memory claim. Exact source pins, test selections and
failed runs are in the [progress ledger](disk-backed-cache-progress-20261003.md)
and [evidence ledger](evidence/disk-backed-cache-20260930/README.md).

## Immediate integration checkpoints

| Checkpoint | Current evidence | Exit still required |
|---|---|---|
| Native constructor and encrypted read owners | Restore26, native15 and Store23 pass on pinned scoped sources. | Preserve these cases on the final joined source; resolve generic diagnostic and provider tails. |
| Large aggregate cache budget | The compact native witness passes the complete230-case Engine/KV join, including16,513-row full fit and shrink/growth under unchanged limits. Both added missing-witness wait/recovery cases pass after correcting their test construction stack. Original failures remain preserved. | Preserve these cases on the final joined source and qualify SDK publication; finish cleanup-current freshness for the complete allocation union. Activate all document/index/public origins on the final source. Explicit limits remain exact. |
| Canonical document and receipt APIs | Seven affected callers, Owner10 and VersionMap2 pass on their recorded sources. All 15 joined document checks, the original Server JSON consumer, native leaf checks in three profiles and all 11 paired durable Entry checks pass; existing graph versions/checksums remain. | Qualify native Engine header kinds, install funded ordinary producers and join their replica/recovery callers. |
| Selected reads and errors | All 56 joined selected-query, measured protobuf, native wire and privacy checks pass on the corrected source. Earlier interface, fixture, compiler-depth and runtime failures remain preserved. | Activate public SDK and transport reads, fund independently retained body/header/extension backing, and retain original loans through cancellation and final alias/control retirement. |
| Atomic publication and full residency | SDK19 passes on the compact native-witness source. The subsequent temporary-retirement source passes normal Engine compilation, but SDK22 fails with 8 passes and 14 completion-timeout failures. Earlier native-witness completion timeouts and physical failures remain preserved. | Diagnose the failed completion paths and qualify positive temporary retirement under the same original bank. Preserve replay, counter-corruption and concurrent-reader behavior. Finish growing audit/feed headers, all commands/indexes and replica capacity before cutover. Passing reruns do not establish a cause or repair for unexplained failures. |
| Final qualification and promotion | Component evidence is retained. | Five workload classes and all required repository/release checks pass on one final source before promotion. |

These are checkpoints within M01–M07; a scoped pass does not close a production
milestone or reduce its feature and workload requirements.

The genuine sparse candidate and retained dispatcher now pass normal
compilation. The paid heap receiver fixes the SDK stack overflow without increasing
test stacks or capacity. The sparse accepted-counter join now compiles with
independent verification intact; SDK commits and retained selected-snapshot reads pass.
The immediate executable sequence is: preserve the passing SDK19 semantic,
counter-corruption and concurrent-reader join; preserve the qualified compact native witness and verify actual missing-witness
recovery; retire actual temporary workspace before narrowing its original
credit; qualify growing audit headers and the original transport graph; then extend
the same producers to all commands, index roles and replica/recovery ingress.
Keep exact native file-owner diagnostics until the earlier physical failures have
an established cause and final-source qualification. Each step must retain
the original capacity settings and earlier failed source. Publication is not
ready for public cutover while any supported sparse operation lacks a producer.

Completion is measured by active behavior, not the number of reviewed components.
The next concrete production result is one ordinary document mutation whose
document, indexes, receipt and audit data share one durable commit, followed by a
read from that committed snapshot. Its temporary journal may contain the affected
rows; its published generation must not rebuild a map of every document. Extend
that result to every supported command, replica and recovery path before enabling
the canonical publisher. In parallel, selected results must survive the actual
SDK and transport cancellation paths under the same accounted owner.

Full residency has a finite, observable completion condition. Compare the complete
eligible allocation union with the shared bound, including pinned versions and
required workspace. A fitting dataset must finish preload/refill and then serve
every eligible document, index and directory lookup from memory. A pressure-mode
low-water mark, a per-collection ceiling or an unfinished text warm-up must not
keep an otherwise fitting dataset on disk. Requested allocation bounds and cache
charges alone do not establish this union or process RSS.

The remaining production work has four explicit integration dependencies:

| Integration | Required dependency | Reviewable production exit |
|---|---|---|
| Ordinary publication | A genuinely funded sparse candidate, native audit/feed headers and receipt writes, plus checked standing-metadata transfer. | An actual SDK write commits document/index/receipt/audit changes in one transaction and publishes a generation without an all-document map. Retained snapshots, returned failures and cancellation retain their original owners. |
| Selected serving | The same committed metadata and reusable encrypted read source; funded result, protobuf and transport backing. | Public point/query/page paths use the exact selected snapshot, preserve current security checks and release actual backing before its credit, including final aliases and cancellation. |
| Complete residency | Registration of every public, current, leased and pinned generation; finite warming for documents and every index kind. | A fitting uneven dataset reaches observable warm-up completion, has zero serving fetches and stays resident through writes. Shrink or budget growth reaches this state again. |
| Final qualification | All supported commands, leader/follower/recovery admission and operational consumers use these paths. | One final source passes the five workload classes and repository/release gates before promotion. |

Owned cache values and registry entries must not strongly retain their owning
cache/source root through their funding bank. After final Database facade Drop
and shutdown of its independently delivered runtime through the established API,
cleanup must positively retire these payloads. Facade Drop does not itself
promise runtime shutdown. Weak controls remain charged through their actual final
destruction. This ownership check applies to the nonempty ordinary publisher
as well as the first empty collection.

Before selected serving activation, verify reads concurrent with a paused write
and standing-metadata transfer; previously captured query owners alone do not
prove new readers can obtain a consistent source during that handoff. Measure
the original fixed-bank tails retained by documents and native audit/feed
aliases after temporary write buffers retire. Permanently reserving unused
operation headroom must not prevent a fully accounted fitting dataset from
remaining resident. Any credit narrowing requires positive disposal of its
actual backing and original retained-tail evidence.

## Remaining execution order

1. **Finish the actual sparse SDK join.** Paired document/receipt commits and
   historical/current selected reads pass. The committed sparse counter join and
   exact unreachable-decoder correction now pass canonical replay, digest
   conflicts, authorization denial, CAS, duplicate and default-document-limit
   rejection with ordinary history retention. Preserve these14 cases and their
   original ownership/refusal checks. Corrupt actual count/body counters and an
   omitted journal row are qualified refusals before publication. Both paused-write
   reader cases and the complete19-case SDK join now pass on the compact native
   witness. Preserve those cases through temporary-workspace retirement; earlier
   intermittent post-release writer completion failures still need diagnosis. Diagnose the earlier
   physical owner error and independently failed storage fixture; a passing rerun
   alone closes neither obligation. Preserve original budgets, assertions and evidence.
2. **Complete ordinary producers and protected acceptance.** Extend the genuine
   publisher to all commands, multiple collections, structured/unique/text
   indexes, growing audit/feed headers, schema and archive operations. Documents,
   indexes, receipts and audit effects must commit together without rebuilding
   resident document maps. Fund source/history and required successor work before
   acceptance on the leader, every follower and recovery path. Retained versions
   and failures keep their actual owners until physical retirement.
3. **Activate public selected serving and operational consumers.** Join actual
   SDK/RPC point, query, transaction, pagination and history paths with funded
   output/body/header/extension backing through cancellation and final aliases.
   Preserve authorization, revocation, key expiry and strict-read audit checks.
   Qualify encrypted reads, restore, native ownership, original Session/schema
   profiles and other affected consumers on the joined source. Remove resident
   serving alternatives and reject obsolete first-release APIs/formats.
4. **Activate full residency.** Bind every public, leased and registered
   generation to the real allocation census; complete finite document and
   text preload/refill. Allow uneven collections and installed native roles
   to use available aggregate cache capacity. After warm-up, the entire
   eligible dataset stays resident whenever its accounted allocation union
   and required workspace fit. Deletion or budget growth restores that state.
   Resolve the default total-reservation ceiling and the RSS/accounting overlap
   at the actual owning constructors. Preserve explicit total bounds; enforce
   one aggregate transient workspace bound through reserve, growth and handoff.
   Raising a cache setting alone cannot close this gate.
5. **Qualify and promote one final source.** Run all five workload classes and
   required repository/release gates, preserving feature/security/recovery/
   backup/audit/shutdown behavior. Record cache accounting, storage reads,
   RSS, swap and latency separately. Promote only that qualified source.

These exits refine the implementation order; they do not narrow the seven
completion criteria or the required workload matrix. Detailed source ownership,
acceptance, retirement, constructor and cutover gates remain binding in the
[preserved detailed gates](disk-backed-cache-progress-20261003.md#detailed-ownership-and-integration-gates-preserved-during-goal-refinement--2026-10-06).
Exact commands, pins, raw failures and recoverable archives remain in the
[evidence ledger](evidence/disk-backed-cache-20260930/README.md).

Public selected-query activation has three concrete contract gaps: the selected
evaluator rejects text requests, selected serializers have no public cursor, and
owning errors lack their public transport join. Complete those producers and
retain the existing authorization, expiry, durable audit and release order
before replacing the public caller. A passing private selected query cannot
close that milestone.

The active change-feed header has a separate concrete growth cliff: the native
map leaf supports16 entries by default (6 with the small-chunks feature), while
the existing history policy retains up to100,000 events or128 MiB. Its sparse
producer must use canonical bounded disk-backed headers while preserving the
existing retention policy. A full-copy growing native tree only removes the
immediate refusal and retains data-sized copying. Retained FeedCommitRef owners
can also hold entire earlier publication-bank quotes through FirstBaselineLease.
Remove that structural retention with exact ownership, not inferred credit
refunds. These are M05/M07 integration requirements, not deferred tuning.

Growing an active audit header beyond one native vector chunk is a separate
prerequisite for ordinary publication. Its source-derived constructor must fund
every installed node, child/value chunk, builder frame and retained descendant
before allocation. Positive retirement must precede credit release. A full-copy
active-header constructor does not bound archive/history growth: that requires a
selected active window, streamed durable archive access and bounded maintenance.

The current unique-index producer checks final batch uniqueness by streaming the
committed primary rows with one reused row buffer. This bounds its memory, but
its time grows with the database and changed-row count. Treat semantic tests as
separate from performance qualification: use the paid selected unique-index
lookup for efficient validation, and measure the final path in the fitting and
pressure workloads. Source-reviewed multi-collection publication and public
generation accounting also require their actual SDK and ownership tests before
they count as production integration.

## SDK shutdown retained-owner diagnosis and restored serving join — 2026-10-07

- actual557 SDK36 on source `72c633` ended with exit101 after 2089.21 seconds,
  including the 19m13s compilation. All 3615 selected source/config leaves
  matched before and after. Runtime observed 27 passes, seven failures and two
  unfinished cases; this is an interrupted failure, not a complete census.
- Process sample SHA `2d9c26db4c51257855e1424d0e45dc9dfaff5854b4b798adb10747c9a5cb7864`
  places both unfinished structured/multi-collection cases in setup-failure
  cleanup at `Database::shutdown` -> `TenantEngine::seal` ->
  `BackendMutationGate::lock_for_seal`. The synchronous wait cannot finish
  while the original failed application retains its mutation permit. ARM
  hardware SHA dispatch is present in this sample; no claim assigns every
  preceding deadline failure to this separate shutdown defect.
- Root interrupted only the verified SDK child PID76670 with SIGINT after
  collecting the sample and original outputs. Budgets, deadlines, concurrency
  and original assertions were unchanged; unrelated jobs were untouched.
- actual558 preserved all 4202 source leaves plus carrier, helper, runtime,
  sample and interruption record. Archive SHA
  `7359f6f86c9db425a6058a342bb546ee339850d09e0bc9469437e760e32b31a3`
  verifies all 4269 members/modes, with source unchanged afterward.
- The nonblocking-seal source packet `65de2fac` replaces the blocking cleanup
  gate with refusal while the same holder is live, preserves poison and current
  state, and propagates retained child drains before dependent storage closes.
  Added tests cover busy/poisoned gate retry without allocation, real Engine
  state preservation and an SDK shutdown held-permit retry. Runtime is pending.
- The eight-leaf restored-serving draft joins genuine imported payload origin,
  a registry node funded before aliases, authentic captured Snapshot proof,
  and the canonical committed metadata/standing owner. Snapshot peer review
  SHA `c09e023149719cab1ce4b3084ed28b8326312c3fd0ec7f9df9b6585b9058f42a`
  found no remaining source blocker after correcting a draft formatter header.
  It is being integrated with the original restore frame; no Cargo, activation,
  feature-parity or goal-completion claim is made by that review.

All C01–C07/M01–M07 remain open. The first-release deletion requirement and the
complete-residency-below-bound requirement remain unchanged.


## Joined shutdown, text and index diagnosis — 2026-10-07

Actual559 applied the combined scalar/array/Decimal/cursor/Japanese and
nonblocking-seal source (`aca164ec8adf02feb538d517ebbd3c142dd0c7054155f6155719927998ab09df`,
4,210 complete files). Actual560 passes all seven backend mutation-gate cases.
Actual561 changes only the new shutdown test observer to retain a Weak rather
than a strong Generation owner; source becomes
`6ea395b92e46b8d6626d43f8d072c9ec16524cb514b2e96c49e035cd6aa54b5e`.

Actual562: three of six cases pass (real Engine seal under a held permit,
actual SDK shutdown/retry, original 32 MiB Japanese Session). All four Session
workloads preserve the original allowance and assertions; maximum allocator
peak is 20,477,947 bytes. Three new scalar/array/Decimal/indexed-fullfit SDK
cases fail setup. Total 590.60 seconds including build, all 3,623 selected
source/config files unchanged. Actual563 preserves the failed full source and
all 4,219 archive members/modes; archive SHA-256
`62ec29d27d1506c528bbe70475567f3c415aff1bb39214cd0c71644a87191430`.

Actual564 query selection fails compilation in an existing test that still
calls `Arc::get_mut` on the canonical `DocumentRef`. Actual565 preserves that
failure. The test now checks `DocumentRef::strong_count` while retaining the
original copy-on-write and historical-value assertions. No production behavior
or limit changes in this repair.

Actual566 adds borrowed original-error inspection to the existing SDK setup
failure cleanup. Actual567 repeats the three failed SDK cases (0/3; 54.53
seconds including build) and identifies precise causes: `First known
declaration quote family differs` for scalar and array/Decimal at revision 0;
`sparse retirement accepted owner, interval or complete roles differ` for
indexed fullfit at revision 2. These are publication failures, not evidence of
cache misses or bounded full residency. Actual568 preserves source
`82ccc212bda7134a75779c891e8ca54f9897bfe4cf2aab61c3b797512186656f` and its failure.

Actual569 applies the canonical test-owner repair. Actual570 passes all five
focused general-scalar/array/Decimal declaration, shared funding, retained
Weak and rejection cases (10.05 seconds including build), with all 3,623
selected files unchanged on full source
`5eaf5b16d6ea217e50fe08bac0ac1b13906a7e37c0a0e69153d2233d9b74cd7f`.

Reviewed successors join First admission to its actual 64-declaration native
quote and sparse retirement to the genuine accepted primary draft's sealed
counter proof. Their runtime gates remain pending. A separate nine-leaf Raft
restore-worker draft preserves the existing original error and backend/store
owners until positive native cleanup, with nonblocking borrowed diagnostics;
it is not yet runtime qualified. General application schema/runtime, canonical
feed/restore/public caller joins, old-code deletion, all five residency
workloads and final repository/release gates remain open. Nothing is promoted
to the live production checkout, and no C01–C07/M01–M07 goal is closed.


## Authenticated sparse retirement and index namespace — 2026-10-07

Actual571 applies the reviewed First admission and sealed sparse-counter
changes (source `6853576f7c96e4ccf28533c1ba36b4b5959aea08dd48fd8eec150d7c937ccf41`).
Actual572 fails only the fixture compilation because it called a private
production reducer predicate. Actual573 preserves that failed source. Actual574
uses the fixture's actual stage authority and verifies all four sealed totals,
including encoded body bytes; production visibility and validation stay intact.

Actual575 completes normally: one of eight cases passes, seven fail, 434.55
seconds including build. All 3,623 selected leaves remain exact on complete
source `52862b4f0b0bace5ec9af59ca1617d54a84f8fca70e21d9cd13fc08ff72e007f`.
The retirement-set case passes actual replacement and both missing/preserved
edge refusal assertions. SDK failures expose primary-page lookup in the wrong
namespace and a remaining sparse single-declaration guard; three other cases
exceed their original write deadlines, whose causes remain independently open.
The final running test was sampled and allowed to finish normally. The sample
and host context establish no causal attribution for those timeouts.

Actual576 preserves all 4,210 source leaves and 4,221 verified archive
members/modes, including sample and host context. Archive SHA-256:
`e433890891027392dab0f3201ec01293d574dee39682e1325dd51d01bc7b3bcc`.
Actual577 applies only the two independently reviewed fixes: explicitly use
`engine.primary.pages` for primary validation under the same selected snapshot
and page-integrity checks; admit up to the existing native 64 declarations
through the original count-specific funded sparse constructor. No allowance,
assertion, concurrency setting or deadline changes. Complete source manifest:
`8d6df1718039383029cb01fb0a95d1b8f47c977a0e75e75a4d817fe6572a3097`;
patch `ebdb41689dc487277466bcc72e6cf30ee9dcb9a8bfdfa589dfc40e3b8f3b4103`.
Actual578 reruns the seven affected SDK scenarios; outcome is pending.

The restore-worker bridge is source reviewed but unqualified. Canonical
restore/import, full schema compilation/runtime, feed/public transport cutover,
old-path deletion, complete below-bound residency and final release gates remain
required. No production source is promoted and all C01–C07/M01–M07 remain open.


## SDK deadline evidence and restore-worker join — 2026-10-07

Actual578 completes with 0/7 passing SDK cases, 308.22 seconds including build
(261.10 seconds runtime), all 3,623 selected leaves unchanged. The earlier
namespace and single-declaration refusals are absent; all seven cases exceed
original write deadlines. A sampled live process is in index/manifest staging,
native directory work and physical writes, including fsync, with ARM hashing.
The short sample has only two observations per thread and cannot establish a
cost distribution. Scalar cleanup also reports a late original apply failure;
this is independent of timeouts until its retained diagnostic is inspected.
No running test was interrupted and no limit or assertion changed.

Actual579 preserves the complete failed source and sample (4,210 files,
4,222 members/modes), archive SHA-256
`4837637c1883b69ac50c8eca6e1294f64d98fc67afdacd30a8d2cfbdbf293bb1`.
Actual580 joins the reviewed restore-worker custody bridge and a test-only
post-shutdown borrow of original apply diagnostics, source
`54cf89e0ef9c1c23f84ef1882fdcf50d99cfe3f6df1701a547e050757c2671d7`
(4,211 files). The worker retains the exact constructor error, backend and
input storage until positive retirement; diagnostics are nonblocking and
reentrant inspection refuses without moving owners. Engine shutdown also
honors a live mutation permit held outside the ordinary ingress slot.

Actual581 fails compilation because snapshot_seed omitted the DrainCompletion
import (22.57 seconds; 3,624 selected leaves exact). Actual582 preserves that
source before the import repair. The restore-worker tests and full canonical
restore remain unqualified. All C01–C07/M01–M07 stay open; no production source
promotion or release is claimed.


Actual583 adds the missing canonical DrainCompletion import and removes its
unused predecessor, source `5e942d6bd03fc82cfc4ef5ffd7685740ae6900c848b8ac8c744273b6db89d63a`.
Actual584 passes all ten selected Raft restore-worker tests: three constructor
cleanup state cases, the actual encrypted retained-constructor case, four
original prepared-child pending/ready/refusal/independent-cleanup cases, and
two received-input cancellation cases. Total 39.21 seconds including 34.29
seconds build, runtime 3.87 seconds; all 3,624 selected leaves exact. This
qualifies the worker bridge, not complete Engine restore or cache residency.
Actual585 runs the real Engine independent-permit shutdown regression and
seven SDK index cases with post-drain original diagnostic inspection; pending.


## Concrete capacity and diagnostic failures — 2026-10-07

Actual585 finishes with 0/8 passing cases (535.46 seconds including build;
3,624 selected leaves exact). The scalar SDK case exposes `First native fixed
original capacity exhausted` on its second CreateCollection, independently of
the remaining original-deadline failures. The new Engine independent-permit
shutdown case correctly refuses shutdown until release, but its final
zero-charge assertion sees 133,416 bytes: the ordinary Notification envelope
retains its original weak backend loan. This is an unresolved retirement defect,
not permission to weaken the assertion. Actual586 preserves the complete
failed source, logs, active-process sample and host context. Host contention
is recorded as context; it does not establish a cause for the deadlines.

Actual587 joins 22 reviewed imported-query, owned-meta-graph and exact-number
prerequisite leaves, source `a2131d852eefb9d60b1fbd8c54095e35bba56c6c13098ba574ad0762108b6443`.
Actual588 and actual589 fail Cargo invocation because excluded vendor packages
cannot be tested as root-workspace members. Neither command compiles or runs
the selected tests. Qualification requires standalone manifests with the same
source patches, features and warm target.

Actual590 applies the three-leaf Rebuild capacity correction and test-only
original-capacity diagnostics, source
`e9ac662e8253531cbe384ccef1c0d931c78469475e09199e0563e1e26511719d`.
The collection-admin quote now includes the real full-primary verification
workspace, already quoted by the initial baseline. Ordinary mutation quotes,
limits, deadlines and assertions remain unchanged. Actual591 runs the
unchanged scalar SDK regression; its terminal failure is recorded below. Canonical feed/restore, complete
schema/transport, full residency, obsolete-path deletion and final release
checks remain open. No implementation is promoted and no goal is closed.


Actual591 completes with 0/1 passing scalar SDK case: original write deadline
expires at revision zero during first-collection setup, before the corrected
second-collection Rebuild quote is exercised. Total 564.77 seconds including
a 9m00s build, 22.89 seconds test runtime, 3,629 selected leaves unchanged.
The capacity correction remains unqualified by this run. Actual592 preserves
all 4,216 source leaves and 4,229 archive members/modes, archive SHA-256
`e4be0eb3a8ea6f7f724916aa2b641edcb150aab47c526d5fc0614c05dfcc333e`.

Actual593 passes all six native numeric-value cases. The schema test target
fails compilation with E0502 in the owned-meta-graph regression, so none of its
four selected cases runs. Actual594 preserves all 4,216 source leaves and 4,246
archive members/modes, archive SHA-256
`10eee2e2ec38f85660c316a4e6728317aecd5131985d0c93542b79058284e939`.

Actual595 applies the 127-leaf canonical query/feed/restore union and deletes
the obsolete snapshot query-anchor implementation, source manifest
`2b9c37017519ca666385fb50b722c3d087e6953b0e3546d603fc2c90917d7cbe`.
Actual596 migrates eight existing SDK tests to canonical feed counters and
owning pages, preserving original limits, deadlines and assertions. Actual597
fails production Engine compilation with 47 errors; it provides no runtime
qualification. Actual598 preserves that complete failed source (4,258 leaves,
4,276 archive members/modes), archive SHA-256
`9221c41a798b5d258350848cf498407e4f59b998d8920ac7b74c35812d59b4ca`.

Actual599–602 join reviewed notification retirement, the schema test lifetime
repair, paid generation field/retirement changes and narrow canonical
name/borrow/feed compilation fixes. The isolated source is 4,259 files,
manifest
`f890cbb1cc3879aac9f45059c4966928b02797c79361e01ffb6a5c6f65c5bfc1`.
Actual603 passes all four original schema cases through exact standalone
manifests (165.40 seconds; all 3,672 selected source/configuration leaves
unchanged). This proves the selected native context, meta-graph, decimal and
integer cases; complete application schema activation remains open. Actual604
failed before compilation; the resolved run is recorded below.

The Engine production build still requires canonical general mutation,
recovery, lease and maintenance callers, plus snapshot validation and bootstrap
integration. The removed resident feed API will not be restored as a shim.
Full schema/transport activation, full-residency workloads and final release
checks remain open. No implementation is promoted and no goal is closed.


Actual604 failed before compilation because the offline cache lacked locked
`syn 3.0.0`. Actual605 preserved its complete source (4,259 files, 4,282 archive
members; SHA-256 `6134774725979c4abcf4d24507b2b95353ec266f340affabbff29bca552ddef0`).
Actual606 fetched the unchanged lock. Actual607 then passed all five native
anyhow retirement cases in 179.78 seconds; 3,672 selected leaves unchanged.
The Engine held-permit/final-zero-charge case remains unqualified.

Actual608 joined 33 numeric, snapshot constructor/retirement and accepted-feed
census leaves, source manifest
`b6999a9cbedffe08cfa9250b583e6bebaf38b28cfd521d8433be08dcc8ac671b`.
Actual609 passed 11/13 value tests; two test oracles rejected exact integer
forms before comparisons. Actual610 preserved the full 4,263-file failed source,
4,330 archive members; SHA-256
`7f6f48e4c303cb1007a26d848a3019ce2567114f89c4cf513646f2a00619ad3e`.
Actual611 replaced only the two oracles with independent exact signed-integer
fraction construction, preserving all 11,025 ordering and 7,290 divisibility
pairs. Actual612 passed all 13 value tests and 7/8 schema allocation tests in
43.07 seconds, with 3,676 selected leaves unchanged. The remaining enum test
expected the portable table upper bound to equal this native table allocation
(actual 1,022 bytes, quoted 1,030 bytes). Complete keyword suites did not run.
Actual613 preserved the full failed source, 4,298 archive members; SHA-256
`5008a046271d14165d784409db99e87f0ad2cbcbc6d715e64bad3d5b1c1bde9c`.

Actual614 joined six native tree/vector leaves for independent funded metadata
copies and retained-range audit copying. Source manifest
`850592c9d92fda2461efdc63fb15b5929ece166d4e8c3b94be5216340d368714`,
4,265 source files. Actual615 fails before runtime; the correction and rerun are recorded below. Canonical bootstrap, original-node fixtures and snapshot relocation
are reviewed drafts, not yet joined. General/recovery, leases, maintenance,
full schema/transport, full-residency workloads and release checks remain open.
No implementation is promoted and no goal is closed.


Actual615 fails native imbl test compilation on one `deny(unsafe_code)` violation
in the new map owner's loan disposal; no native tests run. Actual616 preserves
all 4,265 source files and 4,290 archive members, SHA-256
`8e0baebe3a0c7dc92a66ae6e8c794fbc815ad57752b939b5cd1eb073ddfa09c5`.
The correction uses safe `Option::take` after actual native/frame deallocation.
Actual617 joins that correction, canonical original-governor bootstrap,
original-owner snapshot relocation, 21 fixture caller migrations, authentic
selected-command fixture support, preserved disk payload fixture encoding, and
the independent enum-table allocation oracle. Source manifest
`98cc207b198236b2f2fab2404092c6d47e7af38e79a3e9e50f91a4e4074ac091`,
4,267 source files, 38 changed/added leaves. No old bootstrap fallback is restored.
Actual618 passes all 13 native copy tests (seven vector, six map), including
actual allocation census, escaped aliases and deallocation-before-credit return;
26.33 seconds, all 3,680 selected leaves unchanged.

Actual619 passes all 13 value and eight schema allocation cases. The complete
const/enum/numeric keyword selection passes 344/345; the remaining old test
expects huge scientific-notation multiples of 2^64 to be rejected solely because
the former parser could not handle them. Those positive/negative/decimal cases
are mathematically valid. The corrective test must keep the same inputs, verify
all predicate/error APIs, and add invalid and boundary cases; no runtime limit
or memory assertion is relaxed. Total run 52.66 seconds, 3,680 leaves unchanged.
Actual620 preserves the exact failed source and 4,343 archive members, SHA-256
`a5aebb622d3c9dfcbdad175700d2ea1f738453196a90442aa4e91a5517be853c`.
Actual621 fails with 13 remaining production errors; the exact terminal and preservation are recorded below.

General/recovery and maintenance publication, pagination and historical reads,
remaining Control/bootstrap producers, schema/transport activation, full cache
residency and release verification remain open. Component passes do not satisfy
those acceptance gates. No implementation is promoted and no goal is closed.


Actual621 production Engine check fails with 13 errors (125.88 seconds,
3,680 source/config leaves unchanged): removed feed APIs, old general/recovery/
maintenance/lease builders and one private bootstrap visibility issue. Actual622
preserves all 4,267 source files and 4,316 archive members; archive SHA-256
`ba1593432c04b3e65ddee0fe89de8756c6449975f9c71b5728093a8eeb715d3c`.
Actual623 applies only the bootstrap sibling visibility correction and the
exact scientific-notation test correction, manifest
`a50b5d5834ec3b20a3d0b57f7ce28dbcc20b6686fed1329576ce37a52cd5490f`.
Actual624 passes all 13 value, eight schema allocation and 347 complete
const/enum/numeric keyword cases in 26.45 seconds; all 3,680 leaves unchanged.
The original huge scientific inputs now have mathematically correct expectations
and additional exponent/factor/rejection boundaries. No production behavior,
budget, deadline or memory assertion was relaxed for this correction.

Actual625 joins three canonical snapshot fixture leaves, manifest
`46b9855ead495e0e3468fa7bbd2711e5c4a577ec9f90dc3c255754beccaaeffe`,
4,267 source files. Fixtures retain original limits (validation 64 MiB/64 slots;
restore-budget 64 MiB/32 slots) and real imported/selected ownership. Runtime
qualification is pending. Canonical public reads, general metadata edits and
publication, Control startup, full application schema/transport, full residency
and the release matrix remain open. No implementation is promoted; no goal closes.


Actual626 joins the canonical public lease owner and imported catalog installation
(34 leaves; manifest `5652c437da930ef5e7e45412447b3da034c34a8495fc4bec66b383aa8cf83109`).
Actual627 fails the production Engine check with 12 errors in 52.67 seconds,
3,683 source/config leaves unchanged. Actual628 preserves 4,270 source files
and 4,314 archive members; archive SHA-256
`2582a60cdc68adf7b160c08a11eece99519b787dbeb1f861de708aa53a92b151`.

Actual629 joins the independent native General header, paid metadata aliases,
original selected registration, final generation ownership and lease compile
fixes (33 changed/added leaves, one superseded registry leaf deleted; manifest
`e125ff43497fea96659a493a231ab303502cd8bde6fd5539a0660d3b2eb9f0d0`).
Actual630 fails with 15 production errors in 126.95 seconds, 3,692 leaves unchanged.
Actual631 preserves all 4,279 source files and 4,323 archive members, archive
SHA-256 `439bec2ce5cda33203364fd330450d19baede08b5eef8aff50f14ec28c72ab7d`.

Actual632 joins the canonical Control genesis image, lent topology decoder,
prospectively funded scalar metadata edit, imported native per-collection
census, General constructor-owned census, selected ordered reader and compile
corrections (35 leaves; 4,286 full source files; manifest
`2886d898288e651f96157d6ab3a889c62f8c47be3b72d3d47e35ed753b327300`).
The General census carries independently paid fixed collection totals from the
original selected source or exact accepted journal; it has no edge to the old
Generation. The ordered public page returns its output owner to the same fixed
Database cleanup census. The original resident algorithm remains a test oracle,
not a production dispatch branch.

Actual633 production Engine check fails with ten remaining legacy write and
maintenance errors in 146.64 seconds, all 3,699 leaves unchanged. No new type
errors are reported for the joined metadata, census or ordered query components.
Actual634 preserves all 4,286 source files and 4,332 archive members; archive
SHA-256 `9c53d662406d0c958e9b88f8ae487ac647f613087c8421e0674a8ea9e673f1ff`.
Actual635 passes all six `kasumi-query` ordered-seek cases in 108.58 seconds
(including compilation), with 3,699 leaves unchanged. Cases cover volume,
bounds, both directions, pagination, independent resident-oracle agreement,
cancellation, original source errors, fingerprint/hash equivalence and original
output-grant refusal before body copying. Original limits/assertions remain.

General publication and exact temporary-credit retirement, real checkpoint
selection/repeated reopen, common selected point and historical readers,
transport adapters, full schema/command activation and original Engine fixtures
remain incomplete. Complete residency and final release workloads have not
been qualified. No implementation is promoted; all C01–C07/M01–M07 remain open.


Actual636 joins common physical publication/temporary-retirement proof and the
canonical selected point reader (31 leaves; 4,290 source files; manifest
`f3ee36eab052dd68978b64144fd6de9dd7f6c256b0db8a3d94d16562ec383ef0`).
General temporary-credit retirement accepts only the closed metadata edit proof;
an ordinary mutation still requires its real reducer/receipt/feed retirement.
Actual637 fails with the same ten legacy Engine write errors in 168.97 seconds,
3,703 source/config leaves unchanged. Actual638 preserves all 4,290 source files
and 4,332 archive members; archive SHA-256
`fecc843612c45186bc0bedbd699af537a9b298be343c8f3b2569ff840aeb41d6`.

Actual639 joins authenticated startup checkpoint/replay selection, native derived
projection reconstruction, canonical Control point reads and typed original
failures, a genuine ordered zero-version fixture, archive-inclusive native
census and borrowed canonical metadata accounting (30 leaves; 4,296 source files;
manifest `ea4cfb33b35ac1409fd0e7789f61c4903cc26b4e2beb24c6c03e12b2f007640e`).
The accounting change measures canonical metadata without allocating a second
header/schema graph. Its three allocator/wire-equivalence tests are authored;
Engine test qualification is pending. Startup resets derived namespaces only
after authenticating the actual checkpoint and complete committed tail in the
pre-serving lifecycle; it preserves original checkpoint/log authority.

Actual640 fails Engine checking with 15 errors in 61.96 seconds, all 3,709 source
leaves unchanged: the ten legacy write errors, a missing explicit startup module
path, and four lifecycle callers requiring typed original read-error propagation.
Actual641 preserves 4,296 source files and 4,337 archive members; archive SHA-256
`9f850d4d24bd60e504ec72706bae38cb77b622ce326ecb5844ac2e4be979a70d`.
Actual642 passes all three native `kasumi-raft` startup replay-proof tests in
214.01 seconds including compilation (2.90 seconds runtime), all 3,709 leaves
unchanged. Tests retain the original 64 MiB/32-operation limits and cover exact
storage-pair/single-use authority, actual retained command-body digest, and
absent/purged tail or missing endpoint refusal. This does not qualify complete
Engine startup, repeated reopen, public readers or the release matrix.

The next join carries measured actual document/receipt decoder bounds, owned
consensus metadata publication including nonempty initialization, corrected
canonical public metadata counts, and genuine selected fixtures. General
ordinary/recovery/maintenance producers, typed transport propagation, full
residency activation and final workloads remain open. No code is promoted to
the live checkout; all C01–C07/M01–M07 remain open.


## Persistent source recovery completed — 2026-10-07

All 3,713 selected source hashes match actual644. The full 4,300-file roster is
reconciled: 586 inherited nonselected files, one byte-exact historical vendor
manifest update, and two obsolete Rust modules removed from the older baseline.
Git checkpoint `7d250197e34008c8f84d0e63aaeec6b402371c5b` preserves the recovered
source in `/Users/takemiyamakoto/dev/.kasumi-disk-backed-recovery-20261007/workspace`.
The original actual644 check remains interrupted; a fresh Engine check uses the
existing warm Cargo target. Recovery closes no C/M goal and promotes no code.
Canonical ordinary mutation, audit, target and recovery producers are the next
cutover; old resident constructors and removed feed APIs will not be revived.
See [the recovery completion record](evidence/disk-backed-cache-20260930/actual644-source-recovery-complete.json).


## Canonical producer cutover — 2026-10-07

Actual645 completes the recovered-source Engine check with the original ten
obsolete producer errors; the 4,300 recovered files remain unchanged. Actual646
passes all 16 focused native immutable map/vector cases at checkpoint
`24a1c2ba650da2cc9cb2654b813de79b9bfa3217`, including exact successor allocation,
source isolation and positive retirement. The initial two-error test compilation
is preserved separately. This component pass does not qualify Engine or the
updated vendor inventory.

Checkpoint `09471da` joins the canonical ordinary General mutation producer,
authenticated empty bootstrap, audit-prune ownership, native Control metadata
successors and allocation-free terminal framing. The obsolete resident mutation
implementation is deleted; original behavioral tests remain. Actual647 completes Engine checking with 11 errors: six integration mismatches
and five obsolete producer references. General preaccept capacity, special-command producers, every
public reader, original audit physical limits and same-instance retry remain
open; no C/M acceptance gate closes and no source is promoted.


Actual648 checks checkpoint `d42697ffa8958fa4ba4377be83a474c39958ec2f` and reports
six errors: five obsolete producer references and one missing General workspace
trait import. The latter is corrected at `3989b38`. The joined typed command
family decoder, preaccept/reconstruction census dispatch, bounded selected
terminal point read and borrowed lifecycle completion projection have no
production compile diagnostics. Unreachable First/empty publication fields and
branches are removed. The lifecycle resident completion builder exists only as
a differential test oracle, with exact quota-boundary/allocation tests authored.
Actual649 passes all 83 Types library tests at `3989b38cf0cfe2ae8a7651022642094dac858795`; Engine behavior remains unqualified. The
terminal maximum decoder bound is still overly conservative and must be
optimized and measured without increasing original limits. All C/M goals remain
open; no source is promoted.


Actual650 checks `45955dc4bbd0af5fdce3134053e8098ba1df99ac` after joining selected scalar
commands (policy, limits, suspend, audit and maintenance audit), exact disk
document-limit scanning, canonical whole-commit feed trimming, a joint Entry
target append owner and consume-once Control metadata construction. It reports
five obsolete producer references plus a missing scalar workspace trait import;
the import is corrected after the check. The terminal append is compiled but
not yet dispatched by a complete target semantic producer. Recovery, remaining
schema/staged/lifecycle operations, original fixture migration, preaccept
capacity and all residency/release workloads remain open.


Actual651 verifies all 26 vendor inventories and selected dependencies at
`81b759ef552d98368269f661d5d3c3822ce98c69`. Actual652 passes all 83 Types tests
after the Control role-set maximum bound (`5011af0`). `97c8af8` corrects the
lifecycle future-audit undercount to the existing 64 KiB maximum, and introduces
prospective metadata geometry that binds the exact accepted definition digest
before population; actual653 passes both selected-metadata tests. `d45c95d`
adds a native allocation-free borrowed successor for recovery maps; actual654
passes all 17 growing-container cases. Actual655 checks this source and reports only five obsolete producer errors,
with no new integration diagnostics. Target/Recovery semantic owners and original-constructor ingress are
still drafts, not activated replacements; no C/M gate closes.

Refined M03 explicitly requires all accepted-but-unapplied predecessor shapes,
consume-once LogId/digest/family/source/governor binding, and a canonical
post-restore, pre-replay preparation hook. The existing early source constructor
has only bootstrap Engine state and cannot seed later-snapshot metadata bounds.
Original audit physical limits, same-instance pre-effect-refusal retry, every
public reader/index and final fitting/pressure workloads remain required.


Actual656 passes three selected-metadata tests at `bf8ad95`, including combined
native vector growth boundaries. The earlier two-test pass did not cover that
rounding defect and is preserved. `e5f0be2` joins same-core native physical
accounting, release-tail workspace accounting, and selected recovery topology
ownership; actual657 reports the same five obsolete producer errors with no
new production diagnostics. Original audit physical/retry qualification stays
open. `caca595` joins the native post-restore/pre-replay ordered-capacity hook,
positive cleanup for exact partial admission refusals, and canonical timestamp
reduction with immediate before-image ownership. The required Engine planner
is still absent, so managed startup deliberately refuses. Actual658 ends 101
before tests due to disk exhaustion. The source/evidence were preserved; only
28 stale Engine incremental directories older than two days were removed from
the existing task build lane. All C/M gates remain open and no source is promoted.


Actual659 completes 32 startup tests with 30 passes and two pre-hook source
binding failures in old raw-backend owner fixtures. Explicit Authority-role
fixtures retain their native cancellation/reopen assertions; actual661 passes
all 32 at `3410e1e`. `4d5e14b` adds borrowed recovery route values and combined
Control/document candidates; actual660 checks with exactly five old-producer
errors. `7a84715` removes the resident target builder and joins selected target
reduction/publication plus keyed original constructor slots. Actual662 checks
`23d1644` with four old-producer errors and one Target closure borrow conflict;
`f98fc24` scopes those borrows to the corresponding command arms. Exact counted
verification buffers and fixed Ed25519 decoding are included. Actual663's
Serving test run was interrupted; its handle is absent and no corresponding
Cargo/rustc process is live at continuation. A fresh same-lane run is required.
The complete prefix planner, original audit cap/retry proof, remaining old
producers, public readers and all residency/release gates remain open.


Actual664 passes all 35 Serving library tests at `9ae5469`, including exact
verification buffers and fixed-size signature decoding. Actual663 remains
interrupted. This checkpoint also joins pure native prospective count geometry;
its new boundary tests still require execution. No C/M gate closes.


At `c18b84e`, actual665 passes all 85 Types and 37 Serving library cases after
streaming history/digest validation and borrowing completion inputs. Actual666
passes both native prospective count-geometry tests across vector/map growth
boundaries. Vendor inventory entries match the changed native source. These
component checks close no C/M gate and do not activate the prefix planner.


Actual667 passes all 86 Types tests at `c84426d`, including borrowed recovery
admission and original identity/credential rejection. A subsequent ENOSPC while
writing drafts was resolved by removing only 135 task-owned Kasumi incremental
cache directories older than two days (19.5 GB logical); source, evidence and
current warm artifacts were retained. The cleanup inventory is preserved.
Recovery scratch composition and canonical producer integration remain open.


Actual668 passes 88 Types and 38 Serving cases at `25cfa10`. `7147339` integrates
closed Control-bank refusal cleanup and retry, exact original-obligation checks,
admitted takes during consumer sealing, and concrete Target verification
buffer accounting. Actual669 reports four remaining obsolete-producer errors
and no new integration diagnostics. Engine behavior remains unqualified; no
C/M gate closes. Recovery core/helper census drafts and retirement cutover work
are preserved separately until their complete integration is reviewable.


Actual670 passes all 38 Serving library tests at `7147339` after the borrowed
Control partition comparison. The four obsolete Engine producer errors remain;
new Engine allocator and refusal tests have not run. The goal stays active.


Actual671 preserves the retirement borrowed-wire Sized compilation failure at
`a135a3c`; `0543ada` repairs the generic bound, and actual672 passes all 91 Types
cases. Actual673 passes 39 Serving cases at `933cebc`. Actual674 passes 92 Types
cases at `c6fd874`, including canonical endpoint-origin comparisons. The new
Engine origin allocator test remains unrun.

`009cf03` replaces the resident Recovery reducer with a closed canonical
projection and original semantic/route ownership. Actual675 reports two remaining
obsolete generic producer errors and one new feed-census import error. The
import is corrected in `c2afa3b`, which also integrates original admission custody
for immutable Authority installations and their final shared-owner retirement.
These are component changes: runtime activation, allocator tests and complete
error-path census remain open. Review identified environment-dependent new
backtrace captures outside the quoted semantic budget; bounded error capture
and exact native error envelopes are required before accepting those owners.
No C/M acceptance gate closes, and no implementation is promoted.


Actual676 checks `c2afa3b` with two obsolete generic feed calls and one
Recovery restore-borrow error; `7baa596` fixes that reference. Actual677 passes
92 Types and 39 Serving tests. Actual678 preserves an archive hash test-fixture
constructor compilation error; the fixture is repaired without changing the
production contract. Actual679 preserves the excluded-vendor Cargo invocation
failure. Actual680 runs the correct vendored manifest and passes its native
backtrace scope/frame allocation test, including fresh-process capture behavior.
Actual681 passes 94 Types and 39 Serving tests. Actual682 passes seven canonical
wire cases and one native archive hash allocator case (only the final 64-byte
digest allocation for sorted source bodies, independent of chunk size/count).

`30baa4a` joins complete local Recovery error-frame geometry and bounded capture,
plus general live/archived ordered headers from the original prepaid point
reader. Actual683 checks with exactly two obsolete generic feed calls and zero
new integration diagnostics. `43d9b72` adds body-free point-header assertions on
the same snapshot. The complete-prefix audit is preserved as source/design
evidence, not an activated planner. Original Engine allocator/semantic tests,
canonical remaining producers, full production reads and residency qualification
are still required. No C/M gate closes; implementation remains isolated.


Actual684 passes 39 Serving and 94 Types library cases, seven canonical JSON
cases and the native archive-hash allocation case at `43d9b72`. Actual685
passes the bounded-backtrace guard compile-fail doctest. These are component
checks; Engine compilation still awaits replacement of the two obsolete generic
feed calls. No C/M gate closes and no implementation is promoted.


Actual686 checks selected schema preconditions at `af3038e` with the same two
obsolete feed errors and no new diagnostic. `76686b8` adds bounded same-snapshot
archive interval validation and allocation-free manifest duplicate checking;
archive publication remains separate. `283408f` integrates canonical Retirement
semantics, metadata and original response lifetime. Actual687 preserves its
missed custody caller migration; `6235161` fixes that caller. Actual688 reports
only the original two generic feed errors, with no new integration diagnostic.
Native Raft retirement tests are running; Engine tests remain unrun. All C/M
gates remain open. The active goals are consolidated without losing obligations;
exact prior text is preserved as actual688-goals-before-refinement.md.


### Actual689 / actual691: Retirement and cold registry qualification

At `6235161`, the native Raft Retirement selection finished in 2222.15 seconds:
29 passed, one failed, zero ignored. All five newly added Retirement cases and
the 100,000-orphan-seed recovery case passed. The simulated disk backend keeps
physical images in memory; this long debug fixture is not a production cache
or RSS gate. Samples show first and second recovery scans making progress.

The unchanged control-gate allocator assertion found 64 retained native bytes
after its original credit retired. Actual691 independently reproduces the cold
macOS static Mutex allocation. Commit `820363a` uses inline registry synchronization
and detaches nodes before native deallocation and credit retirement outside the
lock. Per-gate waits and poisoning remain unchanged. Focused allocation and
concurrency requalification is running; no cap or assertion was relaxed.
All C01–C07 and M01–M07 remain open; no implementation is promoted.


### Actual692–697: registry repair, lifecycle integration and full-prefix inputs

The fixed registry at `820363a` passes all five original native allocation,
waiting, identity, poisoning and final-owner cases (actual692). The canonical
Lifecycle producer plus bounded Staged header/chunk validation joins at
`256d254`; actual693 reports exactly the two existing removed-feed callers and
no new integration errors. Engine semantic/allocator tests remain blocked.

Commit `c6cc43c` preserves the actual actor predecessor and every startup log
identity, including metadata-only entries and the uncommitted suffix. All six
startup capacity tests pass (actual694); the Serving filter matched zero tests
and provides no Serving qualification. Complete scalar/source-shape funding,
original constructors and positive same-instance refusal/retry remain required.

Fused schema properties and native literal pattern owners join at `bb613ff`,
with full inventory refreshed at `db97273`. Cargo refuses excluded dependency
unit tests via workspace package selection (actual695). An independent owning
manifest preserves original features/dev-dependencies and forwards source paths
and patched support crates only. Its first offline attempt lacked codspeed
(actual696); the unchanged lock dependencies were fetched (actual697). Actual
native test execution follows; general regex, auxiliary/meta/runtime and Query
activation remain open. No C/M gate is closed and no implementation promoted.


### Actual698–703: native schema and transport qualification

The original owning schema test target compiled and ran 26 cases at `db97273`: 24
passed; two exact std hash-container quotes exceeded actual requested storage
by eight bytes. The native group-width repair is pending; exact assertions
remain unchanged. Native owner/parity/refusal/raw/permanent-provider cases pass.
All 39 original Serving tests pass at `eb0cbd2` after the lifecycle changes.

Original-error transport vendors bytes 1.12.1, http 1.5.0 and tonic 0.14.6 with
verified upstream archives/licenses and 29 exact complete inventories. Its
new owning test is explicitly registered. Offline setup first lacked bencher
(actual700), fetched under its preserved lock (actual701), then exposed a
drop-only field naming lint (actual702). `814cf67` fixes that field without
lint suppression or lifetime changes. All five native tests pass (actual703),
including exact requested HTTP layouts and detached header/body/extension
ownership through final credit release. Server qualification is still separate.

`d6f052b` connects selected Recovery reads, the original nonclonable plan and
known pre-effect retry, and original native error transport. It also adds
actual-selected archive source tests with key-expiry and structural/native
accounting checks. Full Engine test type checking is being run despite the two
remaining old feed calls, so newly authored fixture errors can be corrected
before the final producer cutover. No C/M gate is closed or code promoted.


### Actual704–706 and refined schema ownership

The Engine test-feature check at `d6f052b` reports the two known removed-feed
callers plus three test-utils references to an unlinked OpenRaft dependency.
`10c7555` declares that optional dependency in the test-utils feature; the
original check is being repeated. Unit/integration execution remains open.

Native table geometry is repaired at `a87febf`: the actual target group width
and width-sensitive small-entry bucket floor replace an assumed 16-byte group.
The unchanged schema selection now passes 26/26 (actual705). The independent
reference allocation suite passes 7/7 (actual706), including std and registry
hash tables across 29 capacities and seven shapes with exact size/alignment/clone
and positive-retirement assertions.

Schema planning now explicitly retains its actual compiled artifact or
deterministic diagnostic before acceptance on every replica/startup path,
bound to original roots, LogId, command digest and change ordinal. Application
consumes it only at the established semantic point, preserving authorization,
replay, assertion and validation order. This avoids accepted-time compilation;
it does not excuse native general regex/meta/runtime funding or owning all
source/registry/options descendants. Partial literal support stays unactivated.
All C/M goals remain open.

### Actual707 and original write capacity

The repeated Engine test-feature check at `10c7555` removes all three optional
OpenRaft linkage errors. The two obsolete feed callers still prevent the normal
library from compiling, so authored unit and integration fixtures remain unrun.

The Archive/Staged publication review identifies a remaining original-capacity
boundary: PrimaryStage retains the Engine operation/chunk/error allocation, but
its Store write still obtains fresh encrypted output and transaction grants.
The first-release producer must own those native grants before acceptance.
This requirement is now explicit in the completion order; the repaired cold
registry is no longer listed as an outstanding repair. All C/M gates stay open.

### Actual708–711 and prospective source ownership

`645fa5b` passes two original translation owner tests and two native parser/visitor/
reparse/drop geometry tests (actual708–709). Its Engine check has only the two old
feed errors (actual710). `b4f8c04` joins scalar Lifecycle/Target/Recovery source
census, actual native General header geometry, and owned canonical schema options.
These prerequisites preserve queued predecessor alternatives without cloned DTO
shadows; they do not activate an incomplete planner. The new Engine fixtures remain
unrun until library compilation is restored by the complete producer cutover.

Local disk exhaustion interrupted a draft write; no source was lost. Eight obsolete
test/server executables in this task's own lane were removed (actual711), recovering
about 2.4 GB while preserving its warm dependencies and incremental cache.


### Actual712–720 and publication integration

`0bebb2f` passes all three prepaid encrypted output tests (actual713), after the
first run exposed a test-only concrete error downcast mismatch (actual712).
The shared record encoder preserves the current wire codec and key-access checks;
fixed output comes from the original bank. This does not reserve a transaction.
Canonical schema options pass four tests at `683bc51` (actual715); the failed
private-field assertion compile is preserved as actual714.

`8aa65e8` joins native body-clone census and replayable Archive projections with
one decoded body and one funded reference at a time. `2a999c6` adds original
Registry construction ownership and actor outcome settlement. The Engine check
finds two missed census field references (actual716); `013c9e5` repairs them and
returns to exactly the two old feed errors (actual717). Seven native Registry
receiver/supplied ownership cases pass (actual718).

`94acc1b` connects standalone successful durable truncation to published-prefix
retirement while preserving unpublished replacements. Parent-workspace native
testing was rejected by Cargo (actual719). The owning default-profile compilation
finds three existing private sealing accesses and four redundant fmt qualifications
(actual720). `e6c9d59` repairs them without suppressing tests and replaces primary
tree/index iterator consumers with a row-lending contract. Native actor tests and
Engine checks on this successor are pending. Archive journal/publication and full
native transaction admission remain open. No C/M gate is closed or code promoted.


### Actual721–731 and canonical row loans

All eight native actor outcome/truncation/marker tests pass in both default and
production serde/storage-v2 profiles at `e6c9d59` (actual721–722). The new cursor
initially crossed a private module and missed a shared rebuild verifier caller
(actual723–724). `3ea1617` fixes both through the canonical projection interface;
its Engine check again has only two old feed errors (actual725). All 15 original
Raft source-custody and exact snapshot-tail tests pass (actual726).

`3b18b9f` joins funded native Registry bootstrap and a lending Archive source
cursor. All 152 native reference-resolution library tests pass (actual727), as do
four schema input/allocation tests (actual728) and five original/prepaid record
writer tests (actual729). The Engine check adds no diagnostics (actual730).
`a768223` moves feed census/publication onto the same lending journal interface,
retaining original pointer/allocation assertions. Its check also has exactly two
old feed errors (actual731); Engine unit tests remain unrun. `0efd1a7` adds typed
authenticated startup row proofs for exact reconstructed original publication
state. Startup tests and its joined Engine check are underway. The remaining
native write reservation and full producer/planner integration are still required;
all C/M gates stay open and no implementation has been promoted to the live tree.


### Actual732–743 and original native stream capacity

`0efd1a7` passes all six typed startup capacity cases (actual734); the initial
filename-based filter selected none (actual732), and its Engine check has only
the two obsolete feed calls (actual733). Neither result activates the planner.

The native stream package joins at `2c7f556`. A manifest convention mismatch
stopped the first join; its unjoined filter result is preserved without
qualification (actual735). Three fallible geometry calls fail compilation
(actual736); `eaff0c4` preserves the original errors with `?`. The next run reaches
a missing test import (actual737); `5a88685` repairs it and passes eleven physical
publication cases (actual738). The original stream filter did not match the
actual module name, so its two installed-backend cases were run by exact names
and pass at `d994e07` (actual739). These prove only the native reservation layer.

`d994e07` also joins the original paid meta bundle through the canonical lazy
registry. All 157 native reference-resolution cases pass (actual740), and four
owned schema/allocation cases pass (actual741). Managed native traversal remains
gated until all of its actual allocations and retained outcomes are funded.

The finite-budget geometry test initially used an impossible 4096-page arena
(actual742: two pass, one failure). `3dbcf1b` corrects the fixture to the format's
4095 usable pages, adds explicit 4096 rejection, and passes all seven budget and
original inventory cases (actual743). No production capacity was enlarged.
`27ebb56` joins exact Archive projection counters after complete source replay,
including repeated-peek/pass assertions. Its Engine check is running; original
Engine semantic/allocation tests remain unrun until the generic producer cutover.
All C01–C07 and M01–M07 remain open, with no implementation promoted to the live tree.


### Actual744–751: native stream and paired encryption qualification

The Archive census check at `27ebb56` reports only the two obsolete generic feed
calls (actual744); Engine semantic/allocation tests remain unrun. `d9eda62`
connects canonical registry enqueue: all 159 reference-resolution tests pass
(actual745), as do six original schema input/enqueue/allocation cases (actual746).
The native publication selection passes all 97 cases on that source (actual747),
including the 100,000-row and greater-than-96-MiB image regressions. These are
native checks, not public residency or release performance qualification.

`ba1ddb3` connects the paired encrypted stream to original native funding.
`d5cfac9` repairs cancellation before Core effects by settling the actual held
serialized writer, avoiding reacquisition of its own gate. Actual748 preserves
six passing cases and one fixture namespace failure. `2a4d25d` corrects that
assertion to the actual encrypted record namespace and extends returned/raw
failure ordinals through partially acquired native loans; all seven paired and
prepaid cases pass (actual749). Production limits and original owner assertions
remain unchanged.

The shared-identity run initially completed eight cases and then waited on a
same-task key rotation while its prepared single-image writer held the mutation
gate (actual750; deliberately interrupted, not a pass). `52b4113` preserves the
original rotate-before-commit assertions in parked mode and adds an actual
concurrent rotation contender for serialized mode. All ten selected identity,
closed-final and rotation cases pass in 7.28 seconds (actual751).

### Actual752–753: receiver before preparation

`b45e8e9` joins the reviewed 45-file original-capacity receiver package. The
native slot enters Preparing before provider work, stores the original token,
retains returned/raw failures and requires positive unaccepted cleanup. Snapshot
body token handoff is deleted. Only actual Ready delivery enables retirement
wakeups, so a Pending probe cannot repeatedly wake itself. The complete-prefix
planner and response/decoder/native/schema retirement remain required.

Actual752 preserves two native test compilation errors. `3d4448e` repairs the
missing Cursor import and redundant path qualification. The next default native
suite passes 44 cases but the unchanged close/report contention case times out
(actual753). `4a0ba4e` makes Pending completion probes use try_lock so an existing
report borrower cannot block availability or close; its rerun is underway.
Each native source transition has a complete verified inventory and a new review
checkpoint preserving its predecessor. All 29 source inventories verify; this is
not final Cargo selection or runtime qualification. All C/M gates remain open,
with no implementation promoted to the live checkout.


### Actual754–758: snapshot writer lifetime and Archive source integration

All 45 native capacity/bounded-apply cases pass in both default and
serde/storage-v2 profiles at `4a0ba4e` (actual754–755), including the original
nonblocking close test and all six preparation cases.

The parent Raft selection completes 33 cases, then the closed-authority snapshot
case hangs (actual756). A native sample shows save_vote waiting in WriterGate;
automatic single-image preparation retained that writer before Raft acceptance.
The test hit its unchanged vote deadline and runtime shutdown then awaited the
blocked writer. Root stopped only that test process, preserving log and sample.
`2ecba8c` makes the owner's writer lifetime explicit and requires snapshots to
park it while awaiting acceptance. All 34 selected parent source/fixed-capacity/
snapshot tests pass in 13.03 seconds (actual757), preserving the original vote,
no-late-grant, authority-revocation and positive-cleanup checks.

`46deac4` joins the closed Archive document journal, checked metadata/header
census and scoped consumers. It adopts the original selected source and bank,
validates semantics and replays one document body at a time. The actual Archive
command, audit/outcome and paired durable publisher remain the next connection.
Actual758's Engine check has the two known removed-feed callers plus an implicit
Sized bound in the scoped primary leaf editor. `c3da624` corrects that bound;
the repeated check is underway. No Engine unit tests or production activation
are claimed, and all C/M gates remain open.


### Actual759: Archive scoped consumers compile through the known cutover gate

The Engine check with test-utils at `c3da624` reports exactly the two remaining
removed generic feed callers. The scoped leaf-editor repair introduces no new
normal-library diagnostics. This is not an Engine test pass: canonical Schema
and Staged producers, Archive command publication, and the old reducer cutover
remain required before the original behavior/allocation suites can execute.


### Actual760–763: response prefixes, Archive dispatch and native schema traversal

Actual760 retains 15 completed Store prepared-publication passes, one fixture
mode failure and one unfinished large-operation regression stopped by root after
extended CPU-active scratch staging/compaction. The greater-than-96-MiB image
case passes, but the greater-than-65,536-operation case still requires a full
rerun. Both native stack samples are preserved. No paired/prepaid tests matched
the original supplied filters, so this run supplies no such qualification.
`c96593c` corrects only the multi-batch closed-publication fixture's explicit
writer mode to Parked and clarifies an obsolete test comment.

`c9c6010` joins exact response-prefix retirement, completion cursors and typed
authenticated constructor-row proofs. Native Pending documentation clarifies
that a positively completed prefix is never reentered; a new full OpenRaft
inventory preserves the earlier review. Runtime code there is unchanged.
`32f41af` connects the actual Archive command, source counters, independent
metadata/audit/outcome and unchanged structured/unique roots proven by complete
borrowed source replay. Its actual SDK tests remain unrun. `148d233` joins fixed
StageFunding from the same original aggregate owner; `102690d` bounds new local
notification capture without replacing original provider errors. Whole-producer
native geometry and Resources paired-writer integration remain open.

`3b32002` joins original Registry traversal plus the source-audited native draft
fixture correction. Actual761 records one generic callback type compile error;
`3a0f9d1` annotates that allocation-free callback. All 166 owning referencing
tests pass (actual762), and all eight schema input/enqueue/traversal allocation,
refusal and retirement cases pass (actual763). These reach RegistryPrepared,
not a complete compiler/runtime artifact or Engine activation. All 29 vendor
source inventories verify. All C/M gates remain open; nothing is promoted.


### Actual764: joined Engine source reaches the same two removed callers

The test-utils/tests check at `102690d` reports exactly the two removed generic
feed functions in the remaining resident reducer. No new normal-library errors
come from response retirement, Archive dispatch/index proof, StageFunding or
native traversal. Original Engine tests remain unrun. The bank contract is
refined explicitly: genuine preaccept construction may enlarge the same
original reservation before each new effect, but must seal its final ceiling
before native Ready. Only the actual preparation receiver can supply that phase
authority; the existing ordered-apply path cannot claim it.


### Actual765–767: exact constructor identity and shared Staged semantics

Actual765 records two failed Raft constructor tests and no Store execution. The
fixture incorrectly treated an Arc clone as a different storage pair. `edcd4d6`
constructs a distinct TenantStorageSet over the same original domain handles,
asserts its rejection and explicitly accepts an Arc clone of the original. The
production pointer identity check and reconstruction expectations are unchanged.

`3b541f5` joins six exact Staged leaves: one borrowed Begin/Append/Stop semantic
implementation, checked digest/counter framing, selected header validation and
header-only copies for expiry/Finalize/status. Actual766 passes both constructor
reconstruction tests and all eight selected Store cases, including the repaired
closed-final authority test and seven paired/prepaid owner cases. Actual767
reaches exactly the same two removed generic-feed callers in Engine, with no
new normal-library errors. The six new Staged semantic cases remain unrun.

Active Staged chunks still need the canonical selected native snapshot source,
a fixed received bitmap, funded terminal tombstones and lending Finalize
publication. The selected application snapshot already covers the application
store, so another per-upload snapshot is unnecessary. Old selected snapshots
must preserve deleted chunk bytes through native MVCC. The oversized Store
operation test still requires full execution and performance diagnosis. All
C/M gates remain open; the live checkout has not received the implementation.


### Actual768–770: preserve slow baseline and qualify targeted native fixes

The unchanged oversized encrypted Store operation case was intentionally
interrupted at 71 minutes while foreground writes still progressed. Actual768
retains its SIGINT/exit101 result and sampled diagnosis. About28% of the 65-minute
sample was optional maintenance warming and about5% was unused prior-value reads;
these are sample shares, not predicted speedup. No assertion, operation count,
ordinary bound, durability behavior or deadline changed. The full case remains
required; interrupted execution is not a pass.

Nine commits through `70b071929d8a34f802f15a36fe389e468f093e14` join the reviewed
scratch/maintenance corrections, native record/primary-stage geometry, exact
retained/assigned append prefix, fixed Staged census, original Scalar/Archive
input funding, native syntax ownership and shared sparse mutation steps.
Assertion and mutation directories now use prospectively funded AVL node layouts
and append-only slots; mutation order is sealed by one in-place sort. Review
caught and repaired the assertion node quote before integration. Supported
ordinary and Staged limits are unchanged. All29 vendor inventories verify.

Actual769 passes seven focused KV native geometry, maintenance pressure/failure
custody and no-unused-read cases (70.25s). Actual770 passes six native full-fit,
reopen, replacement/delete, pinned-version, compaction and budget-growth refill
cases (33.44s). Both used the unchanged joined source. Engine/native compiler
checks, full Store oversized execution, all-family preaccept, canonical Staged
and Schema producers and final production workloads remain open. No live
promotion or C01–C07/M01–M07 completion is claimed.


### Actual771–773: native Store passes and preserved integration failures

On `70b0719`, actual771 passes all three focused encrypted Store geometry and
final-accumulator cases (8.57s runtime). Actual772 completes seven Raft passes and
four append-prefix failures; Cargo did not reach the selected Types cases.
Successful selection had correctly released the temporary plan, while the new
append proof incorrectly required it afterward. `c79d09b` retains only a closed
verified seed: the original store Arc identities and three record fingerprints,
with no DTO buffer, added native pin or new allocation. The concrete enclosing
owner layout remains included in capacity accounting. Its unchanged append and
startup cases plus the retained/unplanned phase witness are pending qualification.

Actual773 records an Engine check stopped before Engine diagnostics by private
`regex-syntax::hir::original_construct`. `3c7fe90` changes it to crate-only
visibility for the existing sibling destructor-admission call and refreshes the
exact vendor file inventory. All29 source inventories verify. The owning native
syntax/meta suites and Engine checks still need to run. These failures remain
visible; no C01–C07/M01–M07 gate closes and no implementation is promoted.


### Actual774–775: seed read geometry and unchanged Engine cutover gate

Actual774 on `c79d09b` preserves seven Raft passes and five failures. The retained
seed is now available, but the initial point buffer used the header namespace and
an eight-byte log key. Bootstrap seed extent probes rejected longer actual
namespaces/keys before callbacks. `349fd2f` sizes that same initial backing from
the three exact seed record names/keys and fingerprinted value extents; absent
values remain zero. It neither increases format limits nor substitutes a generic
value ceiling. The original tests plus the phase-transition witness are rerunning.

Actual775 on `c79d09b` reaches precisely the two obsolete `append`/`trim` calls in
the remaining resident Engine reducer. The joined syntax changes now compile in
the normal dependency graph. Engine behavior/allocation tests and owning native
syntax suites remain unrun. The complete Staged header/source/semantic/snapshot
cutover must join together; the frozen snapshot and closed metadata projection
drafts are not activated independently. All C/M gates remain open.


### Actual776–777: exact seed plaintext and owning native syntax tests

Actual776 on `349fd2f` preserves seven Raft passes and five failures. Initial
geometry is now correct; the next assertion incorrectly compares conservative
encrypted-record preflight to exact plaintext length. The preflight deliberately
includes possible key-ID overhead. The retained seed already carries the exact
length and digest, so direct authenticated bounded reads followed by exact
presence/length/digest verification are the appropriate next repair. No negative
stale/foreign/oversize check may be removed.

Actual777 runs the complete actual vendored regex-syntax library suite at the
same source: 161 pass, two fail, 1.59s test runtime. The failures are the original
HIR temporary-retirement access and a class funding request-count assertion.
Diagnosis and owning-suite repair are pending; this is not a suite pass. The
external manifest and lock hashes are retained alongside the exact W source pin.
Full compiler artifact ownership, Engine activation and every C/M gate remain open.


### Actual778–786: repaired append seed and remaining compiler ownership

Actual778 runs the complete owning regex-automata default library at `349fd2f`:
all 209 cases pass. Actual779 retains the owning syntax constructor backtrace;
actual784 retains a diagnostic-only macro compile failure, and actual785 at
`680b578` identifies Unicode singleton construction as the failing branch. The
native operation grows a String with its actual vector minimum capacity, while
the previous quote used only UTF-8 length. A source-derived repair and stronger
live/held/native allocation comparisons are drafted; the complete syntax suites
must pass before this component is qualified. The automata pass does not prove
general compiler/runtime/schema ownership.

Actual780 preserves an interrupted append/startup run with no terminal wrapper
result. Actual781–783 preserve negative-fixture failures (bootstrap digest,
fixture argument type and immutable bootstrap identity); they are not successful
qualification. `3c45c5e` uses an actually installed snapshot cursor for corruption
and verifies the changed bytes before requiring refusal. At `680b578`, actual786
passes all 13 selected Raft cases and both fixed Staged bitmap cases, including
positive startup/append, retained-source phase, stale/foreign source, oversized
seed, same-length digest change and changed absence/presence. Direct bounded
authentication verifies the exact retained fingerprint without treating a
conservative ciphertext bound as exact plaintext size.

The unchanged 65,539-operation encrypted Store image is running in the existing
release build lane at `680b578`; its result is pending. No production limit or
original assertion was increased. Canonical Staged semantics, same-snapshot chunk
reads, final-Entry chunk/terminal operations and streaming snapshot ownership
must join as one producer. Its original bank must also cover the whole primary,
index and feed writer before admission. General schema compilation and caller
migration remain necessary before deleting the resident reducer. All C01–C07
and M01–M07 remain open; no implementation has been promoted to the live checkout.

## Actual787: unchanged large encrypted-store operation case

The fenced release run at `680b57818555c88f26b22b7213fd4ede791d12c1`
passed the original 65,539-operation Store publication test: one passed in
1,734.58 seconds. The native operation bound and original assertions remain
unchanged. Source content remained fixed for compilation and execution. This
is correctness evidence for the large operation case, not a throughput or
end-to-end release qualification. Earlier interrupted runs remain preserved.

`3ecd4d2` subsequently joins exact preaccept provenance and reviewed native
output accounting components. Owning-suite qualification is pending. All
C01–C07/M01–M07 remain open; no live production promotion occurred.

## Actual788–794: native syntax, NFA and preaccept ownership

At `3ecd4d2f5d96fa53e0ce3d7ce03f177dd65e589c`, the complete owning
regex-syntax library passes 164 default tests and 159 without Unicode tables
(actual788–789). At `44f14ecba812a493d9d7e57ebb5c809fea26c2cc`,
regex-automata passes all 217 default and 109 minimal-feature library tests
(actual790–791), including actual native allocation/peak parity, refusals,
original errors, capture metadata and graph-alias retirement. Full compiler
intermediate buffers and matching-runtime ownership are still unfinished.

Actual792 records a command-selection error: the parent workspace cannot run
a dependency's owning dev tests. Using the vendored owning manifest then passes
all 47 OpenRaft capacity/bounded-apply cases in both default and serde/storage-v2
profiles (actual793–794). This verifies exact live receiver observations; it
does not establish the all-family preaccept producer. The physical same-claim
growth prerequisite is joined at `40a3b51`, with its native suite in progress.
All gates remain open and no production cutover is claimed.

## Actual795–796: original physical claim and canonical fixture cleanup

All 13 native physical-publication tests pass at
`40a3b51bd05d1aa60f028061734ae9d1b45e89e6` (actual795). The added
real-file cases retain the same claim identity/count, allocate no new memory
grant, exclude loaned transactions and preserve old rights after growth refusal.

The subsequent normal Engine check finds a stale OpenRaft testing-suite call
to a fixture-only preparation helper (actual796). Native unit builds had hidden
that problem with cfg(test). `c4e732c23dcb6c3211a0dce2218954984569f59b`
converts the caller and removes the duplicated direct Prepared-state fixture
implementation in favor of the canonical begin/install/finish lifecycle.
Normal-library check and native regression reruns are pending. No gate closes.

## 2026-10-08: exact original owners and prefix design

The joined source is `5f41750`, still isolated and unpromoted. The canonical
OpenRaft fixture preparation repair passes 47 tests in each owning profile;
the normal Engine check reaches exactly the two removed generic-feed calls.
RangeTrie/UTF-8 native cache allocation events and Builder weak-reference
retirement are joined and pass owning default/minimal profiles (actual798–805).
The syntax-disabled Builder profile passes 78 tests. Literal-trie events are
joined and await qualification. Full schema compilation/runtime and producer
activation are still required.

Prefix design now reuses existing private Attempt/Inventory records and the
real authenticated startup projection reset. Unaccepted work cannot mutate the
committed epoch. Changed catalog mappings remain bounded retained overlays;
only membership changes build a referenced catalog. Feed progress must be
attempt-specific and retained sequence ranges must settle before reuse.
These decisions refine implementation gates; none is production activation.
All C01–C07/M01–M07 remain open.

### 2026-10-08: canonical compiler and physical writer checkpoint

Recovery workspace source `908fc8c` includes the original growing native/paired
writer, original-bank Engine writer/funding join, shared committed semantic
read owner and complete native HIR-to-NFA compiler. The paired/native/KV scoped
writer suites pass 5/6/6 tests; compiler default/minimal and syntax suites pass
229/121/164. Evidence actual806–818 preserves the interrupted and failed runs
as well as their verified repairs. The ordinary Engine still fails at its two
removed generic-feed calls; this requires completing Schema/Staged/private
predecessor producers and deleting the obsolete reducer.

The refined first-release goals require one canonical path, strict old-format
rejection, full eligible residency whenever the shared bound permits it, and
atomic disk persistence before publication. No C/M goal closes and no storage
redesign has been promoted into the live checkout.

### 2026-10-08: original writer authority and feed attempt ownership

At `e905722`, the recovery workspace includes lexical physical writers,
retained native owners without implicit write authority, exact residual claim
extension, original-bank private source loans, and attempt-specific feed
cleanup. Peer review caught and repaired a retained-sequence overwrite path:
the complete append range is checked before descriptor effects, then individual
slots are checked again immediately before writing. Exact exclusive prefix
ownership and same-source private Head/pin still require the real planner.

Actual819 preserves the initial seven compiler errors; actual820 reaches only
the two existing removed-feed callers after repairs. Actual821 preserves the
incomplete component-harness setup; actual822 passes all eight real feed
codec/plan/progress/prefix tests with physical publication explicitly excluded.
Actual823–826 pass literal syntax default/no-Unicode 167/162 and automata
default/minimal 229/121. The shared semantic candidate must be built before
private physical preparation finishes, but actual actor Ready still requires
the complete graph/effects proof and sealed original writer. This dependency
is now explicit in the goal gates. All C/M goals remain open.
