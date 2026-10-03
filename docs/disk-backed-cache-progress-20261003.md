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

