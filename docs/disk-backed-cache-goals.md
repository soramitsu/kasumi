# Disk-backed storage with full residency below the memory bound

Status: **active; all seven implementation goals remain open**. Established
2026-09-30 from the user's proposal and clarification; current status consolidated
2026-10-08. These goals extend G02 and its query, snapshot and resource-admission
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

The production default must provide a large shared residency budget that scales
with configured host/container capacity. Separate that capacity from bounded
operation workspace. A 512 MiB temporary-workspace ceiling and small per-store
settings must not silently restrict an otherwise fitting large cache. The
aggregate default/workspace correction and the joined 222-case Engine/KV
selection pass, including actual cache backing, generation registration,
last-database-owner retirement and bounded known-union refill. Complete
full-residency activation still requires the full allocation census, every
index kind and a native residency witness that remains current after cleanup.
Explicitly configured small bounds and their rejection tests remain valid.

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

## First-release canonical design

The user reaffirmed on 2026-10-08: remove old code and keep the strongest design.
The release must expose one canonical disk-backed storage and query path.
Delete superseded resident document/index/feed implementations, obsolete APIs,
compatibility readers/writers and permanent feature-switch alternatives when
the replacement is integrated. Preserve supported behavior, security and
operational guarantees through the canonical implementation. Intermediate
coexistence is only a development step, never a released fallback.

Prefer removing a structural memory limit over extending an obsolete resident
representation. In particular, full-copy feed growth and per-commit retention
of an entire publication bank are not the final history design. Use bounded
same-snapshot disk access and exact owned backing; let the shared cache retain
all eligible data whenever it fits. Failed-source archives and test evidence
remain development history and are not executable compatibility paths.

Deletion is part of acceptance, rather than post-release cleanup. The final
source must satisfy these cutover checks:

| Area | Canonical implementation | Code to remove at cutover |
|---|---|---|
| Documents and indexes | Atomic durable roots with snapshot-aware reads and the shared cache. | All-document serving maps, resident-only index dispatch and fallback feature switches. |
| Public queries and cursors | One owning result/page API with current authorization, expiry and cancellation checks. | Resident query/cursor dispatch, duplicate staging APIs and adapters that copy into unaccounted outputs. |
| Change feed and snapshots | Same-snapshot disk records, bounded pages and streaming import/export. | Resident commit history, full-copy feed growth and per-commit ownership of entire publication banks. |
| Storage formats and configuration | One first-release format and one shared residency policy. | Old readers/writers, migration branches and settings that select obsolete implementations. |

Verify each removal with the affected public callers and original behavioral
tests. Keep negative format-rejection tests. A temporary selected API is an
integration step; it is not a second supported serving path. Full residency
must cover the canonical data, including feed and retained snapshot pages,
without rebuilding the deleted resident structures during preload.

## Current production status

**All C01–C07 and M01–M07 remain open.** Work is integrated in an isolated,
source-pinned cohort; production still serves resident documents and indexes.
The live checkout has not received the storage redesign. Passing a component
is a prerequisite, not an activated production feature.

The current implementation checkpoint is `473cdba` in the persistent recovery
workspace. The following results are component evidence; the final joined
release still needs all acceptance gates below.

| Component | Verified progress | Remaining activation work |
|---|---|---|
| Native publication | Disk-backed atomic image/stream regressions and 13 physical-claim tests pass. The six native stream-extension cases pass after exact fixture alias retirement (actual811), including stale/foreign quotes, nonzero growth and refusal. | Thread the original writer through every real producer and qualify mixed prepared prefixes, cleanup and final publication. |
| Paired encrypted writes | Five paired stream cases pass at `b505918` (actual807), including growing the original claim, sealing, expiry and original error/panic custody. Earlier prepaid and identity/rotation checks remain preserved. | Use this writer for actual private primary/index/feed output and final Staged/Archive effects; complete retained-owner retirement. |
| Selected Archive source | The closed journal and scoped consumers are joined. `32f41af` connects the actual Archive command, independent header/audit/outcome and structured/unique index preservation. Replays retain one body and the original source/bank. `ee9e5e5` adds the source-measured archive decode capacity; normal check actual831 still reaches the two obsolete feed callers. | Qualify the actual SDK route once Engine compiles; finish finite original paired native publication and delete the superseded history reducer. |
| Feed preparation and cleanup | Attempt-specific progress and strict framing replace the scope-only journal. Abort checks exact attempt/commit ownership; empty appends cannot erase a later commit. All eight pure codec/plan/cursor/prefix tests pass (actual822). `473cdba` joins the private predecessor feed census, positive reader retirement, and finite mutually exclusive abort/trim liabilities. | Bind the actual exclusive prepared sequence range and same-source private Head/pin, reserve complete cleanup before Ready, and qualify physical mixed-prefix abort/trim/publication. |
| Selected Staged source | `473cdba` integrates the fixed received bitmap, selected/private chunk source, immutable terminal/chunk publication, semantic predecessor adapters, and streaming snapshot callers. | Finish actual family/provider/owned-route activation and same-bank physical custody. Qualify atomic Finalize, replay, snapshot and refusal through the SDK. Joined source is not yet compilation-qualified. |
| Schema ownership | Canonical reference resolution and the complete HIR-to-NFA compiler are joined. All 229 default and 121 minimal owning automata tests pass (actual815, actual817), including native allocation/peak/live parity, funding refusals, errors and aliases. Canonical literal extraction/optimization is joined at `e905722`; syntax default/no-Unicode pass 167/162 tests and automata default/minimal pass 229/121 (actual823–826). Native Aho/Teddy and shared prefilter selection are joined: actual833 passes 155 Aho tests; actual836–837 pass three owning cases and all 232 default automata tests. Actual832 preserves the missing 256-byte allocation failure, repaired by an inline fixed alphabet rather than a larger allowance. Actual843 passes 239 tests including OnePass. Actual844 exposed four needless allocations in scalar DFA cache sizing; a shared fixed encoding constant removes them. Actual849 at `b8163fa` passes all 245 default automata tests, including original native determinization state/traversal. | Finish the enclosing native strategy/engines/runtime caches and the actual compiled-or-error Schema Create/Replace artifact before acceptance. No restricted language substitute. |
| Ordered context | Canonical retained and assigned rows carry full log/predecessor, membership, command and retirement-seed binding, with the unchanged primary fingerprint. All eight prefix tests and six startup tests pass at `c75d0d8` (actual829–830). Only the current retained membership is moved within the original scan grant. Actual835/838 each pass eight cases for whole-request binding and the canonical staged terminal identity. `118a8da` adds distinct actual startup provenance; all seven cases pass in actual839. At `b8163fa`, actual847/848 pass eight append and seven startup cases, including borrowed canonical membership. | Bind these stamps to the actual exclusive cohort prefix; seal each graph before issuing its successor, revoke canceled members, and release ranges only after positive cleanup. |
| Replica capacity | Exact live receiver provenance and canonical fixture preparation pass 47 owning OpenRaft cases in each profile (actual799, actual802). Response-prefix and typed constructor component evidence remains preserved. | Complete all-family predecessor preparation, lexical writer authority and exact response/decoder/native/schema retirement through truncation, snapshots and startup. |
| Canonical Engine producers | Lifecycle, Retirement, Recovery, Archive and source-census components are joined. The original-bank writer/funding path, shared committed-read loans and lexical write authority are joined. Actual820 at `20c9af4` reaches exactly the two old generic-feed callers after the 57-leaf authority cutover and repairs. `8e084bf` adds original-bank immutable private descendants. `01db285` separates semantic preparation, writer sealing and final graph readiness; normal check actual828 still reaches only those two callers. `e9133c0` admits independent descendant reader buffers sharing one immutable native pin, as required by staged finalization. `473cdba` joins the actual sealed private graph, prefix registry, exact full-context General provenance, atomic source bridge, frozen supplemental effects and semantic-source adapters. Normal Engine qualification is in progress (actual850). | Finish family/provider/owned callers and complete Schema origin, settle every installed failure, recover private attempts after crash, delete the obsolete reducer, then pass original Engine/SDK semantic and allocation suites. |

Failed evidence remains preserved. In particular, actual742 records an invalid
native geometry fixture; the repair tests the actual format maximum and rejects
its successor without increasing a production limit. Actual748 preserves a
paired replay fixture's wrong record namespace. Actual750 records an interrupted
rotation test that tried to reacquire its own held writer; actual751 retains
rotation-before-commit coverage in parked mode and adds real concurrent rotation
coverage for serialized mode. No passing component closes a C/M gate.

The next reviewable integration gates are concrete and remain open:

- Compile the joined canonical Engine path with no removed feed API restored.
  Complete actual ordinary, Staged, metadata and Schema producers; route both
  borrowed and owned commands through their preaccepted artifacts.
- Prove lifecycle closure: positively retire census readers before refreshing a
  private pin, settle failed-before-seal owners, revoke canceled suffixes in
  reverse order, and recover unselected attempts from durable storage on reopen.
- Bound the prefix registry itself. Selected retirement must prune or reseed
  ancestor controls and banks; a growing immutable chain cannot become a new
  memory-resident history directory.
- Pass the original Engine/SDK tests and physical failure-injection cases before
  the final full-residency/cache-pressure and release qualification workloads.

The completion order follows the actual dependencies:

1. Finish canonical Schema, Staged and Archive producers and migrate their live
   callers so Engine compiles without either removed generic feed function.
   Archive must carry its closed journal through independent header/audit/outcome
   construction and original paired writes. Staged transactions must preserve
   complete validation, permanent outcomes and atomic publication. Full schema
   compiler artifacts must be owned before acceptance. Delete each superseded
   resident reducer when its complete replacement is connected.
   Include every membership/no-op/custody row in the private sequence. Retained
   append rows and startup reconstruction must use their actual borrowed native
   scope, never a fabricated ordinary request or applied context. Startup must
   also discover and clean unselected private attempts from disk: an in-process
   registry and the old global pending pointer cannot recover them after a crash.
   The earlier two compiler diagnostics concealed a complete producer/provider
   replacement. The larger integration at `473cdba` now requires ordinary
   compilation and original behavior/failure tests.
   `prepare_command_ordered` still serves the borrowed ordinary route, an owned
   fallback and local fixture helpers. General selected Schema/Create/Replace
   publication is still missing: selected preconditions and the restricted first
   collection constructor do not provide it. Migrate these routes and their
   original behavioral fixtures together, then delete the resident reducer and
   its remaining recovery/staged mutation helpers. A runtime rejection for a
   supported family, a test-only copy of the obsolete reducer or restored
   generic feed functions cannot substitute for that cutover.
2. Run the original Engine semantic/allocation and SDK suites on that joined
   source. This unlocks qualification of already integrated Recovery, Lifecycle,
   Retirement, Archive and scoped consumers. Preserve original limits, failure
   ownership, authorization and permanent-outcome assertions; repair failures.
3. Finish and activate the complete preaccept/startup prefix planner for every
   supported family. Cover every accepted predecessor, partial preparation,
   overwrite, snapshot and durable truncation outcome. Publish or retire exact
   original response/decoder/native/schema owners. A known Pending cleanup may
   retry only after positive settlement; unknown outcomes retain their owners.
   Run unchanged audit capacity/refusal/same-instance retry cases.
4. Complete public read/cursor/transport cutover and delete all superseded
   resident dispatch, format and configuration paths. Then run all five cache
   workloads, the complete allocation census and repository/release checks on
   one final source before promotion. A fitting database must return to full
   residency after finite startup, shrink or budget-growth refill.

Original stage normalization is joined at `148d233`/`102690d`: selected work
uses the same fixed First bank; ordinary preparation acquires one original
complete bank. Its native subloans cannot obtain another aggregate grant. The
physical writer must own the complete operation reservation before actor
acceptance, including graph/index/feed writes and cleanup. A producer with a
known complete shape can prepare it once. For generated Field/text output, the
same original bank and native stream claim may extend prospectively during
genuine preaccept construction, before each corresponding effect. This is one
ledger slot, physical claim and stream throughout, not one grant per batch.
Seal the complete producer and its final ceiling before Ready. The actual
preparation receiver supplies that authority; ordered apply cannot relabel
itself preaccept or grow a sealed bank. Five original normalization tests await
the Engine compilation gate.

The producer cutover and prefix planner are one dependency chain, not independent
release steps. Complete these joins before deleting the remaining reducer:

1. Bind the command, original receiver and exact selected predecessor to a live
   preaccept scope. Borrow the standing owner without running providers or disk
   work under its mutex, and include every retained-but-unapplied predecessor.
2. Prepare the semantic journal and native output under the same original bank.
   Freeze the immutable semantic candidate while the genuine preparation loan
   remains live, then build its private physical graph. The native writer may
   grow during this construction; semantic candidate availability is not actor
   Ready. Require the complete graph/effects proof and sealed original writer
   before that final transfer. Extend the original native claim before new effects when geometry is learned
   from actual output. A refusal must precede the effect; interruption retains
   the original owner and diagnostics.
3. Seal and retain the completed command owner before Ready. Ordered apply
   consumes that owner after verifying its exact log position, bytes and
   predecessor; it does not reconstruct it or acquire a replacement allowance.
4. Test partial preparation, capacity refusal, duplicate/replayed commands,
   conflicting prefixes, snapshot replacement and durable truncation. Only real
   actor settlement or publication can authorize cancellation or retirement.
   Then migrate the original semantic fixtures and delete obsolete code.

The preaccept receiver provenance and native physical claim growth are joined
prerequisites. The remaining prepared-prefix work has these concrete gates:

- Preserve every membership/no-op transition in the real ordered prefix. Prepared
  application stamps must match the actual full applied context, including the
  membership log identity and retirement seed. The canonical row producer is
  qualified; closed cohort issuance and cancellation are still required.
- Separate read provenance from publication authority. A prepared successor
  reads the exact retained predecessor, including its private primary mappings,
  Staged records and feed head. It never manufactures a committed receipt or
  borrows an accepted apply guard. Authorization and storage expiry apply to
  these in-memory overlays as well as disk reads.
- Keep unaccepted attempts outside the committed epoch chain. Stage their
  counted objects in the existing attempt/inventory namespaces; publish the
  attempt, preceding tail, epoch totals, selector and application effects in
  one final atomic Entry. Do not change committed epoch counters while preparing.
  The authenticated startup reconstruction already replaces all derived primary
  namespaces before serving, so a second crash-recovery format is unnecessary.
- Borrow changed catalog mappings from sealed original effects, with the same
  source for point lookup and enumeration. Reuse the existing referenced catalog
  for membership changes; do not rewrite every collection for each document edit.
- Isolate feed progress by its original attempt and protect every retained
  sequence range. Conflicting prefixes may reuse a range only after actual
  truncation and positive retirement; private preparation cannot trim committed
  history or delete a retained predecessor's output.
- Abort excluded descendants before ancestors, retain grants through actual
  cleanup, and preserve failed/unknown outcomes. Test partial publication and
  restart against the real stored checkpoint and committed replay tail.

These are required production joins, not completed features. The final source
must remove the old accepted-only staging entrance and remaining resident
reducer after their canonical replacements and behavior tests pass.

The detailed component chronology, including failed and interrupted runs,
is preserved in the [evidence ledger](evidence/disk-backed-cache-20260930/README.md)
and [prior goal record](evidence/disk-backed-cache-20260930/goals-before-canonical-cutover-refinement-20261008.md).
The large unchanged 65,539-operation encrypted Store test passes in the existing
release lane (actual787, 1,734.58 seconds). This establishes correctness for that
case; its staging throughput remains unqualified. Native snapshot preparation
parks its writer during acceptance so vote persistence can progress; the
original vote/deadline tests pass (actual757).

The family cutover must be completed explicitly before planner activation:

| Family | Current concrete progress | Required before activation |
|---|---|---|
| Target and Recovery | Canonical reducers consume keyed original constructors; local verification/error geometry is integrated. | Run original semantic/allocation tests, selected coordinator reads and complete predecessor-prefix funding. |
| Create collection, mutation and scalar commands | General mutation/scalar producers exist; collection creation has only the restricted funded-genesis constructor. | Build the general selected Create/Replace producer with the full schema artifact and index rebuild; replace fresh accepted-apply grants with original preaccepted constructors. |
| Retirement | Canonical semantic, metadata and independent response ownership are integrated. | Pass permanent-outcome and native lifetime tests, then activate consume-once preaccept hooks. |
| Schema | Selected preconditions compile; all 26 fused/literal compiler and seven native allocation cases pass. | Retain the complete supported compiler artifact before acceptance, including native graph/runtime/source owners; consume it in order and complete all index rebuilds. |
| Lifecycle | Canonical producer is integrated; all 39 Serving cases pass. | Run Engine permanent success/rejection, native ownership and end-to-end tests, then activate original preaccept hooks. |
| Staged transactions and history archives | Archive validation/projection uses one prepaid snapshot and one live body; primary/feed consumers lend rows. Paired original-bank stream and identity/rotation regressions pass seven and ten cases. | Connect the bounded journal and original native transaction subclaims, every retained chunk/reference and terminal outcome, then delete resident paths. |
| Metadata, audit pruning and startup | Native reconstruction callback exists. | Original metadata constructors; seed actual restored state, cover every committed/uncommitted prefix member and forward through owned backend. |

For schema changes, compilation belongs to the original preaccept owner on every
replica and during startup reconstruction. Retain the actual schema source,
compiled graph or deterministic diagnostic, options/registry and native provider
under the exact `(roots, LogId, command digest, change ordinal)` identity. Consume
the artifact once at its original ordered semantic point. Authorization, replay,
read assertions, epochs, duplicate definitions and existing-document validation
keep their established order; precompilation must not decide their outcomes.
The full language and runtime must be supported before activation. Compilation
at accepted application time, leaked borrowed lifetimes, guessed wire multipliers
and post-allocation accounting do not satisfy this gate.

The planner must cover mixed accepted batches, repeated probes, term overwrites,
snapshot replacement and cleanup refusal. Classifying all families is not a
capacity proof. Do not activate a subset with unsupported families counted as
zero or recover by granting new node capacity after acceptance. The detailed
[activation audit](evidence/disk-backed-cache-20260930/actual683-preaccept-activation-audit.txt)
records the actual missing consumers and acceptance tests.

The complete-prefix planner is the common activation gate. It must reserve the
complete successor overlap on each replica before local acceptance and bind the
constructor to the exact LogId, command digest, family, source roots and governor.
Cover every intermediate predecessor, including earlier accepted schema changes,
same-sized substitutions, repeated probes, overwrite and snapshot retirement,
saturation, and partial preparation failure. Apply consumes each original owner
once and never obtains a replacement grant.

Startup must use the actual restored checkpoint as that planner's baseline.
Authenticate complete committed replay coverage before selecting the matching
primary root; never bootstrap from a later durable selector. Seed the restored
state directly while its original restore owner holds the gate, then fund the
complete accepted and uncommitted tail before replay. Forward the same preparation
through the owned backend. Reconstruction remains a closed, crash-restartable
pre-serving operation. Test fresh startup, snapshot restart, repeated reopen,
interrupted construction and missing coverage with the original limits.

Canonical producers must preserve all original deterministic successes and
rejections, permanent outcomes, audit and snapshot quotas. Every temporary
metadata copy and native growth must be funded before it occurs. Independently
own the final header: no chain of previous generations or complete historical
construction banks may escape into publication. Archive-inclusive counts come
from the authenticated selected census, including metadata-only commands.
Lifecycle completion must reserve the existing maximum audit event, including
snapshot framing and decimal counter growth.

Shared Authority trust retains its original installation owner. Its allocator
and failure-path tests remain required, along with complete local error frames,
provider failures, native backtraces, transport headers, extensions, bodies and
final shared aliases. A message-size bound alone does not cover those owners.
Public source and output work must retain exact snapshot, authorization, expiry,
audit, cancellation and cleanup semantics.

Preserve the original audit physical bound of 64 MiB and 128 slots, alongside
its separately configured aggregate limits. A same-instance retry after a proven
pre-effect refusal must succeed under those unchanged caps. Restart/replay,
arbitrary increases, relaxed deadlines or skipped assertions are not substitutes.
Memory and performance gates remain separate: bounded scans still need measured
latency and an efficient selected unique-index lookup. Maximum supported Staged
streams must not introduce quadratic copying of large assertion keys or mutation
payloads. Fund the concrete directory node layout, including links and allocator
overhead, before allocation; exercise descending and mixed-order streams at the
unchanged supported limits. The greater-than-65,536-operation encrypted Store
case must complete its original publication/readback assertions. Sampled progress
or an interrupted performance baseline is diagnostic evidence, never that pass.

The recovered baseline remains independently committed as
`7d250197e34008c8f84d0e63aaeec6b402371c5b`. Keep source and checkpoints in persistent
storage, preserve failures, and promote only a fully qualified joined source.
The earlier detailed narrative is retained in the
[pre-refinement goal record](evidence/disk-backed-cache-20260930/actual688-goals-before-refinement.md)
and [progress ledger](disk-backed-cache-progress-20261003.md). No goal closes
because a component compiles, its source is reviewed, or its plan is reorganized.

## Integration state and next observable gates

| Area | Current state | Next required result |
|---|---|---|
| Native storage and shared capacity | Disk directory, snapshot lookup, page caching and the large aggregate budget have scoped passing evidence. ARM hashing passes nine original digest/corruption tests. | Preserve the original cases on the joined source, then prove the complete native/document/index allocation union and bounded above-capacity behavior. |
| Publication and shutdown | Multi-collection publication, generation accounting, idempotent read sealing and admitted-producer drain order are applied in the isolated source. Nonblocking sealing and actual SDK shutdown/retry now pass; the wider SDK36 remains unqualified. | Complete the unchanged SDK suite, including refusal, replay, counter-corruption, held readers and cleanup. Diagnose any failures without enlarging limits or weakening assertions. |
| Structured indexes and cursors | Cursor, scalar/composite, array and Decimal changes are applied. Five focused declaration/funding cases and the authenticated retirement-set test pass. First/sparse count admission, sealed counters and primary-page namespace repairs are applied; all seven SDK reruns still exceed original write deadlines. | Diagnose late apply failures and staging cost, then pass original SDK publication, retained-snapshot pagination and uniqueness checks without changing their deadlines. |
| Text and schema | Shared prepared Japanese dictionary passes the original 32 MiB Session allocator case. Other text/schema construction and selected evaluation still need complete funded paths. | Pass original analyzer/schema profiles and general application schema compilation/runtime, then expose full supported query behavior through canonical selected reads. |
| Feed and snapshots | Bounded disk feed records, shared query/feed cleanup, streaming export/import and the genuine restore producer are being joined. The actual Raft restore-worker bridge passes ten constructor/cancellation/retirement tests. | Compile the complete canonical producer join, then pass original Engine history, retention, backup/restore, cancellation and failure-custody cases; remove resident history and reconstruction. |
| Public callers and transport | Owning pages/errors and response adapters exist as integration work. | Cut over every supported caller with funded body/header/extension backing, current authorization and expiry, strict audit, and final-alias retirement. Delete superseded APIs and dispatch. |
| Full residency and release | Native below-bound and shrink/growth witnesses pass on earlier sources. The indexed multi-collection witness currently fails during publication, before its residency assertions. | Complete finite preload/refill for every index and public generation, then all five workloads and repository gates on one final source. |

A reviewed or compiled component is not an activated feature. Exact commands,
source hashes, past passes, failures and recoverable archives are recorded in the
[progress ledger](disk-backed-cache-progress-20261003.md) and
[evidence ledger](evidence/disk-backed-cache-20260930/README.md).

The next integration gate includes canonical bootstrap imports using the original
node governor, original-owner snapshot validation and relocation, independent
metadata ownership, and disk-backed pagination. Metadata copies must not keep
an unbounded chain of prior generations alive. Shared metadata aliases retain
their own allocation credit until final destruction. Test fixtures must exercise
the real durable publisher and canonical imports, preserving their existing
limits, deadlines and behavior checks; deleted resident helpers must not return.

Keep memory and performance acceptance separate. The current uniqueness check
streams primary rows with bounded memory but scales with database size and the
number of changed rows. Replace it with the paid selected unique-index lookup
and measure the final fitting and pressure workloads. Feed/audit retention must
also use bounded disk access and maintenance; a growing full-copy tree or one
entire publication bank retained per commit does not meet the design.

The detailed source-ownership, acceptance, retirement and constructor gates
remain binding in the [preserved detailed gates](disk-backed-cache-progress-20261003.md#detailed-ownership-and-integration-gates-preserved-during-goal-refinement--2026-10-06).

## Production milestones

| Milestone and C goals | Production outcome still needed | Executable exit gate |
|---|---|---|
| **M01: Repair and preserve qualification** — C05, C06, C07 | Preserve the original startup/catalog 223-case pass and separately qualified bounded memo, numeric, encrypted Store, sparse, reopen and lifecycle results. Qualify the repaired panic-custody owner through integrated callers; finish genuine Japanese Session and schema compiler/runtime joins. Earlier failures and baseline failing profiles stay visible. | Every affected original scenario reaches its intended assertion on the final source. Keep original limits and negative configurations. Passing reruns do not diagnose unexplained physical enrollment failures, and component passes do not establish production readiness. |
| **M02: Reusable encrypted reads** — C01, C05, C06; supports C02 | Route earlier control planning, selected capture and installed terminal scans through their actual operation-owned point backing. Finish constructor/retirement custody and the exact read-owner handoff. | Real encrypted reads reuse bounded backing without mandatory per-record reservations; snapshot, table, provider, authentication and current expiry checks remain exact. Two distinct cleanup failures retain both originals. Verify the large capture path separately from fixture setup. This does not yet prove postcommit capacity. |
| **M03: Protected publication capacity** — C01, C05, C06 | Activate real current/next source rights and reusable workspace; fund escaped historical sources before return. Replace production legacy generation references and plain validator references with actual payload and Weak-tail funding owners. Bind complete successor capacity to local leader/follower acceptance, recovered accepted suffixes, membership/catalog changes and snapshot installation. | After accepted admission, saturating ordinary capacity cannot introduce a new mandatory source/planner/capture refusal. Several writes progress while old snapshots stay readable and charged. Copied metadata-bank retirement cannot certify shared payload retirement or authorize the next apply. Refusal happens before local acceptance; canceled waiters cannot release accepted capacity. Recovery and all ingress paths use the same owned guarantee. |
| **M04: Authoritative disk documents** — C03, C04, C05, C06 | Preserve the isolated normal Engine compilation of the actual primary tree and projection modules and genuine fixture-only gates. Install and retain the actual committed baseline and bound query metadata in the production apply lane; preserve the prior and accepted candidate through publication, capture failure and exact recovery resolution. Wire primary construction, edits, deletes and recovery into actual ordered publication. Switch document queries to exact durable roots and activate full-fit document caching. Remove the resident all-document serving alternative. | Normal compilation and real factory/standing-owner callers pass before claiming production integration. The real service performs point reads, scans, CAS, batches, idempotent replay, retained-version reads and restart with documents larger in total than RAM. Fitting new/updated/rarely read documents stay resident after warm-up. Document publication and all associated metadata are atomic. Coordinate the cutover with M05 so existing index features remain available. |
| **M05: Disk indexes and growing metadata** — C01, C03, C04, C05, C06 | Persist structured/unique/text indexes and bound their build/edit/query work. Replace remaining data-sized resident history, archive references and active staging. Preserve the implemented scalar retained-log endpoints and streaming header fold; qualify their exact immutable-source proof through append, truncate and snapshot transitions. Finish bounds for protocol-owned term metadata, requested entry batches and opaque response bytes; retain the exact active window needed for consensus. Keep already-disk-backed receipts/terminal rows on their canonical paths. | All supported filters, ordering, projections, aggregates, pagination and text analyzers/ranking agree below and above the bound. Documents and index roots commit together; schema/uniqueness behavior is preserved. Startup, log/header traversal and builders do not materialize a full data-sized map/vector. |
| **M06: Complete residency and accounting** — C01, C03, C05, C07 | Integrate one total budget across native and decoded caches, query/output work, protected sources, retained versions and bounded collection reservations. Bind every genuinely published public/leased/registered generation to the census. Activate the finite production refill worker and complete selected text warming. Let one large collection or native role use available aggregate capacity; installed per-database limits cannot strand a fitting dataset cold. Expose finite preload/refill completion and budget-change behavior. Develop this alongside M04/M05. | A complete fitting dataset has zero serving document/index/directory fetches and no capacity eviction after warm-up, including after writes. Growth through the bound evicts gradually; cold scans preserve the hot set; deletion/budget growth refills everything that fits. Actual live and weak/pinned tails stay charged until release. RSS/swap are measured separately from cache accounting. |
| **M07: Final operational qualification** — all C01–C07 | Run the final canonical implementation through standalone/replicated operation, restart, snapshots, backup/restore, archive/audit, maintenance, security and shutdown. Validate deployment defaults and document measured limits. | The five existing workload classes pass on final source, together with repository/release gates. Preserve the completed 100,000-row recovery and 4,200-command permanent-custody snapshot/reopen results; rerun affected checks on final source. Demonstrate bounded maintenance progress and actual physical reclamation; reject older formats. Publish measured cache/RSS/swap/latency results without a universal hit-rate or disk-size claim. |

Security, durability, version consistency and original memory ownership apply
through every milestone. A milestone closes only when its code is active in
supported production paths and its acceptance gate passes. Test-only paths,
copied accounting, source reviews and component totals cannot substitute for
those gates.

## Unresolved qualification obligations

These remain release gates even when related component reruns pass:

- **Physical enrollment:** the narrow rejection of prepaid allocation contraction
  above unchanged EOF is repaired and scoped-qualified by NodeDisk191 and the
  original encrypted byte-image and expiry/reopen scenarios. The current
  predicate and regression bodies remain literal to that qualified source.
  The OS trigger remains unverified. Later opaque `InvalidData`, native-root
  checks and concurrent completion timeouts are separate open obligations;
  correlate the first existing effect, fixture identity and failing predicate
  before teardown. Preserve strict identity/EOF/custody checks and original
  evidence; a passing rerun alone does not explain these newer failures.
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
  The global simultaneous workspace bound must include temporary native
  storage and rehash backing; classifying only operation reservations misses
  current temporary allocations charged as resident. Keep explicit total-cap
  settings exact while deriving a large deployment-scaled default.
  A cache limit alone is not a bound on process RSS or operating-system page
  cache. Measure those separately and document the process memory envelope.
  Prove the materialized allocation union used for full fit: sampled RSS plus
  all reserved credit currently overlaps live owned backing, while reservations
  may also cover future peak work. Neither blindly adding nor subtracting those
  measurements establishes the required union.
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

Run these required gates on the final joined source, using the existing warm
Cargo lane. Record each result with the source manifest and raw output:

```sh
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked --no-deps -- -D warnings
cargo fmt --all --check
python3 -m unittest discover -s scripts -p 'test_*.py'
```

These repository gates supplement the five production workloads and operational
release checks; they do not substitute for them.

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
