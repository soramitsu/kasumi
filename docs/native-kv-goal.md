# Native Kasumi key-value engine goal

Storage update, 2026-09-30: the active
[disk-backed cache goals](disk-backed-cache-goals.md) require a large cache
that retains the complete working database while it fits and supports eviction
and disk-backed reads above the bound. The native key directory must become
disk-backed with bounded page caching; durable writes, encrypted storage and
ownership contracts remain required. Historical checkpoints below do not
establish completion of that redesign.

Status: active. The 2026-09-24 direction replaces the planned redb-backed G02
implementation. Kasumi will own its durable key-value engine in Rust and remove
the redb dependency and vendored fork. This change must preserve the public
encrypted store and Raft storage contracts while replacing the physical format.

The current production implementation is the segmented engine described in
[`kasumi-kv`](../crates/kasumi-kv/README.md) and the
[node group contract](node-file-envelope.md). The earlier single-file format
and the checkpoint results below describe superseded source; they do not verify
the current implementation.

## Completion criteria

1. Implement a Kasumi-owned transactional file format with atomic durable
   multi-key and multi-table batches, serialized writers, stable ordered read
   snapshots, crash recovery, corruption rejection, and explicit close custody.
2. Charge persistent and scratch growth and resident work through the installed
   disk and memory owners. Preserve encrypted records, key catalogs, and scratch
   storage without storing plaintext on the persistent backend.
3. Cut over all production and retained-opening/read paths, then remove redb
   from Cargo, vendor inputs, dependency-review scripts, and current operating
   documentation. Retain historical evidence as historical evidence.
4. Pass focused engine failure/restart tests, the store's injected-I/O and
   encryption tests, Raft storage conformance and crash replay, and the complete
   repository gates required by `CONTRIBUTING.md`.
5. Qualify capacity, recovery, and performance against the release ledger. A
   passing unit suite alone does not close the production release goal.

This is the first release, so backward compatibility is forbidden. The new
format must identify itself distinctly and reject every older physical format;
do not add a migration, fallback reader or dual-write path.

## 2026-10-05 verification and remaining ownership work

The current dependency inputs contain no redb reference. The last stable native
library checkpoint passes all 608 cases, including crash recovery, control
allocation refusal and actual final allocation retirement. Earlier mandatory
workspace formatting and all 295 Python repository tests also pass. These
checkpoints do not verify later changed source or production release workloads.
The reviewed replay/benchmark checkpoint also passes the formatting gate and all
295 Python tests, with unchanged recorded source. Later leader recipe changes
still require their own final source gates.

The node facade and body now share their original registered database
allocation. Node shutdown and actual allocation retirement remain independent
observations, and the initializer registry retains its first whole original
before removing the actual joined handle. Supported constructor and snapshot
callers retain typed whole failures in their prior startup census. Authority
enrollment uses that same original inventory after caller loss.

The focused startup/input executable passes twelve of fourteen Engine checks
and all three Raft checks. Its allocator control passes for each of the three
actual startup controls, preserving the original charge while system
deallocation is paused. Two success fixtures kept a shadowed installed facade
until scope exit; explicit facade drops repair them without weakening their
zero-credit assertions. These are unqualified diagnostics because two consumed
Store helpers changed during compilation. Fresh repaired runtime checks remain
required.

The next combined all-target build compiles all production crates and the
Server, Store, Authority and Benchmark unit executables. It stops at one old
snapshot error assertion in the contracts integration target, after the thirteen
retirement assertions were repaired. That last assertion now borrows the typed
original as well. Four current-source runtime checks refuse to execute because
thirteen consumed Store files changed after compilation. No runtime pass is
claimed for those refused checks.

Workspace Clippy now checks every production crate and reaches integration
fixtures. Scoped large-error lint reasons preserve inline originals instead of
adding refusal-path allocation. Actual production LogId types use the existing
Raft export; benchmark leader waits borrow their mutex inventory exclusively
without requiring original panic payloads to be Sync. Equivalent lifecycle and
Default lint repairs preserve their exact original states. The remaining fixture
lint cut, all-target compilation and runtime gates remain required.

The reviewed replay reader now prospectively quotes its actual immutable shared
control and plaintext buffer in one original point grant. Ordinary replay
borrows authenticated encoded command bytes and carries the same storage
custody, without copying into a replacement command buffer. Its blocked
allocation test has an unwind release guard. Reviewed benchmark cleanup retains
the original node receipts in its initial startup resource inventory, including
actual shutdown-future disposal and external-alias refusal. Both changes are
applied; their fresh compile and runtime checks remain pending.

An earlier preserved executable passes all 35 target-call and node-start
controls and the authority strict-replay control. Three consumed Store files
changed during its compilation, so these are explicitly unqualified diagnostics.
Earlier drifting builds and failed assertions remain retained in the evidence
cache.

The leader encoded-input handoff retains its original proposal reservation
through apply without a second grant. Its reviewed actual mutation-tree recipe
is applied: ordered target identities, duplicate String temporaries and concrete
tree node layouts are prospectively quoted in that same reservation, with an
exact one-shot claim before the original producer allocates. Actual allocator
and refusal checks remain pending. Follower ingress, replay semantic producers,
reducer and candidate state, snapshot reconstruction and enclosing worker
controls remain open. The persistent goal remains active pending these
ownership joins, stable-source repository gates and the release capacity,
recovery and performance ledger, including the genuine 24-hour HA run.

## 2026-10-05 canonical constructor checkpoint

The segmented engine now prepays its actual backend cell and retains the
original constructor failure through independently observed close and disposal.
Native close stops operations; explicit disposal observes backing destruction
before returning its original admission credit. Failed disposal remains retained.
Scratch and snapshot constructors carry typed original failures through Store,
Raft and Engine; owning source contexts are not retirement proofs.

The rebuilt native library passes **597 of 597** cases in **337.84 seconds**,
with its executable and consumed native sources unchanged during the run.
The corresponding original failed run, **571 passed / 26 failed**, is retained:
its cleanup fixtures checked released credit without first observing disposal.
The repaired fixtures preserve the original zero-live-credit assertions.
Fresh integration runs pass **nine owner-fencing** and **eight rollback** cases.
Crash recovery's first run passes **eight of nine** cases; the remaining fixture
has been changed to observe native close and disposal before checking its
original zero-slot assertion. The rebuilt run passes **all nine** cases in
**26.38 seconds**, with unchanged consumed native sources and executable.
The aggregate cache allocation control also passes, including cross-thread
final guard retirement.

Focused canonical Raft runs pass three apply-preparation, eleven source-custody,
five scratch-inventory and two startup-report cases. Its startup-owner run
passes fifteen and fails two: an async error-conversion wrapper destroys the
original future while its poll panic unwinds. A transparent, directly polled
wrapper preserves the same admitted future layout and its original custody;
the rebuilt startup-owner suite passes **all seventeen** in **9.57 seconds**.
Store scratch verification first passes forty-five
and fails eight, exposing a lazy mutex allocation, missing explicit disposal in
two fixtures, and an outdated two-grant writer assertion. The fixes use the
actual inline mutex, observed disposal and the real three-grant writer quote;
the zero-allocation and released-credit assertions remain intact. Its rebuilt
suite passes **all fifty-three** in **41.64 seconds**. Both repaired runtime
checks have unchanged consumed library sources and executables; unconsumed
integration sources are excluded explicitly from their provenance checks.

The first build including Server stops on **27 compiler diagnostics** after
**260.93 seconds**, with no consumed source drift. Server's supported constructor
and RPC callers are being migrated to the same admitted original-failure
inventory. Separate earlier compile-time Engine source changes and rejected
runtime provenance checks remain unqualified. The current Python repository
suite passes **295** tests in **57.11 seconds**. These are component checkpoints;
the complete repository checks, persistent document/index serving, prospective
accepted-source capacity, release workload measurements and genuine 24-hour HA
run remain open. The persistent goal is active.

The subsequent storage integration build compiles every Native, Store and Raft
test target from unchanged consumed sources. All five read-barrier cases pass
in **45.12 seconds**, preserving the original quorum, membership and timeout
assertions. Raft conformance passes two and fails four; its separate shutdown
case fails to reopen. These failed runs remain retained. The reopened-file
fixtures require observed native node close after their worker and source
owners drain, and crash replay's synthetic backend requires an explicit
installed physical owner for admitted read preparation. Those fixture repairs
are written. The remaining Suite apply failure needs inspection of its original
preadmitted report; a new diagnostic borrows that same report without turning
the foreign marker into retirement evidence. Three native documentation tests
pass. Strict native Clippy stops on twelve large-error return diagnostics in
the deliberately inline, prepaid constructor custody; no new error-path Box is
an admissible repair. The full source and release gates remain open.

A concurrent native change replaces the closed shared control with a fallible,
preallocated control and explicit strong-reference ownership. It adds actual
allocation-refusal, uninitialized-control, alias, final-destruction, panic and
alignment checks. The first conformance rebuild raced that incomplete change
and failed compilation; it is retained as unqualified evidence. The preceding
four commit-allocation cases pass in **2,146.96 seconds**, but native sources
changed during that run, so they do not verify the new control implementation.
The fresh native test build has no consumed source drift; its crash suite passes
**all nine** cases in **27.51 seconds**, and its cache allocation control passes.
The new native library run passes **608 of 608** cases in **340.74 seconds**;
two externally changed native test files prevent qualifying the current test
source from that executable. Two subsequent Raft
builds expose private-field accesses in the new fixture shutdown helper; those
are repaired through the existing application and custody accessors. None of
these component results closes the complete repository or release gates.
The repaired Raft fixture build then succeeds without consumed source drift.
Its conformance target passes **five of six** cases in **46.89 seconds**:
actual append/commit crash replay, log/vote reopen, snapshot reopen and the
registered-constructor marker now pass. The separately rebuilt shutdown case
passes in **5.87 seconds**. Borrowed inspection confirms the remaining Suite
failure is the missing exact retained first-membership log header. The abstract
Suite applies membership entries while intentionally keeping its tested log
empty; a separately admitted actual source-log fixture is required to supply
Kasumi's production protocol prerequisite without changing those assertions.
Strict native Clippy subsequently passes across all targets and features with
unchanged consumed sources. The affected constructor and fixture functions now
explain their deliberately inline original custody in scoped lint attributes;
the remaining test diagnostics are repaired directly. Native formatting and
scoped whitespace checks also pass. The complete workspace gates remain open.
After that stable native build, a concurrent edit reverts the scoped constructor
lint annotations in Core, its opening module and Builder. Four direct runtime
checks reject the resulting source mismatch before executing. The passing
Clippy result belongs to its recorded checkpoint; the current constructor lint
gate and new runtime qualification require reconciliation and a fresh build.
The subsequent native build and runtime are stable: **608 of 608** library
cases pass in **346.57 seconds**, all **nine** fencing cases pass in
**8.43 seconds**, and all **eight** rollback cases pass in **3.09 seconds**.
All four commit-allocation cases pass in **2,192.42 seconds** on that build,
with unchanged native sources and executable. The second
six-library build stops after **149.01 seconds** on **22** Server diagnostics,
with no consumed source drift; the changing conformance integration body is
explicitly unconsumed by this library command. Ten ordinary caller bodies need
explicit error types. Authority startup also needs an actual admitted carrier
for its typed constructor original before outer cleanup; an Anyhow annotation
alone would erase that custody. These repairs are in progress.

The third six-library build succeeds in **390.74 seconds**, with no consumed
source drift. Authority startup now installs the actual original-failure
inventory before constructor effects. Its two initial-donor controls pass;
fourteen recovery-inventory and five RPC original-custody controls also pass.
The existing ten target-call controls pass. A separate review found that the
target-call producer's ordinary await can destroy its future before staging a
returned original, and can discard independent destructor panics. An explicitly
polled carrier under the same initial inventory charge is being implemented;
those passing baseline tests do not qualify this newly identified corridor.
Fresh unchanged-source runs also pass all **53** Store scratch cases in
**47.50 seconds**, all **17** Raft startup cases in **9.97 seconds**, and all
four Engine capture controls. Engine snapshot controls pass four and fail one:
the empty logical fixture no longer enters scratch construction, so its intended
registered-directory refusal was not exercised. That failed run is preserved.

The separate actual source-log conformance adapter compiles from unchanged
sources. Its runtime passes five and fails three of eight cases in
**50.25 seconds**. Borrowed inspection finds no retained apply failure, but
deferred cleanup reaches workers cancelled when the Suite destroys its per-case
runtime. The two added positive-drain controls also retain **102,709,180 bytes**
instead of the required zero. Both actual runtime ownership and reservation
retirement require repair; worker cancellation and a returned cleanup marker
are not successful-drain evidence. No Suite log assertions or memory bounds
have been weakened.

The conformance ownership trace identifies installed physical-disk registry
metadata, which its production contract retains after node shutdown. The fixture
must establish the exact two installed-owner charges before transient store
effects and require zero additional reservation after actual drains; comparing
all installed metadata to zero is not a valid transient-credit assertion. The
repair also invokes the unchanged Suite cases under one owned runtime so its
workers remain available for observed cleanup. Both repairs remain unverified.
The Engine snapshot fixture now carries an actual authenticated mutation receipt
into decoding, and keeps its encoded bytes and original charge together through
worker disposal. Its original registered-error and retirement assertions remain.
The deliberately inline constructor-return lint annotations have been reconciled
after the long native run; strict native Clippy again passes in **5.24 seconds**
from unchanged consumed sources. These attributes change no runtime behavior.
The rebuilt current native library subsequently passes all **608** cases in
**341.01 seconds**, with no native source or executable drift. The repaired
Engine snapshot controls pass all **five** cases, including the actual registered
constructor original and unchanged retirement assertions.

The next conformance run again passes five and fails three cases. Its baseline
check fails **before** native/store effects: the allocator trace identifies four
initial installed metadata reservations totaling **103,108 bytes**, preceding
the two distinct NodeDisk installations. Their real constructor and pure quote
must be included in the fixture's prospective installation model. That run does
not yet verify the continuing runtime or the later positive-drain assertions.
The exact trace, failed runs and executable/source pins remain retained. Strict
Store/Raft production-library Clippy passes after two direct conditional cleanups
and scoped explanations for deliberately inline original-failure custody.

An independent production apply trace confirms that no candidate/reducer credit
currently reaches CompletionInvocation, OrdinaryAction and ApplyOwner. Leader
proposal credit remains local; follower durable append has no candidate ticket;
invocation begins after commit; replay and restore bypass that invocation.
Initial funding, pre-accept tickets and a real allocation/overlap model with
accepted-backlog bounds remain prerequisites. Fixed completion grants and
cfg-only source cohorts do not close this release criterion.

A further conformance rebuild stops on **eight** Store compiler diagnostics in
**16.53 seconds**, without consumed source drift. A concurrent constructor
admission cut had changed its callers before publishing the new installer,
failure carrier and census registration definitions. Those external definitions
have since appeared and are being reviewed; no result is inferred before a
fresh coherent build. The conformance fixture now prospectively quotes its
actual scratch governor and both physical NodeDisks, with all twelve standing
fees and unchanged zero-transient/census/resource checks.

The shared budget handoff is being changed to one closed, typed control whose
final control deallocates before its original reservation payload is dropped.
Serving worker budgets and scratch failure seats must receive that same carrier
directly, with no opaque Arc adapter. This closes the carrier's own control only;
enclosing raw controls, nested payload backing and producer capacity still need
their independent custody. Target producer cancellation and independent
poll/future/output-disposal observations are implemented with new controls,
but compilation and runtime qualification remain pending.

The shared-carrier storage library build subsequently succeeds. Its first
successful build has concurrent constructor-source changes and is unqualified;
the next build has unchanged consumed sources. All three actual shared-control
tests pass, including alignment, concurrent final aliases, and an original
payload panic after observed control deallocation. The constructor refusal
selection passes two and fails one: the test provider's first diagnostic output
allocates 64 bytes. That original failed result is retained; its fixed diagnostic
writer still requires a fresh runtime check. The 73-case scratch selection passes
70 and fails three old constructor fixtures. A registered provider refusal now
has its own prepaid census receiver, whereas an unavailable receiver is refused
before the provider runs. The repaired fixtures explicitly test both boundaries
with unchanged 64 MiB/32 limits, exact original errors and ledger assertions.

The 17-case Raft startup selection passes 16 and fails an old unregistered-error
expectation; its repair uses actual fixed census receivers to exercise preclaim
refusal without a new provider callback. Two separate startup-report controls
pass. An initial mistaken startup filter runs zero cases and is not verification.
The final conformance adapter rebuild succeeds in **56.99 seconds**, and the
separate shutdown case passes in **6.73 seconds** with unchanged sources and
executable. The eight-case conformance run passes seven and fails the Suite on
an actual source-log append gap after **158.78 seconds**. Store fixture/provider
sources change during that run, so it does not qualify the current combined
source. The original failure, memory bounds, log-hole rejection and Suite
assertions remain intact while the adapter's actual source history is repaired.

The first combined eight-library build stops on 33 Server startup joins after
the typed native constructor change. Those joins now preserve the whole startup
failure under their original participant inventory. A nonclone begin capability
checks and enters that paid seat before callback construction; returned errors
and successful node owners are staged before independently observing callback
destruction. Concurrent alternative startup wrappers have been removed by their
author. The canonical source, callback-disposal controls, and affected test
fixtures need a coherent rebuild and runtime verification. The goal remains
active; none of these component results closes the repository or release gates.

The next unchanged-source storage build succeeds in **153.88 seconds**. All
**12** constructor receiver controls pass, including exact original errors,
zero-allocation first refusal, provider token custody and independent panic
observations. All **17** Raft startup-owner cases pass in **6.83 seconds** after
the fixture exercises actual census exhaustion before provider entry. The
scratch selection passes **72 of 73** cases; its remaining assertion omitted
the prepaid constructor receiver from the servicing census. That assertion is
corrected without changing the zero-payload or zero-native-effect requirements,
and awaits a rebuilt runtime check. The Engine/Authority build stops on three
typed test joins and has concurrent fixture drift. Their repairs preserve the
actual opening ID and both original error addresses after facade disposal.
The latest nine-case conformance adapter builds in **21.52 seconds**, but a
concurrent Store test edit prevents qualifying that source record. A fresh
combined build and current-source runtime checks remain required.

The rebuilt Raft integration target passes **all nine** cases in **238.20
seconds**, including every unchanged upstream Suite case, exact applied-boundary
gap controls, crash replay and durable reopen. The separate shutdown case passes
in **6.50 seconds**. The broad source record reports edits to two Store unit-test
bodies during conformance; their actual `cfg(test)` module guards and the
executable's exact Store compiler dependency record prove neither was consumed
by this integration target. Its executable and consumed source remain unchanged.
That supplemental proof preserves the original broad record and does not
qualify later source or the complete repository. The next combined library build
compiles Server but stops on two new Store test helper joins; those helpers
have since been corrected and await rebuilding.

The next combined eight-library build succeeds in **279.01 seconds**, with no
source drift. On that checkpoint, all **85** selected Store scratch/constructor
cases pass in **42.76 seconds**, all **12** Engine admission/capture cases pass,
and all three shared-control cases pass. Authority's seven-case selection passes
six and fails while borrowing the missing-group replay error. The Server
selection passes all four native-start controls and eighteen of twenty target
controls; it exposes an obsolete provider-refusal fixture and a poll panic
incorrectly projected as `Unavailable` rather than `UnknownOutcome`. Fifteen
recovery-inventory controls pass. A separate enrollment retry retains its actual
failure but waits indefinitely in generic cleanup; that discovery run was
stopped and its log retained. The workspace all-target build stops on a missing
benchmark import, now corrected. Later constructor edits and staged repairs
require fresh builds; no final gate is inferred.

Workspace Clippy then stops on four deliberately inline Store startup errors,
eighteen Engine diagnostics, and twenty-nine Server diagnostics. Repairs keep
the whole originals in their prepaid owners, use narrowly scoped layout reasons,
and remove only identity conversions. The target dispatcher now admits its
exact slot before producer construction. Review also finds three real report
contention paths: a completed panic can evade fencing, output claim/disposal can
panic, and dispatch recording can lose its original before installation. The
repairs use an inline atomic panic observation, an independent one-shot dispatch
slot in the same quoted cell, and typed retained refusals before touching an
output. Four actual contention controls are written; runtime checks are pending.
The first combined Server/Authority rebuild finds one remaining shutdown fixture
using the removed helper; it is migrated without changing its assertions.

The freshly rebuilt Authority replay case still fails in **32.02 seconds**:
its outer original IO error is `InvalidData`, whereas the new fixture expects
`NotFound`. A borrowed diagnostic now records that original and its independent
physical directory report before the unchanged assertion. Both failed replay
runs remain preserved. Composite node ownership, inspectable retained startup
terminals, and accepted-source producer funding are still implementation work;
the persistent goal remains active.

## 2026-09-24 implementation checkpoint

- `kasumi-kv` now owns the format, transactional tables, admitted reads and
  writes, retained opening/close custody, and two-stage crash-safe compaction.
  The `redb` Cargo dependency and vendored source are removed. Active database
  filenames use `.kv`; the node envelope rejects the previous format.
- The native crate passes 44 unit and seven crash/recovery integration tests on
  the current local source, including direct failed-constructor and retry-close
  panic custody, named-file directory sync, final-symlink rejection, and
  same-host reopen after a failed commit sync and strict-create EEXIST rejection.
  Store setup now observes
  database close after a post-open table or Ready failure, with two focused
  regressions passing. The immediately preceding all-features store library
  passes 421 cases (two ignored), the registered-opening overlay passes 424
  (two ignored), and Raft storage conformance passes five. The final combined
  store and strict workspace gates still require reruns after the latest fixes.
  The first full workspace gate on the 39-unit checkpoint passed the authority
  and engine libraries, then exposed an admission fixture that exhausted native
  Raft storage headroom. That fixture now installs the production maintenance
  reserve and passes focused. The complete final-source gate remains open.
- Compaction needs temporary disk headroom equal to the live set and waits for
  active snapshots to drain. Audit maintenance prepays a 128 MiB native KV
  escrow. Only scoped, synchronous preparation and apply work can draw its
  resident leases. A separate 128 MiB and four-slot free reserve excludes
  ordinary operation charges, including retained descendants, while Raft log
  storage uses ordinary Resident admission. Resident saturation can still block
  the asynchronous Raft proposal and archive completion. End-to-end progress
  under that condition, capacity, recovery duration, sustained overwrite
  performance, and final production release gates remain unqualified.

The earlier 34-unit/7-crash locked offline native KV log and exact source hashes
are recorded in the integration evidence ledger. The combined store checkpoint
passes 417 runnable cases before subsequent admitted-read changes, and its
source is not the final checkout. The parent-sync/close audit's four identified
paths now have source fixes: direct Core/Builder failures explicitly close their
backend and retain unproved custody, named-file acquisition binds to a held
parent directory, data and parent descriptors get observed closes, and final
symlinks are rejected. Direct callback panics and post-engine NodeStore setup
failures now retain original outcomes and attempt exact close.

The later six-file production `NodeStore` constructor cutover now adopts one
registered opening from acquisition through table setup and close. Its exact
candidate postimages are present on `master`. Three focused production opening
cases pass. Two additional regressions prove failed file acquisition with no
returned descriptor can close and retire the registered opening without
poisoning disk admission. Scratch tables now explicitly close on last table or
batch drop; a failed bootstrap retains its original error and unproved owner.
Its 13 focused cases pass. Production read/write transactions still escape as
raw handles rather than individually registered census children, except for
the now registered and independently reviewed production catalog point read.
Its focused applied-source tests pass 3/3 with no source drift; derived catalog
allocation accounting remains open. A separately reviewed strict-create
`FileBackend::create_new` removes the old `open` API and its EEXIST adoption
fallback. The later applied store library passes 434 runnable cases, with one
shared-checkout source change during that run. The direct scratch-table builder,
parent namespace custody for standalone named files,
direct Core/Builder API boundary, and final-source qualification remain open;
this does not complete G02.

The later applied standalone API cut removes the path-only existing-file reopen
constructor; the native KV suite passes 45 unit and seven crash/recovery cases
on unchanged selected source. The independently reviewed registered tenant
point-read cut then passes 440 serial store cases (two ignored) on 95 unchanged
selected tracked inputs, strict all-target/all-feature store Clippy, formatting,
and a no-default-features check. Native ciphertext admission is exact and does
not duplicate an outer point-read reservation. Plaintext decrypt/output
admission, named namespace ownership, raw transaction children and the final
release gates remain open.

The next reviewed native KV boundary cut removes public `FileBackend` and
`Builder::create_file` outright. Its live suite passes 45 unit and seven crash
cases, and the store no-default-features check passes. A store unit fixture
still used the removed builder method; the failed compilation is preserved in
the integration evidence. The private raw-format fixture is now migrated to
an observed one-shot native close; 21 node-file tests, strict store Clippy and
formatting pass on unchanged selected applied source. The embedding namespace
owner and other G02 release criteria remain open.

The reviewed routine registered-read retirement cut is now applied on
`master`. The serial applied-source store library passes 448 cases (two
ignored), with a focused engine regression, strict store Clippy, a
no-default-features check and formatting also passing. The exact candidate,
review, source pins and logs are in the
[integration evidence](evidence/installed-disk-integration-20260923/README.md).
The broader exact-parent child-census gap is addressed by the next reviewed
four-file cut. Its applied-source serial store library passes 451 cases (two
ignored), with strict store Clippy, no-default-features and formatting passing.
Its negative control reproduces the previous parent completion while a child
lease survived. The [integration evidence](evidence/installed-disk-integration-20260923/README.md)
retains the parallel I/O safety abort separately. Raw transactions, the
breaking plaintext-owner cutover and other G02 acceptance gates remain open.

The target-only breaking point-owner cutover in
`target/g02-breaking-point-owner/README.md` removes the old Vec-returning
point API and passes focused store tests and strict checks. It is not applied:
Raft has 17 direct caller compile diagnostics because its `StorageHandle`
must keep the shutdown lease attached to every returned admitted value.
A lease-carrying adapter and full supported-caller migration remain required;
no compatibility facade is permitted for the first release.
The later frozen store+Raft prerequisite and target-only 16-file engine
continuation reduce the engine library migration to two explicit type errors:
the pending tenant audit command still requires a Vec Raft write, and service
audit publication still requires a Vec ciphertext segment. Their exact patches
and failed check attempts are recorded in the
[integration evidence](evidence/installed-disk-integration-20260923/README.md).
Neither patch is applied while those owner handoffs and G01 composition remain
open.

The target-only raw transaction audit at
`target/g02-raw-transaction-children/README.md` records a separate native
retained-read guard lifetime gap, 15 persistent raw read/write sites, and
scratch-table raw transactions. Its implementation patch is intentionally
empty. The successor two-file native retained-read guard cut is applied on
`master` after exact pre/postimage checks. Held tables, ranges and output
guards now keep their exact read snapshot alive until close and disposal can
settle; its applied-source suite passes 48 unit and seven crash/recovery cases,
strict Clippy and formatting. The [integration evidence](evidence/installed-disk-integration-20260923/README.md)
records the patch and logs. Store child adoption, retained write custody,
scratch direct ownership and final G02 qualification remain open.

The reviewed installed-node registered-read adoption is now applied on
`master`. It covers paired deployment, catalog, tenant scan and long-lived
views, and retains original scoped-body panic payloads in their exact census
children. Applied-source KV tests pass **49 unit and seven crash/recovery**,
the serial store library passes **462** with two ignored, and the replicated
engine reopen module passes **11/11**. Strict KV/store Clippy and affected
formatting pass; the workspace format check fails on an unrelated concurrent
engine fixture edit. Exact source pins and the one-line later import drift are
recorded in the [integration evidence](evidence/installed-disk-integration-20260923/README.md).
The later long-lived view cut retains its exact registered reader and native
report after view drop, with two applied focused cases passing. Raw write and
scratch children, plaintext output ownership and all final release gates
remain open.

The production catalog save now uses an admitted, registered write child with
exact terminal custody. On applied `master`, its focused cases pass **3/3**;
the serial store library passes **465** with two ignored; strict store Clippy,
formatting and no-default-features library check pass. The
[integration evidence](evidence/installed-disk-integration-20260923/README.md)
pins the patch, source and logs. Remaining raw write and scratch paths, typed
allocations, plaintext outputs and full G02 qualification stay open.

The typed catalog read/open cut bounds map shape before Serde and retains an
installed-memory lease with the decoded owner. Applied selected source passes
**470** serial store cases with two ignored, **50 native KV unit plus seven
crash/recovery** cases, strict store Clippy, package formatting and no-default
check. Exact source and logs are in the
[integration evidence](evidence/installed-disk-integration-20260923/README.md).
Catalog clones and later growth still need admission; G02 remains open.

The installed missing-binding branch now owns admitted serialized and
encrypted buffers through a registered write child. A native `delete_key`
method can stage a tombstone without reading a prior large value. The combined
selected applied source passes **474** serial store cases with two ignored,
**54** native KV unit plus seven crash/recovery cases, strict KV/store Clippy,
no-default-features checks and workspace formatting. Exact receipts are in
the [integration evidence](evidence/installed-disk-integration-20260923/README.md).
At that checkpoint the store's production delete caller still needed cutover;
other raw transaction paths, scratch ownership and final G02/G03 gates remain
open.

The native commit path now synchronizes both commit-header slots before
acknowledging a batch. A failed mirror sync remains an unknown commit and fences
the live core; one damaged slot after a successful commit can no longer reopen
at the preceding generation. The applied-source native suite passes **50 unit
and seven crash/recovery** cases, plus strict native Clippy and formatting.
These results do not close the remaining G02 release gates.

The production store delete arm now calls native `Table::delete_key` and does
not admit the old ciphertext merely to discard it. Its pinned-view/reopen
regression passes with an 8 MiB old value and 4 MiB headroom; an unchanged
caller fails that control. On the later combined applied `master` source, the
serial store library passes **479** cases with two ignored and the replicated
engine suite passes **3/3** after the registered binding disposal repair.
Exact source and log hashes are in the [integration evidence](evidence/installed-disk-integration-20260923/README.md).
Generation-addressed publication, durable bounded reclaim, shared guard pins
and the final native-platform gates remain **HOLD**.

A separate target-only generation retirement candidate pins returned
ciphertext guards as well as views and resumes a cursor after at most 64
logical tombstones per step. Its native suite passes **63 library plus seven
crash/recovery** tests on the isolated overlay. The candidate remains
unapplied: logical deletion alone cannot release append-only file space,
per-generation metadata is still unbounded, and source authority plus paired
Raft publication are unresolved. The exact patch and controls are in the
[integration evidence](evidence/installed-disk-integration-20260923/README.md).

The next physical-reclaim review proves the held logical cursor cannot release
file space: one completed unpinned row retirement grows the native backend from
141,642 to 142,135 bytes. The current whole-database compactor may run before
the bounded retirement loop and requires full-live-set shadow headroom. Its
crash and capacity controls pass, but a resumable extent/relocation format is
needed for bounded physical progress. No native patch is applied from this
review; exact evidence is in the [integration ledger](evidence/installed-disk-integration-20260923/README.md).

The source-bound `target/g03-reclaim-design-20260924/DESIGN.md`
pins the same physical negative control and held-overlay native results. It
requires a distinct first-release format with bounded segment relocation,
durable root/cursor publication, exact pinned-reader and file-delete custody,
and no old-format reader. This is a **HOLD** design, not an implemented reclaim
path or a passing G03 gate.

## 2026-09-25 replacement verification

The applied native engine passes **55 unit and seven crash/recovery tests**.
Commit and compaction now synchronize both commit-header slots before reporting
success; one damaged slot after either operation still reopens the acknowledged
generation. A failed mirror sync remains an unknown commit and fences the live
core. The focused three-node recovery fixture passes **1/1**, including exact
retained authority resolution, target activation, serving, and shutdown. Its
Control read used 9.2 seconds within the original bounded operation; nested
Control observations now consume the original remaining deadline instead of an
independent five-second limit. The repository Python gate passes **191/191**.

The native replacement is an implementation checkpoint. Bounded physical
reclaim, capacity and sustained-workload qualification, and the final production
release gates remain **HOLD** under G02 and G03.

## 2026-10-04 current-source audit

The active Cargo manifests and lockfile, Rust source, dependency review inputs,
and vendor trees contain no redb dependency. The store and Raft use
`kasumi-kv`. Current root, segment, and directory formats are
`KASUMI-KVROOT003`, `KASUMI-KVSEG0004`, and `KASUMI-KVDIR0002`; production
files carry the `KASUMI-NODE-SEG1` envelope. The native README and node group
document now describe those actual formats and their strict rejection rules.

Current source implements immutable ordered directories, durable atomic
multi-table batches, pinned snapshot roots, and incremental evacuation,
directory packing, and reachability reclamation. A source audit inspected the
commit, recovery, close, and injected-failure test paths. Fresh execution of
the complete repository gate remains required. The refreshed Python suite
passes **294/294**, and workspace formatting passes. The current native crash
suite passes **9/9**, covering commit and compaction effects, cached visibility,
corruption fencing, and close ownership. A reused-build compilation failure
was followed by a fresh target-directory build, which exposed API mismatches
during the pinned-CA cutover. Both the canonical provider and the server now
require the validated CA bytes.

The source-cohort installation prototype remains an isolated test path. It
requires accepted replay/ingress coverage that production construction does
not yet provide, and its current envelope cannot cover snapshot restore.
Its test-only construction boundary must not be presented as installed
production capacity. The broader G02/G03 and production qualification gates
remain open; this goal remains active while current-source verification runs.

### Completion audit of the current implementation

| Criterion | Current status | Remaining work |
| --- | --- | --- |
| Native transactional format | Implemented; final verification pending | Complete the current-source native and downstream failure/restart gates. The source audit found no demonstrated transactional correctness defect. |
| Installed ownership and encryption | Incomplete | Canonical charged point/scan/visitor owners and Raft/archive handoffs are implemented. Production synchronous writes now have registered children; native staging controls and table names own admission before allocation. Scratch point results retain the original native buffer and database. Complete runtime and refusal-path verification, then finish the remaining typed and scratch constructor/transaction ownership paths. Encryption and native physical reservations are present. |
| Production cutover and redb removal | Audited | Current Cargo, Rust, scripts, and vendor inputs use the native engine. Retain the strict old-format rejection checks in final verification. |
| Repository gates | Running with failures | The pre-plaintext ownership baseline reports authority **61 passing / 16 failing**, Engine library **651 passing / 15 failing / one ignored**, native KV library **563 passing**, client **71 passing**, and clock **6 passing**; integration suites continue with further failures. The graceful shutdown repair passes **30** focused OpenRaft cases and the original Authority control shutdown regression. Refreshed ownership selections pass **19 native**, **59 Store**, and **14 Raft** cases. The Engine completion selection passes **13**; the original archive-point, backup-expiry, and local startup regressions pass. These are scoped development results with their exact source epochs recorded in the cache ledger. Complete affected operational regressions and all final-source gates. |
| Capacity, recovery, and performance | Open | Finish the production source/document/index ownership dependencies, then qualify the release ledger's incompressible standalone/HA corpus above 3 GiB, recovery/reclaim measurements, original performance matrix, and genuine 24-hour HA endurance. |

A subsequent enclosing-owner audit finds an installed ownership gap in criterion
2: the current opening quote does not explicitly cover the raw node wrapper's
body/control, second path copy, or extra registered-opening Arc. Native shutdown
can retire the database grant while node aliases still hold those allocations.
The planned canonical repair reuses the existing census control for a composite
node payload, prepays its actual body/path under the same initial grant, and
separates native/worker close from observed final node retirement. Merely adding
bytes to the current opening quote cannot repair its lifetime. This design is
recorded for implementation; it is not a passing runtime result.

The audit found point-read and scan APIs returning owned plaintext vectors
without an installed lifetime charge. The canonical replacement uses one
zeroizing authenticated backing that retains its exact provider's charge.
Scans retain those buffers and their separately admitted row metadata; callbacks
borrow from the charged backing. Escaping Raft outputs and stored proposal
clones retain their original storage shutdown lease. Archive publication carries
its original ciphertext owner through workers and HTTP bodies. These changes
and tests are written; affected production libraries and supported test callers
compile after their canonical owner migrations. Ordinary pinned-view traversal
uses the same admission, preserving caller-funded prepared workspaces. The first
focused runtime selection now verifies point, scan, visitor, scratch and writer
lifetimes; the complete operational and final-source gates remain open.
Temporary decrypt admission alone
cannot close an escaped-output gap. Raw transaction custody remains required;
those surfaces are explicitly identified in
[`storage_opening.rs`](../crates/kasumi-store/src/storage_opening.rs).

The baseline's backup failure retained a real document-source admission error:
the streaming grant was held across an earlier ordered maintenance publication.
The grant now starts immediately before streaming and is released after its
actual buffers and producer finish, before the final ordered audit. One original
Authority materialization case now passes that phase and the corrected physical
fixture. Its later missing enrolled group exposed a bypass of the disk owner's
namespace check; the acquisition correction now passes the original scenario,
including exact repeated close-error identity. Complete native-group
inventories, content fingerprints, and stopped-process restore helpers replace
the old physical fixture assumptions; cold rollback and broader materialization
scenarios still need final reruns. The archive-point regression also
retained a real source-admission refusal while its 192 MiB export grant overlapped
the ordered start audit. A phase correction now validates the prefix while
borrowing it, acquires export memory after that audit, and retains only the
actual manifest backing after chunk disposal. The original archive-point
shutdown/lifetime regression passes on the rebuilt executable. The original
serving-expiry scenario exposed an unproved later preparation error despite
positive source drain. Its repaired controlled Planner path now ties retirement
to the actual registered reader and point backing, preserving the same original
error and failed response. The original shutdown and exact reopen regression
passes in **42.67 seconds** on the attempt-10 Engine executable. The
stopped-process cold rollback regression also passes in **9.02 seconds**,
including all four child processes and selection of the exact restored
generation. Later concurrent NodeDisk edits are recorded separately; these
results verify that compiled checkpoint. Changed inputs and the final repository
source still require verification. The fresh attempt-12 executable also passes
cold rollback in **7.97 seconds**. Its expiry case reaches a different, preserved
post-publication capture failure: the sink returned, the action retained its
original error, and the exact source drain completed. The diagnostic preserves
that result. The coherent attempt-13 build passes the actual early capture
control, but full expiry reaches a later read refusal whose exact
`SelectionFailure<Workspace>` retains its original denial and decode grant.
The corrected assertion inspects these two canonical owners directly. Its real
Entry control passes early refusal, late selection refusal and an owning-context
negative in **8.88 seconds**. The unrelated selection error with an independent
point-retirement panic also passes in **2.94 seconds**. Arbitrary contexts and
source chains remain invalid, and the production retirement proof is unchanged.
The original serving-expiry regression passes in **43.10 seconds**, preserving
queued and late refusal, failed responses without acknowledgment, shutdown and
exact reopen. Its rebuilt helper executable and 1,468 consumed Engine input
pins remain unchanged through all three runs. The original
cold rollback also passes in **10.14 seconds** on attempt 13, with all four child
processes and exact restored generation. Its 1,461 Engine input pins remain
unchanged; 140 unrelated Server inputs are excluded explicitly after the strict
whole-build preflight refused a concurrent Server test edit.
Separate startup, credential-clock and admission fixture repairs preserve the
configured policy and original outcome assertions. Remaining operational and
capacity failures retain their original diagnostics; no final gate is inferred.

The refreshed native lease controls verify that the original provider Box and
output backing deallocate before refund, including the original refund-panic
payload. A separate enclosing-owner audit found that shared control allocations
also need that disposal order. The attempt-12 selection passes **22 of 25**
cases and detects first-use allocations missing from the original constructor
accounting. Actual allocator observations and the pinned Rust implementation
identify separate macOS synchronization backing. The corrected constructors
quote and initialize it under their original grants before aliases escape.
Attempt 13 passes **28 of 28** selected native cases, including actual control
deallocation before the original native/cache refund, concurrent final aliases,
zero new closed controls on first shell refusal, and original panic inspection.
The inline panic gate serializes a real non-Sync payload without allocating and
releases its gate after a callback panic. The same unchanged build passes **61**
selected Store and **16** Raft cases; all five related libraries compile from
1,601 unchanged input pins. The full native library passes **589** cases in
**349.73 seconds**. Its **nine crash-recovery, nine owner-fencing and eight
rollback** integration cases also pass, with every executable and all 95
consumed native input pins unchanged. These results verify this checkpoint;
the following constructor cut and final repository source still require gates.

Direct Core/Builder opening still eagerly allocates an erased backend Arc and
boxes an unproved constructor failure. The canonical constructor cut must admit
the actual backend cell first, retain original errors and independent close and
disposal observations, and keep the same cell/grant through backend destruction.
Retained opening and registered disposal must observe that actual sequence;
returning from a Drop fallback cannot prove retirement. Scratch construction's
typed failure corridor and its production callers remain part of this cut.
The target catalog's original
32-slot configuration cannot hold its fifteen durable leases plus two required
nine-lease scratch groups. No stale snapshot explains that pressure. A canonical
constructor requirement plan or reviewed aggregate owner is still required;
increasing the test cap alone does not close the failure.

The current ordinary native batch bound remains 65,536 operations and 96 MiB.
The large atomic-image results in the disk-backed cache history belong to an
unpromoted cohort. Production document/index serving and accepted source
capacity likewise remain unfinished. Neither these historical component
results nor a passing workspace suite establishes criterion 5.
