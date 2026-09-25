# Native Kasumi key-value engine goal

Status: active. The 2026-09-24 direction replaces the planned redb-backed G02
implementation. Kasumi will own its durable key-value engine in Rust and remove
the redb dependency and vendored fork. This change must preserve the public
encrypted store and Raft storage contracts while replacing the physical format.

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
