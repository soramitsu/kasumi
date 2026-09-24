# Kasumi physical admission prerequisite

This fork is selected by Kasumi's production dependency graph through the root
Cargo patch, while remaining excluded from the workspace member list. It is a G02
prerequisite, not G02 acceptance. The installed NodeDisk adapter supplies backend
and admission access from the same retained physical file owner. Complete storage
owner census, retained opening/writer adoption, and total workspace admission remain
unfinished; selecting the fork does not establish those contracts.

## Source provenance

The base is the unmodified locally cached published `redb-4.2.0.crate`, whose
SHA-256 is `de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36`.
That checksum identifies the original registry package; the current root Cargo.lock
selects this local patched package. The package's retained
`.cargo_vcs_info.json` identifies upstream commit
`23b6ba05473b13e69ed4db82f4b5bc07f0c33be9` at
<https://github.com/cberner/redb>.

The published package lists the derive example but omits its redb-derive path
dependency. The exact missing companion source and its original manifest were
restored from that same upstream commit, obtained from
<https://codeload.github.com/cberner/redb/tar.gz/23b6ba05473b13e69ed4db82f4b5bc07f0c33be9>.
The archive SHA-256 is
`3aabc11f3779daebfc463b077e4c63779c384adb4ea3a4a947f03ac3cc6a244f`.
The companion implementation is unmodified. Its manifest's inherited package fields
were expanded for standalone resolution, and its tests now supply the required
admission capability. Its original manifest is `crates/redb-derive/Cargo.toml.upstream`.
Upstream licenses and authorship are retained. The evidence directory contains the
file-level provenance manifest and patch against the original package.

The admission checkpoint is commit `8fa529231e474e49572691028050fbe9477f4e2b`.
The subsequent canonical-format cleanup has separate provenance and validation in
`../../docs/evidence/redb-canonical-20260920/`; the admission evidence remains an
immutable record of the earlier checkpoint.

## Canonical API

`StorageBackend::close` now requires an explicit `BackendCloseOutcome`, with no
default implementation. Logical errors and native-resource drain are separate.
The retained database/opening owners keep their original errors through explicit
failed operational disposal; unknown native closure cannot authorize that path.
FileBackend invokes native close once and never retries an uncertain raw handle.
The NodeDisk adapter additionally requires an exact terminal owner witness and a
later accepted whole-owner census before its storage registration can retire.
The scratch-spool adapter uses one observed native close and retains the exact
spool on failed sync, unwind, or uncertain native closure. Positive drain precedes
key/buffer retirement and charge release. An uncertain native result also retains
its file/extent/pending accounting after aggregate destruction. Spool construction still allocates
buffers after descriptor acquisition, and inherited destruction can bypass this
explicit protocol; constructor/destructor custody, consuming caller adoption,
and total error/panic/RSS admission remain required G02 work, not accepted exceptions.

Every writable or read-only constructor requires `Arc<dyn StorageAdmission>`.
There is no optional admission hook, default owner, unlimited production owner, or
late conversion from an unowned database. Unlimited fixtures exist only in unit
tests and the separate integration-test executables. The runnable examples use an
explicit finite per-file budget; they do not represent NodeDisk integration.

`reserve_growth(current_len, requested_len)` runs before every physical extension,
including first creation and repair allocations. `CapacityDenied` performs no
physical extension, marks the entire transaction for rollback, and does not fence
the owner. All allocator clones share that transaction state. Abort settles the
successfully retained, synced physical extent rather than releasing its charges.
Physical I/O or owner uncertainty latches `OwnerFailed` once and fences subsequent
cached as well as physical accesses. The owner remains retained after database
handles close; this layer never performs an unverified accounting refund.

Commits always prepare and sync data, system metadata, and allocator snapshots
before the winning header. The old durability-selection APIs and volatile commit
machinery are removed. Pages referenced by the old durable root remain unavailable
for allocation until publication. The prepared serialized allocator uses detached
allocator copies with the deferred frees applied, so clean reopening does not lose
that free space. Constructor repair and integrity repair stage recounted roots into
the same transaction protocol. An unclean writable reopen verifies the winning
user/system root checksums before accepting a matching allocator snapshot; allocator
metadata alone cannot prove payload integrity.

Stored table identities must match exactly. The inherited legacy classification
metadata and matching rules have been removed; unsupported type tags cannot select
a decoder even through an untyped table open. One-phase headers are rejected before
mutation, and the reader never substitutes a secondary root for the winning root.
The canonical writer emits slot version 4, a mandatory two-phase bit, and type tags
1/2/4. Older slot versions and removed system-history tables are rejected before
mutation. Allocator keys have exactly five bytes: tag 3 with a little-endian region
index, or tags 4/5 with zero padding for tracker/stamp. Tags 0–2 have no decoder or
writer. A mandatory raw tree walk checks key encoding, ordering, branch routing,
page geometry, ancestor cycles and stamp lengths before typed allocator traversal
or repair. Borrowed payload checks validate nested bitmap geometry, summaries,
buddy overlap/merging and a complete contiguous snapshot. They accept retained
tracker capacity and snapshots saved before shrink; a matching winner cannot
discard allocated pages. Complete correspondence to reachable root pages and
total traversal resources remain open. No alternative decoder, migration, or
backward compatibility exists.

Deferred allocation history is reclaimed in a bounded prefix of at most 400 rows
before eligible DATA history, also limited to 400 rows. DATA reclamation waits when
an eligible allocation prefix remains. Readers and savepoints still determine
eligibility, and live frees remain deferred until the winning header. Nested
bitmap, buddy and region serialization validates exact geometry before writing
directly into one destination buffer. These changes do not bound the full prepared
allocator copy, output buffer, maintenance page demand, or whole-database scans.

`Database::close` and `ReadOnlyDatabase::close` return `CloseError<T>`. A busy error
returns the original database for retry after all borrowed handles drain. Stored
persistent savepoints alone do not prevent close. Writable close explicitly flushes
and settles its clean header; read-only close only releases its backend. Destructors
perform no checkpoint or trim. Backend close runs once, including failed construction
and explicit-close failures. Dropped writes roll back transaction allocations and
settle physical growth without an allocating checkpoint.

The borrowed `RetainedDatabase`, `RetainedWriteTransaction`, and
`RetainedDatabaseOpening` APIs retain original attempts and their outcomes across
separate observation and disposal calls. Opening installs partial backend/cache,
memory, database and bootstrap transaction owners before their respective fallible
effects. It preserves the original opening/body error or panic separately from
terminal, rollback, disposal and close outcomes; failed phases cannot expose a
ready database. The admission proxy latches failure before a once-only owner
callback and retains a callback panic without replacing the original storage
error. Repair callbacks require `Fn + Send + Sync`. Kasumi must still precharge and
register these owners before effects and retain them independently of public
facade cancellation; the vendor API alone does not install that production census.

`compact(NonZeroUsize)` requires an old/new relocation-buffer byte allowance. A call
retains at most 64 candidate paths and performs at most one relocation batch and a
fixed number of cleanup generations. Candidate discovery still scans the full tree;
Kasumi must separately admit its scan, metadata, and CPU costs. This interface alone
is not a complete NodeAdmission maintenance envelope.

## Publication boundary and remaining integration obligations

After the winning-header write, physical sync and optional shrink/sync can still
fail. They return `OwnerFailed`; the committed outcome is uncertain and recovery may
observe either complete root. A capacity denial cannot originate from those steps.
Memory reclamation, tracker updates, and destructor bookkeeping do not allocate.
The backend and admission callbacks invoked in that phase have an explicit
non-allocation contract; Kasumi's owner adapter must meet it too. This fork does not
claim to bound arbitrary user backend implementations or the preparation phase's
heap footprint.

The same NodeDisk capability must own backend access, admission reservations,
settlement, installed-root accounting, growth and shrink rights, and its failure
fence. Kasumi must also supply charged metadata/preparation envelopes and recovery
coordination. Existing path convenience constructors are admitted, but constructing
the required owner for an unrelated path is a caller contract violation; the
production adapter must prevent that mismatch structurally.

## Validation status

Development logs, including failed tests and calibration attempts, are retained in
`../../docs/evidence/redb-admission-20260920/`. They are a development record, not a
claim that every logged source state is the final source state. The original
upstream suite exposed assumptions about optional nondurable commits, implicit
Drop checkpoints, and postcommit reclamation. Tests were changed to exercise the
new required immediate publication and explicit close contracts; no tests are
ignored to bypass those failures.

`just test`, `just test_all`, and `just fuzz_ci` were attempted and returned exit 127 because `just`
is not installed. Podman, cargo-deny, and cargo-fuzz were also unavailable during
initial inventory. Direct host Rust validation is recorded separately and does
not substitute for a successful required upstream container/audit/fuzz run.
The evidence README distinguishes broad-run attempts, fixture corrections and
checkpoint checks; input manifests identify their source hashes. Later integrated
development evidence is in `../../docs/evidence/installed-disk-main-20260920/`.
Attempts 157–161 record 204 all-feature vendor unit tests, strict vendor and
workspace Clippy, workspace/vendor formatting, and 296 tests across all ten public
vendor integration targets. Those are source-specific component results, not a
final release qualification. The unavailable upstream container, audit and fuzz
workflows remain unpassed gates. The reviewed vendor inventory must also be
refreshed and verified for the final source state before release.
Attempt 162 adds allocator payload and branch-routing validation and passes all
211 vendor unit tests; attempt 163 passes strict vendor Clippy on those bytes.
Successful borrowed-helper checks allocate no heap collections; their coverage
does not establish total database or process memory bounds.

The first-release no-compatibility contract supersedes upstream's instruction to
preserve older file interpretations. Unsupported inputs are rejected; no migration
or fallback is provided.

## Canonical page-number representation

The sole raw page-number decoder rejects every reserved bit and unsupported order
before creating a typed page number. Table definitions stay borrowed raw metadata
until checked conversion; branch access validates the complete child vector;
used reclamation entries and multimap/savepoint roots use the same decoder.
Relocation and merge paths preflight pointer vectors before changing their output.
An unused checksum-invalid transaction slot remains opaque and is serialized
verbatim until a new commit replaces it; it never supplies a decoded root.
Supported region/order geometry and canonical writer bytes are unchanged.

This prerequisite does not establish complete reachable-root allocation ownership,
maintenance extension reserves or total workspace admission. Its target-only
validation package records the exact checks performed; prior checkpoint results
do not qualify the changed source.
