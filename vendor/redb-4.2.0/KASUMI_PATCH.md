# Kasumi physical admission prerequisite

This fork is a prerequisite for G02. It is excluded from the Kasumi workspace and
is **not selected by Kasumi's production dependency graph**. It does not constitute
G02 acceptance or a production NodeDisk installation. Integration must construct
the backend and admission capability from the same retained physical file owner.

## Source provenance

The base is the unmodified locally cached published `redb-4.2.0.crate`, whose
SHA-256 is `de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36`.
That checksum matches Kasumi's root Cargo.lock. The package's retained
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

## Canonical API

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

`Database::close` and `ReadOnlyDatabase::close` return `CloseError<T>`. A busy error
returns the original database for retry after all borrowed handles drain. Stored
persistent savepoints alone do not prevent close. Writable close explicitly flushes
and settles its clean header; read-only close only releases its backend. Destructors
perform no checkpoint or trim. Backend close runs once, including failed construction
and explicit-close failures. Dropped writes roll back transaction allocations and
settle physical growth without an allocating checkpoint.

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
The evidence README distinguishes the broad-run attempts, fixture corrections, and
checkpoint checks; the input JSON manifests identify their source hashes. The unavailable upstream container,
audit, and fuzz workflows remain unpassed gates. This commit is a component
prerequisite, not G02 acceptance or authorization to ship.

This admission checkpoint still inherits upstream type-name legacy aliases and
one-phase-header interpretation. They are pending removal in the separate
first-release canonical-format commit and are not accepted release behavior.
