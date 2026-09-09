# Streaming snapshot contract

The first-release format carries bounded semantic records, rather than one
serialized tenant value. Unsupported earlier JSON and postcard snapshot images
are rejected. `Limits.max_snapshot_bytes` is a checked `u64` resource quota;
there is no 2 GiB format ceiling. Documents, requests, transactions, individual
records, results and admitted node work retain independent bounds.

Tenant images begin with `KASUMIT5`. Every record has an eight-byte big-endian
payload length, one explicit category byte, then canonical JSON. The category
byte is included in the digest and must equal the decoded semantic record kind
before the record reaches a resident-state or permanent-table consumer. Records explicitly identify metadata,
collections, documents, archive references, command receipts, staged metadata and
chunks, change-feed headers and individual changes, history archives, schema and
retirement records, audit events, Control history, target lifecycle records, and
Control recovery operation, phase, and target identity records. Ranks 21 and 22
carry immutable staged outcomes and target resolution rows into encrypted point
tables; their aggregate length is separate from resident state. Recovery records
retain their independent 1 MiB work bound; other payloads cannot exceed 32 MiB. Records must follow the specified category/key order, with contiguous
indices for sequence members. The terminal zero-length record carries checked
64-bit record and byte counts and SHA-256 over the preceding image. The decoder
rejects missing or inconsistent trailers, unordered/duplicate records, embedded
records in metadata, noncanonical JSON, unsupported formats and trailing bytes.
AEAD-encrypted storage/backup envelopes and authenticated transport bind this
image to its trusted origin; an unkeyed digest alone is not authority.

Persistent ordered document maps and primary-ID roots are shared between live
and leased generations. Snapshot serialization does not allocate a sorted copy
of every document ID. The accounting cache measures this exact record format and
updates affected records when commands commit. Recovery history uses persistent
map differences to account only added, changed or removed records; unchanged
roots do not cause history scans. Recovery records require an installed Control
snapshot and are rejected by application-backup verification. Coherent point/scan leases keep
only the shared read roots, definitions and required history references. Their
budget covers metadata plus old document/reference versions and conservative
persistent-tree path retention caused by concurrent writes. Budget or node
pressure expires the lease with `CursorExpired`; a lease never changes revision.

Raft images use `KASUMIS2`: a bounded metadata record, consecutive data records of
at most 64 KiB, and a final byte count, record count and digest. Snapshot transfer
uses encrypted scratch files and runs filesystem/crypto work on blocking workers.
Each scratch file has an ephemeral random key and authenticated 64 KiB slots;
plaintext scratch files and persisted scratch keys do not exist. Immutable image
handles offer independent readers and constant-size clones. Public snapshot
capture and staged restore preparation use these encrypted images. Private
logical candidate codecs require an explicit disk byte budget when encoding.
No public engine snapshot API constructs a tenant-sized byte vector. Durable staging
writes bounded encrypted chunks and publishes their manifest together with the
matching custody/applied position. Interrupted publication preserves the previous
recoverable image or the complete new one. `RaftLimits` supplies the installed
per-group transfer budget (64 GiB by default), separately from the tenant quota.

Full backups publish data chunks, then pages of at most 256 chunk descriptors,
then a constant-size final root. Pages form an immutable reverse chain with
ciphertext digests on every edge. Verification first checks that chain into an
encrypted fixed-slot spool, then traverses it forward while checking chunk
counts, lengths, hashes, origin, key dependencies and the final resident digest.
Historical verification builds an encrypted point index containing checked offsets
into its immutable encrypted spool. It validates documents, unique values,
lineage, staging, change feeds, cold references, permanent outcomes, audit counters,
and target signatures one bounded record at a time. Cold-history chunk parsing,
hashing and encrypted point lookups run in owned blocking workers, retaining the
original cancellation, deadline, state and workspace through completion. Two temporary tables each
have an 8 MiB page cache; their keys and pages are encrypted too. The declared
workspace is a 128 MiB index/cache floor plus the measured maximum structural
record work, independent of aggregate tenant size. A fixed-buffer preflight
admits that record work before constructing any record DTO or point index. Immediate
completion instead compares the full authenticated stream to private evidence
from the exact captured generation and reuses its immutable roots with a 64 MiB
workspace estimate. Both paths verify every transitive dependency and key catalog.
Genesis/bootstrap persistence, target materialization readback and Raft restore
also consume streaming readers. Bootstrap manifest format 2 uses checked 64-bit
byte and chunk counts and binds the same image digest in custody metadata.
Every cold-history dependency is verified before a backup proof or restored
bootstrap can be published. A single encrypted backup object is limited to
32 MiB; that is not the size limit of an aggregate backup.

The source generation and decoded replacement state remain resident where needed
for correctness. Streaming removes serialized copies proportional to tenant size;
it does not make the database disk-resident or eliminate index rebuild memory.
Capacity and endurance release gates must be run against final release binaries.

Raft captures immutable backend roots and retirement evidence at the exact applied
position, then releases its applied-state mutex before materializing the encrypted
image. Authority snapshots use bounded typed metadata and keyed record frames
(`KASUMIA2`) with the same strict length/count/digest/EOF rules. A pinned database
read transaction supplies stable encrypted pages while committed writes continue.
An encrypted temporary point table supplies canonical ordering and cross-record
validation with an 8 MiB page cache. Restore replaces the verified namespace in a
single durable transaction without collecting its records or deletion batch.

Audit metadata retains its permanent stream UUID, next sequence, pruning watermark,
hot byte count and archive root. Hot audit frames use absolute stream positions;
restoration does not renumber history. The archive-before-prune subsystem must
preserve the ciphertext dependencies named by those roots on every replica and
in backup/replacement workflows before their pruning transitions become usable.

Application Raft backends use the canonical `KASUMID1` dependency bundle inside
`KASUMIS2`. A bounded canonical source-purpose header precedes 64 KiB frames of
`KASUMIT5`, an explicit logical-stream terminator, and the audit ciphertext chain
in reverse sequence order. Each archive record is at most 8 MiB. The final record
binds checked logical/archive byte and record totals and the complete bundle
digest; missing dependencies, extra records and logical-only transport are
rejected. The aggregate Raft disk quota must cover the logical image, retained
audit ciphertext and framing.

Capture retains only immutable generation and storage handles. Materialization
reads one local archive at a time and verifies its original source purpose,
restore lineage, wrapping-key dependency and AEAD. The receiver applies the same
checks and durably publishes each exact ciphertext to its own installed private
archive cache before accepting the bundle. Failed verification can leave verified
immutable orphans, but cannot publish an archive head or pruning watermark. Cache
paths and external destination settings remain local installation bindings. A
replacement can produce the same archive-complete snapshot without the original
source. Snapshot transfer materializes the unpublished replacement state; it is
separate from indexed historical backup verification. Full backups copy and verify
the same chain in their owned session namespace and stage target cache dependencies
before publishing restored genesis. Restore relocation rewrites bounded records
between encrypted spools, then materializes the actual target state once under a
separate node reservation retained through publication. These reservations are
estimates, not allocator or RSS limits. Final 3 GiB, RSS, disk-capacity and endurance
acceptance remains required. Encrypted temporary files and tables retain the
shared ScratchDisk owner; its physical disk charging is separate from RAM work.

The public `TenantEngine::snapshot(admission, timeout_ms)` asynchronously captures
a complete backend bundle using the installed store and explicit node admission.
The public `prepare_snapshot_restore(image, admission, timeout_ms)` verifies and
stages that bundle without changing live state or any applied position. Its first
pass checks framing, complete counts, digest and EOF with a 64 KiB buffer; logical
allocation is admitted before semantic decoding. The semantic pass recomputes
and matches the admitted per-kind counts, bytes and peak work before returning. All blocking work keeps the
exact store/OS ownership and byte reservation through actual completion, including
when a caller cancels or times out. The staged result holds only the verified
image and identity metadata, not another resident tenant generation.

These backend images do not contain the enclosing Raft LogId/membership envelope.
Publication belongs to the owning Raft snapshot transaction or the exclusive
stopped-installation recovery coordinator. Public running-state overwrite and
logical-format decoder/encoder aliases have been removed. Arithmetic and
corruption tests use an explicitly gated `test-utils` candidate codec; production
builds without fixture features cannot call or decode that fixture API.

Every application bootstrap with retained archive references is verified against
its installed cache before Raft opens or serves after restart. Standalone and
ordinary HA startup use the installed node admission, and target-phase startup
uses its existing owned recovery work and original phase/credential fences.
Missing, corrupt or unavailable historical dependencies therefore prevent a
restored genesis from reopening; a previous verification does not substitute for
current durable availability.

Production standalone, ordinary replicated and target startup install the node's
audit maintenance pool before Raft replay. The application and Control groups
share two reserved 64 MiB lanes, separate from the service security ledger's
64 MiB workspace. Database construction starts archival only after this explicit
installation. Restore and target operations require the security ledger's exact
node governor; an additional governor cannot create independent capacity. Reusing
that same governor on a database is idempotent, and substituting another is a
conflict. Deterministic fixtures select gated fixture bootstrap functions
explicitly, including Control fixtures; reserved storage purposes do not disable
production maintenance.

Control bundles use the same framing but authorize only the exact `NodeControl`
storage purpose and `__kasumi_control` domain. Their archive records use the
current store's exact-purpose audit decoder and the stream/head committed in the
Control state. They cannot invoke application historical-key verification or
cross-incarnation restore lineage. The application backup verifier continues to
reject all reserved storage purposes.

Planned retirement uses canonical `kasumi.retirement-closure.v2` records. Live
persistent roots and indexed backups share the same record projection. Logical
document IDs merge hot and archived records in order; each contributes its exact
version and full-document digest. Staging and feed headers/payloads remain separate
bounded records, and every category has a final count. Immutable lineage and
target history are covered along with policy, resource limits and permanent
command identities. Intrinsic audit/Raft revisions and retirement-attempt records
remain outside this application closure. The first release has no v1 decoder.
