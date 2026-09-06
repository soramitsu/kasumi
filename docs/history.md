# Durable change delivery and archived logical history

These are first-release contracts. Collection definitions explicitly choose
`retention_class` (`operational` or `archivable_history`); there is no old-state
default or conversion path. Archivable history must be append-only. Mutable
authority, balances, sessions, policy and other operational state stay resident.

## Durable change feed

`Database::read_change_feed` and `KasumiClient::read_change_feed` return a bounded
pull page for one to sixteen explicitly authorized collections. `Beginning`
starts at sequence one, `Now` establishes a position at the current committed
head, and `After` resumes a returned cursor. Cursors bind tenant, incarnation,
principal and exact collection scope. A cursor is a position, never a grant:
every request checks current authority, a quorum read barrier, release policy,
tenant key access and any required strict read audit.

Successful document mutations append full after-images or deletion tombstones
in canonical collection/ID order. All records of an atomic command have one
revision and carry a global sequence, ordinal and total commit event count.
Rejected writes, receipt replays, audits and physical archival emit no document
changes. Pages can split a commit. A consumer must buffer its selected records
until its cursor passes `sequence - ordinal + commit_event_count - 1` before
publishing a complete projection of that commit. Scoped feeds can skip other
collections and can return an empty page with an advancing cursor.

Each request examines at most 1,000 records and returns at most the requested
page limit and tenant response-byte limit. There is no subscriber queue or
unbounded stream. Persisted retention removes whole commits under explicit
event and byte budgets; a single oversized commit is rejected atomically with a
durable failure receipt. A stale position returns `RetentionGap`, never silent
success. Rebuild a projection from a coherent snapshot after such a gap; do not
interpret the remaining feed as complete history. Restoring into a new
incarnation invalidates old cursors.

## Archive an append-only revision prefix

Trusted operators install approved destination aliases with
`Database::install_archive_destination`. An alias cannot be replaced at runtime.
`Database::archive_history` and the private native administration RPC accept an
archive identity, logical collection, cutoff revision and destination alias.
The operation exports eligible resident documents through that cutoff into
encrypted, immutable objects, verifies each object by reading it back, and then
publishes one replicated catalog change. Appends can continue into the same
logical collection. The archive identity resolves a published operation to its
original receipt; a different request cannot reuse it.

Objects use the tenant's existing authenticated encryption and fresh historical
key authorization. The committed manifest binds collection, source incarnation,
cutoff, schema epoch, ordered chunks and plaintext/ciphertext digests. Publication
checks each replica's eligible source documents against the manifest before
removing resident bodies. Cancellation or an uncertain upload before publication
can leave encrypted orphan objects, but does not remove source documents.
Administrative orphan reclamation is not implemented.

Retained ID/version/body-digest metadata and exact declared structured index
values preserve existence, absence assertions, immutable identities and unique
constraints without retaining every body. Archival does not change document
versions or the collection's logical data epoch. Native permanent staged-command
identities and operational state are never archived.

Ordinary point reads, structured queries, coherent snapshots and leased point/ID
pages resolve archived bodies through verified chunks. A missing destination or
object returns `Unavailable`; a digest or structural mismatch returns
`Corruption`. Neither becomes absence or a partial successful aggregate. ID
pages can traverse a logical collection larger than a single materialization
budget. The archive registry must be installed again when opening a database.

## Explicit current limits

One export selects at most 100,000 documents and 64 MiB of source bodies. Each
chunk is at most 8 MiB; manifests are at most 4 MiB. Exports exceeding these
limits require an earlier revision cutoff. Cold read materialization is bounded
by the tenant cursor-byte budget; query discovery remains bounded by the
existing candidate limit. Cold text search is not implemented, so text-indexed
collections cannot be archived. Collection/index definitions cannot change
after archived references exist.

History manifests explicitly identify a `history_subset`; they are not full
database backups. The [chunked full-backup path](chunked-backup-plan.md) streams
one coherent resident generation and copies all verified archive dependencies.
Restore requires a full-database manifest and verifies the complete dependency
graph before installing a new suspended incarnation. The configured target key
provider must retain access to historical wrapping-key dependencies.

Engine tests cover durable feed restart, strict audit, retention gaps, complete
commit rejection, current policy, exact numbers, archived point/query/snapshot
and leased ID reads, unique indexes, physical restart, and missing/corrupt
objects. Further tests exercise multiple real encrypted chunks, full restore
after loss of original cold storage, permanent command replay, missing/corrupt
dependencies, historical key authority, and cancellation of stalled uploads.
Native tests cover authenticated feed/archive dispatch and exact values.
These are local correctness tests; they do not establish Linux deployment,
large-fleet performance or a recovery objective.
