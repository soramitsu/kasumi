# Chunked full backups and archive-aware restore

`Database::backup` exports a complete logical database as an encrypted manifest
and verified chunks. The private native management `Backup` operation uses this
same path. A history-prefix archive is a subset export and is never accepted as
a complete backup. This is the first-release format; no monolithic-state
fallback or conversion path is present.

1. Capture one committed tenant generation after current administrative
   authorization and a quorum barrier. Stream its canonical resident-state JSON
   through a bounded producer/consumer queue into at most 8 MiB encrypted chunks.
   The retained generation and producer own cancellation/work registrations and
   memory reservations until the actual work finishes.
2. Authenticate each chunk by create-only upload, bounded readback, ciphertext
   digest and decrypted plaintext digest. A full-database manifest records tenant,
   source incarnation/revision, ordered chunk descriptors, total resident bytes
   and the digest of the complete canonical stream. Publish that encrypted
   manifest last. No monolithic legacy-state fallback is part of this v1 API.
3. Copy every archive manifest and chunk referenced by the captured state into
   the same approved backup destination. Verify source and destination objects,
   current tenant key access and administrative policy. The resident state
   contains the transitive dependency descriptors, so no historical body must be
   retained in the exporter's memory. Incomplete work can leave only encrypted
   orphan objects; a completed manifest is not returned before all dependencies
   are verified.
4. Restore accepts an approved source alias and provider. Verify the full-kind
   manifest, bounded chunks, canonical stream digest and tenant identity before
   validating the complete resident state. Verify every archive dependency with
   both the source key authority and the target tenant provider before writing
   bootstrap state. Missing/corrupt objects or unavailable historical keys fail
   closed before activation.
5. Keep immutable archive source-manifest provenance distinct from a retained
   archive's current `storage_destination` alias. Restore binds that alias to
   its approved backup destination identically on all replicas and recomputes
   cached metadata accounting. It preserves original object ciphertext/UUIDs;
   independently randomized re-encryption must not produce different replicated
   genesis states. Historical wrapping-key dependencies remain required.
6. Existing restore semantics still require a fresh incarnation, identical
   replicated genesis, suspended/pending state, durable restore audit and
   explicit activation. Permanent native command identities and all operational
   state are included; archived bodies remain outside resident memory.

The embedded restore functions take `RestoreSource { destination_alias,
destination, keys, timeout_ms }`. The operator installs the alias on every replica. The required timeout is
1..=600,000 ms and bounds admission to the bootstrap gate and the complete
verification phase; native management supplies an explicit 300,000 ms budget.
Large resident decoding, validation and re-encoding run in bounded blocking
workers. A caller timeout does not release their memory/work charge before the
actual worker finishes. Expiry is checked again immediately before persistence.
Synchronous final disk persistence is not claimed to be preemptible. The
replicated restore configuration also takes the actual node admission governor.
The implementation verifies historical objects using the source key authority
and target tenant provider; unavailable historical keys reject restoration.
It does not silently re-encrypt or discard inaccessible history.

The resident stream remains bounded by the 2 GiB snapshot format and the node
admission budget. Export holds a coherent generation and a one-chunk channel;
restore reconstructs only resident state, not every historical body. Archive
metadata and declared structured index values remain resident. Each referenced
historical object is read and checked separately. Aborted operations can leave
encrypted orphan objects; automatic orphan collection is not implemented.

Tests exercise real multiple-chunk exports, loss of original cold storage,
restoration into a fresh encrypted database, cold point and leased reads,
permanent replay, rejection before state installation, interrupted uploads and
identical replicated restore genesis. Local correctness checks do not establish
production recovery time or large-fleet performance.
