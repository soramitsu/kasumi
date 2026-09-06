# Chunked full backup contract under implementation

The completed history-prefix archive is a subset export. Its manifests must
never enter full-database restore. The current full-backup operation rejects
archived databases until the following path is implemented and tested.

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

Acceptance requires multiple actual chunks, source archive loss after a complete
backup, restore into a fresh encrypted database, resumed cold point/index/leased
reads and permanent replay, corrupt/missing dependency rejection before state
installation, interrupted export without a successful manifest, current key
revocation, and identical replicated restore genesis. Local correctness checks
do not establish production recovery time or large-fleet performance.
