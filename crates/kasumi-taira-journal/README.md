# Taira deployment journal

This crate records one DPN/Taira deployment as eight immutable Kasumi phase records:
intent, then signed preparation and verified observation for each of the native
`iroha taira dataspace-deploy` phases, followed by completion. The maintained
phase order is **catalog**, **bootstrap**, **aliases**: an additive physical
dataspace catalog parameter, its immutable bootstrap grant, then the paid alias
transaction containing the dataspace and account alias `Create` instructions.
The three verified phase records retain the exact authenticated evidence.
Completion binds their digests and retains the native four-validator completion
receipt bytes. Each record has a deterministic document ID and idempotency key.
Large records are split into immutable 128 KiB payload chunks, each independently
bound to the deployment identity and whole-record digest. The chunks are written
and read back before the phase manifest is committed. An interrupted append may
leave orphan chunks; retrying the same exact payload finishes it, while a
different payload conflicts. An uncertain Kasumi write is resolved against its
original batch and read back from an authenticated snapshot; an absent receipt
is never taken as proof that the write did not happen.

Provision the selected collection with `write_mode: "append_only"` and
`retention_class: "operational"`, and grant the installed database principal
Read and Write on that collection. The collection definition and policy are
installation preflight requirements. The journal does not create or weaken them.
The caller supplies an independently authenticated `InstalledProfileBinding`
and checks the format-2 profile digest, tenant, incarnation, principal, and
credential family before the first journal request.

Before signing, the native deployment CLI must preflight the installed Kasumi
policy limits and collection: `max_document_bytes` must be at least 384 KiB,
`max_batch_bytes` at least 384 KiB, and the collection must be append-only and
operational. It must also confirm authenticated Kasumi access and the pinned
Taira network/genesis/capabilities. Once a phase is signed, it must append and
read back the exact signed wire through this journal **before** its Taira
broadcast. If that append remains uncertain, it must stop and recover the same
transaction; it must never sign a replacement or dispatch with only a local
prepared file. The native CLI remains responsible for submitting through its
maintained Iroha interface, verifying the
receipt and deployed objects against the installed chain/genesis and expected
identities, and only then appending a phase proof. On resume it reads the saved
signed transaction, checks Taira first, and must not generate a different
transaction for the same phase. A completion document is not itself evidence of
current Taira state; clean-client
validation rechecks the chain and the Kasumi journal independently.

The journal accepts the maintained native CLI's 8 MiB bound for each signed
transaction, phase evidence, and completion receipt. Kasumi's maximum document
body is 1 MiB and maximum batch is 8 MiB; chunking keeps every individual
document below the stated 384 KiB installation requirement. In one retained
clean-client Linux fixture, exact signed wire was 2,537 bytes for catalog,
774 for bootstrap, and 880 for aliases; the corresponding prepared JSON files
were 8,945, 3,074, and 6,910 bytes. Four completion receipt files were
175,708–175,716 bytes. These are observations, not size limits. The exact
payload is checked and persisted before dispatch regardless of its size within
the native bound.
