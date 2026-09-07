# Independently encrypted retirement recovery substrate

The first-release storage contract installs two encryption domains for each
application database incarnation. `TenantStorageSet` contains the application
store and the fixed `kasumi.custody/{application tenant}` catalog. Both belong to
one `NodeStore`, with independent wrapping policies, keys and UUID catalog
identities. The immutable binding is encrypted under the custody key. There is
no same-key default, optional custody provider or reader for old development
catalogs/log formats. The custody prefix is reserved and cannot be installed as
an application tenant, preventing an application/control namespace collision.

Normal engine open, local and replicated execution, and all restore entry points
take `Arc<TenantStorageSet>`. Production startup supplies both explicit Transit
providers through `transit` and `custody_transit`; control databases have the same
requirement. Existing Rust embeddings create the set before calling an engine
opener. A raw `TenantStore` remains suitable for independently keyed security
audit or storage-level use, but it cannot open a serving engine.

## Durable execution linkage

Raft application bytes stay in application storage. The separately encrypted
control catalog contains votes, committed and purged cursors, group/node identity,
log headers, exact applied positions and closed retirement seeds. A normal log
header contains only an actual log identity and digests. Retirement seeds contain
the exact prepared request, verified checkpoint/closure observation, original
principal, captured authorization, admission time, scopes and bounded source
policy/accounting metadata. They cannot carry arbitrary documents or operations.
Their canonical command is reconstructed and its digest checked on decode.

The append transaction publishes an application's ciphertext, its header and any
retirement seed atomically, before acknowledging durable append. Commitment
remains a distinct durable Raft operation. A seed without commitment is never
returned by the recovery reader. Truncation deletes the whole uncommitted suffix;
normal overwrite explicitly clears stale seeds. The seed records the installed
bootstrap digest and catalog binding, preventing substitution across incarnations.

The state-machine adapter supplies the actual `LogId`, previous applied position,
membership and command digest. The engine recomputes retirement seed metadata
against its current ordered generation before executing. Only the actual retained
successful retirement receipt can produce an accepted boundary. The adapter
validates that receipt against the durable seed and writes the boundary together
with its exact applied position. Interrupted projection publication can therefore
be distinguished from a completed applied retirement.

Snapshot bodies and chunks remain encrypted in the application domain. The final
snapshot manifest and its exact control coverage publish atomically after all
chunks. Recovery checks content digest, snapshot identity and membership coverage
before restoring the application backend. Ordinary purge deletes application log
bodies and control headers together. After an accepted retirement boundary, purge
retains the remaining source ciphertext and permanent retirement seeds; it does
not retroactively restore previously compacted log bodies.

## Metadata-only recovery boundary

`CustodyStore::open` needs only the custody provider and checks the installed
application catalog's wrapped identity. `ControlLog` reads a locally committed
retirement seed without constructing an application provider, unwrapping its keys,
opening an engine or decoding payload. A crash after commit but before applied
projection therefore preserves enough closed metadata for the next deterministic
custody reducer.

`CommittedRetirementSeed` establishes local durable log coverage. It cannot mint
`VerifiedRetirementReceipt`, authorize a payload operation, establish a fresh
quorum or enable an incarnation. The native server still starts its normal engine
with both key domains. A closed custody-only native startup, deterministic policy
rotation/recovery reducer, current authenticated proof release and independent
serving-lease authority are subsequent prerequisites. This substrate does not
enable source-quorum-unavailable restore activation.

The metadata-only reader also covers a replica that learns accepted retirement
solely through a full Raft snapshot. The backend returns application bytes and
closed retired metadata from one generation. The portable snapshot capsule binds
the exact prepared command seed, original applied position/receipt and bootstrap
to that image, including the Admin set and policy epoch **as of its capture**.
The receiving backend validates the complete image and returns its independently
derived closed metadata for exact comparison before publication. The receiver
rebinds the seed to its own installed custody catalog; source key identities are
never copied as receiver authority.

After bounded chunk staging, the final application manifest, snapshot coverage,
closed capsule, permanent accepted boundary and explicit snapshot applied cursor
publish in one encrypted cross-domain transaction. Snapshot publication and log
cleanup share the same per-store control gate; application apply also holds this
gate when publishing its accepted cursor. An older capture cannot regress a newer
accepted cursor. The snapshot cursor contains image/coverage digests and Raft
metadata, with no invented command digest.

Committed snapshot coverage stays separate from the raw committed-log cursor.
A crash before physical log purge therefore retains exact local custody recovery
input without claiming the receiver possesses the original source log. Beneath a
committed snapshot, only its exact accepted seed can be returned. A conflicting
uncommitted local seed is superseded, subsequent physical suffix cleanup preserves
the accepted seed. Physical log repair beneath snapshot coverage remains legal,
but cannot substitute the exact accepted retirement entry or promote a new
candidate into accepted custody. Equal index but different term identities fail
closed. Missing or substituted capsules,
backend policy/receipt differences, stale projection digests and mismatched local
bootstrap bindings reject installation or recovery.

Application serialization can reorder equivalent persistent maps after a restart.
Every published image keeps its own exact byte digest; two independently validated
encodings at the same applied position must retain identical complete custody
metadata and membership. A builder recapturing that position reuses the current
image only after checking its application and custody coverage together. Replacing
the Admin set or policy epoch in both the incoming image and capsule still fails
against the already published custody identity.

Closed metadata is bounded at 2 MiB including the existing 256 KiB seed ceiling;
a counting serializer rejects oversized metadata without allocating an additional
unbounded JSON copy. These are first-release snapshot/cursor formats, with no old
format decoder. The mandatory `StateMachineBackend` snapshot/validation contract
returns `BackendSnapshot` / `Option<RetiredSnapshotState>`; engine, Database and
Rust SDK openers are unchanged by this tranche.

This capsule is immutable **local recovery input**, not a freshly authorized
custody proof. Current policy rotation after the snapshot must still be replayed
by the forthcoming closed native custody reducer. Native custody-only startup,
current credential/revocation handling, quorum-authorized proof release and
independent serving-lease/DR fencing remain required.

A nonretired `Stopped` outcome continues to require the ordinary source serving
and current administrative authority path for fresh proof recovery. Neither an
uncommitted retirement seed nor a stopped identity can select retired custody
mode. Planned retirement cannot substitute for independently fencing an unavailable
source, and no copied application journal receipt grants current custody authority.

## Verification scope

Storage fault tests inject failures through transaction and fsync positions and
reopen the last synchronized image. They check atomic cross-domain writes, key
expiry, catalog substitution, commit-before-projection recovery with application
key revocation, applied-boundary atomicity, stale seed removal and ordinary purge.
Engine tests create real verified full backups, retire the actual database,
rotate the custodian, install a snapshot into a second encrypted Raft replica,
restart and recapture that replica, then recover its seed without opening source
data. A stopped
retirement retains no retired snapshot marker. Adapter tests inject every storage
failure position during snapshot publication and check whole image/seed/boundary/
cursor recovery, equivalent re-encoding, policy substitution at a fixed position,
stale candidate suppression and late truncation. Quorum tests check
that custody key sealing interrupts reads and rejects new writes. These checks
run alongside upstream OpenRaft storage conformance and native mTLS regression.

Metadata fixture receipts in low-level adapter tests exercise linkage and fault
handling; they are not source administrative proofs. Physical power-loss tests,
independent host failure domains and operator KMS policy custody remain deployment
validation responsibilities.
