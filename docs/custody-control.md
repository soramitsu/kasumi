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

The metadata-only reader currently covers a node that durably appended the
retirement seed. A follower that first learns the retired state solely through
an installed full snapshot has exact independently keyed snapshot coverage, but
does not yet receive a separately recoverable retirement seed and accepted
boundary. Snapshot-carried closed custody metadata and engine validation are
required before custody-only recovery covers that follower without application
keys. A checkpoint from the local append path does not establish that coverage.

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
The engine test creates a real verified full backup, retires the actual database
and then reopens its control seed without opening source data. Quorum tests check
that custody key sealing interrupts reads and rejects new writes. These checks
run alongside upstream OpenRaft storage conformance and native mTLS regression.

Metadata fixture receipts in low-level adapter tests exercise linkage and fault
handling; they are not source administrative proofs. Physical power-loss tests,
independent host failure domains and operator KMS policy custody remain deployment
validation responsibilities.
