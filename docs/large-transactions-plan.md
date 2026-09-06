# Next implementation wave: large atomic work

This is a concrete implementation design, not completed functionality or
acceptance evidence. The bounded transaction primitives in `transactions.md`
are the current implementation. This wave follows secure native SDK extraction.

## Staged transaction protocol

Add `begin_staged_transaction`, `append_staged_chunk`,
`finalize_staged_transaction`, `abort_staged_transaction`, and
`staged_transaction_status` to embedded Rust and native gRPC. Every request is
authenticated and tenant-selected by the existing boundary. Identity is the
pair of authenticated principal and caller-chosen transaction ID.

A required immutable manifest contains the ordered canonical-JSON SHA-256
digest of every chunk, total encoded chunk bytes, total mutations, total read
assertions, and the sorted read/write collection names. A chunk contains
`read_set` and `operations`. The begin request declares and reserves bounded
tenant staging capacity. Repeated begin/chunk calls must match the same manifest
and chunk bytes exactly; no last-writer-wins replacement is possible. Chunk
indexes can arrive out of order, but final assembly follows manifest order.

Each chunk is a bounded ordinary Raft proposal persisted under the tenant's
encryption. Staging lives in a dedicated replicated state field, invisible to
document, index, discovery and query APIs. It is included in snapshots and
backups so leader loss, process death, compaction and restore cannot fabricate
an empty transaction. Chunk acceptance does not apply business document effects.

Finalize is one ordered command. It rechecks current read/write permissions,
resolves an existing terminal result, verifies complete counts/digests, and
evaluates every read assertion against one current pre-write state. It then
validates schemas, append-only modes, CAS, unique constraints and quotas before
publishing all document/index changes in one generation. The existing trusted
admission deadline applies to finalize. No per-chunk partial publication is
allowed. A duplicate target or inconsistent repeated read dependency rejects the
whole transaction. Exact duplicate snapshot identity assertions across pages
may be normalized by the client before manifest creation; contradictory fences
must never be silently merged.

Terminal success, failure or explicit abort permanently retains the owner,
transaction ID, manifest/digest identity, chunk digests, collection authorization
scope and bounded outcome. Payload chunks are released. A terminal result uses
one revision and operation count, avoiding an unbounded per-document version
map; every changed document has that revision. The tenant's explicit permanent
transaction record quota fails closed and has no automatic eviction. A caller
resolves uncertain finalize using this status API and identical transaction ID.
There is no 24-hour identity reuse window for staged transactions.

Explicit limits bound chunks, total transaction bytes, mutation and assertion
counts, active transactions, aggregate reserved staging bytes and terminal
records. They are mandatory first-release configuration/state fields, with Rust
construction defaults but no old-state deserialization defaults. Chunk input
stays within the existing native request bound. Commit admission reserves its
larger materialization workspace before proposal; replicas either finish a
committed materialization or become unavailable under existing guarantees.
Canonical snapshot accounting includes staged metadata and payloads and updates
only changed stage entries. Terminal quota rejection must preserve the permanent
result whenever its reserved outcome headroom permits it.

## Coherent large reads

Add explicit `open_snapshot_lease`, `read_snapshot_page`, `scan_snapshot_page`
and `close_snapshot_lease` methods. Open establishes a quorum barrier and pins
one immutable generation for a bounded lease of at most 60 seconds. The token is
random and bound to principal, tenant, incarnation, policy/schema epochs and
leadership term. It is a transient read handle, not a resumable transaction or
a durable report artifact.

Point pages accept bounded named document keys and return the existing
`SnapshotReadResponse` shape, all from the leased generation. This lets a large
financial compiler collect exact version/absence dependencies in pages without
mixing generations. Collection scan pages use explicit `after_id` and `limit`
and return deterministic ID-order document pages plus the same snapshot identity
and collection data epoch. The complete scan supplies large report inputs and
the collection fence prevents phantoms if the scan feeds a write. Index-driven
sorting/filtering and persistent report artifacts remain separate features.

Every page rechecks current collection authority, key leases, policy, leadership,
deadline and resource admission, then performs any required read audit before
release. A policy change, failover, expired lease or memory-pressure eviction
invalidates the token; callers reopen and recompute instead of combining pages
from another generation. Explicit close, expiry, key sealing and shutdown release
owned generations and memory reservations. Active workers retain their own
registration/reservation until completion even if the caller disconnects.

Lease count, retained-generation byte estimates, page rows and encoded response
bytes are bounded. The estimate contributes to the existing RSS governor and
does not claim allocator-level accounting. Scans stop before exceeding output
capacity and must always advance or return a clear oversize-document error.

## Acceptance cases

Use actual local and replicated databases for interrupted chunk upload/reopen,
lost finalize response, duplicate/conflicting chunks, incomplete manifests,
stale authority/read fences, expiry while queued, atomic cross-collection index
publication, append-only protection, retained terminal identity and bounded
resource rejection. Snapshot tests cover more than 256 dependency documents,
concurrent writer generations across pages, absence, report scans, exact-money
bytes, policy revocation, key sealing, lease expiry and shutdown draining.
Canonical serialized size must equal incremental accounting across stage
begin/chunk/finalize/abort, rejected operations, restore and terminal replay.
