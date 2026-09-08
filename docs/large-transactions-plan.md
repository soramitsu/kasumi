# Large atomic transactions and coherent read leases

These first-release APIs are implemented in embedded Rust, native gRPC and the
secure typed Rust SDK. They extend the 2026-09-05 acceptance baseline; they do
not inherit that baseline's Linux or performance evidence. The bounded ordinary
transaction primitives remain described in `transactions.md`.

## Staged transaction protocol

Use `begin_staged_transaction`, `append_staged_chunk`,
`finalize_staged_transaction`, `stop_staged_transaction`, and
`staged_transaction_status` in embedded Rust and native gRPC. Every staged
request retains the explicit original `StagedTransactionScope` (tenant,
incarnation and principal), verified against current native authority and
preserved through backup/restore. The permanent key within a tenant is the pair
of authenticated principal and caller-chosen transaction ID; its original scope
cannot be rebound to a replacement incarnation.

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
one revision with an empty version map; the manifest retains the operation
count. Every changed document has that revision. The tenant's explicit permanent
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

Use explicit `open_snapshot_lease`, `read_snapshot_page`, `scan_snapshot_page`
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
retained roots and their reservations. Native adapters bind the exact lease to
the response fence through encoding and transport handoff, so a page that expires
during encoding is rejected. Active workers retain their own bounded selection
and reservation until completion even if the caller disconnects.

Lease count, retained-generation byte estimates, page rows and encoded response
bytes are bounded. The estimate contributes to the existing RSS governor and
does not claim allocator-level accounting. Scans stop before exceeding output
capacity and must always advance or return a clear oversize-document error.

## Required limits and lifecycle

`Limits.atomic` is required in serialized configuration and state. Its Rust
construction defaults allow 100,000 mutations, 100,000 assertions, 64 MiB of
encoded chunks, eight active uploads, 128 MiB of aggregate declared upload bytes,
100,000 permanent identities, eight read leases and 256 MiB of retained lease
estimates per tenant. These are independent of document, audit, snapshot and
node RSS limits. A chunk has at most 256 mutations, 512 assertions and 8 MiB;
there are at most 512 chunks. Operators may lower limits; they cannot invalidate
already accepted active payloads or completed transaction history.

Begin reserves one permanent identity before accepting payload. It also reserves
declared staging capacity and 8 KiB of snapshot outcome headroom. Upload TTL is
required, from one millisecond to 24 hours. The serialized admission timestamp
at begin fixes expiry; retries never extend it. Each ordered staged operation
reclaims expired active payloads and persists their terminal identity. Expiry is
therefore ordered cleanup, not an independent wall-clock write on each replica.
Guarded stop retains the exact original begin request (manifest and upload TTL)
with fresh attempt-local read assertions. It requires a current snapshot fence
and trusted authorization deadline; read dependencies are checked during ordered
execution and again before final response release. Missing identities become
permanent stopped identities without an upload lease or active payload reservation.
Retries preserve the original terminal outcome. Finalize of an aborted or expired
identity returns conflict. Incomplete finalize leaves the upload open;
a complete finalize stores either its successful receipt or deterministic error.

Status returns `Uploading`, `Finished { outcome }`, `Aborted { receipt }` or
`Expired { receipt }`. Use `outcome.resolved()` to distinguish unfinished work
from a permanent result. Terminal status keeps the manifest and no payload. The required `expires_at_ms`
field is an explicit nullable value: `null` only for a never-started stopped
identity, otherwise the original upload expiry. A missing field is invalid.
See [guarded resolution](guarded-staged-stop.md) for authority and uncertain-outcome
handling.

Point pages accept at most 256 IDs. Scan pages accept up to 1,000 rows, use the
maintained primary ID index and return `next_after_id`; the encoded result remains
at most 8 MiB. Each page starts with a fresh quorum barrier. Opening a lease
shares immutable document, archived-reference, archive-manifest and primary-ID
roots. Its private metadata is charged before capture. Generation publication
charges additional retained values and a conservative bound for copied tree
paths, including ID insert/delete paths. It expires the oldest leases when the
aggregate tenant budget is exceeded; a committed write keeps its exact outcome.
Expiration and generation publication share the same lock as root capture and
page selection, so a burst of writes cannot wait for a later read or monitor tick
to enforce that budget.

Whole leased roots stay inside the manager. A page worker receives only its
bounded document/reference selection and required archive manifests, covered by
a separate node reservation. Expiring the lease releases all other old roots
immediately; in-flight selections remain charged and fail their final release
check. Selection, publication accounting and idle expiration use owned blocking
work. Estimates include cloned policy/schema metadata, allocated value payloads
and conservative tree-node/key overhead; they are not allocator instrumentation
or a measured production capacity result. Duplicate common snapshot assertions
from separate pages must be deduplicated before creating a staged manifest.

## Regression evidence

The [staging suite](../crates/kasumi-engine/tests/staged_transactions.rs) exercises
600 mutations and dependencies across collections, interrupted encrypted uploads
with process kill/reopen, complete snapshot recovery, tampered counters, permanent
identity quotas, stale assertions, append-only failures and lowered future limits.
It also reads the same 600 dependencies across concurrent writes, scans in bounded
ID order, and checks strict auditing, policy revocation and lease expiry. Every
ordered test command compares canonical serialized size with incremental accounting.

The [queued service test](../crates/kasumi-engine/src/service_staging_tests.rs)
controls trusted admission time and caller cancellation. The
[native test](../crates/kasumi-server/src/api_staging_tests.rs) crosses authenticated
native request/response handlers and preserves exact large JSON numbers. Key
revocation and retained generation eviction are covered by
[engine contracts](../crates/kasumi-engine/tests/contracts.rs). The
[replicated service suite](../crates/kasumi-engine/tests/replicated.rs) resumes
a 300-mutation upload after leader isolation, fences historical lease pages on
the isolated leader, publishes once on its successor and resolves the identical
terminal receipt after all three nodes restart. These focused tests
are not a refreshed Linux release gate, maximum-size payroll benchmark, persistent
report artifact implementation, or a 10,000-tenant capacity measurement.
