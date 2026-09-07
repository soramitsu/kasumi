# Guarded permanent staged resolution

`Database::stop_staged_transaction(context, request)` and the authenticated native
`StopStagedTransaction` RPC return `StagedTransactionStatus`. The Rust SDK exposes
`KasumiClient::stop_staged_transaction(bearer, &request)` through its required
pinned TLS 1.3/mTLS connection. There is no reference-only abort API.

```rust
StopStagedTransaction {
    original: BeginStagedTransaction { transaction_id, manifest, ttl_ms },
    admission: Vec<ReadAssertion>,
}
```

The permanent identity binds the authenticated principal, transaction ID, exact
original manifest and upload TTL. The admission assertions belong to this attempt
and are never hashed into that identity. Reusing an ID with a changed manifest or
TTL conflicts. The original manifest must satisfy the first-release hard limits;
subsequently lowered limits cannot invalidate a retained terminal identity.

Every attempt requires a current `Snapshot` assertion and a `Before` assertion.
For an exclusive application expiry, encode `Before(expiry - 1)`. The engine
checks all supplied document versions/absence and collection data epochs, including
current read authority over those dependencies, during ordered execution using
its captured trusted admission time. The native credential's original live
monotonic deadline remains a separate admission and response fence. Callers must
supply their entire evaluated authority graph; Kasumi does not infer application
membership or business meaning from JSON documents.

A missing identity becomes a permanent `Aborted` identity containing the original
manifest/TTL but no chunk payload, active-upload reservation or invented expiry.
The required `expires_at_ms` field is explicitly `null` for that state. An actually
begun upload retains its original non-null expiry after it stops. Permanent
identity capacity is checked before accepting a missing stop; snapshot/audit and
node resource limits still apply. Rejected admission does not create a tombstone.

An uploading identity clears invisible chunks and becomes `Aborted`. A retained
terminal identity keeps its exact original outcome, including successful or
failed finalization and prior expiry. Each guarded resolution itself obtains a
new ordered acknowledgement; its returned status still contains the original
terminal receipt. A delayed begin, append or finalize cannot revive a stopped ID.
Encrypted restart and snapshot validation retain these semantics.

The same fresh assertion set is retained with an admission reservation through
status readback and final native response encoding. A changed authority document,
policy/schema/incarnation, expired deadline, credential, key lease, or release
admission suppresses the response. Once ordered execution has accepted the stop,
a failed acknowledgement is `UnknownOutcome`; no rollback is implied. Ordered
rejections remain definite and cannot be interpreted as an accepted stop.

For financial cleanup, include the exact immutable intent version and permanent
business receipt absence in addition to current application authority. If the
original command commits first, its receipt may invalidate that absence fence.
The cleanup attempt then fails; the successful original outcome remains durable.
Recover the permanent business receipt with fresh authority. An admission error,
missing preflight status, caller cancellation, expired upload, or lost response
never independently proves that the original business command was aborted.

The [encrypted integration tests](../crates/kasumi-engine/tests/guarded_staging.rs)
cover permanent missing stops, exact identity, fresh terminal resolution, quota,
read authority, final-release races and commit/stop races. The
[ordered service tests](../crates/kasumi-engine/src/service_staged_stop_tests.rs)
cover queued expiry, caller cancellation, preceding authority changes and closed
acknowledgements followed by encrypted restart. The
[native test](../crates/kasumi-server/src/api_guarded_staging_tests.rs) exercises
closed JSON input, verified bearer scopes, tenant routing and the real secure SDK.
These tests do not establish application policy completeness or fleet/DR closure.
