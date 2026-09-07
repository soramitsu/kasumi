# Verified snapshot-carried retirement custody

The complete offline, locked workspace gate passed 303 tests with no failures.
Two live external-service tests remain explicitly opt-in: MinIO and OpenBao.
Strict Clippy covered all targets and features; workspace formatting, formatting
of explicitly included test files and the diff check passed. All 141 recorded
native source inputs remained unchanged through the run. See verification.json
for exact commands, hashes, platform and logs.

This checkpoint binds a validated application snapshot to its exact accepted
retirement seed, receipt, bootstrap, applied position, membership and custody
policy as of capture. Snapshot installation atomically publishes the application
manifest and independently encrypted custody projection, receiver-local seed
binding, accepted retirement boundary and applied coverage. A replica that has
only received the snapshot can recover that metadata without application keys.

Coverage includes actual engine backup/retirement/policy rotation, transfer to
a second encrypted Raft replica, restart and recapture with 32 journal entries.
Adapter cases cover publication failure at every storage operation, stale
uncommitted candidates, late truncation, term mismatch, cached-image substitution,
equivalent image re-encoding and matching-but-substituted policy metadata at the
same position. Every image retains its exact integrity digest. Upstream OpenRaft
storage conformance and the existing native TLS suites also pass.

The initial failed conformance gate remains in ../snapshot-custody-20260907-a.
The interrupted gate remains in ../snapshot-custody-20260907-b and is incomplete
evidence. Neither earlier record was replaced or presented as a pass.

This is local durable recovery input. It does not establish a fresh custody
administrative proof, custody-only native startup, post-capture policy replay,
independent serving leases or source-quorum-unavailable disaster recovery. A
nonretired Stopped outcome acquires no retired custody marker. Those authority
and lifecycle integrations remain required.

The mandatory Rust StateMachineBackend snapshot/validation return types changed;
all in-repository backends were updated. Database, SDK and tenant storage opener
contracts are unchanged. These are first-release formats with no compatibility
decoder.
