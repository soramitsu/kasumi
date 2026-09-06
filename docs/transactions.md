# Conditional transaction contracts

These first-release additions extend the original 2026-09-05 acceptance baseline.
The original manifests remain evidence for their recorded source; they do not
certify the changed implementation. New collection definitions require
`write_mode`, batches require `read_set`, and persisted state requires the
new schema and collection epochs. There is no old-state migration or implicit
default for these fields.

## Atomic read dependencies

A `MutationBatch` contains one principal-scoped idempotency key, a `read_set`,
and mutations. Consensus application rechecks current permissions, resolves an
exact retained receipt, validates all read assertions against the same pre-write
state, and stages the entire batch. Any failed assertion, schema, uniqueness,
write-mode or quota check publishes no document changes. Rejected outcomes are
retained just like other deterministic mutation errors.

The supported JSON assertion forms are:

```json
[
  {"kind":"snapshot","incarnation":"tenant-incarnation","policy_epoch":4,"schema_epoch":2},
  {"kind":"document","collection":"sessions","id":"s1","expected":{"kind":"version","version":31}},
  {"kind":"document","collection":"receipts","id":"command-1","expected":{"kind":"absent"}},
  {"kind":"collection","collection":"approvals","data_epoch":29},
  {"kind":"before","not_after_ms":1788652800000}
]
```

There is no `any` read assertion. Document and collection assertions require
current read permission in addition to the write permissions for mutation
targets. A batch allows at most 512 assertions and rejects duplicate assertion
identities. It permits one snapshot identity fence and one deadline fence.

Collection data epochs change only when their documents change; audits,
rejected batches, exact receipt replays and deleting an absent document leave
them unchanged. A collection epoch fences query phantoms as well as updates.
Schema epochs change when definitions change. The snapshot assertion also
fences policy changes and restoration into another incarnation. Exact retained
receipt replay precedes these assertions, while current authorization still
precedes receipt disclosure. Native receipts retain the configured lifetime
(24 hours by default). Applications needing permanent replay protection must
store their permanent receipt in the same atomic batch as the business effects.

## Coherent reads

The embedded Rust request `ReadSnapshotRequest` and native JSON request are:

```json
{
  "documents": [{"collection":"sessions","id":"s1"}, {"collection":"receipts","id":"command-1"}],
  "queries": [{"collection":"approvals","allow_scan":true,"limit":100}]
}
```

The response contains `revision`, `incarnation`, `policy_epoch`, `schema_epoch`,
`collection_epochs`, ordered `documents` and ordered `queries`. Each document
entry has `key` and `document`; an authorized absent ID returns `null`.
Every result comes from the same immutable generation captured after the quorum
read barrier. Each query's revision equals the response revision.
`collection_epochs` contains queried collections; named document reads use
their exact version or absence. `SnapshotReadResponse::read_assertions()` builds
the corresponding snapshot, document and collection assertions.

Requests are nonempty, with at most 256 unique document keys and 16 queries.
Queries cannot use cursors. Each query must fit its requested limit (itself
bounded by `Limits.max_page_size`), and the combined response must fit
`Limits.max_result_bytes`. Incomplete results fail with `RESOURCE_EXHAUSTED`;
the API never silently truncates a dependency set. Existing candidate, query
work, memory admission and cancellation limits still apply. Large coherent
report paging and batches above the existing 256-write/8-MiB limits are not
provided by this primitive.

The service authorizes every collection and audits strict reads before release,
then rechecks current authority and key availability. The returned revision
identifies the captured data generation, not any later read-audit entry. This
operation is available in embedded Rust and native gRPC; the existing MCP tools
accept conditional batches but do not provide a coherent snapshot tool.

## Admission deadlines

`Before.not_after_ms` is an inclusive Unix-millisecond bound on trusted leader
execution admission. A database serializes proposal workers through a tenant
gate. A worker samples the server clock after acquiring that gate, stamps the
replicated command, and retains the gate until its Raft write resolves. All
replicas evaluate that stamped time, never their own clocks. A queued request
admitted after its deadline fails with `CONFLICT`; equality is accepted.
The background worker retains ordering and shutdown ownership when its caller
times out or disconnects. Resolve uncertainty using the original receipt/key.

This is an admission deadline, not a deadline on quorum persistence or client
receipt. A command admitted before expiry can finish after expiry. Server clocks
are trusted deployment inputs and must be correctly synchronized. The embedding
application supplies the earliest authoritative session/MFA/policy deadline and
adds document or collection assertions for mutable identity, segregation of
duties, entitlement and policy dependencies. Kasumi cannot infer those domain
rules from arbitrary JSON. An exact already-durable receipt remains resolvable
after its original deadline, subject to current authorization and retention.

## Append-only collections

`write_mode` is `mutable` or `append_only`. Append-only collections accept only
`put` with an `absent` precondition for an absent ID. Overwrite and deletion fail,
including for administrators. Replacing a definition can strengthen mutable
storage to append-only but cannot weaken it. Schema/index replacement still
validates every retained document. This protects journal, audit, outbox and
permanent receipt records from in-place mutation through data/admin APIs;
it does not make a trusted host or its storage administrator untrusted.

## Focused regression evidence

The [engine contracts](../crates/kasumi-engine/tests/contracts.rs) exercise stale
versions, absence, phantoms, write skew, permission checks, receipt replay,
append-only changes and actual local Raft snapshot reads concurrent with writes.
The [service unit test](../crates/kasumi-engine/src/service.rs) controls admission
time and the proposal gate to cover expiry in the queue, canceled callers,
inclusive deadline acceptance and durable replay after expiry. The
[native adapter test](../crates/kasumi-server/src/api.rs) preserves an exact
large decimal and rejects a commit based on an obsolete snapshot. Exact
incremental snapshot accounting remains covered by
[snapshot budget tests](../crates/kasumi-engine/tests/snapshot_budget.rs).
