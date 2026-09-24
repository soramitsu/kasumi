# BOI first-release state contract

BOI Core uses one dedicated Kasumi tenant. Its native credential and collection
policy grant the Core principal access to that tenant only. Provision two
collections before starting Core; a missing collection is a deployment failure,
not a reason for the application to create or adopt another tenant.

| Collection | Write mode | Document | Purpose |
| --- | --- | --- | --- |
| `boi_core_owner` | `append_only` | `owner` | Permanent first-owner marker |
| `boi_core_state` | `mutable` | `central-state` | One versioned `CentralState` |

Both use `retention_class: "operational"`, no indexes, and explicit JSON
Schema Draft 2020-12 definitions. The owner schema is:

```json
{"type":"object","required":["schema","owner"],"additionalProperties":false,
 "properties":{"schema":{"const":"boi.core-owner.v1"},
               "owner":{"const":"boi-core.is2"}}}
```

The state schema is:

```json
{"type":"object","required":["schema","owner","state"],"additionalProperties":false,
 "properties":{"schema":{"const":"boi.central-state.v1"},
               "owner":{"const":"boi-core.is2"},
               "state":{"type":"object"}}}
```

Core checks the exact owner and schema strings and validates its full
`CentralState` on every read. Schema validation alone does not authenticate the
writer: Kasumi tenant policy and the bound credential do that. On startup, Core
uses one `ReadSnapshotRequest` containing exact reads of both named documents
and complete, bounded queries of both collections (`allow_scan: true`,
`limit: 2`). A query exceeding its limit fails rather than returning a partial
inventory. Exactly one owner marker and one state document is the only
established state. Both collections empty is the only initial state; one missing
document, another ID, or a malformed body fails closed.

The authorized initial claim is one `MutationBatch` with a fresh
`idempotency_key`, the snapshot's read assertions (including both collection
epochs), and two `Put` operations with `Precondition::Absent`. Kasumi commits
both documents in one ordered mutation or neither. A competing claim conflicts.
Subsequent state replacements use `Precondition::Version` from the exact
coherent read, retain the owner marker, and include any dependent snapshot
assertions. Core never uses `Precondition::Any` for this document.

For an uncertain write, resolve the **original** batch with
`KasumiClientPool::resolve_mutation`, the independently expected
`MutationReceiptScope`, and its exact body/read set/preconditions. An absent
receipt is unknown, not permission to issue a different claim. Read back both
documents after any committed result. The retained receipt and state survive
snapshot recovery; the owner marker cannot be overwritten or deleted through
the data API.

Load the installed native profile with `ClientProfile::load_with_sha256` and
compare its digest to an independently signed deployment value. Call
`require_database_binding` with independently signed tenant, incarnation,
principal, and credential-family IDs before constructing a client. For a
standalone node, a one-member `KasumiClientPool` uses
`profile.connection(false)` and a `FileCredentialSource` for
`profile.bearer_file`; it reloads the credential on each invocation. This
profile does not supply a signed multi-member data route.

The default `max_document_bytes` is 1 MiB. BOI must configure and enforce its
own bounded state size; a 6 MiB serialized state ceiling leaves room below the
native request cap of 8 MiB plus 64 KiB. Keep `max_batch_bytes` at least 8 MiB
and `max_result_bytes` at least 8 MiB, and test actual encoded request and
snapshot sizes. Increasing a tenant limit beyond the native wire cap does not
make a larger single-document update transportable.

Kasumi does not hide or delete application documents at a TTL. BOI payment
claim expiry remains a field in `CentralState` and is enforced by Core's state
transition rules. If a transition needs Kasumi's trusted leader admission time,
bind its observed document version and use `ReadAssertion::Before` or
`ReadAssertion::NotBefore` in that same mutation batch. Receipt resolution is
read-only and does not reinterpret an old deadline.
