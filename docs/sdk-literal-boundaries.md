# SDK-owned literal JSON boundaries

This checkpoint is source-only until its frozen compiler and test gates execute.
It preserves the separately validated `fb172be` snapshot checkpoint in its original
worktree. It does not depend on an external application's root Cargo patch.

The first-release resource types are `ClientDecodeLimits`, `JsonReadOptions`,
`SnapshotReadOptions`, and `AdmittedResponse<T>`. The snapshot-only limit/response
names have been removed. Ordinary `query`, `read_change_feed`, `read_schema`,
`export_security_audit`, and pooled query/page calls require explicit
`JsonReadOptions` with a shared `Arc<ClientResources>` and an original finite
deadline. Snapshot options additionally retain the required expected incarnation.
No unlimited overload or old decoder remains for these SDK-owned responses.

```rust,no_run
# async fn example(mut client: kasumi_client::KasumiClient, token: &str,
# query: &kasumi_types::QueryRequest) -> Result<(), kasumi_client::ClientError> {
let resources = kasumi_client::ClientResources::new(64 << 20, 4)?;
let options = kasumi_client::JsonReadOptions {
    resources: resources.clone(),
    limits: kasumi_client::ClientDecodeLimits {
        max_request_bytes: 64 << 10,
        max_wire_bytes: 1 << 20,
        max_json_bytes: 1 << 20,
        max_decoded_bytes: 8 << 20,
        max_rows: 100,
        ..Default::default()
    },
    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
};
let page = client.query(token, query, &options).await?;
for row in &page.rows { println!("{}", row.id); }
// Arc clones share the same immutable result and retained reservation.
let retained = page.clone();
drop(page);
drop(retained);
# Ok(()) }
```

The shared admission policy reserves four times the request-byte limit, four
times the protobuf-wire limit, twice the decoded-work limit, and 256 KiB for
bounded metadata/authorization/framing overlap. The two decoded allowances cover
retained request metadata and the constructed response. Borrowed request traversal
bounds node, string, numeric and decoded work before encoding or cloning. Pooled
query handles retain the admitted original request as well as the returned result.
Each retry acquires another full owner; the first request owner remains retained.
Application-created Values and copies made from a borrowed result are application
allocations. There is no uncharged `into_inner` transfer.

The transport adapter is shared with snapshot reads. It admits exactly one unary
message, its declared/aggregate size across split frames, and bounded metadata
before forwarding to tonic. TLS/HTTP2 frames and headers have already been
allocated when the adapter sees them. These are SDK-accounted budgets, not hard
RSS or pre-transport allocation guarantees.

Ordinary Query responses use an allocation-free protobuf traversal. Every row and
aggregate JSON body contributes to one aggregate token/decoded-work budget before
any document body or returned Query DTO is constructed. Unknown/duplicate scalar
protobuf fields, invalid lengths, and noncanonical varints fail explicitly. The
subsequent traversal constructs literal Values directly. Pooled continuations
retain their original member, query, cursor and revision; they cannot silently
restart a later generation.

Change-feed, schema and audit responses first admit all JSON tokens. Metadata is
decoded into bounded typed fields and borrowed `RawValue` spans; document/schema
bodies and audit records are constructed directly from those spans. The parser
counts ignored/overwritten tokens, escaped string expansion, depth, numeric
lexemes and shallow arrays. Both `$serde_json::private::Number` and
`$serde_json::private::RawValue` remain ordinary keys, including escaped spellings.
Their string values never start a second JSON parser. Exact large-number lexemes
are parsed as Number directly. No literal Value is sent through generic
`serde_json::from_value<T>` afterward.

The owned blocking decoder retains bytes, request metadata and the admission
through actual completion after a waiter is cancelled. The original deadline is
checked during work and again before worker/client/pool response release. Error
payloads are normalized while ownership remains alive; `ClientError::DecodeRejected`
carries a status code and static diagnostic. Other unmodified administrative
response APIs retain their existing contracts.

Canonical input helpers `decode_mutation_json`, `decode_staged_chunk_json`,
`decode_query_json`, and `decode_schema_change_json` accept bytes with the same
explicit finite options and return admitted immutable DTOs. They require the
complete fields emitted by the canonical Serialize representation, build tagged
mutations/predicates/schema changes directly, and preserve the original digest.
They do not grant authorization or validate an operator's policy intent.
Use these helpers when loading persisted intents. Arbitrary caller use of stock
Serde on Value-bearing public DTOs is outside this preservation guarantee and can
reinterpret data before it reaches the SDK. The server's vendored correction,
including rmcp's earlier pre-handler parse, remains a separate dependency change.

Pending gates include the full prior snapshot cohort, the new ordinary literal
response/canonical-input/aggregate-budget/cancellation tests, strict client and
workspace checks, actual migrated native query/TLS/audit fixtures, and a consumer
workspace with stock serde_json and no root patches. Source formatting is not
compiler or acceptance evidence.

Source review successor to `b0ca8e8` binds change-feed retention gaps to the exact
original requested position, validates retained/head ranges and nonnil cursor
identity, and checks sequence/ordinal/commit relationships while allowing filtered
sequence gaps. It also treats the trusted Number serializer's synthetic field and
lexeme as numeric work; literal document marker keys still use string limits. The
new regression cases remain unrun until the frozen small cohort executes.

The request preflight now reserves each declared map's borrowed-entry sorting
workspace at `serialize_map`, before a canonical serializer may allocate it.
Parent workspaces remain charged during child visits; each compound releases its
own workspace on success, error, or unwinding. Checked node/string/workspace sums
share the decoded-work limit. Sorted maps are charged conservatively as well.
Shared `ClientResources` admission already precedes the entire request walk.
This prepares the separate canonical map serializer integration; it does not
claim that integration's preserve-order feature gate has executed.
