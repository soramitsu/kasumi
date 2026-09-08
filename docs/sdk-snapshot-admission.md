Native snapshot calls require `SnapshotReadOptions` containing an explicitly shared `Arc<ClientResources>`, `SnapshotDecodeLimits`, the caller's installed `expected_incarnation`, and one finite Tokio deadline. There is no unbudgeted snapshot overload. The expected incarnation comes from installed resource configuration; the client never infers it from unverified JWT text. The server remains responsible for authentication and authorization.

For example, a caller can select a 64 KiB JSON payload limit and a separate 2 MiB decoded-capacity charge:

```rust,no_run
# async fn example(pool: &mut kasumi_client::KasumiClientPool, incarnation: uuid::Uuid) -> anyhow::Result<()> {
use kasumi_client::{ClientResources, SnapshotDecodeLimits, SnapshotReadOptions};
let resources = ClientResources::new(16 << 20, 8)?;
let options = SnapshotReadOptions {
    resources: resources.clone(),
    expected_incarnation: incarnation,
    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
    limits: SnapshotDecodeLimits {
        max_request_bytes: 64 << 10,
        max_wire_bytes: (64 << 10) + 16,
        max_json_bytes: 64 << 10,
        max_decoded_bytes: 2 << 20,
        max_rows: 100,
        ..Default::default()
    },
};
let lease = pool.open_snapshot_lease(&kasumi_types::OpenSnapshotLease { ttl_ms: 5000 }, &options).await?;
// A later logical operation receives a new explicit deadline and retains the
// same resource owner and the same opaque, member-pinned lease.
let next = SnapshotReadOptions { deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(2), ..options };
let page = pool.scan_snapshot_page(&lease, "docs", None, 100, &next).await?;
assert!(page.documents.len() <= 100);
# Ok(())
# }
```

The resource contract covers SDK-accounted capacity, not process RSS, allocator fragmentation, kernel buffers, or allocations made by application code. A 64 KiB wire page does not imply a 64 KiB decoded object. `SnapshotDecodeLimits::accounted_bytes()` reports the capacity reserved for each attempt: four times the request limit, four times the protobuf message limit, the selected decoded-capacity limit, and a 256 KiB allowance for bounded metadata/authorization/framing overlap. `max_wire_bytes` includes the protobuf envelope; the five-byte gRPC header is accounted separately. A caller wanting 64 KiB of JSON must allow its protobuf framing too.

Admission precedes request traversal, encoding, expected-point metadata cloning, pool routing and dispatch. Outbound serialization first walks borrowed values without copying them, bounding depth, nodes and string/request work; the output writer rejects its byte limit before growing its buffer. Retries keep the original deadline, credential snapshot and member pin. Prepared requests retain the first full reservation until the logical operation finishes. Every subsequent attempt acquires another full reservation, even if the previous transport has exited; cancelled attempts still performing work retain their own reservations too. Allow at least two owners and twice `accounted_bytes()` to permit one retry. If capacity is unavailable, the retry fails admission before dispatch and does not replace the original request or snapshot.

The response adapter receives already-allocated HTTP/2/TLS frames. It checks the gRPC header across split frames, compression flag, aggregate body length and exactly one response message before forwarding bytes into tonic. It rejects oversized initial headers before tonic can decode `grpc-status`/`grpc-message`, and caps admitted initial/trailing metadata together at 64 KiB. Underlying transport frame and header allocations precede this adapter; this is explicitly not a pre-transport allocation guarantee. Compression is unsupported on this snapshot path.

The protobuf decoder accepts exactly one canonical bytes field and checks its length before taking the JSON bytes. A no-allocation JSON token scan checks the entire input, including ignored and overwritten fields, nesting, shallow node counts, decoded escaped-string lengths and arbitrary-precision number lexemes. Its versioned decoded-capacity model charges 512 bytes per node/key and eight bytes per decoded string byte/numeric lexeme byte. These conservative charges describe the SDK admission policy, not measurements of allocator internals.

Borrowed metadata inspection verifies exact point counts and order, document keys, original lease fields, expected incarnation, revision bounds and scan continuation ordering before document/aggregate Values are constructed. Query result counts/revisions/completeness, row versions against their own collection data epoch, and duplicate row IDs are checked; the client does not re-evaluate the database's query predicate or arbitrary sort expression. Initial reads establish a revision within the explicitly expected incarnation; subsequent lease pages must retain their admitted revision/epochs exactly.

Document and aggregate Values are built literally from the admitted grammar. Maps and arrays are constructed directly; only isolated string slices and numeric lexemes use their respective String/Number decoders. Neither Value::deserialize nor serde_json::from_value is used for final snapshot construction. Consequently `$serde_json::private::RawValue` and `$serde_json::private::Number`, including escaped key spellings, remain ordinary document keys and cannot cause a second hidden JSON parse.

An owned blocking worker retains the raw bytes, prepared request and admission until actual completion, including after cancellation or panic. Deadline checks occur during token/build work and again at worker and pool response release. `AdmittedSnapshot<T>` shares one immutable response and retained reservation through Arc clones. It intentionally provides no uncharged `into_inner`; copying a borrowed document is an application-owned allocation. The full conservative reservation remains charged while the returned response or lease is retained. Choosing small explicit limits for lease creation avoids retaining a large page-sized maximum for a small lease header.

Snapshot parser/transport failures are normalized while the owned receive/worker scope remains alive. `ClientError::SnapshotRejected` carries a status code and static diagnostic only; peer-controlled JSON field names, status messages, details and metadata are dropped before the admission is released. Pool retries preserve the status-code classification. No owned error payload can escape this snapshot path and silently outlive its reservation.

This checkpoint is source-only until its frozen compiler and functional gates run. The included regressions cover framing/envelope rejection, malicious initial error headers, token expansion, original-scope/count/order failures, literal-marker preservation, aggregate ownership, cancellation and worker panic. They are not acceptance evidence until executed.

The native/MCP/storage ingress audit is separate. The fixture-free production 3a8d512 dependency graph already included serde_json raw_value and arbitrary_precision, as recorded in its release evidence; the explicit client feature can also enable raw_value in smaller dependency graphs. Other stock typed Value deserializers retain the marker hazard until their own literal parsing boundaries are corrected. This SDK change does not claim to repair those ingress paths.

The shared native authorization helper marks bearer metadata sensitive before insertion. The transmitted Authorization value remains unchanged, while metadata/request Debug output redacts it and HTTP/2 can avoid indexing it. This fixes a pre-existing diagnostic-exposure gap across users of the shared helper; it was not introduced by snapshot admission.
