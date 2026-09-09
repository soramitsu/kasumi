# First-release literal JSON byte contract

Kasumi's durable mutation, staged-transaction, schema-activation and history
identities must not depend on a downstream crate enabling serde_json's
`preserve_order` feature. `CanonicalJsonValue` defines the literal payload
contract: recursively sort object keys by Rust string order; preserve array order,
string values, and the exact `Number` representation. Literal private marker keys
are map keys, never instructions to reinterpret the containing object.

The serializer is attached to exactly three typed fields:

| Field | Digest and byte consumers |
| --- | --- |
| `Mutation::Put.body` | `MutationBatch::digest`; engine mutation receipt replay; `StagedManifest::from_chunks`; append, terminal validation, and snapshot reconstruction of staged chunks |
| `Document.body` | `HistoryArchiveChunk` plaintext writer and hash; publication checks in `history_state`; document-reference checks in `history_reads` and `backup_verify`; typed document bytes throughout snapshots |
| `CollectionDefinition.schema` | `SchemaChangeSet::reference`; permanent activation input/replay checks; typed schema bytes in snapshots and requests |

The enclosing struct/enum field order and typed map order remain explicit parts
of each type's serialization. A `BTreeMap<u64, T>` orders keys numerically, not
lexically. This is a deliberate typed contract, not a generic JSON canonicalizer,
RFC 8785 implementation, or compatibility mechanism. `staged_digest` hashes the
encoding supplied by its type. An untyped `Value` caller must explicitly pass
`CanonicalJsonValue(&value)` to request literal object canonicalization.

Current `QueryRequest` predicate Values are not inputs to `staged_digest` or a
persisted/signed query identity. The query schema validator hashes a bare schema
Value for a process-local weak cache key; differing order can cause an extra
cache entry, not a different authorization or replay result. Inspected
Control/lifecycle, authority, signing-domain and custody digest DTOs contain no
untyped Value field. This checkpoint does not rewrite those structural formats.

All existing typed plaintext writers consume the same field serializer. In
particular `history_export` hashes the actual serialized `HistoryArchiveChunk`
bytes, while ordered publication and later reference checks recompute through
`staged_digest`. A digest-only adapter would leave those two paths inconsistent.

## Source and memory boundary

The wrapper traverses borrowed Values. Already sorted maps stream directly;
unsorted maps allocate only a fallibly reserved vector of borrowed entries and
sort it in place. There is no `to_value`, `from_value`, payload clone, or encoded
payload buffer. Nested maps can retain their parent entry metadata during
serialization. Existing per-document/schema/request limits still apply; this is
not a new tenant-wide memory reservation or a disk-capacity primitive.

A real `Value::Number` delegates to Number's arbitrary-precision serializer.
Literal marker objects use `SerializeMap`. This proves the intended emitted JSON
bytes, not the safety of stock serde_json Value deserialization of a marker-first
object. The SDK's literal input parser and native/storage decoder boundaries need
their own gates; a serialization fix cannot establish that end-to-end property.

## Cross-feature gates

The six contract tests in `crates/kasumi-types/tests/canonical_json.rs` are reused
here verbatim. They compare permuted nested inputs with explicit golden bytes and
fixed SHA-256 values for mutation, chunk, document and schema identities. They
also exercise literal marker objects, escaped keys, distinct large numbers,
caller map immutability, archive plaintext alignment, typed numeric-key ordering,
and bounded writer rejection. Tests construct literal objects directly instead of
passing them through stock Value deserialization.

This separate consumer can unify `preserve_order` without enabling it across the
Kasumi production workspace. Its seventh test proves that the raw serde_json map
order really differs between the two feature graphs; equal results cannot be
credited to accidentally running the same graph twice.

No Cargo commands, compilation, or functional tests have run for this source
checkpoint. A compiler lane is required before generating this isolated fixture's
lockfile and freezing it for both invocations. The production lockfile is unchanged.
After that dependency preparation, run both exact locked graphs with a dedicated
target and one job:

```sh
CARGO_TARGET_DIR=/tmp/kasumi-canonical-json-target cargo +1.97.1 test \
  --manifest-path tests/canonical-json-feature-unification/Cargo.toml \
  --locked -j1 -- --test-threads=1
CARGO_TARGET_DIR=/tmp/kasumi-canonical-json-target cargo +1.97.1 test \
  --manifest-path tests/canonical-json-feature-unification/Cargo.toml \
  --locked -j1 --features preserve-order -- --test-threads=1
```

Also run the normal kasumi-types suite and strict Clippy, then the affected staged,
receipt, schema and history integration gates on the final combined source. Direct
rustfmt and source inspection do not replace those tests. There is no alternate
legacy digest, migration, or fallback acceptance path.
