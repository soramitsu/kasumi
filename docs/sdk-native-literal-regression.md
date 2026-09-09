# Native SDK literal regression

Source-only checkpoint based on validation `b1851d5`. The named test is
`api::tests::native_sdk_query_feed_schema_preserve_literal_values_and_admission`
in `crates/kasumi-server/src/api_sdk_literal_tests.rs`.

The test starts separate data and administrative TCP listeners with actual
TLS 1.3/mTLS, installed CA trust and exact server leaf pins. The existing durable
engine fixture supplies a resource-bound JWT and its normal policy. Every operation
under test enters through a high-level Rust SDK connection; it does not substitute
an in-process NativeData/NativeAdmin method call for TLS.

It covers:

- Canonical schema bytes with escaped private-marker keys, admitted by
  `decode_schema_change_json`, activated through the SDK, and read through the
  bounded `read_schema` path. The schema carries literal objects under `const`.
- Canonical mutation bytes admitted by `decode_mutation_json`, then actual native
  consensus application and query/feed readback. Both marker spellings, nested
  marker objects, an integer beyond u128, an exact decimal and `1e400` remain
  literal. The mutation dispatch retains the remaining original input deadline.
- Pooled query pagination: retain the original page and revision, commit another
  document, and continue the original cursor without including the newer row.
- Real supported count aggregates whose aliases are the two marker spellings,
  exercising literal aggregate maps instead of fabricating an unsupported result.
- Feed continuation with exact tenant/principal/incarnation/collection cursor
  fields; page boundaries may split a two-document commit.
- Shared immutable DTO ownership and eventual zero admission after final release.
  A small numeric decode limit rejects query/feed/schema responses; the original
  feed cursor remains usable and committed document data epochs remain unchanged.
  An expired operation fails through its original deadline.

The fixture uses explicitly gated local key/auth bootstrap helpers; this is an
integration regression, not fixture-free standalone installation acceptance.
It shuts down and joins both listeners and the engine/audit workers. It does not
reopen the database, restore a backup, test MCP, or claim process RSS bounds.
Those remain separate release gates. The source did not add aliases, legacy
formats or fallback decoders.

No Cargo command or native test has run on this checkpoint. After the combined
workspace compiles and the root grants a native window, use the pinned toolchain
and one owned process group:

```sh
cargo +1.97.1 test --locked -p kasumi-server --lib --all-features -j1 \
  api::tests::native_sdk_query_feed_schema_preserve_literal_values_and_admission \
  -- --exact --test-threads=1 --nocapture
```

Require exactly one passing test, bounded runner timeout and complete process-group
drain. Preserve exact source/tree/lock/configuration hashes, raw failures and test
executable hash before any rebuild. Direct formatting is not compilation evidence.

## Source review follow-up

The bounded review of `a407cab` found two response metadata gaps in the SDK:

- A feed document with a version older than its event revision was accepted.
  The engine publishes complete after-images and its durable feed validator
  requires `document.version == commit.revision`. The SDK now checks exact ID
  and revision before constructing the literal document body. Deletes still
  accept the explicit null document, and the outer read revision may be newer.
- A schema response could claim `schema_epoch > policy_epoch`, or return an
  existing collection with a zero schema epoch. These violate the engine's
  canonical state checks. The SDK rejects them; absent requested collections
  still permit a zero schema epoch or an already established schema epoch.

The added pure tests are
`literal_decode::tests::change_feed_after_image_requires_exact_commit_version_and_identity`
and `literal_decode::tests::schema_read_rejects_impossible_schema_and_collection_epochs`.
They have not run yet. The native test, payload and original deadlines are unchanged.

Source tracing confirmed that the numeric fixture fits Kasumi's current bounded
exact-decimal model: at most 100 input digits and exponents between -1000 and
1000. The JSON Schema dependency enables arbitrary precision and compares the
constant's literal object recursively. The SDK token admission precedes raw-span
construction; literal object maps and numbers do not cross a generic
`from_value` bridge. Pooled query pages retain their originating member, original
query revision and request owner; each retry acquires its own response admission.
This review is not execution evidence and does not extend accounting to general
mutation RPC encoding or claim that schema compilation has been exercised.
