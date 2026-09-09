# External stock-serde_json SDK consumer

This fixture was prepared on SDK source
`b0ca8e8e5c7835da6444c152d49de9e6eddd51b5`, then advanced through the feed/numeric
and decoder import corrections to `9aad42eb6754b4d6eedad801497fe7eac0162015`.
Dependency preparation at that checkpoint passed on Rust 1.97.1: lockfile
generation, locked metadata and strict graph guards for default and ordered
features. All five process groups drained, and tracked source stayed unchanged.
No Rust compilation or Rust test has run for this fixture. It owns a nested
workspace; both verified graphs exclude the Kasumi root dependency overrides.

The generated consumer lockfile has SHA-256
`a8e28648a99e39be408e011d28559ec2edbc8cc5c333f207b59315c438471699`.
The retained preparation record is
`/tmp/kasumi-stock-sdk-dependency-preparation-9aad42e/evidence.json`, SHA-256
`e883b57d45f78d97368974c8ff8c017cdd6c49b8b6eb42148db932ea977ffb22`.
Its raw output and exact commands remain beside it. This records an executed
dependency preparation, not behavioral validation of the SDK.

The source subsequently includes the canonical-map admission correction
`f52fc14`, canonical payload writer `dea23f9`, and actual writer admission
regression `032686f` (cherry-picked into this fixture workspace). These source
changes leave all consumer dependency manifests and its generated lock unchanged.
Their Rust tests remain unexecuted here. Revalidate metadata on the final source
before compiling it.

The graph permits only the consumer plus `kasumi-client`, `kasumi-types`,
`kasumi-clock`, `kasumi-serving` and `kasumi-transport` as local packages. It
requires one registry serde_json 1.0.151 with its published checksum, Serde/core
1.0.229, and the expected effective features. Engine, store, server and Raft
packages are forbidden by that exact local-package set. No listener, provider,
database or TLS connection is created. This diagnostic deliberately omits root
dependency overrides; it is not approval of all stock dependencies for release.

Public APIs available without a connection are `decode_mutation_json`,
`decode_staged_chunk_json`, `decode_query_json`, `decode_schema_change_json`,
resource usage/owner guards, `MutationBatch::digest`, `staged_digest`, and
`StagedManifest::from_chunks`. The fixture covers those APIs using nested literal
marker objects, escaped keys, invalid inner JSON remaining a string, exact large
integers/decimals, owned DTO clones, malformed outer input and explicit byte,
node, numeric-token, owner and expired-deadline rejection. Every error owner must
drain within a finite bound. A stock-decoder counterexample is an intentional
witness that the global fork is absent; SDK parsing must preserve the same keys.

The public SDK does not expose its response decoders as byte helpers. Those
ordinary/coherent network response paths therefore remain outside this fixture;
this test does not bypass privacy or create a fixture server. Digests are compared
within each effective feature set. Cross-feature object-order canonicality is a
separate investigation; this fixture must not be described as proving it. A
caller-owned DTO clone is outside SDK resource accounting.

Request encoding is private SDK code. The byte-input helpers do not traverse
the canonical serializer, so they cannot prove its sorting admission. Select
the real client unit test
`snapshot_decode::request::tests::canonical_wrapper_admission_bounds_actual_sorting_workspace`
from this external workspace under `ordered` to cover that path. It passes the
actual canonical wrapper over reverse-inserted nested maps through the private
bounded encoder, checks small-budget rejection and larger-budget success, and
checks caller-map immutability and owner drain. The two existing probe tests
separately check that admission occurs before the sorter body. This adds no public
SDK API or alternate format.

The consumer's `default` feature set is empty, but SDK dependencies already require
`arbitrary_precision` and `raw_value`. Thus `default` and `numbers-and-raw` are
expected to have the same effective serde_json features. `ordered` adds
`preserve_order`. The saved graph, not the feature label, is authoritative.

## Commands queued for explicit authorization

Use a dedicated target and output directory. The actual consumer lockfile is now
retained. Revalidate the locked metadata before testing a changed source
checkpoint; do not regenerate the graph implicitly. The exact direct semantic
dependency versions and resolved transitive graph are pinned.

```sh
export CARGO_TARGET_DIR=/tmp/kasumi-stock-sdk-consumer-target
export CARGO_BUILD_JOBS=1
export RUST_TEST_THREADS=1
consumer=external-tests/stock-json-sdk/Cargo.toml
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --format-version 1 > /tmp/stock-sdk-default-metadata.json
python3.12 external-tests/stock-json-sdk/check_graph.py /tmp/stock-sdk-default-metadata.json --mode default
cargo +1.97.1 tree --manifest-path "$consumer" --locked --edges normal,build --format '{p} {f}'
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --features kasumi-stock-json-sdk-consumer/ordered --format-version 1 > /tmp/stock-sdk-ordered-metadata.json
python3.12 external-tests/stock-json-sdk/check_graph.py /tmp/stock-sdk-ordered-metadata.json --mode ordered
```

The explicit workspace-package feature name above must be used for client package
selection too. The guard verifies the consumer's selected features as well as the
resolved serde_json features, preventing an unrelated decoder feature from being
mistaken for the requested consumer selection. Metadata cannot prove compiled
feature unification by itself; retain each selected test's `compiler-artifact`
feature records as well. The commands below remain pending explicit execution.

After the graph and generated lockfile are accepted, use an owned process group
and a finite per-gate timeout for each command. Stop on the first failure; preserve
logs, source/lock hashes, Cargo-reported executable hashes and process drain.

```sh
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 --test consumer --message-format=json-render-diagnostics -- --test-threads=1
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --features numbers-and-raw --format-version 1 > /tmp/stock-sdk-number-raw-metadata.json
python3.12 external-tests/stock-json-sdk/check_graph.py /tmp/stock-sdk-number-raw-metadata.json --mode numbers-and-raw
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 --features numbers-and-raw --test consumer --message-format=json-render-diagnostics -- --test-threads=1
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --features kasumi-stock-json-sdk-consumer/ordered --format-version 1 > /tmp/stock-sdk-ordered-metadata.json
python3.12 external-tests/stock-json-sdk/check_graph.py /tmp/stock-sdk-ordered-metadata.json --mode ordered
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 --features kasumi-stock-json-sdk-consumer/ordered --test consumer --message-format=json-render-diagnostics -- --test-threads=1
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 -p kasumi-client --lib --features kasumi-stock-json-sdk-consumer/ordered --message-format=json-render-diagnostics snapshot_decode::request::tests::canonical_wrapper_admission_bounds_actual_sorting_workspace -- --exact --test-threads=1
```

These commands are plans, not completed evidence. No fixture-free Kasumi daemon,
production release, capacity, performance or live native/MCP claim follows from
this consumer test.
