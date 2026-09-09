# External stock JSON SDK validation

Frozen source `3f88b449299a33b23c48543566365cd97ebdb1ab`, tree
`fe2b6babfd7b1ab264c1ef17d96ed9b85298db22`, passed the actual external SDK
cohort on Rust 1.97.1, macOS ARM64. The private canonical-admission regression
passed once with `preserve_order`; all six public consumer tests passed under
both default and ordered features. These are 13 test executions across three
gates, with zero failures or ignored tests. The private gate filtered out 30
unselected client tests.

Each command had one Cargo job, one test thread, a 300-second timeout and owned
process-group cleanup. All groups drained. Tracked source and the consumer lock
stayed unchanged. Actual Cargo artifact records confirm one registry
serde_json 1.0.151, the intended features and only the permitted local SDK graph.
The consumer workspace does not inherit Kasumi's root dependency patches.

| Retained stage | Actual result |
| --- | --- |
| [Dependency preparation](01-dependency-preparation/evidence.json) | Lock generation, default/ordered metadata and graph guards: 5/5 passed on `9aad42e`; no compilation. |
| [Initial selection failure](02-selection-failure/evidence.json) | Metadata and guard passed; selecting only the client dependency with the consumer's feature failed before compilation. Remaining tests did not run. |
| [Corrected selection diagnostic](03-compile-only-diagnostic/evidence.json) | Selecting both packages compiled the exact client test target with stock ordered features. `--no-run` executed no tests. |
| [Actual functional run](04-functional-pass/evidence.json) | Both graphs/guards and all three test gates passed on `3f88b44`; exact counts and executable hashes are in [the summary](04-functional-pass/summary.json). |

The initial Cargo error was `cannot specify features for packages outside of
workspace`. The compiled-feature guard also reported no decoder artifacts
because Cargo had exited before compilation. This was a command-selection
failure, not an executed SDK test failure. It remains preserved. The correction
selects both `kasumi-stock-json-sdk-consumer` and `kasumi-client` while enabling
the consumer's namespaced feature. Cargo's [feature documentation](https://doc.rust-lang.org/cargo/reference/features.html#resolver-version-2-command-line-flags)
describes selected workspace feature syntax; the actual compile-only diagnostic
establishes that this mixed package selection works with the pinned Cargo.

The public tests exercise SDK-owned literal decoding of mutation, staged-chunk,
query and schema inputs, including nested and escaped marker-shaped keys,
arbitrary-precision numbers, invalid inner JSON retained as strings, owned DTO
round trips, malformed input, byte/node/number/deadline bounds and owner drain.
The private test exercises the actual canonical wrapper over reverse-inserted
nested maps through bounded request encoding, including small-budget rejection
and larger-budget success. It introduces no public API or alternate format.

Default consumer features already include serde_json `arbitrary_precision` and
`raw_value` through SDK dependencies. Ordered adds `preserve_order` and its
`indexmap` dependency. These results do not test those mandatory features being
disabled. The permitted local packages are the consumer, client, types, clock,
serving and transport. Engine, store, server, Raft, fixture capabilities and
listeners are absent. This evidence does not establish actual native/MCP
behavior, full combined-source production acceptance, capacity or endurance.

## Reproduction and provenance

The actual consumer lock SHA-256 is
`a8e28648a99e39be408e011d28559ec2edbc8cc5c333f207b59315c438471699`.
The final cohort evidence SHA-256 is
`6c840e923c533d9261192e0f7260fc49373f183ca0866bb81ba5e48f94380ad5`.
The earlier preparation, failure and diagnostic evidence SHA-256 values are
respectively `e883b57d45f78d97368974c8ff8c017cdd6c49b8b6eb42148db932ea977ffb22`,
`2e951892edcbb52aec675fa92b2d4172ae9cd4d17fee7d4df116bd5adcb11df2`, and
`43d7b072d144ef593d07dd073ee45993fb558548223ecb123d99111b29a219ba`.

[preservation-manifest.json](preservation-manifest.json) binds every copied raw
record, runner and captured fixture file to its original path, size and SHA-256.
The stage JSON retains original absolute paths; the table above maps stages to
their archived directories. Original files are copied without rewriting their
contents. Source-before/after records include tracked-file hashes; runner records
include tool, lock, command, timeout, process, metadata and compiled-artifact
provenance. Captured fixture source is an exact historical input, so its README's
pending wording and old single-package command describe the pre-execution state.
Use the corrected commands below for the successful selection.

Check out exact source `3f88b44` and use its nested consumer workspace and pinned
toolchain. Resolve no new lock implicitly. The captured scripts under `runners/`
show the exact executed commands, output handling and assertions; their original
absolute output directories were exclusive and should not be overwritten.
The final run reused only the prior verified diagnostic target. The operative
test selection is:

```sh
consumer=external-tests/stock-json-sdk/Cargo.toml
export CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --features kasumi-stock-json-sdk-consumer/ordered --format-version 1
# Save metadata and run check_graph.py --mode ordered before the selected test.
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 -p kasumi-stock-json-sdk-consumer -p kasumi-client --lib --features kasumi-stock-json-sdk-consumer/ordered snapshot_decode::request::tests::canonical_wrapper_admission_bounds_actual_sorting_workspace -- --exact --test-threads=1
cargo +1.97.1 metadata --manifest-path "$consumer" --locked --format-version 1
# Save metadata and run check_graph.py --mode default before the default suite.
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 --test consumer -- --test-threads=1
cargo +1.97.1 test --manifest-path "$consumer" --locked -j1 --features kasumi-stock-json-sdk-consumer/ordered --test consumer -- --test-threads=1
```

Retain machine-readable Cargo artifacts, bounded process handling and source
checks as in the runners. The short commands above omit those evidence options.
Actual executables and secret material are not copied into this archive. Their
hashes remain verifiable against separately retained executable copies:

| Executable scope | SHA-256 |
| --- | --- |
| Ordered client unit target | `18608ad21bd91615d0f7bbd76b823e0e78843c1449ee930ec6189f2b0ee1c84d` |
| Default consumer target | `c5ba017741a977ed205c84d0ce4a55d256ab895efd069309430421602f5be3f4` |
| Ordered consumer target | `11a0a34330aef9398e8b2fb159b19bc7e9dd79af0c2634fea401004b427e55ab` |
