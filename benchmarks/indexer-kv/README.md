# Polkaswap indexer KV replay

The [included fixture](fixtures/README.md) is a verified slice of finalized
network Stats history. To include the ordinary Kasumi database policy's
maintenance work during writes, pass a fourth argument `inline`; the default
is `after-ingest`. The inline run calls one bounded maintenance step with
the default units and publication allowance before each block, includes its
time and disk writes, and reports reclaimed bytes and deferrals. Both modes
also run the explicit end-of-ingest maintenance and reopen checks. The fifth
argument selects Kasumi's new-database directory format. Use `fixed` (the
default) or `lz4`. The latter encodes directory pages only. Both read phases
reopen from the persisted format. The RocksDB configuration is identical in
both comparisons.

The process observer samples regular-file allocation in each engine's private
directory about every 50 milliseconds and at exit. Its peak is a sampled
lower bound on the true transient high-water mark; after-close footprint is an
exact sum of the files then present.

The [measured results](RESULTS.md) separate this live benchmark from the
[frozen-run library](../../crates/kasumi-frozen-run/README.md). To compare
already-finalized history, first decompress the [included fixture](fixtures/README.md),
then run:

```sh
node benchmarks/indexer-kv/frozen.mjs /tmp/kasumi-block-stats.jsonl \
  /path/to/polkaswap-indexer/node_modules/@harperfast/rocksdb-js 5 > sealed-results.json
```

The sealed benchmark builds a new run and a freshly compacted RocksDB from
the **same final rows**. It alternates fresh reader processes, opens RocksDB
read-only, authenticates Kasumi against the root returned by the builder,
and checks every key/value in descending order. It times 1,024 distributed
point reads, 64 repeated latest-24 queries after one warm-up, and 64 pages
spread across the full time interval. Each query uses a descending timestamp
index scan followed by exact primary lookups. It checks returned documents
and cross-engine digests outside the timed calls. The JSON includes RocksDB's
persisted SST compression setting. These are warm native-Rust versus Node
binding timings. They include those API costs and do not measure GraphQL.

To retain the sample file instead of using temporary benchmark databases,
run the example directly; `write` refuses an existing destination. Keep the
printed root with the source cutoff and obtain it from the trusted builder
when opening the file. The file is read-only after sealing.

```sh
cargo run --locked --release -p kasumi-frozen-run --example polkaswap-frozen -- \
  write /tmp/kasumi-block-stats.jsonl /tmp/polkaswap-history.ksfr
cargo run --locked --release -p kasumi-frozen-run --example polkaswap-frozen -- \
  read /tmp/kasumi-block-stats.jsonl /tmp/polkaswap-history.ksfr EXPECTED_ROOT_HEX
cargo run --locked --release -p kasumi-frozen-run --example polkaswap-frozen -- \
  latest /tmp/polkaswap-history.ksfr EXPECTED_ROOT_HEX
```

`latest` needs only the sealed file and the trusted digest. It returns up to
24 newest indexed BLOCK document IDs and their original MessagePack values
in hex; no RocksDB instance or reference trace is required.

Run the same ordered raw bytes through Kasumi's native disk-backed `Core` and the Polkaswap indexer's installed `@harperfast/rocksdb-js` package. Use Node 26 with development headers, Cargo with the repository's toolchain, and a C compiler on macOS or Linux.

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  node benchmarks/indexer-kv/run.mjs /path/to/trace.jsonl \
  /path/to/polkaswap-indexer/node_modules/@harperfast/rocksdb-js 3 inline lz4 > results.json
```

Every JSON line is one nonempty atomic batch. Use `["put", keyHex, valueHex]` or `["del", keyHex]` inside its `ops` array. Keys are nonempty, all hex uses lower case, and a put may have an empty value. The trace must leave at least one live row. The runner creates and removes its own private temporary databases. `NODE_INCLUDE` can select alternate matching Node headers. `INDEXER_KV_HARNESS` can select a prebuilt Kasumi release test binary with the same benchmark protocol.

Each round alternates the engine order. The writer, reader, maintenance worker and final reader use separate OS processes. Each reader checks every surviving key and value in order against an independent replay and rejects extra rows. Read timings cover 1,024 point lookups and 64 bounded pages of up to eight rows in each direction. For a Polkaswap network snapshot trace they also cover 64 timed reverse pages of the most recent 24 BLOCK timestamp index entries followed by their primary document reads. Each page includes row checks, and the first also computes its SHA-256 digest. The output includes nearest-rank median and p95 page latency. Kasumi additionally times its seek-per-row implementation against its descending cursor. The runners compare the ordered document digest before and after maintenance.

Kasumi uses the real NodeDisk segment group, persistent files, authenticated data, transaction admission and synchronization path. TestDiskMemory supplies bounded memory admission and the disk installation uses test quotas. Each batch calls Core::commit once. RocksDB uses its installed transactional JS wrapper in binary key/value mode, with the WAL enabled. The binding defaults to asynchronous WAL durability despite the synchronous JS commit. The writer persists database initialization, then syncs the same WAL descriptor after every batch using F_FULLFSYNC on Apple and fsync on Linux. It checks each appended WAL length and rejects WAL rotation. This comparison is limited to traces that fit in one active RocksDB WAL. Both engines use an 8 MiB block/page cache. They run without competing writers.

The per-phase footprint sums logical lengths and allocated file blocks. It includes database metadata, log files and any retained arenas. Ingest reports allocation while the writer is open as well as after clean close. The RocksDB binding flushes memtables on close. After ingestion and the first verified reopen, the runner requests one native Kasumi compaction cycle, bounded to 60 seconds or 100,000 steps, and explicitly flushes and compacts RocksDB. The maintenance result records completion, deferral or exhaustion and a fresh process verifies the remaining data. The OS process write counters cover the entire worker including open and close. They measure kernel-attributed I/O and do not measure physical-device wear. Timings include each engine's API handling and row validation; they exclude input decoding and process startup, except for the separate whole-worker CPU counters. OS page caches remain warm. Raw replay excludes GraphQL, chain fetching, cryptographic signing and production traffic.
