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

The `compact` selection uses Kasumi's single-writer live database with a
durable WAL, a bounded change buffer and tiered compressed runs. Supply it as
the fifth argument with `inline`. `INDEXER_KV_LIVE_HARNESS` accepts a
prebuilt `polkaswap-live` release example. `INDEXER_KV_ADDON` adds the
[Kasumi Node binding](../../crates/kasumi-live-node/README.md);
`INDEXER_KV_NATIVE_ROCKS` adds the [upstream C++ LZ4 control](frozen-codec.md).
With all four engines, use four rounds so every engine occupies every
execution position. The JSON records the native binary hashes, trace hash,
ingest time, OS write bytes, and independently verified state and page checks.
Process peak RSS includes the whole worker and the predecoded fixture.

For a closer timing comparison of the two Node bindings, `paired-node.mjs`
holds both handles open and alternates which writes first in each 64-block
window. Each block is acknowledged separately with the same durability as
in the isolated worker. The paired run records a duration for every window
and checks the entire database in both directions after reopen and compaction.
The optional last argument (default 1) sets how many **already available**
blocks share a durable acknowledgement. Use 1 for single arrivals or 8 for
catch-up. Every original block is a separate WAL frame or RocksDB transaction;
neither writer acknowledges any input in the group until its whole group is
synchronized. Do not compare an eight-block result with a single-block result.
The script does not wait to fill a group or measure incoming chain latency.

```sh
node benchmarks/indexer-kv/paired-node.mjs /tmp/kasumi-block-stats.jsonl \
  /path/to/polkaswap-indexer/node_modules/@harperfast/rocksdb-js \
  "$PWD/target/release/kasumi_live_node.node" auto 2 > paired.json
```

Use `node benchmarks/indexer-kv/summarize-paired.mjs FILE.json[.gz] ...` to check
every reported round, both recovered state digests and the aggregate throughput.
When close counters are present it also charges explicit compaction and both
closes; allocation is reported before close, after close and after compaction.

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

To compare a pre-change fixed-format build in the same run, set
`INDEXER_KV_BASELINE_HARNESS` to its release test binary. The runner copies
and hashes both native binaries. Three rounds place the baseline, the selected
Kasumi format and RocksDB in each execution position once, using a fresh
database per engine per round.

With two engines the run alternates their order. The writer, reader, maintenance worker and final reader use separate OS processes. Each reader checks every surviving key and value in order against an independent replay and rejects extra rows. Read timings cover 1,024 point lookups and 64 bounded pages of up to eight rows in each direction. For a Polkaswap network snapshot trace they also cover 64 timed reverse pages of the most recent 24 BLOCK timestamp index entries followed by their primary document reads. Each page includes row checks, and the first also computes its SHA-256 digest. The output includes nearest-rank median and p95 page latency. Kasumi additionally times its seek-per-row implementation against its descending cursor. The runners compare the ordered document digest before and after maintenance.

Kasumi uses the real NodeDisk segment group, persistent files, authenticated data, transaction admission and synchronization path. TestDiskMemory supplies bounded memory admission and the disk installation uses test quotas. Each batch calls Core::commit once. RocksDB uses its installed transactional JS wrapper in binary key/value mode, with the WAL enabled. The binding defaults to asynchronous WAL durability despite the synchronous JS commit. The writer persists database initialization, then syncs the same WAL descriptor after every batch using F_FULLFSYNC on Apple and fsync on Linux. It checks each appended WAL length and rejects WAL rotation. This comparison is limited to traces that fit in one active RocksDB WAL. The historical fixed-page and RocksDB controls use an 8 MiB block/page cache.
The compact engine uses its own bounded per-run decoded caches and its
persisted live-write budget. Runs are serial; isolated trials open one
engine, while the paired test keeps both open and writes to one at a time.

The per-phase footprint sums logical lengths and allocated file blocks. It includes database metadata, log files and any retained arenas. Ingest reports allocation while the writer is open as well as after clean close. The RocksDB binding flushes memtables on close. After ingestion and the first verified reopen, the runner requests one native Kasumi compaction cycle, bounded to 60 seconds or 100,000 steps, and explicitly flushes and compacts RocksDB. The maintenance result records completion, deferral or exhaustion and a fresh process verifies the remaining data. The OS process write counters cover the entire worker including open and close. They measure kernel-attributed I/O and do not measure physical-device wear. Timings include each engine's API handling and row validation; they exclude input decoding and process startup, except for the separate whole-worker CPU counters. OS page caches remain warm. Raw replay excludes GraphQL, chain fetching, cryptographic signing and production traffic.

## Offline Stats GraphQL check

Build the Kasumi Node addon and copy the platform library to a `.node` file as described in the [binding guide](../../crates/kasumi-live-node/README.md). Supply a built Polkaswap indexer release with its native dependencies and compiled `dist/tests/pinned-network-volume-fixture.js`. Node 26 ran the retained check.

```sh
node benchmarks/indexer-kv/application-stats.mjs \
  /path/to/built/polkaswap-indexer \
  /absolute/path/to/kasumi_live_node.node
```

The script creates two disposable local databases, seeds both with the same 4,096 finalized BLOCK snapshots and index entries, compacts them, and reopens them. It executes the published wallet BLOCK fees and volume queries through the indexer’s GraphQL schema, repository query planner and document codec. For Kasumi, a test-only read adapter supplies the ordered binary secondary-index scans and MessagePack primary reads used by the real repository. It holds no copy of the expected results. Each query must issue native reverse index reads and native document reads, match the independently decoded fixture amounts in descending order, and return the same GraphQL page and cursor as RocksDB.

The macOS run returned seven positive fee rows and one positive volume row. Kasumi visited 8,192 descending index rows and hydrated 8,192 primary documents across the two queries. The compiled resolver, repository and document codec in the retained indexer build matched the SHA-256 digests of those files in the fixture’s source release `4c604157bd68d1f5175d88f4ebaaf1de4a4b3ebe`. The output records the exact addon, module, query and GraphQL response digests. [Recorded application result](results/application-stats-macos.json)

This check covers the BLOCK Stats read paths over an already materialized local slice. Whole-worker block processing, production repository selection, entitlement recovery and a live database migration require separate validation.

### Repository ingestion timing

The opt-in upsert mode decodes each original BLOCK document and calls the release’s actual `RocksRepository.upsertMany([document])` once per block on each backend. This exercises document normalization, validation, replacement checks, primary encoding, secondary indexes, index counters and collection counts. The code alternates the first writer in 64-block windows and reverses the starting order on each fresh round.

```sh
node benchmarks/indexer-kv/application-stats.mjs \
  /path/to/built/polkaswap-indexer /absolute/path/to/kasumi_live_node.node \
  --upsert 4096 4 > application-upsert.json
```

A short smoke can use `--upsert 16 1`. Supply a C compiler and Node headers (`CC` and `NODE_INCLUDE` are optional), or set `INDEXER_KV_SYNC` to a compiled copy of the supplied `sync.c` Node addon. Each block receives its own durable acknowledgement on both stores. The Rocks binding performs its real transaction, followed by a full-device WAL flush inside the repository transaction promise. Kasumi stages the repository callback’s ordered writes and serves its point reads from the pending transaction or native store. It completes one native durable commit before that callback’s caller resumes. The opt-in adapter supports the transaction operations reached by this fixture and refuses transactional scans after a staged write.

Every round reports ingest nanoseconds, writer-close nanoseconds, and maintenance reopen/compact/close times. `paid_ns` sums those components for each backend. Directory file allocation is measured before closing writers, after closing them, and after explicit maintenance closes. Separate final reads verify the complete physical key/value state, including bootstrap metadata, and compare all fixture values independently after MessagePack decoding. Both published Stats GraphQL queries then run against freshly reopened repositories. Verification and setup are outside the reported write and maintenance times.

## Estimating the Zstandard block codec on existing data

`codec-probe.py` reads the raw stream of a stopped live database and reports
the size of its rows as sorted-run blocks under Zstandard, to compare with the
database's allocated bytes before creating a Zstandard copy
(`kasumi-live-transfer import NEW_DIRECTORY zstd`). It needs Python 3.14 or
newer and writes nothing:

```sh
kasumi-live-transfer export-read-only DIRECTORY \
  | python3 benchmarks/indexer-kv/codec-probe.py --levels 7
```

It compresses canonical rows only and counts no directories or indexes. The
blocks of a real import, which also prefix-codes keys, are usually a little
smaller than its figure.

