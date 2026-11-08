# Upstream RocksDB sealed codec controls

`frozen-codec.py` resolves the trace into its final bytewise-sorted key/value pairs. The C++ worker bulk-loads a fresh RocksDB directory, flushes its memtable, and compacts the whole key range. It builds one uncompressed control with the default table block target, one LZ4 control with that target, and one LZ4 control with a 32 KiB target. The worker checks the actual compression property of every SST on creation and after reopening. Format 7 records the sorted compression types present between semicolons. `04` denotes LZ4. Uncompressed blocks remain legal within an LZ4 table.

Compile against a matching upstream RocksDB library and headers with LZ4 support. For a locally installed copy with pkg-config metadata:

```sh
# Linux also needs -lcrypto for the live page digest. macOS uses CommonCrypto.
c++ -std=c++20 -O2 benchmarks/indexer-kv/frozen-codec.cc \
  $(pkg-config --cflags --libs rocksdb) -o /tmp/kasumi-frozen-codec
python3 benchmarks/indexer-kv/frozen-codec.py /tmp/kasumi-frozen-codec \
  benchmarks/indexer-kv/fixtures/network-blocks-28280001-28284096.jsonl.gz 3
```

The recorded macOS run used the static archive and headers from Homebrew's upstream RocksDB 11.1.2 ARM64 Sequoia bottle, extracted into a private temporary directory. The OCI manifest digest was `sha256:f2305493fc60198deb00b3eee9815e6f49e7fe6bedf63d80d9c88c3674793f20` and the verified bottle layer digest was `sha256:e228befa618e9b544cabf1cc97a25ffc937fb9ac86e684a4f5a6c20316f5043c`. The native worker linked the existing snappy, LZ4, Zstandard, zlib and bzip2 libraries. The recorded C++ flags were `-std=c++20 -O2`.

Each read starts a new read-only process with an 8 MiB cache, scans the complete database in descending order, and compares every byte against the sorted reference. The worker times 1,024 verified point reads and 64 warm latest-24 pages, collecting secondary keys before fetching the primary documents. It runs one warmup page. Per-query byte equality checks occur after each timer. The output includes both deterministic reference digests and nearest-rank p50/p95 observations. Fresh read workers rotate through the three controls. Sealed storage counts both all persistent files and the SSTs alone.

These timings use the native C++ API. For installed JS binding timings, use `frozen-rocks.mjs`.


For the live control, set `INDEXER_KV_NATIVE_ROCKS` to this executable when
using `run.mjs` with `inline compact`. It creates an upstream bytewise database
with LZ4 and a 32 KiB table block target, and calls `DB::Write` with
`WriteOptions.sync = true` once per original batch. It retains the WAL and
uses RocksDB's normal flush and compaction policies during ingest. Later
processes verify the resulting rows, flush and compact, and verify the rows
again. The macOS bottle used for measurement contains RocksDB's
`HAVE_FULLFSYNC` implementation for the WAL device barrier. [Upstream POSIX file implementation](https://github.com/facebook/rocksdb/blob/v11.1.2/env/io_posix.cc#L1555-L1567)

The November 9 native Linux control used the official Homebrew RocksDB 11.1.2
ARM64 Linux bottle (verified layer SHA-256
`84c243b567cdc3890b3d5ce2a4717cab24107062cc31dcdac45d2966fe60054e`).
The same worker compiled against its matching headers with Debian g++ 14;
the dynamic library used LZ4 and gflags 2.3.1. Its raw replay and the hashes
of both native workers are in the [four-way Linux results](results/live-default-linux-four-way.json.gz).
