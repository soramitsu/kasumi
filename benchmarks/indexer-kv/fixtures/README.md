# Polkaswap Stats BLOCK trace

The gzip file contains 4,096 consecutive canonical network BLOCK snapshots, heights **28,280,001–28,284,096**. Its timestamps are 1794078558–1794106158. The source was the Pi indexer's native RocksDB, opened read-only, using indexer release `4c604157bd68d1f5175d88f4ebaaf1de4a4b3ebe`. The exporter reads only aggregate network snapshots and their three secondary index entries. It does not export accounts, addresses, or application secrets.

Each JSONL line contains one batch of seven puts: the original primary document bytes, the three original secondary entries (timestamp, type + timestamp, type + height), and three counters computed as if this slice were inserted into an empty store. Keys and values are native, hex-encoded bytes. These batches model inserting BLOCK snapshots; they are **not** captures of the whole worker's per-block transaction. There are 28,672 puts, 16,387 final keys, and 1,993,818 live key/value bytes before storage overhead or compression.

Verify the included corpus without a database or network:

```sh
node benchmarks/indexer-kv/fixtures/verify.mjs
gzip -dc benchmarks/indexer-kv/fixtures/network-blocks-28280001-28284096.jsonl.gz > /tmp/kasumi-block-stats.jsonl
```

The uncompressed SHA-256 is `7dc977b532aafb42ae07c4c9aa006cc56bb90ae04110f66daef4ea7e342b43dd`. The verifier also checks the reconstructed key/value state and a descending timestamp page with 32 hydrated primary documents. Pass an absolute path to a built indexer release with its native dependencies installed to additionally test the production Brotli option on every document. All 4,096 compact data objects serialize to 323–351 JSON bytes, below the indexer's 1,024-byte threshold. Both document settings produce the same tuples on this slice; this does not compare their behavior on larger documents in other collections.

To export another slice, use a **read-only** database with the matching release and its installed dependencies:

```sh
node benchmarks/indexer-kv/fixtures/export-stats-trace.mjs INDEXER_RELEASE ROCKSDB_DIRECTORY FIRST_HEIGHT COUNT > trace.jsonl
```
