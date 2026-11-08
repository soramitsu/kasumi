# Polkaswap indexer KV replay

Run the same ordered raw bytes through Kasumi's native disk-backed `Core` and the Polkaswap indexer's installed `@harperfast/rocksdb-js` package. Use Node 26 with development headers, Cargo with the repository's toolchain, and a C compiler on macOS or Linux.

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  node benchmarks/indexer-kv/run.mjs /path/to/trace.jsonl \
  /path/to/polkaswap-indexer/node_modules/@harperfast/rocksdb-js 3 > results.json
```

Every JSON line is one nonempty atomic batch. Use `["put", keyHex, valueHex]` or `["del", keyHex]` inside its `ops` array. Keys are nonempty, all hex uses lower case, and a put may have an empty value. The trace must leave at least one live row. The runner creates and removes its own private temporary databases. `NODE_INCLUDE` can select alternate matching Node headers. `INDEXER_KV_HARNESS` can select a prebuilt Kasumi release test binary with the same benchmark protocol.

Each round alternates the engine order. The writer, reader, maintenance worker and final reader use separate OS processes. Each reader checks every surviving key and value in order against an independent replay and rejects extra rows. Read timings cover 1,024 point lookups and 64 bounded pages of up to eight rows in each direction. For a Polkaswap network snapshot trace they also cover 16 reverse lookups of the most recent 24 BLOCK timestamp index entries followed by their primary document reads. The runners compare the ordered document digest before and after maintenance.

Kasumi uses the real NodeDisk segment group, persistent files, authenticated data, transaction admission and synchronization path. TestDiskMemory supplies bounded memory admission and the disk installation uses test quotas. Each batch calls Core::commit once. RocksDB uses its installed transactional JS wrapper in binary key/value mode, with the WAL enabled. The binding defaults to asynchronous WAL durability despite the synchronous JS commit. The writer persists database initialization, then syncs the same WAL descriptor after every batch using F_FULLFSYNC on Apple and fsync on Linux. It checks each appended WAL length and rejects WAL rotation. This comparison is limited to traces that fit in one active RocksDB WAL. Both engines use an 8 MiB block/page cache. They run without competing writers.

The per-phase footprint sums logical lengths and allocated file blocks. It includes database metadata, log files and any retained arenas at each measurement. After ingestion and the first verified reopen, the runner requests one native Kasumi compaction cycle, bounded to 60 seconds or 100,000 steps, and explicitly flushes and compacts RocksDB. The maintenance result records completion, deferral or exhaustion and a fresh process verifies the remaining data. The OS process write counters cover the entire worker including open and close. They measure kernel-attributed I/O and do not measure physical-device wear. Timings include each engine's API handling and row validation; they exclude input decoding and process startup, except for the separate whole-worker CPU counters. OS page caches remain warm. Raw replay excludes GraphQL, chain fetching, cryptographic signing and production traffic.
