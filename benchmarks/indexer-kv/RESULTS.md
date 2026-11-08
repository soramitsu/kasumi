# Polkaswap Stats storage comparison — 8 November 2026

**Sealed historical data:** Kasumi used 47.9% less allocated storage than
upstream RocksDB with the same LZ4 codec and 32 KiB block target, and served
the latest page in 12.3 µs at p95 versus 48.4 µs. **Live indexing:** the
packed mutable directories reduced compacted Kasumi storage by 49% and raised
median durable throughput by 20%. RocksDB still led on disk and ingest.

These are local Apple M4 Max / Darwin arm64 measurements on the [same finalized BLOCK snapshot fixture](fixtures/README.md). They cover a native Kasumi library and the indexer's actual Node RocksDB binding 2.4.0 / RocksDB 11.1.2. They do not measure GraphQL, RPC, other collections, network traffic or production Linux storage. The two questions are different: can we replace the live writer, and can we store already-finalized records more efficiently?

## Live writer

### Packed directories with inline maintenance

The previous Kasumi build on `master` (`86caa65b`), the new build
(`902a3e7f`) with `DirectoryPageFormat::Lz4`, and RocksDB replayed the
same 4,096 durable block batches. Each engine ran first, second and third
once, using fresh databases and the same 8 MiB cache limit. The table shows
medians across three runs. Each reader compared all 16,387 surviving rows
with the original trace, both before and after compaction. All nine trials
returned the same digest for the latest 24 documents. Both Kasumi builds
completed all requested compaction cycles. [Raw measurements](results/mutable-packed-inline.json)

| Measure | Previous Kasumi | Packed Kasumi | RocksDB |
|---|---:|---:|---:|
| Durable blocks/s | 58.8 | 70.5 | 130.0 |
| Ingest time (s) | 69.61 | 58.13 | 31.51 |
| Writer CPU time (s) | 12.96 | 12.35 | 1.46 |
| OS-attributed bytes written per block | 193,473 | 107,462 | 16,907 |
| Sampled peak writer allocation (MB) | 312.29 | 84.23 | 3.24 |
| Allocated after writer close (MB) | 147.36 | 84.23 | 1.68 |
| Allocated after explicit compaction (MB) | 20.84 | 10.70 | 1.77 |
| Latest 24 documents, first reopen p95 (µs) | 349.5 | 326.6 | 107.5 |

MB is decimal. Ingest ranged from 57.45–73.11 s on the previous build,
52.33–67.49 s on the packed build and 28.52–43.71 s on RocksDB.
Packed Kasumi wrote 44% fewer OS-attributed bytes per block than the previous
build and used 49% less disk after compaction. Its compacted database was
still 6.0 times the size of RocksDB's, and RocksDB ingested 1.84 times as many
durable blocks per second. These figures compare the complete builds, including
the new file verification and directory lookup paths. Each retains one durability
boundary per block. [Replay method](README.md)

### Earlier fixed-page comparison with maintenance after ingest

On three alternating, fresh-database runs, the optimized mutable Kasumi engine preserved every byte and substantially improved its footprint, but remained slower and wrote more than RocksDB. Each of the 4,096 batches has its own durability boundary. Both engines have an 8 MiB cache and were opened again in separate processes, before and after maintenance. Full result: [raw measurements](results/mutable-final.json). These timings are medians of three runs, not production latency guarantees.

| Measure | Kasumi mutable | RocksDB |
|---|---:|---:|
| Durable blocks/s | 79.0 | 132.4 |
| Ingest wall time | 51.87 s | 30.94 s |
| Writer user + system CPU | 12.49 s | 1.67 s |
| OS-attributed bytes written per block | 205,106 | 16,871 |
| Allocated while writer open | 486.25 MB | 3.24 MB |
| Allocated after writer close | 486.25 MB | 1.68 MB |
| Sampled peak during maintenance | 496.07 MB | 1.77 MB |
| Allocated after explicit compaction | 33.95 MB | 1.77 MB |
| p95, newest 24 indexed documents, first reopen | 0.391 ms | 0.108 ms |

MB is decimal. The p95 is the median of the three per-run p95s of 64 pages; the ranges were 0.384–0.858 ms and 0.099–0.111 ms. Both engines agreed on the complete 16,387 rows and the 24-document page before and after compaction. All requested Kasumi compaction cycles completed. The binding doesn't expose synchronous WAL commit; see the [harness](README.md) for its single-WAL durability protocol, process boundaries, sampling, and cache treatment.

The [pre-optimization run](results/mutable-before-writes.json) used the same release-profile native writer with bounded seeks available, before the two write optimizations. It used 928,944,128 bytes after close, versus a final median of 486,248,448 bytes (47.7% less). This comparison is one baseline run against three final runs. The patches coalesce changes to the same leaf and copy a common parent only once when several child leaves change. A unit regression verifies that the new descending cursor reads six directory pages to return the same 700 rows that took 1,400 reads with independent seeks. Cached point lookups now remember the midpoint of a variable-length directory page without additional cache storage.

The original fixed-page format stores the full key and a 32-byte value location per live entry. On this data even **just** the 856,166 live key bytes, 524,384 bytes of locations, and 1,137,652 live value bytes total 2,518,202 bytes. This excludes table names, segment records, branch pages, and reclaimable pages. Vacuuming alone cannot bring the fixed layout down to RocksDB's measured 1.77 MB on this workload. Packed pages compress those key and location bytes on disk.

**Inline maintenance sensitivity.** In a separate [single full paired run](results/mutable-inline.json), Kasumi performed the normal per-write maintenance budget during ingest. It reclaimed 268,386,304 bytes inline with no deferrals. Peak writer allocation fell to 311.80 MB, after-close allocation to 146.98 MB, and after explicit compaction to 20.94 MB, at 53.00 s ingest. RocksDB took 27.95 s and ended at 1.77 MB. Maintenance timing matters to disk usage but did not change the live-writer decision.

## Sealed historical data

The new [frozen-run library](../../crates/kasumi-frozen-run/README.md)
seals a sorted stream into a single immutable file. It selects the smaller
of ordinary and common-prefix encoded keys per block, compresses with LZ4,
and verifies the requested block against a directory authenticated by the
caller's trusted SHA-256 root. It serves point, ascending and descending
reads; it cannot acknowledge new blocks or replace a transaction log.

All readers verified the same 16,387 key/value pairs and latest 24 documents
after reopening. The timings below are the medians of five fresh reader
processes' warm p95s. A page includes its timestamp-index lookup and all 24
primary document reads. RocksDB is **11.1.2** in both the deployed binding
and the native C++ controls. The controls verified the stored codec for every
SST; the binding defaults to `kNoCompression`. Both engines see the same
original indexer-encoded values. See [binding comparison](results/sealed-final.json),
[native controls](results/sealed-native-codecs.json) and
[upstream reproduction instructions](frozen-codec.md).

| Read-only storage | Total allocated bytes | Data file(s) alone, allocated | Mixed point p95 | Latest 24 p95 |
|---|---:|---:|---:|---:|
| Kasumi frozen V2, LZ4, 32 KiB | 151,552 | 151,552 | 1.25 µs | 12.33 µs |
| Native RocksDB, LZ4, 32 KiB | 290,816 | 225,280 | 1.75 µs | 48.42 µs |
| Native RocksDB, LZ4, 4 KiB | 372,736 | 307,200 | 1.75 µs | 39.71 µs |
| Native RocksDB, no compression, 4 KiB | 1,679,360 | 1,613,824 | 1.88 µs | 40.67 µs |
| Indexer's JS RocksDB binding, no compression, 4 KiB | 1,683,456 | 1,613,824 | 7.58 µs | 251.08 µs |

Even excluding RocksDB's metadata and logs, the Kasumi file used **32.7%
less allocated storage than the 32 KiB LZ4 SST alone**. In the separate
pagination test, 64 different pages spread across the full interval returned
the same 1,536 documents in the same order: 13.00 µs p95 for Kasumi and
137.08 µs for the deployed binding. We did not run that pagination test
against the C++ controls. Memory, storage hardware and cache temperature
affect these timings; the trace fits in memory. They do not predict full
indexer performance or a cold read from production disks.

The included fixture seals to a 151,114-byte file with trusted root
`e2b8bb171680d94e61b3ba8892070c3dfb7aede3da82539de2e3231a24fbb815`.
The V1 file also reopened with its original root and produced identical
state and page digests. See the [standalone query command](README.md) to
read a sealed page without the source trace or RocksDB. The fixture root
identifies this specific data set; it does not certify chain history.

The public indexer was left on RocksDB. A production archival tier would
need an indexer-owned manifest binding trusted roots to finalized cutoffs,
and a query path that merges archive and live records without gaps or
duplicates. No production history was deleted or moved.
