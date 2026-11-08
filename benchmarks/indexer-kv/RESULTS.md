# Polkaswap Stats storage comparison — 8 November 2026

These are local Apple M4 Max / Darwin arm64 measurements on the [same finalized BLOCK snapshot fixture](fixtures/README.md). They cover a native Kasumi library and the indexer's actual Node RocksDB binding 2.4.0 / RocksDB 11.1.2. They do not measure GraphQL, RPC, other collections, network traffic or production Linux storage. The two questions are different: can we replace the live writer, and can we store already-finalized records more efficiently?

## Live writer

**Keep the live indexer on RocksDB.** On three alternating, fresh-database runs, the optimized mutable Kasumi engine preserved every byte and substantially improved its footprint, but remained slower and wrote more than RocksDB. Each of the 4,096 batches has its own durability boundary. Both engines have an 8 MiB cache and were opened again in separate processes, before and after maintenance. Full result: [raw measurements](results/mutable-final.json). These timings are medians of three runs, not production latency guarantees.

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

The mutable format stores the full key and a 32-byte value location per live entry. On this data even **just** the 856,166 live key bytes, 524,384 bytes of locations, and 1,137,652 live value bytes total 2,518,202 bytes. This excludes table names, segment records, branch pages, and reclaimable pages. The current layout cannot reach RocksDB's measured 1.77 MB on this workload through vacuuming alone.

**Inline maintenance sensitivity.** In a separate [single full paired run](results/mutable-inline.json), Kasumi performed the normal per-write maintenance budget during ingest. It reclaimed 268,386,304 bytes inline with no deferrals. Peak writer allocation fell to 311.80 MB, after-close allocation to 146.98 MB, and after explicit compaction to 20.94 MB, at 53.00 s ingest. RocksDB took 27.95 s and ended at 1.77 MB. Maintenance timing matters to disk usage but did not change the live-writer decision.
