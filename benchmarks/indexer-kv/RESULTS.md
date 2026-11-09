# Polkaswap Stats storage comparison — 9 November 2026

The opt-in compact live engine on Kasumi master is measured below. The Stats comparisons use the same 4,096 finalized BLOCK snapshots. The separate Points replay uses historical operations from the private Points worker. [Stats fixture](fixtures/README.md) The storage replays measure durable KV ingestion and local reads. The application replay separately exercises the indexer's repository and Stats GraphQL resolvers. Neither measures chain RPC, unrelated collections or the full production worker. The [previous mutable formats](#packed-directories-with-inline-maintenance) and [sealed-only archive](#sealed-historical-data) are distinct engines.

## Imported Polkaswap Points data

At checkpoint 372,381, both Kasumi formats imported 5,526,276 physical rows with identical logical contents. Master commit `72958a86` can include an authenticated Bloom filter in a new imported base. The filtered database used 3,043,549,184 allocated bytes, up 6,905,856 from the legacy base. All nine private replays independently reproduced the same final logical digest. [Measured operations, builds and allocation](results/points-bulk-filter.json)

The 128-block storage trace contained 2,495 steady point reads and 129 durable commits. The filter ruled out 851 of the 860 absent keys that reached the immutable base. Nine required an exact lookup. All 333 present base keys passed the filter. An additional 1,302 reads resolved against newer writes. A complete import audit also checked the filter against every physical key. [Results](results/points-bulk-filter.json)

| Time in 2,495 point reads | Legacy build and base | Filter-aware build, legacy base | Filter-aware build, filtered base |
| --- | ---: | ---: | ---: |
| After the captured startup sequence | 255.2 ms | 286.8 ms | 62.7 ms |
| Cold data files, 0% resident | 225.3 ms | 224.7 ms | 57.8 ms |
| Warm data files, 100% resident | 130.3 ms | 147.2 ms | 32.7 ms |

Each case used a fresh physical copy, checked its cache residency and validated every returned value and the final sorted state. These timings measure native reads in the worker's recorded sequence. [Raw measurements](results/points-bulk-filter.json)

## Live writer

### Actual Stats repository writes and GraphQL reads

**Kasumi won all four application rounds on Linux ext4.** The real indexer
`RocksRepository.upsertMany([document])` ingested 4,096 consecutive finalized
network BLOCK documents per engine per round. Its own validation, document
codec, secondary index updates, counter reads/writes and transaction callback
ran on each backend. Each block was acknowledged after full WAL durability.
The harness alternated the first writer in adjacent 64-block windows and
rotated that order between rounds; it never combined several upserts into one
acknowledgement. The raw storage replay below measures a separate workload.

| Application result, four fresh rounds | Kasumi (Node) | Indexer's RocksDB (Node) |
|---|---:|---:|
| Durable documents/s, total documents / total ingest time | **4,364** | **3,657** |
| Documents/s including writer close and explicit reopen, compaction and close | 4,339 | 3,577 |
| Median allocated bytes with writer open | 462,848 | 21,037,056 |
| Median allocated bytes after writer close | 462,848 | 1,687,552 |
| Median allocated bytes after explicit compaction | **159,744** | **1,732,608** |

Kasumi was **19.3% faster** on the ingest path, used **72.6% less disk** after
writer close, and **90.8% less** after compaction. Every round compared
all 16,389 recovered key/value rows between engines (including bootstrap
metadata), checked the 16,387 trace rows against source values, then executed
the wallet’s pinned BLOCK fee and volume queries through the indexer’s real
GraphQL resolver and repository. Both produced identical bytes, ordered
results and cursors; the fixture has seven positive fee rows and one positive
volume row. Each engine received the same decoded documents. Creation, input
decoding and GraphQL verification are outside the timed ingest interval.

This is an offline qualification of the Stats document write path with a
scoped Kasumi storage adapter, not a live production cutover, chain RPC
benchmark or certification of other collections and entitlement history.
[Raw application rounds and binary/source hashes (gzip)](results/live-application-linux.json.gz) ·
[Release module hashes](results/live-application-release.json) ·
[Reproduction instructions](README.md) · [Independent query replay on macOS](results/application-stats-macos.json).

### Default live engine on master (`cc719b23`)

On the 4,096-block Stats trace, Kasumi beat the indexer's installed RocksDB binding in **both durable ingest throughput and total allocated storage** on the local ARM64 Linux ext4 guest. Both sides received identical Node buffers and returned only after a full durability barrier. At one block per sync, Kasumi won **11 of 12** complete rounds. Across all rounds it was **34.8% faster** and used **90.9% less compacted disk**. It also wrote each original block as a distinct transaction when an eight-block backlog shared a flush.

| Linux ext4, both Node APIs | Kasumi | RocksDB 11.1.2 / JS 2.4.0 |
|---|---:|---:|
| Single-block ingest, all rounds (blocks/s) | 4,972 | 3,688 |
| Single-block ingest, median round (blocks/s) | 5,332 | 4,378 |
| Single-block ingest including explicit compaction and both closes (blocks/s) | 4,934 | 3,648 |
| Eight ready blocks per sync, all rounds (blocks/s) | 21,367 | 16,147 |
| Eight ready blocks per sync including compaction and both closes (blocks/s) | 20,704 | 15,100 |
| Median allocated bytes, single-block writer open | 458,752 | 22,704,128 |
| Median allocated bytes, single-block writer closed | 458,752 | 1,675,264 |
| Median allocated bytes, compacted, both modes | 159,744 | 1,753,088 |

The 12+12 rounds were fixed before starting, with a fresh database per round and the first writer alternated in each 64-block window and between rounds. Overall throughput divides all 49,152 blocks per engine and mode by summed ingests, including outliers. Each round verified all 16,387 keys and values in both orders after writer close and again after explicit compaction. The 4 MiB budget is charged to pending mutations, not reserved disk. The closed, uncompacted database used about 73% less space; the larger open-RocksDB footprint includes preallocated files. The reported paid rate charges writer close, explicit compaction and maintenance close, but excludes process setup and read verification. The initial two-round [single-block](results/live-default-linux-pilot-x1.json) and [grouped](results/live-default-linux-pilot-x8.json) pilot is separate: single-block total times split, while Kasumi won both grouped trials.

[All Linux confirmation rounds (CSV)](results/live-default-linux-rounds.csv) · [Single-block raw windows (gzip)](results/live-default-linux-12-x1.json.gz) · [Eight-block raw windows (gzip)](results/live-default-linux-12-x8.json.gz) · [Toolchain and native binary provenance](results/live-linux-build.json). Use `summarize-paired.mjs` on either raw file to validate the checked rows, phase digests, and aggregate rates.

The new default persists a 4 MiB budget instead of flushing at 512 KiB. Linux uses a full-integrity synchronized write for each single block where the filesystem supports it; on macOS Kasumi uses `F_FULLFSYNC`. Both keep a separate recoverable WAL frame for every logical block. The indexer's JS RocksDB package exposes a synchronous JS transaction but does not request a device flush for every transaction by default. For equal durability the comparator synchronizes the actual WAL before acknowledgement. Rates are for that contract, not the package's less durable default or production chain-processing throughput.

On the same Apple M4 Max host running macOS directly, the final Node [single-block comparison](results/live-default-macos-x1.json) favored Kasumi in both rounds, **145.9 vs 137.6 blocks/s** in aggregate (6.0% faster). Compacted allocation was 159,744 vs 1,765,376 median bytes. The [eight-block macOS test](results/live-default-macos-x8.json) split one win each and was **slower for Kasumi overall**: 741 vs 1,020 blocks/s. Relative speed varies with storage, OS and commit mode. The Linux host was a local four-vCPU Debian 13 arm64 VM on this Mac, using ext4 on its own virtual block device, not the production server.

A separate [four-way Linux matrix](results/live-default-linux-four-way.json.gz) rotated each worker through all four positions in isolation. The final Node result held: median 5,668 vs 4,808 blocks/s and aggregate 5,596 vs 4,302. Against native C++ RocksDB 11.1.2/LZ4 with 32 KiB blocks, Rust Kasumi was faster at the **median** (5,768 vs 5,348 blocks/s), but a 1.285 s Kasumi run reversed the **aggregate** (4,866 vs 5,363 blocks/s). The native comparison does not establish a universal speed win. Compacted native allocation was consistently **159,744 vs 335,872 bytes**, and the latest-page p95 medians were 4.02 vs 20.83 µs. Native RocksDB was faster at individual point lookups. Linux OS write-byte counters were unavailable; they were not treated as zero.

### Earlier compact live engine: 512 KiB budget

The first four-round matrix used the tiered engine at `32858b91` on Apple M4 Max / Darwin arm64. Every contender ran once in each position, using a fresh directory. Both Node bindings ran under Node 26.13.0. The native RocksDB 11.1.2 control uses LZ4 and 32 KiB table blocks. The primary speed comparison is Node against Node; the native controls independently test whether language bindings or compression settings explain the result. [Raw measurements, binary hashes and verified digests](results/mutable-tiered-macos.json)

| Median of four runs | Kasumi Node | RocksDB Node (installed) | Kasumi Rust | RocksDB C++ / LZ4 |
|---|---:|---:|---:|---:|
| Durable blocks/s | 103.3 | 121.4 | 112.9 | 122.1 |
| Ingest time (s) | 39.89 | 33.80 | 36.29 | 33.61 |
| Ingest + writer close + final compaction and close (s) | 39.95 | 33.87 | 36.34 | 33.62 |
| Whole writer process CPU (s) | 1.21 | 1.67 | 0.97 | 0.85 |
| OS-attributed write bytes/block | 11,862 | 17,052 | 11,862 | 16,504 |
| Sampled peak allocated bytes during ingest | 303,104 | 4,040,704 | 346,112 | 3,235,840 |
| Allocated bytes with writer open | 217,088 | 3,231,744 | 217,088 | 3,235,840 |
| Allocated bytes after writer close | 217,088 | 1,679,360 | 217,088 | 3,235,840 |
| Allocated bytes after compaction | 159,744 | 1,769,472 | 159,744 | 339,968 |
| Latest 24 documents, first reopen p95 (µs) | 71.3 | 90.8 | 6.5 | 27.4 |
| Latest 24 documents, after compaction p95 (µs) | 73.8 | 98.4 | 9.5 | 29.7 |

On this matrix both Kasumi interfaces use 91.0% less disk after compaction than the installed RocksDB binding, and 53.0% less than native LZ4 RocksDB. Kasumi Node uses 30.4% fewer OS-attributed write bytes per block, but its median throughput is **14.9% lower** than RocksDB Node. With native interfaces Kasumi is 7.5% slower. Individual Kasumi Node ingests ranged from 36.07 to 50.91 seconds; RocksDB Node ranged from 31.14 to 36.43. CPU includes process startup and fixture decoding; ingest timing excludes them. Read timings should only be compared within the same interface pair. Full data and the latest-24 digest matched after both reopens for every run. The compact engine is opt-in for a fresh database and this is not a migration test.

The [two adjacent-window Node runs on the same original build](results/mutable-tiered-macos-paired.json) took 40.87 vs 44.67 s and 39.99 vs 26.86 s (Kasumi vs RocksDB). Kasumi won 73 of 128 windows but only one complete round. The whole-run comparison includes every stall.

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
