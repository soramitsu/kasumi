# Kasumi and Redis under matched durability and TLS

This comparison measures standalone Kasumi and Redis 8 on the same machine,
with the same key space, document bytes, client concurrency, timing method and
transport security. It exists to find where Kasumi is slower or heavier than
Redis, fix what can be fixed, and state plainly what Kasumi's design costs.

The servers do not offer the same guarantees, so read every row with the
[settings table](#what-is-compared). Results come from a shared
development Mac that usually runs at a load average of 70–150; every row
records the load around it. These are development observations, not a launch
SLA or capacity qualification.

## What is compared

| Setting | Kasumi (`kasumi`) | Redis (`redis-always`, `redis-everysec`) |
| --- | --- | --- |
| Server | standalone `kasumid serve`, release build | `redis-server` 8.x (Homebrew), default `io-threads 1` |
| Durability | every acknowledged write is durable: journal entry and applied state are flushed (`F_FULLFSYNC` on macOS, `fdatasync`/`fsync` on Linux) before the reply | AOF with `appendfsync always` (flushed before the reply, batched per event-loop turn; `F_FULLFSYNC` on macOS) or `appendfsync everysec` (up to ~1 s of acknowledged writes can be lost) |
| Snapshots/compaction | journal snapshot every 5,000 entries, background segment compaction | `save ""` (no RDB); default automatic AOF rewrite |
| Transport | TLS 1.3, client certificate from the installation CA, pinned server certificate | TLS 1.3 (`tls-protocols "TLSv1.3"`), `tls-auth-clients yes` with a private CA |
| Authentication | Ed25519 bearer token (JWT) verified on every request and audited durably: per request in the baseline, once per connection and token since 1a0f7bc5 | ACL user and password once per connection (`AUTH`) |
| Authorization | per-collection RBAC re-checked before release | ACL `~* &* +@all` for the benchmark user |
| Encryption at rest | yes (AEAD per record, wrapped keys) | no |
| Audit | durable service audit of every authentication; mutation audit; optional strict read audit (`kasumi-audited`) | none |
| Idempotency | every mutation stores a durable receipt keyed by its idempotency key | none |
| Data model | JSON document `bench/k0000000042`, schema-validated, one declared number index on `/n` | string `doc:k0000000042` with the same JSON bytes; sorted set `idx:n` holds the same index |

Each logical write updates the document and its index entry atomically on
both sides: a Kasumi upsert in an indexed collection, or a Redis
`MULTI; SET; ZADD; EXEC` (batches use `MSET` and one multi-member `ZADD`).
The driver keeps one connection set per client: Kasumi's SDK opens a read and
a write HTTP/2 connection, Redis one RESP connection.

## Workloads

All workloads pick keys uniformly at random from the loaded key space
(default 100,000 keys of exactly 1,024 bytes of JSON).

| Workload | Kasumi call | Redis commands |
| --- | --- | --- |
| `load` | `Mutate` with 100 upserts per batch | `MULTI; MSET (100); ZADD (100); EXEC` |
| `point-read` | `Get` | `GET` |
| `point-write` | `Mutate` with one upsert | `MULTI; SET; ZADD; EXEC` |
| `mixed` | 90% `Get`, 10% one-upsert `Mutate` | 90% `GET`, 10% `MULTI; SET; ZADD; EXEC` |
| `batch-read` | `ReadSnapshot` of 10 distinct documents | `MGET` of 10 keys |
| `batch-write` | `Mutate` with 10 upserts | `MULTI; MSET (10); ZADD (10); EXEC` |
| `range-scan` | `Query` `/n` in `[s, s+50)`, sorted by `/n`, limit 50 | one `EVALSHA`: `ZRANGE idx:n s (s+50 BYSCORE LIMIT 0 50` then `MGET` |

Every response is checked: reads must return every requested document, range
scans exactly 50 rows, and writes a successful receipt or `EXEC` reply.

## Metrics

- **Throughput and latency** come from `kasumi-bench-compare`: closed-loop
  clients, a warmup interval that is not recorded, then a fixed measured
  interval. Latency is the full client-observed call (nearest-rank p50, p90,
  p99, p99.9). Operations in flight at the end finish inside the interval.
- **Server CPU** is user+system CPU seconds of the server process during the
  measured run (`proc_pid_rusage` on macOS, `/proc/PID/stat` on Linux),
  reported per operation. Under host load this is steadier than throughput.
- **Memory** is the server's resident set (`ri_resident_size` / `VmRSS`),
  sampled every 250 ms; macOS also reports the physical footprint.
- **Write amplification** is the bytes the server process wrote to the device
  during the run (`ri_diskio_byteswritten` / `write_bytes`) divided by the
  logical bytes the clients wrote (document id plus JSON body). The logical
  variant uses bytes passed to `write(2)` instead.
- **Idle cost** is server CPU and device writes over 10 s with the data loaded
  and no requests (`--idle-seconds`).
- **Startup and recovery** are timed from spawning the server process to the
  first successful authenticated read of a loaded key, after a graceful
  `SIGTERM` stop and after `SIGKILL`.
- **Disk usage** is the allocated size of the data directory after the
  workloads.
- **Compaction during a case** (Kasumi only) comes from the node database's
  `kasumi_storage_*` metrics, read with the installation's Control profile
  before and after each case: the compaction cycle and phase at both ends
  and the bytes reclaimed and relocated in between. A cycle that runs inside
  a write case slows it, so compare Kasumi builds only on cases with the same
  compaction activity.

## Running it

Build the server, the driver, and install Redis:

```sh
brew install redis   # or the distribution package; needs TLS support
cargo build --release --locked -p kasumi-server --bin kasumid --bin kasumictl
cargo build --release --locked -p kasumi-bench --features network --bin kasumi-bench-compare
```

Run the matrix (about 25 minutes with the defaults):

```sh
python3 benchmarks/redis-comparison/run.py \
  --kasumi-bin target/release \
  --driver target/release/kasumi-bench-compare \
  --work /tmp/kasumi-redis-work \
  --output benchmarks/results/redis-comparison/local \
  --systems kasumi,redis-always,redis-everysec \
  --clients 1,16 --keys 100000 --value-bytes 1024 --duration 20 --warmup 3
python3 benchmarks/redis-comparison/report.py benchmarks/results/redis-comparison/local/results.jsonl
```

`--work` must not exist; it holds both installations, their keys and data,
and is deleted afterwards unless `--keep-work` is given. Add
`kasumi-audited` to `--systems` to measure strict read auditing. The script
records the host, Redis version, arguments and load average in
`results.jsonl`; nothing it writes contains credentials or document bodies.
Kasumi credentials expire after an hour, so the script runs
`kasumid credential watch` on the tenant and Control profiles for the length
of the run.

A Kasumi compaction cycle starts once the retained files grow past a
threshold, so where one falls depends on how much the earlier cases wrote,
and a build that writes faster in one case can move a cycle into the next.
`--compact-before start` requests a cycle just before every Kasumi workload
case, so it runs inside the case; `--compact-before finish` requests one and
waits until it completes, so the case starts on a freshly compacted store.
Use one of them to compare builds on a change that is not about compaction;
the default leaves compaction alone. On macOS a full flush (`F_FULLFSYNC`) is
device-wide, so any other process flushing to the same device slows every
Kasumi write case. That includes a second benchmark, a test suite that
creates durable stores, or a server opening a large store. Run builds one
after the other, never side by side, and check `ps` for such processes
before trusting a round.

To profile a server during a workload on macOS, attach `sample PID 10` while
the driver runs (Linux: `perf record -g -p PID`). The driver alone can also be
run against any installation; see `kasumi-bench-compare --help`.

## Baseline results (2026-11-06)

Kasumi 6ff7734d (release profile: thin LTO, one codegen unit), Redis 8.10.3
(Homebrew, libc malloc), macOS 27.2 on a 16-core Apple M3 Max with 128 GiB.
100,000 keys of 1,024-byte documents, 30 s measured after a 3 s warmup.
The host was shared and loaded: load averages ranged from 19 to 160 across
rows and are recorded per row in the raw results
([Kasumi](results/redis-comparison-20261106/kasumi-6ff7734d.jsonl),
[Redis](results/redis-comparison-20261106/redis-8.10.3.jsonl)). The Redis
systems ran interleaved; Kasumi ran afterwards on its own because its first
two loads failed (see below). Treat differences under about 2x as noise.

**1 client** (ops/s; p50 and p99 in ms; server CPU per operation in µs)

| Workload | Kasumi ops/s | Kasumi p50 / p99 | Kasumi CPU/op | Redis always ops/s | always p50 / p99 | always CPU/op | Redis everysec ops/s | everysec p50 / p99 | everysec CPU/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| point-read | 19 | 41 / 170 | 10,989 | 11,545 | 0.03 / 0.65 | 19 | 11,998 | 0.03 / 0.61 | 19 |
| point-write | 10 | 79 / 227 | 23,154 | 83 | 8.55 / 30 | 302 | 5,221 | 0.05 / 4.14 | 38 |
| mixed | 34 | 17 / 167 | 6,632 | 783 | 0.10 / 16 | 56 | 2,394 | 0.05 / 7.69 | 31 |
| batch-read | 40 | 16 / 124 | 6,226 | 5,005 | 0.05 / 1.34 | 31 | 6,380 | 0.04 / 1.06 | 27 |
| batch-write | 6 | 127 / 544 | 51,764 | 65 | 12 / 35 | 333 | 1,037 | 0.12 / 14 | 81 |
| range-scan | 7 | 105 / 369 | 70,296 | 1,189 | 0.27 / 10 | 237 | 1,391 | 0.28 / 7.85 | 246 |

**16 clients** (ops/s; p50 and p99 in ms; server CPU per operation in µs)

| Workload | Kasumi ops/s | Kasumi p50 / p99 | Kasumi CPU/op | Redis always ops/s | always p50 / p99 | always CPU/op | Redis everysec ops/s | everysec p50 / p99 | everysec CPU/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| point-read | 90 | 158 / 662 | 4,024 | 21,384 | 0.23 / 15 | 14 | 22,060 | 0.24 / 12 | 14 |
| point-write | 15 | 927 / 3,520 | 20,998 | 685 | 18 / 46 | 55 | 6,628 | 0.29 / 64 | 20 |
| mixed | 64 | 45 / 2,133 | 5,933 | 849 | 12 / 132 | 30 | 11,309 | 0.27 / 19 | 15 |
| batch-read | 27 | 419 / 2,106 | 19,377 | 6,288 | 0.41 / 56 | 25 | 6,893 | 0.36 / 54 | 23 |
| batch-write | 5 | 2,356 / 7,064 | 55,652 | 128 | 102 / 389 | 85 | 4,765 | 0.74 / 37 | 42 |
| range-scan | 15 | 966 / 2,929 | 70,941 | 1,639 | 3.70 / 94 | 222 | 2,170 | 3.84 / 68 | 218 |

| Measure | Kasumi | Redis always | Redis everysec |
| --- | ---: | ---: | ---: |
| Load of 100,000 documents | 454 s, 220 docs/s (4 loaders) | 6 s, 15,730 docs/s | 2 s, 61,443 docs/s |
| Device bytes written per logical byte, load | 61.6 | 1.1 | 1.0 |
| Device bytes written per logical byte, 1-client point writes | 770 | 19 | 1.1 |
| Peak resident memory during the runs | 780-980 MiB | 155-163 MiB | 160-410 MiB |
| Idle after load: CPU, device writes in 10 s | 28%, 65 MB | 0.06%, 0 | 0.15%, 5 MB |
| Data directory after the runs (99 MiB logical) | 992 MiB | 209 MiB | 385 MiB |
| Graceful restart to first read | 22.9 s | 0.67 s | 0.93 s |
| `SIGKILL` recovery to first read | 22.6 s | 0.53 s | 0.78 s |

Two Kasumi loads with 16 concurrent loaders failed before this run. In one,
a 100-document batch did not complete within the 60 s client deadline; in
the other, the server refused a batch with `proposal admission deadline
exceeded` because sixteen proposals queued behind the one being applied.
Redis absorbed both loads at that concurrency.

## Where Kasumi's time goes

Profiles below are macOS `sample` captures of a standalone `kasumid` built
from 6ff7734d with line tables, serving 20,000 documents to four clients
(`benchmarks/redis-comparison` driver). Counts are samples across all server
threads over 8 seconds; they rank costs, they are not exact shares.

1. **Every request waits for a durable audit record.** The listener
   authenticates each request and waits for an `AuthenticationSucceeded`
   record in the service audit store before reading the body
   (`kasumi-server/src/request_admission.rs` -> `Authenticator::authenticate`).
   Concurrent records share one commit, but a lone client pays one full
   device flush per read. In a read-only run those audit commits were the
   node's only writes, yet they held the storage lock for 1,443 samples.
   Since 1a0f7bc5 only a token's first request on a connection waits;
   see [changes](#changes-measured-here).
2. **Readers wait for commits on one storage mutex.** `kasumi-kv`
   serializes every operation on a node through `Shared::run`, and a commit
   holds that mutex through its root publication, including the final full
   flush (`root::publish` -> `sync_root`). Of 1,076 samples in point-read
   lookups (`read_view::get_at`), 1,046 waited for the mutex; range scans
   waited 5,247 samples and batch reads 5,195. Background maintenance held the
   same mutex for 760 samples during reads. During a 100,000-document load
   one 100-document batch did not complete within 60 seconds.
   Since 89e011ed a commit releases that mutex while it writes and flushes its
   root; see [changes](#changes-measured-here).
3. **Writes are serialized through two durable commits.** Besides its audit
   commit, each write needs a journal append and an application publication,
   each a durable commit, and the engine admits one proposal at a time
   (`proposal_gate`) through both. A tenant's write throughput therefore stays
   near one write per two commits at any client count.
   Redis `appendfsync always` shares one flush among every client served in
   an event-loop turn.
4. **Each document read opens and closes a registered read view.** Forking
   the view (`TenantStorageReadView::fork`) and closing it took about 60% of a
   point read's own work. Closing used to spin with `yield_now` while another
   operation held the database owner's lock (`RegisteredNodeRead::finish`);
   it now sleeps on that lock (see [changes](#changes-measured-here)).
5. **Physical identity checks on every file operation.** Each read, write
   and sync re-verifies the file and its parent directory (`openat`,
   `fstatat`, `fstat`, `lstat`, `geteuid`): about 830 samples in the write
   run, half as many as the flushes themselves.
6. **Copy-on-write directory pages amplify writes.** Each commit appends new
   directory pages from leaf to root for every table it touches (documents,
   indexes, receipts, journal, audit). During the load the store filled a
   64 MB directory file about every 30 seconds.
7. **Token verification.** Ed25519 signature checking and claim decoding
   cost about 140-180 µs of CPU per request on this host. This is fixed:
   see [changes](#changes-measured-here).
8. **Compaction cycles slow writes while they run.** On 10,000 documents a
   cycle makes about 290 durable publications, because evacuation rewrites or
   skips each directory leaf in a root publication of its own. It takes 4–12 s
   on an idle node (31 s once, during another session's test suite) and
   6–14 s under 16-client mixed load, and in 8 of 10 instrumented runs that
   load committed 15–65% fewer times per second during the cycle than after
   it. The store's node worker also holds the
   opening's lock, which every registered read and write takes to begin,
   through each maintenance step and through its warm-up call's wait for an
   in-flight commit. When single commits took 1–8 s under another benchmark's
   flushes, that wait reached 6–7 s; in one such run a client's 5 s connection
   deadline expired.

## Changes measured here

| Change | Status | Before | After |
| --- | --- | --- | --- |
| Verified-token cache: a token this key set already verified skips its Ed25519 signature check and claims decode; signed times, scopes, credential liveness and the audit record still run per request (`kasumi-server/src/auth.rs`) | committed, caf0d2a9 | 143-178 µs of CPU per request for verification (release micro-benchmark on this host) | 0.6-5 µs |
| Unknown token key IDs no longer re-read the private signer file (security fix, same file) | committed, caf0d2a9 | every request naming an unknown `kid` re-parsed every signing key | at most one reload per replacement of the signer file |
| Closing readers sleep on the database owner's lock instead of spinning on `yield_now` (`kasumi-store/src/storage_opening/reads.rs`) | committed, 1f375877 | server CPU per point read 2,318 µs, per range scan 32.9 ms (16 clients, release build without LTO, two alternating rounds) | 1,908 µs (−18%), 21.0 ms (−36%); throughput unchanged within noise |
| Record a bearer token's success once per connection and count the later ones in one record when the connection changes token or closes; refusals are still recorded one by one (`kasumi-server/src/auth.rs`, `authenticate_on`) | committed, 1a0f7bc5 | 1-client point reads 20/s, p50 44 ms, 7.3 ms server CPU per read; 16 clients 117/s, p50 172 ms; range scans 7.3/s (1 client) and 15/s (16); mixed 90/10 16/s and 30/s | 2,015/s, p50 0.31 ms, 0.30 ms CPU per read; 6,900/s, p50 1.9 ms; 77/s and 56/s; 71/s and 58/s; writes unchanged within noise |
| A commit releases the kv state mutex while it writes and flushes its root, so reads continue on the previous root. It records the cache identities it supersedes outside the cache and reconciles them once the root is durable; maintenance, warm-up, configuration and close wait on a separate commit gate (`kasumi-kv/src/core.rs`, `disk_state.rs`) | committed, 89e011ed | mixed 90/10: 189/s with 1 client (p99 47–138 ms) and 252/s with 16; point reads 4,431/s (1 client) and 9,569/s (16); profiled under 16-client mixed load, 93% of kv point-read samples waited for the mutex | 240/s (p99 34–60 ms) and 211/s, a 16-client drop that did not reproduce once compaction was recorded or pinned (next row); 4,809/s and 9,546/s; 64% |
| Record each Kasumi case's compaction cycle, phases and reclaimed bytes from the node's metrics, and pin the cycle with `--compact-before start` or `finish` (`benchmarks/redis-comparison/run.py`, `report.py`) | committed, c78efd57 | lock split, 16-client mixed 90/10: 252 → 211/s (−16%), two of five runs after the change at 107–146/s, with no record of which windows had a compaction cycle | the same sequence, recorded: in four more rounds the only 16-client window with a cycle was the old build's, at 50/s. Pinned (medians of three rounds on a device other sessions' startups and tests still flushed to; the rounds of both builds overlap): 151 vs 151/s with the cycle in the window, 164 vs 208/s with it finished first. Both builds made 284–300 maintenance publications per cycle; the node worker ran 74–82% of its attempted steps before the change and 62–74% after |

The per-connection row comes from a separate A/B run of two builds without
LTO at 51f47f27 (10,000 documents of 1 KiB, 15 s per case, two alternating
rounds per build for reads and four for writes and mixed, medians, host load
average 90–510 from other work; [raw
results](results/redis-comparison-20261106/per-connection-audit/), same host
and harness), so compare it only with its own baseline column. Writes did
not change beyond noise in that run. A point write, like a batch of ten
documents, costs two kv commits: the journal append and the apply
publication. Each commit issues six syncs on this host (three segment-log
syncs, one directory sync, two root syncs), so a write costs 12. The
`sync-trace` build of `kasumi-store` counts them and, with
`KASUMI_SYNC_TRACE_STACKS=1`, attributes each commit to its callers. A third
commit per write appears only while a compaction cycle runs, when the node
worker's maintenance publications interleave about one for one with
foreground writes. A batch of more than 32 documents, such as the harness's
100-document load batches, also stages its mutation receipt in a commit of
its own. In some rounds of both builds, 16-client
writes stalled for 16 to 111 seconds. Every stall fell inside a window in
which another session was running flush-heavy Kasumi benchmarks on the same
SSD, though not every overlapping phase stalled. Their `F_FULLFSYNC` calls
slow each of Kasumi's syncs and its buffered writes, and Kasumi applies one
write at a time through its proposal gate with no group commit, so each of
16 closed-loop clients waits behind the other 15 writes: about 16 times the
slowed time of one write. Group commit, or fewer syncs per commit, would
shrink that amplification. So would committing a write's journal entry
together with its apply, which halves its syncs. That needs the apply to end
cleanly when its one commit is refused for capacity, as the journal append
does today.

The lock-split row compares two builds without LTO at 47a37475 (10,000
documents of 1 KiB, 20 s per case, three to five alternating rounds per
build, host load average 19–122, medians), plus a 15 s `sample` profile of
each build under the 16-client mixed workload; the 89e011ed commit message
has the ranges and the profile. The 16-client mixed case is bound by the serialized
writes, and its slow runs coincided with an active compaction cycle.

The compaction row tested whether the change lets the store's maintenance
worker compete harder with foreground writes ([raw
results](results/redis-comparison-20261106/compaction-ab/), same host,
harness, document count and durations). It does not. Where a cycle falls
depends on how much the earlier cases wrote: the load of 10,000 documents
leaves about 229 MB of retained files against a 268 MB trigger, so the first
cycle starts in the first write case after it and the next once another
256 MiB is retained, and the change made single-client `mixed`, the case
before the 16-client one, 27% faster. Four more alternating rounds of the
original `point-read,mixed` sequence with the original two builds put a
cycle in one 16-client window only, the old build's (50/s against 138–219/s
without). With the cycle pinned, two builds carrying temporary counters
(0d3fb2d4 and 89e011ed) ran five alternating rounds of each condition. The
medians come from the last three. Another session's flush-heavy benchmark
overlapped most runs of the first two rounds and had stopped by then, but
the device was never quiet. Other sessions' store startups and a full
`kasumi-engine` test suite still flushed to it during rounds three to five.
With the cycle in the window those rounds gave 118–211/s before the change
and 83–212/s after; with it finished first, 162–226/s and 122–236/s. The
throughput medians therefore only show that no difference stands out of
that noise; the verdict rests on the counters. Over all
five rounds both builds made 284–300 durable maintenance publications per
cycle, and maintenance held the writer gate for 3.1–5.4 s of each cycle
before the change and 3.5–5.9 s after. The node worker found the gate free
less often after the change (62–74% of its attempted steps against 74–82%),
so more of the same work fell to the inline steps of writes. The 16-client
difference of the original rounds did not reproduce. In the raw results,
`sequence.jsonl`, `pinned.jsonl` (the original builds, two rounds) and
`pinned-instrumented.jsonl` hold the harness lines, each with an `ab_run`
naming its build, condition and round, and `instrumented-counters.jsonl`
holds the counters of each case.

## Summary: where Kasumi stands against Redis

On this host, matched for TLS 1.3 with client certificates and for durable
acknowledgements, Redis is faster and lighter than Kasumi on every workload
measured here, by two to three orders of magnitude on reads. Most of the gap
is not data structures or encryption but four design decisions, each of
which buys a guarantee Redis does not offer:

- **Durable authentication audit.** In the baseline every request, read or
  write, waited for a flushed service-audit record: the floor under Kasumi's
  read latency and the main source of its audit-archive growth. Since
  1a0f7bc5 only a token's first request on a connection waits, which made
  single-client point reads 100 times faster (20 to 2,015 per second) and
  16-client point reads 59 times faster in an A/B run; a client that
  reconnects for every request still pays it. Redis keeps no audit log.
- **One storage mutex held through each commit's flushes, and serialized
  proposals.** Readers queue behind writers' device flushes, and a tenant
  applies one proposal at a time through two durable commits. Redis serves
  reads from memory on its event loop and shares one AOF flush among all
  clients in a turn.
- **Copy-on-write durable structures with six device syncs per commit.**
  These give Kasumi crash-consistent encrypted pages, receipts and audit at
  the cost of 60-800x write amplification.
- **Startup by journal replay.** A restart replays every entry since the last
  snapshot through the same durable publication path. Here no snapshot had
  been taken (the cadence is 5,000 entries), so the restart replayed an
  estimated 2,500 entries in 22.9 s, roughly 9 ms each; Redis loaded its AOF in
  under a second.

Kasumi is ahead of Redis on what that cost buys: encryption at rest, exactly
once mutations with durable receipts, schema validation and declared indexes
maintained in the same commit, per-request authorization and revocation, an
encrypted hash-linked service audit, and no configuration in which an acknowledged
write can be lost (`everysec` can lose about a second). It also spreads
requests over many cores where Redis serves commands on one thread, which
starts to matter once reads stop waiting for flushes: recording
authentication once per connection made 16-client reads 59 times faster
than its own baseline, yet its 6,900 reads/s trail the 75,944 that Redis
served in the same run.

Since 89e011ed reads run while a commit publishes its root: the commit records
the cache identities it supersedes outside the cache, writes and flushes both
root slots without the storage mutex, then recaptures pins and reconciles the
cache under it. Readers still wait for a commit's three segment-log syncs and
its directory sync, which stay under the mutex, and for maintenance and
warm-up steps, which hold it through their I/O; in a profile of the mixed
workload those are now what readers wait for. On Linux all six of a commit's
syncs are `fdatasync` calls (on macOS only the last is a full flush), so
fewer syncs per commit is the larger lever there.

To approach Redis on throughput Kasumi would still need, in order of
measured effect: stop holding the storage mutex across a commit's log and
directory flushes and maintenance I/O, so reads proceed during them; group
concurrent proposals into one journal append and one publication; reduce
the syncs per commit; and batch journal replay. Each is described in [where
Kasumi's time goes](#where-kasumis-time-goes).
