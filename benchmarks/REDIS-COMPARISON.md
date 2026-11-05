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
| Authentication | Ed25519 bearer token (JWT) on every request, verified and audited durably | ACL user and password once per connection (`AUTH`) |
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
`kasumid credential watch` for the length of the run.

To profile a server during a workload on macOS, attach `sample PID 10` while
the driver runs (Linux: `perf record -g -p PID`). The driver alone can also be
run against any installation; see `kasumi-bench-compare --help`.
