# Kasumi benchmark protocol

The [measured v1 results](RESULTS.md) cover all fifteen required cases and 99,000
successful operations. The [cohort manifest](results/release-cohort-macos-arm64-20260905-listener/cohort.json)
retains twelve unchanged embedded observations and three corrected-network
observations at their original source identities. The [portable report tools](results/release-cohort-macos-arm64-20260905-listener/tooling/COHORT-RENDERING.md)
regenerate the derived report. Shared-host and sample limitations are explicit;
these measurements establish no Redis speed ratio or production SLA.

These are development measurements, not launch SLAs. Raw map lookup, embedded
access, authenticated gRPC, MCP, local durable writes, and quorum durable writes
have different guarantees and are reported separately. No Redis speed ratio is
inferred. External comparisons require matched payloads, replication,
persistence, indexing, authentication, concurrency, hardware and audit settings.

## Build and run

Use a quiet machine, a stable checkout and the same Cargo.lock. Keep the warm
Cargo target directory. The default local harness has one million exact 1 KiB
JSON documents total, 1/100/1,000 tenant configurations, and 10,000 operations
per measured workload:

```sh
cargo build --release -p kasumi-bench
./target/release/kasumi-bench --output benchmarks/results/local-release.json
```

For independent memory estimates, run each mode and tenant count in a separate
process. This also avoids allocator retention between cases:

```sh
./target/release/kasumi-bench --documents 1000000 --tenants 100 \
  --operations 10000 --modes local --output benchmarks/results/local-100.json
```

The `--smoke` option uses 100 documents, 1/3 tenants and 32 operations. Explicit
arguments after it override smoke defaults. `--work-parent` selects the parent
for temporary encrypted database files. Each case closes all groups and removes
its own temporary data. The harness does not touch other project data.

Modes:

| Mode | What runs |
| --- | --- |
| `raw` | Borrowed Rust HashMap lookup, no body clone, identity, index or durability |
| `local` | Actual Database API and one OpenRaft voter backed by encrypted redb |
| `replicated` | Three real OpenRaft voters, separate encrypted redb files, in-process transport |
| `text` | Local engine with English and Japanese Tantivy indexes, including indexed writes |

The replicated benchmark and server use the same explicit v1 Raft timing
profile: heartbeats every 250 ms, randomized election timeouts of 1,500–3,000 ms,
and a 30,000 ms snapshot-install timeout. Each case records its actual settings
in `raft_timing_milliseconds`. Embedded one-voter startup retains OpenRaft's
local defaults. Application read-barrier and write deadlines remain 5 and 10
seconds; no timed operation is automatically retried. Longer election intervals
reduce idle per-tenant traffic and tolerate scheduler/persistence variance but
also lengthen leader-loss detection. These are disclosed runtime settings, not
a guarantee against overload or network partitions.

The three-voter mode runs on one machine. It measures local quorum persistence;
it does not claim independent hardware failure domains or real network costs.
The local harness uses an explicitly test-only wrapping provider with real
authenticated encryption, excluding Transit requests. Successful-read strict
auditing is disabled; mutation audits, receipt persistence and current RBAC are
active. Each node also owns the mandatory separately encrypted service audit
store, using a wrapping key distinct from the customer data keys. The
`security_audit_stores` field declares that additional store count; capacity
reports include its memory and disk cost without counting it as another Raft
group. Older reports without that declaration retain their historical topology.
`shutdown_seconds` measures complete database closure and fixture-store release. The separate `recovery_seconds` timer starts after shutdown and includes
reopen, index reconstruction, key access, readiness and a checked point read for
every tenant. Final cleanup is excluded. Crash recovery and fault injection have
separate acceptance tests.

Each database case loads batches of up to 256 documents, then measures owned and shared-handle point
reads (separately), single-document durable writes, 90/10 and 50/50 read/write mixes, and
structured indexed equality. Ratios are distributed evenly and truncated to the
nearest achievable operation count. Text measurements add phrase, prefix,
bounded fuzzy and Japanese term queries. Text tokens are distributed within each
tenant; rare terms keep candidate counts inside the same deterministic limits
at every dataset size. Queries consume every historical page before the next
query begins. Writes change an indexed revision token, including Tantivy
commit/reload work. A workload stops at its first failed attempt without retrying. Its successful
samples, failed-attempt duration/code, attempted count and unattempted count
remain in the report. Later independent workloads can continue: mutations use
unique idempotency keys and unconditional replacements that preserve ordinal
identity, so an unknown prior write does not create a false CAS failure. Each
workload/phase checkpoints its progress. After-workload RSS, disk size and the
available process peak are saved before closing, then successful shutdown timing
is saved before reopening. An incomplete load, failed shutdown or failed recovery
retains earlier progress and measurements. Any failure produces a nonzero exit;
no success is inferred for unattempted work.

Latencies are sequential closed-loop samples measured with a monotonic clock.
Success percentiles exclude failed attempts, whose durations are reported
separately. Success throughput divides completed successes by the whole elapsed
workload interval, including any failed-attempt delay. When there are no
successes, the success latency distribution is null.
p50/p99 use the nearest-rank percentile. Timers include the actual API call;
throughput also includes driver setup and leader selection. No pipelining or
concurrent load is claimed. Raw sub-microsecond measurements include timer
cost. RSS and disk bytes are physical process/file observations. For database
cases, `peak_rss_bytes` samples the OS process peak after the workloads and before
shutdown; it is not refreshed after recovery. It covers the process lifetime up
to that checkpoint, not the final whole-run peak. Separately reported
`after_recovery_rss_bytes` can exceed it. Raw cases sample their peak after map
lookups; network fixtures do not report a server lifetime peak. Allocators may
retain pages after a case. Capacity planning must include shared dictionary/runtime overhead and
node memory admission headroom; fit is never inferred from document bytes alone.

## Actual authenticated TLS network measurements

Build the production server plus both drivers and fetch the verified OpenBao
fixture binary:

```sh
python3 scripts/fetch_openbao.py
cargo build --release -p kasumi-server -p kasumi-bench \
  --features kasumi-bench/loopback --bins
./target/release/kasumi-bench-loopback --documents 100 --tenants 1,3 \
  --operations 32 --output-prefix benchmarks/results/network-smoke
```

The loopback fixture creates an ephemeral CA and Ed25519 issuer, serves real
TLS JWKS, starts actual OpenBao 2.6.2 with TLS and distinct wrapping keys, and
launches a separate production `kasumid` process. All credentials reach only
that child through its environment; no system trust or global environment is
changed. Native administration creates the collection and native mutations load
the dataset. The client measures both native mTLS+OAuth and current MCP
2026-07-28 with OAuth. Service authentication auditing and mutation auditing are
real durable writes. This is a single-voter, loopback network workload. These
costs are not interchangeable with the in-process wrapping fixture or a remote
production deployment. Its temporary service, issuer and key material are
removed on exit. Use 1,000,000 documents and 1/100/1,000 tenants for the larger
matrix; ensure RAM and audit budgets fit before doing so.

The independent endpoint runner can also use operator-provided test services:

```sh
./target/release/kasumi-bench-network network-config.json output.json
```

An example config is [network.example.json](network.example.json). It accepts
only HTTPS, requires native client certificates and a server certificate SHA256
pin, and reads access tokens from named environment variables. Tokens, document
bodies and query values never enter reports. Connection setup and one warmup
read per credential are reported separately. Every request authenticates; tokens are
not refreshed by this harness. Configure sufficient lifetime for the experiment.

Reads are the default. Dedicated benchmark targets can specify exact JSON
replacement files using `mutation_body`; adding `--allow-writes` then enables
write and mixed workloads. Every target must have a replacement body for those
workloads. These updates persist in the configured service. The runner never
creates or deletes an external tenant. Query definitions are optional; when all
targets have one, it measures complete paginated results. No automatic retries
hide uncertain outcomes. Disclose the endpoint's mode, hardware, audit policy,
KMS, dataset and server build alongside its report.

## Publication gate

Check in reproducible commands, source-tree/executable identity, build profile,
OS/CPU, payload size, dataset and tenant counts, logical quotas, throughput,
p50/p99, RSS, disk use, group opening time and recovery time. Record errors and
incomplete modes, and publish all runs rather than only the best sample. The
agreed matrix is one million 1 KiB documents at 1/100/1,000 tenants across the
separate paths below. A run with permitted competing host load must retain that
qualification. Stop only this task's validation/build workloads; unrelated
projects must remain untouched.

Before using these observations to set production capacity policy, repeat on
the selected Linux hardware and add concurrent-client and sustained
admission-pressure experiments. Those follow-up experiments provide different
evidence from this sequential matrix; the matrix alone does not establish
saturation throughput or a maximum safe capacity. Preliminary and incomplete
runs in `results` do not substitute for the complete agreed matrix.

## Gated full matrix

The matrix driver requires Python 3.11 or later. It builds the server and all benchmark binaries once, checks the
source and executable identities, screens the host for competing builds/VMs,
and runs every mode and tenant count in its own process. Its minimum matrix uses
1,000 measured operations per workload. At that count p99 has roughly ten tail
observations; it does not establish a confidence interval or repeatability.

```sh
python3 scripts/fetch_openbao.py
python3 scripts/run_benchmark_matrix.py \
  --output-directory benchmarks/results/release-matrix \
  --documents 1000000 --tenants 1,100,1000 --operations 1000
```

Use a fresh output directory for each run. `matrix.json` records the exact
commands, source/executable hashes, dirty/untracked Git status and outcome.
`host-samples.jsonl` records CPU/load, raw OS memory counters, disk space and
process names/PIDs/RSS every five seconds. It never captures command arguments,
environment values or data payloads. Executable metadata is monitored during a
case and its hash rechecked at completion, avoiding repeated hashing of large
binaries inside measured workloads. Source changes, replaced binaries, disk
pressure stop the driver and preserve its partial evidence. A failed case records
its exit code and result hash, then independent cases continue. The overall
matrix ends as `completed_with_failures` with a nonzero exit when any case failed.
Only this driver's own process groups and temporary data are cleaned up.

The default screening rejects compiler/linker/VM processes and excessive
background load. It is a screening method, not proof of exclusive hardware.
Unrelated projects must not be stopped to improve a result. If a quiet interval
is unavailable, `--allow-host-load` records every detected violation and labels
the matrix `completed_under_host_load`. Such measurements do not justify an
external speed comparison or a claim of isolated performance. Thresholds and
sample counts are recorded so readers can judge the limits directly. A full
matrix can take an hour or more, depending on storage, text indexing, and group
startup costs. `--operations 10000` provides a longer follow-up run.

The [capacity protocol](CAPACITY.md) explains memory stages and all six API
layers. The matrix also writes `capacity.json`/`capacity.md`, binding derived
observations to the recorded result and executable hashes. Empty groups and
empty indexes are sampled before documents load. Network `shutdown_seconds`
measures SIGTERM through successful server process exit; `recovery_seconds`
starts after shutdown and runs from a fresh server process spawn through one
verified authenticated read per tenant while the issuer and key service remain
running. Shared API footprints are referenced once;
missing observations are never filled with estimates.
