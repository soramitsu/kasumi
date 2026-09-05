# Capacity measurement protocol

The matrix reports observed memory and work at one million exact 1 KiB JSON
bodies total, distributed across 1, 100, and 1,000 tenants. It does not infer a
maximum tenant count or a production RAM recommendation from those three points.
Use the same frozen source, release executables, configuration, and host for each
case. Run one deployment/count per process; retained allocator pages from prior
cases would bias tenant-overhead differences.

`run_benchmark_matrix.py` writes `capacity.json` and `capacity.md` automatically.
To regenerate them, including an honest partial report after a failed matrix:

```sh
python3 scripts/report_benchmark_capacity.py benchmarks/results/release-matrix
```

The reporter binds observations to the matrix's per-result and executable
SHA256 hashes before calculating overhead. Missing or mismatched results remain
visible with an issue; absent measurements stay null. Failed-case phase checkpoints
retain partial workload observations and are excluded from qualified tenant-overhead
estimates. After-workload RSS, disk size and the available process peak are saved
before shutdown; a shutdown or recovery failure preserves these measurements.
Failure and unattempted counts distinguish partial from complete samples. The source identity covers
Rust, Protobuf, manifests, lockfile, and benchmark scripts. `--skip-build` records
existing binary identities and does not prove their relationship to current
source; use a normal frozen-source build for release evidence.

| API layer | Capacity source | Measured work |
| --- | --- | --- |
| Raw HashMap | `raw-N` process | Borrowed point lookups |
| Embedded access | `local-N` process | Owned and shared point reads, indexed equality |
| Local durable writes | Same `local-N` process | Durable writes, 90/10 and 50/50 mixes |
| Replicated durable access | `replicated-N` process | Quorum reads, writes, mixes, indexed equality |
| Authenticated native RPC | `network-N` server process | OAuth/mTLS reads, writes, mixes, complete query pages |
| Authenticated MCP | Same `network-N` server process | OAuth reads, writes, mixes, complete query pages |

English/Japanese indexed text is a separate `text-N` deployment with phrase,
prefix, fuzzy, and Japanese term queries plus writes that change indexed text.
It carries one numeric index and two text indexes per tenant. Other database
cases carry one numeric index per tenant. Raw maps carry no indexes. Native and
MCP use the same loaded server sequentially, with durable successful
authentication auditing; the second protocol can observe allocator/cache and
audit growth from the first. Their shared footprint must not be counted twice.

Text selectivity is constant within a tenant, so result cardinality decreases
with per-tenant document count. At 1/100/1,000 tenants, English phrase, bounded
fuzzy and Japanese term queries each return 1,000/10/1 rows; the English prefix
query returns 10,000/100/10 rows. The timed operation consumes every page.
Structured equality returns one row. Changes in text latency across tenant
counts therefore include changing result cardinality, alongside group/runtime
costs; they are not an isolated tenant-overhead comparison.

Every local case records process RSS at baseline, after opening empty tenant
groups, after creating **all** empty collection/index definitions, after loading,
after measured work, and after recovery. Collection/index setup time is separate
from document loading. Each body is measured by exact serialized byte length;
replicated mode holds three copies of the same unique logical dataset. The
network fixture records empty groups, empty indexes, loaded state, work, and
recovery for the actual `kasumid` process. It has N tenant groups, one additional
control group, and a separate protected service-audit store. OpenBao, issuer,
and client memory are excluded from server RSS and separately visible in the
five-second host process samples. In-process local/replicated fixtures include
the driver and all voters in their RSS.

The empty-group difference `(RSS_N - RSS_1) / (N - 1)` estimates the cost of an
additional tenant in that deployment. Empty-index differences also include the
schema, declared indexes, and creation receipts/audits. The replicated report
additionally divides by three resident voters, while retaining the combined
per-tenant figure. These differences include associated runtime, policy, KMS,
audit, and allocator costs; they do not isolate Raft allocations. OS and
allocator noise can produce negative differences, which are retained rather
than clamped or presented as savings.

Loaded RSS per unique payload byte includes process infrastructure, indexes,
keys, receipts, auditing, and replica copies. The report also provides a ratio
per resident payload byte, dividing the replicated denominator by its three
copies. Neither ratio is a heap-object overhead measurement. Disk observations
are file lengths, not allocated blocks or bytes written to the storage device.
The local peak is process-lifetime RSS, including load/work but recorded before
recovery; a later recovery high-water mark is not captured by that field. Network
peak RSS is not measured directly. Five-second host sampling can miss short
transient peaks.

`shutdown_seconds` measures complete database closure and fixture-store release
in the embedded harness. In the network fixture it measures SIGTERM through
successful `kasumid` process exit. `recovery_seconds` starts **after** that shutdown
and measures reopen (or a fresh server process spawn), index reconstruction,
lease acquisition, readiness, and one verified read per tenant. The network
verification uses authenticated native reads while the issuer and OpenBao stay
alive. Final cleanup of the recovered database is excluded from both timings.
The derived capacity report exposes these as `clean_shutdown_seconds` and
`clean_recovery_seconds`. Missing timings stay null, including shutdown in older
reports. Crash/power-loss behavior and failed recovery have separate acceptance
tests; these timings are not crash-test evidence.

Each workload is a sequential, closed-loop run. The minimum matrix measures
1,000 operations, leaving roughly ten observations in the p99 tail. It does not
measure saturation, confidence intervals, admission-pressure curves, or
concurrent-client fairness. Use repeated runs and separately specified
concurrency/pressure experiments before deriving capacity policy. Leave RAM
headroom for staged indexes, snapshots, cursors, receipts, audit retention,
background operations, and OS memory; a successful observed fit is not a
maximum safe capacity claim. The host sampler records physical RAM, raw memory
counters, load, competing process counts, and disk availability. Loaded-host
runs retain that status and do not support external speed comparisons.
