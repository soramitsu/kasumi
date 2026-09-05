# Run06 analysis of the first 12 completed cases

**12 of 15 cases had completed at the inspected 2026-09-05 11:38:30 UTC snapshot.**
All passed with exit zero: every mode at 1 and 100 tenants, plus raw/local at
1,000 tenants. Their 73 measured workloads contain 73,000 successes, zero failed
attempts and zero unattempted operations. Replicated/text/network at 1,000 tenants
are outside this observation. The live matrix is not declared complete, and no
capacity report was regenerated.

All 12 result files were checked against [matrix result hashes](matrix.json),
client executable identities and the [passed release build](../macos-validation-20260905-embedded-audit/release-build.json).
Both completed network fixture server hashes match the matrix and release build.
Every case reports 1,000,000 exact 1,024-byte JSON bodies, or 1,024,000,000 unique
logical payload bytes; tenant distribution is 1,000,000/10,000/1,000 documents per
group at 1/100/1,000 tenants. Source remains
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`. All inspected raw files
are unchanged. [The one-tenant note](one-tenant-analysis.md) retains its detailed
earlier interpretation; additional completed result bindings are below.

| Additional completed case | Verified result SHA256 |
| --- | --- |
| [raw-100](raw-100.json) | `c01d88f56d5842bbe4949ba593e9c74f9fbe13b68fef6a3c954695c922455e20` |
| [local-100](local-100.json) | `14d36a6babdf76b921c9c42236c829d31b88d8f7b78712344ca6551da6775075` |
| [replicated-100](replicated-100.json) | `b41391f4925cda0755f36a8895dbcb5ebc04c9a28f9ec1fa555977e0926393c0` |
| [text-100](text-100.json) | `9aa4b539a7c2601864ce82dce8412ef3c3c03cb52efb7893430e00cfbc9f2dad` |
| [network-100](network-100.json) | `0b61f2dd4d1b6c3fd60ea4870c9d8d1693028cfcce065ead33610dcd51cbcf13` |
| [raw-1000](raw-1000.json) | `10c0747e7ea42c3c3385ad443579df7d9e42e714021d4cc4c34a94ca5dfaae7a` |
| [local-1000](local-1000.json) | `a4d375869c8391abcd85d1728b541211671836f0c828c8c8a7d2cdb48a1f1537` |

## Access and durable-write observations

Selected rows use microseconds and successful operations per second. Each row
has 1,000 sequential samples. Mixed traffic and every structured/text query also
passed; complete rows remain in the linked JSON. These are single observations,
without saturation-throughput or statistical-repeatability claims.

| Case/path | Operation | p50 µs | p99 µs | Successes/s |
| --- | --- | ---: | ---: | ---: |
| raw-100 | Raw borrowed lookup | 0.458 | 1.667 | 1,998,169.677 |
| local-100 | Owned point get | 1.750 | 6.958 | 285,990.062 |
| local-100 | Shared point get | 0.542 | 0.792 | 576,161.325 |
| local-100 | Durable single-document write | 25,689.417 | 101,452.042 | 27.381 |
| replicated-100 | Owned point get | 31.791 | 121.417 | 25,299.429 |
| replicated-100 | Shared point get | 19.000 | 60.583 | 40,003.133 |
| replicated-100 | Durable single-document write | 77,243.708 | 354,077.000 | 8.365 |
| text-100 | Durable single-document write | 27,850.417 | 96,382.292 | 26.336 |
| network-100/grpc | Authenticated point get | 12,963.792 | 40,236.042 | 71.085 |
| network-100/grpc | Durable single-document write | 40,445.792 | 110,039.375 | 17.973 |
| network-100/mcp | Authenticated point get | 13,009.250 | 40,057.417 | 61.621 |
| network-100/mcp | Durable single-document write | 39,736.708 | 151,610.042 | 16.154 |
| raw-1000 | Raw borrowed lookup | 0.333 | 0.542 | 2,670,818.900 |
| local-1000 | Owned point get | 2.291 | 10.625 | 207,218.111 |
| local-1000 | Shared point get | 0.625 | 1.125 | 523,845.993 |
| local-1000 | Durable single-document write | 24,857.958 | 43,802.916 | 29.625 |

Raw borrowing omits authorization and durability. Embedded owned/shared results
include actual policy and consistency checks; replicated reads require a quorum
barrier, and writes require persistence plus complete local application. Native
RPC/MCP add authenticated TLS and durable authentication audits against an actual
server and OpenBao; strict successful-read audits remain disabled. The network
case has one voter per tenant, whereas replicated holds three voters per tenant
in one process on one host. No independent failure-domain or remote-quorum cost
is inferred. Fixed workload order and permitted host contention preclude a
causal speed comparison across counts or an external 50× claim.

Text queries drain all historical pages. At 100 tenants, fixture-derived result
cardinality falls from 1,000 to 10 rows for phrase/fuzzy/Japanese terms and from
10,000 to 100 for prefix. Consequently text-100 phrase p50 27.833 µs versus
3,337.458 µs at one tenant measures much less result work, not a same-query
100-tenant speedup. The timing loops do not emit observed row/page counts.
Native/MCP equality queries expect one row at either count.

## Memory and clean lifecycle

Memory/disk are GiB. Embedded/text/replicated include the whole harness and all
voters; network is the server process only. Native and MCP share its footprint.
Payload size is fixed across counts, while per-tenant state and result work change.

| Case | Empty groups RSS | Empty indexes RSS | Loaded RSS | After work RSS | After recovery RSS | Disk |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| raw-1 | 0.067 | — | 1.969 | 1.969 | — | 0.000 |
| local-1 | 0.070 | 0.074 | 4.061 | 5.540 | 9.884 | 4.000 |
| replicated-1 | 0.071 | 0.074 | 13.967 | 15.303 | 26.254 | 12.000 |
| text-1 | 0.071 | 0.079 | 5.275 | 5.683 | 10.623 | 4.000 |
| network-1 | 0.019 | 0.021 | 4.031 | 4.202 | 6.955 | 4.000 |
| raw-100 | 0.067 | — | 1.912 | 1.912 | — | 0.000 |
| local-100 | 0.079 | 0.084 | 4.032 | 4.071 | 4.459 | 1.945 |
| replicated-100 | 0.105 | 0.116 | 12.082 | 12.197 | 12.356 | 7.305 |
| text-100 | 0.078 | 0.090 | 4.476 | 4.507 | 4.473 | 3.672 |
| network-100 | 0.035 | 0.039 | 3.974 | 4.084 | 3.949 | 3.219 |
| raw-1000 | 0.067 | — | 1.999 | 1.999 | — | 0.000 |
| local-1000 | 0.114 | 0.166 | 4.336 | 4.379 | 4.773 | 1.891 |

Each non-raw local/text/network replica node has one separately encrypted
service audit store shared across all its tenant groups; replicated has three.
That store count stays fixed as tenant groups increase. Network adds one control
voter. Thus replicated-100 has 300 resident data voters, while local-1000 has
1,000, without turning audit stores into additional Raft groups.

Empty-state RSS increases from 1 to 100 tenants by about 0.084 MiB/additional
local tenant, 0.348 MiB/additional replicated tenant (three voters),
0.080 MiB/additional text tenant and 0.163 MiB/additional network tenant.
Local 1-to-1,000 gives about 0.045 MiB/additional tenant before indexes and
0.095 MiB after empty index creation. These are whole-process deltas between
independent cases, including policies, keys, runtime and allocator behavior,
not isolated per-group allocation sizes. Local-1000 additionally has the setup
interference disclosed below.

Loaded/recovery RSS and durable file sizes are not monotonic in tenant count.
For example, replicated recovery RSS is 26.254 GiB at one tenant and 12.356 GiB
at 100; local is 9.884/4.459/4.773 GiB at 1/100/1,000. Different group sizes,
recovery/allocation histories and shared-host conditions are not isolated here.
Do not interpret the lower observations as proven memory savings or a maximum
safe capacity. The sampled `peak_rss_bytes` precedes shutdown and may be exceeded
by later recovery RSS; network does not report a server lifetime peak.

| Case | Open s | Collection setup s | Load s | Shutdown s | Verified recovery s |
| --- | ---: | ---: | ---: | ---: | ---: |
| raw-1 | 0.000 | — | 1.346 | — | — |
| local-1 | 0.202 | 0.029 | 156.815 | 1.802 | 47.114 |
| replicated-1 | 0.534 | 0.057 | 376.497 | 4.443 | 119.991 |
| text-1 | 0.229 | 0.028 | 234.405 | 1.173 | 104.870 |
| network-1 | 1.196 | 0.036 | 209.604 | 0.991 | 27.986 |
| raw-100 | 0.000 | — | 0.995 | — | — |
| local-100 | 19.527 | 2.797 | 160.800 | 0.634 | 17.746 |
| replicated-100 | 55.734 | 7.023 | 384.576 | 2.079 | 52.699 |
| text-100 | 18.473 | 2.632 | 213.427 | 0.687 | 65.062 |
| network-100 | 18.586 | 4.714 | 231.479 | 0.742 | 20.909 |
| raw-1000 | 0.000 | — | 1.016 | — | — |
| local-1000 | 191.966 | 41.802 | 192.086 | 0.576 | 17.692 |

All 12 have terminal case success. Shutdown and recovery are separate; recovery
includes reopen/spawn, index reconstruction, key access/readiness and a verified
read per tenant. Final cleanup lies outside the timers. Local-1000 opening
includes sequential creation of 1,000 tenant groups; recovery is a different
path and its shorter observed duration is not a direct opening-speed comparison.
These clean recoveries do not substitute for crash/power-cut or partition tests.

## Host activity and cache-cleanup interference

This is a shared macOS arm64 host with 16 logical CPUs and 128 GiB RAM. The
live manifest recorded 890 competing-process violations at the inspected
snapshot under `--allow-host-load`. The additional case intervals show sampled
background CPU spanning 265.2–1,529.1% in aggregate (100% is one CPU), with
compiler/linker and QEMU names in [host samples](host-samples.jsonl). The figures
are neither isolated-host measurements nor evidence of a particular contention
cause. The earlier one-tenant cases had similarly heavy disclosed activity.

[Incremental-cache cleanup](artifact-cleanup-incremental/result.json) ran from
2026-09-05 11:32:37.361619 UTC through 11:33:14.871082 UTC, lasting 37.509463
seconds. It removed 207 inventoried cache units and observed an 8,839,000,064-byte
free-space increase. It records unchanged source and 130,488 retained compiled
files, including current binaries and dependencies; all raw measurements remain.
Only internal Cargo incremental caches were removed.

The interval is 208.48–245.99 seconds after local-1000 case start. Its measured
opening plus collection setup totals 233.77 seconds, so cleanup overlapped
collection setup and may have continued into roughly the first 12 seconds of
loading. Phase checkpoints have no exact timestamps; this overlap is inferred
from the recorded case start and phase durations. Setup/load timings and later
I/O/cache state require this additional qualification. No improvement is attributed
to cleanup, and no isolated setup measurement is claimed. [Run notes](RUN_NOTES.md)
preserve the activity and tradeoff.

The remaining three cases and every finite failure must remain visible before
publishing the complete matrix. This analysis adds interpretation only; it
neither restarts a workload nor modifies raw results or generated capacity.
