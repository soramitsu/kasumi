# Run06 early completed-case analysis

**3 of 15 cases completed at the inspected 2026-09-05 10:41:15 UTC snapshot.**
Raw-1, local-1 and replicated-1 passed with exit zero. The matrix remains live;
only these completed cases are interpreted here. Text, network and the 100/1,000-
tenant cases are outside this early note. This is not a final report or general
speedup claim. The final renderer waits for the terminal 15-case matrix.

The [matrix](matrix.json) binds source
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`.
All three JSON files match their recorded result hashes and the matrix executable
hash; their narrower Rust/Cargo fingerprints have the documented separate scope.
Each case loaded 1,000,000 exact 1,024-byte JSON bodies: 1,024,000,000 logical
payload bytes. Every listed workload completed 1,000 operations, with zero failed
or unattempted samples.

| Case file | Verified SHA256 |
| --- | --- |
| [raw-1.json](raw-1.json) | `8bb8b7a23426818098563ddda7fd418ed4bcf007606c52afa0693f5c0cb80dee` |
| [local-1.json](local-1.json) | `81c25fe8892a0858c36880225216ba992ae1428ae827c2130ab0c71ef91393d8` |
| [replicated-1.json](replicated-1.json) | `97b966bcfff78ce790d6ce4db24aa7da7a4597f78f46a9d537f376bc565118f7` |

## Latency and throughput

Latency columns are microseconds; throughput is successes per second over the
whole workload interval. These are sequential closed-loop observations, with
one run and about ten observations in the p99 tail. No confidence interval,
saturation throughput or success SLA is inferred.

| Deployment | Workload | p50 µs | p99 µs | Successes/s |
| --- | --- | ---: | ---: | ---: |
| raw | Raw borrowed lookup | 0.375 | 0.542 | 2,570,965.063 |
| local | Owned point get | 3.125 | 6.625 | 195,977.561 |
| local | Shared point get | 1.042 | 1.292 | 344,288.359 |
| local | Durable single-document write | 23,801.084 | 28,839.041 | 36.629 |
| local | 90/10 read/write | 3.583 | 28,749.791 | 131.216 |
| local | 50/50 read/write | 32.666 | 203,462.250 | 52.562 |
| local | Indexed equality | 25.125 | 57.792 | 32,459.013 |
| replicated | Owned point get | 19.375 | 30.875 | 46,870.055 |
| replicated | Shared point get | 18.250 | 27.083 | 48,394.610 |
| replicated | Durable single-document write | 65,922.625 | 122,481.333 | 12.387 |
| replicated | 90/10 read/write | 26.250 | 140,264.833 | 70.097 |
| replicated | 50/50 read/write | 50,001.916 | 874,020.375 | 14.914 |
| replicated | Indexed equality | 45.292 | 75.417 | 20,046.525 |

Raw lookup borrows a resident body without authentication, cloning, index or
durability work. Embedded access includes actual tenant authorization; owned
and shared-handle return paths are separate measurements. Local reads capture
committed resident state, while replicated reads establish a fresh quorum barrier.
Owned reads precede shared reads over the same IDs, so the lower observed shared
latency does not isolate cloning cost or establish an intrinsic speed multiplier.
Raw and database rows have different contracts and cannot justify a Redis ratio.

Durable rows include schema/index work, encrypted immediate two-phase redb
persistence, receipts and mutation audits. Replicated acknowledgment additionally
requires quorum persistence and local application. Three voters use separate
files in one process on one host, excluding remote network latency and independent
physical failure domains. Mixed percentiles combine read/write distributions;
the 50/50 median is sensitive to their boundary. Strict successful-read audit
is disabled. The test wrapping provider uses real encryption but excludes Transit
network latency; RPC/MCP are not measured by these cases.

## Resident state, groups and clean recovery

Memory and disk figures below are GiB. They include the entire harness process,
allocator state and all resident replicas, rather than only document heap size.

| Deployment | Resident voter instances | Service audit stores | Loaded RSS | After work RSS | After recovery RSS | Disk |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 0 | 0 | 1.969 | 1.969 | — | 0.000 |
| local | 1 | 1 | 4.061 | 5.540 | 9.884 | 4.000 |
| replicated | 3 | 3 | 13.967 | 15.303 | 26.254 | 12.000 |

Local and replicated each represent one logical tenant Raft group, with one
and three resident voter instances respectively; these cases have no control
group. Separately encrypted audit stores are shared per replica node. Their
opening/key/memory/disk costs are included, not counted as extra Raft groups.
The empty-state increase over process baseline is 3.328 MiB local and 4.219 MiB
replicated; empty index setup adds 3.172 and 3.078 MiB. These whole-process
initialization deltas do not isolate individual Raft or audit-store costs.
Incremental tenant overhead needs the completed 100/1,000-tenant comparisons.

Loaded RSS per resident payload byte is 2.065 raw, 4.258 local and 4.882 replicated
(14.646 replicated per unique logical payload byte). These include infrastructure
and replicated copies, not a claim about document-object overhead or maximum
capacity. Recovery RSS is materially above loaded RSS and requires headroom.

| Deployment | Open s | Load s | Shutdown s | Recovery s |
| --- | ---: | ---: | ---: | ---: |
| raw | 0.000001 | 1.345809 | — | — |
| local | 0.202037 | 156.815198 | 1.801610 | 47.113793 |
| replicated | 0.533787 | 376.497120 | 4.442756 | 119.991308 |

Shutdown finishes database-owned work and storage closure. Recovery starts
afterward and includes reopening, index reconstruction, key access, readiness
and a verified point read per tenant; final cleanup is outside those timers.
These three cases reached normal case completion, including final cleanup. They
are clean-recovery observations, not injected crash or power-cut evidence.

In database case JSON, `peak_rss_bytes` is the OS process peak sampled **before shutdown**,
not refreshed after recovery. Its local value is 7.529 GiB and replicated value
23.370 GiB; later after-recovery RSS reaches 9.884 and 26.254 GiB respectively.
Those fields are preserved unchanged and must not be described as a final
whole-run peak. Five-second host sampling can also miss short excursions.

## Shared-host qualification

[Host samples](host-samples.jsonl) show substantial permitted background activity.
Within these completed case intervals, sampled aggregate background CPU was
1,585.4% for the single raw sample, approximately 1,330–1,586% for 52 local samples,
and 350–1,571% for 132 replicated samples; 100% represents one logical CPU.
Compiler/linker and `qemu-system-aarch64-headless` names appear among competing
processes. The inspected live manifest recorded 201 competing-process violations
under the explicit `--allow-host-load` override. This is macOS arm64 with 16
logical CPUs, not isolated benchmark hardware. No unrelated process was stopped.

These observations do not establish which background process caused an individual
latency, nor intrinsic engine speed, production Linux capacity or a cross-database
advantage. The remaining cases and every finite failure must stay visible in the
terminal matrix before a complete capacity interpretation is published.
