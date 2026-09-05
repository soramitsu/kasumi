# Measured capacity

Matrix outcome: `failed`. Quietness screening passed: `False`.

Footprints are shared between API layers and must not be added together. Missing values mean not measured.

| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Shutdown s | Recovery s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 1 | 68.64 | — | 2015.45 | 2015.45 | — | — |
| local | 1 | 71.88 | 75.19 | 4178.59 | 4921.58 | 0.938 | 27.809 |
| replicated | 1 | 72.77 | 76.06 | 13422.11 | 14326.20 | 3.427 | 94.250 |

The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.

- One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.
- API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.
- Service security-audit stores are shared per node, included in memory/key/disk observations, and counted separately from tenant/control Raft groups. Older results without declared counts retain their original fixture attribution.
- Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.
- RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.
- Shutdown is timed separately through complete database closure or successful server process exit. Recovery starts after shutdown and covers reopen/spawn through verified reads; final cleanup is excluded. OpenBao and issuer remain running for network restart. These are not crash/power-loss measurements.
- Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.
- An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.
- replicated-1: incomplete, mismatched, or not bound to matrix result/executable hashes; observed values are not used for overhead derivation
- text-1: no result file
- network-1: no result file
- raw-100: no result file
- local-100: no result file
- replicated-100: no result file
- text-100: no result file
- network-100: no result file
- raw-1000: no result file
- local-1000: no result file
- replicated-1000: no result file
- text-1000: no result file
- network-1000: no result file
