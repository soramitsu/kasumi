# Measured capacity

Matrix outcome: `failed`. Quietness screening passed: `False`.

Footprints are shared between API layers and must not be added together. Missing values mean not measured.

| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Recovery s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 1 | 68.59 | — | 2016.09 | 2016.09 | — |
| local | 1 | 71.94 | 75.20 | 4166.42 | 5270.45 | 28.658 |
| replicated | 1 | 72.84 | 76.14 | 12961.08 | 14032.58 | 86.523 |

The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.

- One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.
- API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.
- Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.
- RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.
- Clean reopen is distinct from crash/power-loss safety. OpenBao and issuer remain running for network restart.
- Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.
- An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.
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
