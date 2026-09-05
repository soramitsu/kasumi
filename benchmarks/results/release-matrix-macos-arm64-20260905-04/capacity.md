# Measured capacity

Matrix outcome: `failed`. Quietness screening passed: `False`.

Footprints are shared between API layers and must not be added together. Missing values mean not measured.

| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Shutdown s | Recovery s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 1 | 68.56 | — | 2016.23 | 2016.23 | — | — |
| local | 1 | 71.81 | 75.12 | 4179.55 | 5123.75 | — | 28.990 |
| replicated | 1 | 72.78 | 76.20 | 12588.14 | — | — | — |
| text | 1 | 72.00 | 81.19 | 5123.25 | — | — | — |

The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.

- One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.
- API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.
- Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.
- RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.
- Shutdown is timed separately through complete database closure or successful server process exit. Recovery starts after shutdown and covers reopen/spawn through verified reads; final cleanup is excluded. OpenBao and issuer remain running for network restart. These are not crash/power-loss measurements.
- Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.
- An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.
- replicated-1: incomplete, mismatched, or not bound to matrix result/executable hashes; observed values are not used for overhead derivation
- text-1: incomplete, mismatched, or not bound to matrix result/executable hashes; observed values are not used for overhead derivation
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
