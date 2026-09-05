# Measured capacity

Matrix outcome: `completed_under_host_load`. Quietness screening passed: `False`.

Footprints are shared between API layers and must not be added together. Missing values mean not measured.

| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Shutdown s | Recovery s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| network | 1 | 19.45 | 21.41 | 4190.81 | 4923.83 | 1.090 | 29.221 |
| network | 100 | 36.00 | 40.64 | 4290.42 | 4425.16 | 0.657 | 19.266 |
| network | 1000 | 191.19 | 235.05 | 4717.44 | 4829.89 | 1.608 | 52.016 |

The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.

- One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.
- API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.
- Service security-audit stores are shared per node, included in memory/key/disk observations, and counted separately from tenant/control Raft groups. Older results without declared counts retain their original fixture attribution.
- Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.
- RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.
- Shutdown is timed separately through complete database closure or successful server process exit. Recovery starts after shutdown and covers reopen/spawn through verified reads; final cleanup is excluded. OpenBao and issuer remain running for network restart. These are not crash/power-loss measurements.
- Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.
- An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.
- raw-1: no result file
- local-1: no result file
- replicated-1: no result file
- text-1: no result file
- raw-100: no result file
- local-100: no result file
- replicated-100: no result file
- text-100: no result file
- raw-1000: no result file
- local-1000: no result file
- replicated-1000: no result file
- text-1000: no result file
