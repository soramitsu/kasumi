# Measured capacity

Matrix outcome: `completed_with_failures`. Quietness screening passed: `False`.

Footprints are shared between API layers and must not be added together. Missing values mean not measured.

| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Shutdown s | Recovery s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw | 1 | 68.64 | — | 2016.27 | 2016.27 | — | — |
| local | 1 | 72.09 | 75.27 | 4158.53 | 5672.70 | 1.802 | 47.114 |
| replicated | 1 | 73.00 | 76.08 | 14302.70 | 15670.70 | 4.443 | 119.991 |
| text | 1 | 72.23 | 81.17 | 5401.50 | 5819.05 | 1.173 | 104.870 |
| network | 1 | 19.56 | 21.53 | 4127.77 | 4302.84 | 0.991 | 27.986 |
| raw | 100 | 68.72 | — | 1958.19 | 1958.19 | — | — |
| local | 100 | 80.41 | 85.86 | 4128.55 | 4169.14 | 0.634 | 17.746 |
| replicated | 100 | 107.50 | 118.59 | 12372.02 | 12490.14 | 2.079 | 52.699 |
| text | 100 | 80.20 | 92.61 | 4583.86 | 4615.48 | 0.687 | 65.062 |
| network | 100 | 35.69 | 40.09 | 4069.02 | 4182.27 | 0.742 | 20.909 |
| raw | 1000 | 68.66 | — | 2046.52 | 2046.52 | — | — |
| local | 1000 | 116.89 | 170.48 | 4439.72 | 4483.97 | 0.576 | 17.692 |
| replicated | 1000 | 755.22 | 973.72 | 14725.50 | 15166.94 | 6.363 | 106.412 |
| text | 1000 | 91.66 | 135.34 | 5620.39 | 5716.81 | 2.444 | 119.304 |
| network | None | — | — | — | — | — | — |

The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.

- One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.
- API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.
- Service security-audit stores are shared per node, included in memory/key/disk observations, and counted separately from tenant/control Raft groups. Older results without declared counts retain their original fixture attribution.
- Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.
- RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.
- Shutdown is timed separately through complete database closure or successful server process exit. Recovery starts after shutdown and covers reopen/spawn through verified reads; final cleanup is excluded. OpenBao and issuer remain running for network restart. These are not crash/power-loss measurements.
- Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.
- An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.
- network-1000: incomplete, mismatched, or not bound to matrix result/executable hashes; observed values are not used for overhead derivation
