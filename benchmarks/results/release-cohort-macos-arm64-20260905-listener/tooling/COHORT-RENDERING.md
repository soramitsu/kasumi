# Verify and regenerate the measured report

The final report selects fifteen completed cases with 99,000 successful
operations. Twelve embedded observations retain source `a3205990…`; three
network observations use `28aeb801…`. The exact unchanged embedded executable
and the TLS-only source difference justify reuse. No raw record is relabeled.

These archived helpers locate the repository through
`scripts/run_benchmark_matrix.py` in an ancestor directory. Keep
`release_cohort.py`, `render_release_report.py` and
`render_completed_release_report.py` together. They use sibling imports and do
not depend on an ignored build-directory copy. Run commands from the repository
root.

The complete read-only provenance check is:

```sh
python3 benchmarks/results/release-cohort-macos-arm64-20260905-listener/tooling/release_cohort.py
```

It checks all terminal outcomes, wrapper/source identity, release executable
bindings, raw result and log hashes, platform/service evidence, exact 1 KiB
payloads, requested sample counts, both network protocols and capacity derivation.
Failures remain failures; a failed startup creates no observed ready groups.

To regenerate the report, choose fresh output paths. This example must not be
reused if its output files already exist:

```sh
mkdir -p benchmarks/results/release-cohort-reproduction
python3 benchmarks/results/release-cohort-macos-arm64-20260905-listener/tooling/render_release_report.py \
  --matrix benchmarks/results/release-matrix-macos-arm64-20260905-06 \
  --network-cohort benchmarks/results/network-rerun-macos-arm64-20260905-listener \
  --cohort-manifest benchmarks/results/release-cohort-reproduction/cohort.json \
  --cohort-capacity benchmarks/results/release-cohort-reproduction/capacity.json \
  --output benchmarks/RESULTS-reproduced.md
```

The helpers perform no benchmark or service operation. The renderer refuses to
overwrite existing cohort JSON. Each raw link retains its origin; the manifest
has separate case source identities and records the actual archived helper
hashes. The original failed network-1000 remains in the report's history.

The report separates six API layers and indexed text, and includes outcomes,
p50/p99, throughput, memory, shutdown, recovery and incremental tenant overhead.
It distinguishes one logical tenant Raft group from its resident voter instances,
pre-shutdown peak RSS from after-recovery RSS, and configuration from observed
readiness. Authentication auditing, disabled strict read auditing, host activity,
text result sizes, sample limits and earlier cache-cleanup overlap are explicit.
No Redis multiplier, saturation capacity or production SLA is inferred.

Eight synthetic reporting checks passed in the original and temporary archive
locations. Their [portable check log](cohort-renderer-tests-portable.log),
[archive check log](cohort-archive_unit_tests.log) and
[portability record](cohort-renderer-portability.json) are retained. They are
reporting checks, not database measurements. The readiness-time check correctly
blocked the then-running network supplement. Subsequent
[prose-only corrections](../report-wording-correction.json) clarify selected
observations and resident voters without changing numerical derivation or guards.
