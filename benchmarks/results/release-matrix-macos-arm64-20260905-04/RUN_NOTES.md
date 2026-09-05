# Matrix interpretation

This run follows the validated frozen source. Unrelated host activity remains
recorded; it is not an isolated-machine measurement or external database speed
comparison. Temporary `caffeinate -i` inhibits automatic idle system sleep only
for the driver lifetime, with no global power-setting or display changes.

The matrix source SHA256 is
`c55682adadd4c92e499f8a252a6f8fdb496184b4b0f693fe53a6e49195728f58`.
It includes crate sources, manifests, lockfile, scripts and applicable configuration
files. Inner local reports use the narrower Cargo.toml/Cargo.lock plus crate
`.rs`/`.toml`/`.proto` scope, SHA256 `58d2da6a2807d6faa30b4238c38a562e4eec180c88e01f1719ceeb7daa43d79d`.
Both hash scopes are intentional. Actual binaries and completed result files
also have recorded SHA256 identities. Inner preliminary-development labels remain
unchanged; frozen provenance does not establish repeatability or maximum capacity.

Owned reads precede shared reads over the same deterministic IDs. Raw maps run
in a separate process. Native RPC precedes MCP on the same server, with one
untimed read per credential before each protocol's measured work. Cache warmth,
allocator retention, receipts and audit growth can affect later workloads.
No workload randomization or repeated-run confidence interval is claimed.
With 1,000 samples, the p99 tail comprises roughly ten observations.

Each workload stops at its first failed attempt without a hidden retry. Reports
preserve preceding successful samples, the failure's duration/code and explicit
unattempted count. Success percentiles exclude failures; success throughput uses
whole elapsed workload time including a failed-attempt delay. Zero successes
produce null success latency. Safe later workloads and independent cases continue;
unknown writes remain unknown and subsequent unconditional replacements preserve
the ordinal invariant used by recovery verification. Phase checkpoints retain
earlier observations if loading or recovery fails. Any failed case causes a
nonzero overall exit and `completed_with_failures` after the remaining cases.

The authoritative run status is in `matrix.json`; this note does not claim that
an unfinished matrix completed. Shared API footprints must not be added together.
Three voters share one process/host with separate durable stores, so physical
failure domains and remote network costs are not measured here. Strict successful
read auditing is disabled; mutation audits remain enabled, and network requests
also persist authentication audits. Recovery and capacity definitions are in
`benchmarks/CAPACITY.md`.

The only changes after the preceding full Rust validation are a disk-guard
precedence fix and its Python regression. Exact diff, unchanged-source hashes,
and unchanged executable identities are preserved in run02/guard-validation;
both Mac and Linux passed the three Python guard and independent-case continuation tests.

The outer execution wrapper runs in its own OS session. Both wrapper and matrix
driver use `/dev/null` stdin and regular-file `driver.log` stdout/stderr, verified
through their live file descriptors. `execution.json` records wrapper/driver
PIDs and terminal exit status. This avoids the previous run’s broken output pipe
when its initiating tool session ended. `execution-wrapper.py` preserves the
exact wrapper source; it is separate from the unchanged measured implementation.
