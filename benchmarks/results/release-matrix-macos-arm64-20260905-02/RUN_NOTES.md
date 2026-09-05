# Matrix interpretation

This run follows the validated frozen source. Unrelated host activity remains
recorded; it is not an isolated-machine measurement or external database speed
comparison. Temporary `caffeinate -i` inhibits automatic idle system sleep only
for the driver lifetime, with no global power-setting or display changes.

The matrix source SHA256 is
`a36dd4e69700ea7e20aec5784106c0034f306d50edfec8939ad2b46ba439a63f`.
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
