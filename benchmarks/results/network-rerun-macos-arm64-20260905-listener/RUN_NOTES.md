# Network listener correction measurements

This supplement repeats native RPC and MCP at 1, 100 and 1,000 tenants, with
1,000,000 exact 1 KiB fixture documents total per case and 1,000 operations per
workload. It uses the TLS-only correction on source `28aeb801…`, following fresh
macOS/Linux all-feature/all-target gates and actual OpenBao/MinIO validation.
The archived driver changes only the selected modes and locates the repository
for replay; the original resource, source and executable guards remain active.
The detached wrapper logs to regular files and inhibits idle sleep only for its
own lifetime. It never stops unrelated processes or lowers the 30 GiB disk floor.

The release build's embedded `kasumi-bench` executable is byte-for-byte identical
to the previous run06 executable (`a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7`).
The twelve raw/local/replicated/text cases remain at their original paths and
retain their original `a3205990…` source identity. A final cohort may combine
those cases with this supplement only after checking all hashes and terminal
outcomes. The prior network-1000 startup failure remains retained; this
supplement does not relabel the earlier matrix as successful.

These are one sequential closed-loop measurement per workload on a shared
macOS host, with competing activity explicitly permitted and recorded. They
are not isolated-host limits, production Linux results or external database
comparisons. At 1,000 samples, nearest-rank p99 has approximately ten tail
observations; no repeatability interval, Redis multiplier or launch SLA is claimed.
Native RPC and MCP use real loopback TLS, signed user tokens and OpenBao.
Authentication and mutation auditing are active; strict successful-read auditing
is disabled. Setup, observed service footprint, workload, shutdown and recovery
have separate fields and scopes. Raw JSON and host samples are authoritative.

Reproduction requires the repository's pinned dependencies and cached OpenBao
fixture as described in `benchmarks/README.md`. Use the archived `network-driver.py`
with a fresh `--output-directory`, `--documents 1000000 --operations 1000
--tenants 1,100,1000 --skip-build --allow-host-load` after a matching release build.
Do not overwrite the original evidence directory. The wrapper additionally
requires and verifies the recorded source-specific platform and service gates.
