# Frozen integration launch

The exact d403c55 source is running native Linux ARM64 functional gates in the
pinned validation image after all current lease, activation and remote signer
checkpoints were integrated. Host preflight, toolchain, formatting, Python and
patched dependency gates passed. By the captured progress JSON, the workspace
gate had failed while linking the server test executable; the initial README
incorrectly described that gate as still running. The raw JSON is unchanged.
Kernel and cgroup records confirm that the 7 GiB limit caused an OOM kill of
`ld`. The full workspace tests did not execute. Later gates continue, but this
attempt cannot produce a candidate. The full failure log is retained here.

The runner owns an exclusive VM output directory. Its source is read-only and
its 200 GiB reference disk preserves the earlier failed workspaces. A successful
whole functional run is required before its script attempts candidate packaging
and repeated-assembly checksum comparison. Later results must retain their
actual status; this launch is not final release acceptance.

The equivalent integrated macOS worktree passes a full all-target/all-feature
locked compile check. It does not replace the actual full functional gates.
