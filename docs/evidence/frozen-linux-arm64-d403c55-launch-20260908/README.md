# Frozen integration launch

The exact d403c55 source is running native Linux ARM64 functional gates in the
pinned validation image after all current lease, activation and remote signer
checkpoints were integrated. Host preflight, toolchain, formatting, Python and
patched dependency gates passed before this capture; workspace execution and
later gates were still running. This directory records launch provenance only.

The runner owns an exclusive VM output directory. Its source is read-only and
its 200 GiB reference disk preserves the earlier failed workspaces. A successful
whole functional run is required before its script attempts candidate packaging
and repeated-assembly checksum comparison. Later results must retain their
actual status; this launch is not final release acceptance.

The equivalent integrated macOS worktree passes a full all-target/all-feature
locked compile check. It does not replace the actual full functional gates.
