# Frozen functional attempt at 7732c06

This run failed acceptance. The frozen source, dependency lockfile and per-gate
executable hashes are in `evidence.json`; raw output and source inventory remain
beside it. Nothing in this record certifies the current integration or release.

Rust 1.97.1, formatting, Python, dependency patch checks/regressions, strict
workspace Clippy, the production feature graph and all three production binaries
passed on macOS ARM64. Workspace tests failed four targets: engine security-audit
fixtures, lifecycle rejection handling, response-release fixture admission and
server audit/local-recovery fixtures. Raw failures are retained in `workspace.log`.

Subsequent source changes address those failures: `621b7d4` and `03adc0e` use one
fixture governor; `26210c1` retains the local recovery governor; `d190465` resolves
an ambiguous original lifecycle completion with a fresh quorum observation before
retrying the unchanged command. Focused sibling checks do not replace a new full
integration attempt. Production executables remain at the recorded absolute
paths under `/tmp/kasumi-functional-20260908-custody-signer/target/release`.
