# Restore workspace handoff evidence

Source `b002771` transfers verification workspace into materialization after
index drain and retains its original reservation through target publication.
The real encrypted backup/verify/materialize/publish/reopen fixture fits the
unchanged 512 MiB budget with 192 MiB maintenance and 128 MiB destination work
already retained. This resolves the overlap found in the failed frozen Linux
`3ee5787` run; that failed run remains preserved separately.

On this macOS ARM64 source the real three-runtime TLS lifecycle test passed
(69.56 seconds test time), all eleven backup tests passed, the handoff and actual
expiry-drain tests passed, and strict workspace Clippy, fixture-free server
checks and formatting passed. This is not a final-source Linux gate, actual
3 GiB capacity measurement or completed recovery-coordinator acceptance.
