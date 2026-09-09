# Focused shutdown and receipt checkpoint: failed

Source `711b32d962f7406820129dd53533c45a3c5fd2a8`, tree
`aaa88a77afeef3ba437ad2e4a418f62d6cf1690e`, remained clean and unchanged.
The macOS ARM64 runner used Rust 1.97.1, one Cargo build job and one test
thread. Actual executable hashes, lockfile and tool hashes, commands, logs and
process-group drain evidence are in `evidence.json`. Session 28258 exited 101.

| Executed group | Result | Total command seconds |
|---|---|---:|
| Verifier task registration and cancelled drain | 1 passed | 32.874 |
| Security audit retention, worker ownership and reopen | 5 passed | 118.395 |
| Tenant audit maintenance | 1 passed, 1 failed | 4.380 |

The new `tenant_audit_worker_keeps_its_owner_through_cancelled_shutdown`
fixture failed at `audit_maintenance_service.rs:179`: its tenant policy lacked
the required administrator. This happened before its shutdown ownership
assertions. The failed fixture is not a passing ownership regression.

The runner stopped at that failure. The remaining memory, coherent-read,
receipt, target, signer, native/MCP and three-node restored-runtime restart
groups, strict lint, production check and formatting **did not run** in this
attempt. Nothing here establishes that the earlier Linux database-lock failure
has been corrected. This implementation checkpoint is not integrated as a
validated change.

This is functional evidence from a shared host. A separate warm compiler-only
cohort briefly overlapped; its scope and the observed memory headroom are
recorded in `shared-host-scope.json`. No quiet-host performance, 3 GiB capacity,
endurance or final release acceptance is claimed.
