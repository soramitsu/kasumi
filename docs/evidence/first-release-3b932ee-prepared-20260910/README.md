# Prepared combined first-release cohort

Status: **PREPARED, UNRUN**. No compiler or test result is asserted by this record.
The isolated checkout is `/tmp/kasumi-first-release-3b932ee-check`, commit
`3b932ee0a2de86b76655b5bef6dd4cc4fff82fab`, tree
`4f696e370e184ea36e5f3314feeb064679b6d3ba`.

It combines canonical administration, acknowledged pair/singleton catalog owners,
strict local recovery publication, standalone operator retention and configured HA
tenant enrollment. The prior prepared `be04883` plan was superseded before any
dispatch when enrollment became available. Both plans are retained byte-for-byte.

The new plan retains the original 900-second workspace compiler, 300-second
formatting, 900-second complete store library and 600-second strict-store limits.
All previous 32 required store tests remain, plus 12 singleton/pair acknowledgement
tests. Compilation uses Rust 1.97.1, locked/offline dependencies and one build job.
The existing runner stops after the first failure and records exact process-group
drain, source, toolchain, dependency and executable provenance.

This is a diagnostic cohort. It does not execute the new standalone/HA server
regressions, the entire workspace test suite, platform or production builds, actual
capacity, provider interoperability, recovery faults or endurance gates. Explicit
Control genesis, canonical leaf drain results and persistent disk/native capacity
remain separate implementation work. Foreign ordered-seek work is excluded.

The bounded standalone source review is retained separately with its actual scope
and limitations. Its conclusion is not a substitute for those unrun tests.
