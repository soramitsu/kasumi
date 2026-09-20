# Frozen ownership cohort interrupted for main-checkout restriction

Frozen source `6d969f3332befac76e15b686bb225da7e3f49725` / tree
`e816699752212742e5246242f582c3d3cd1b3ad9` began on September 20, 2026,
at 07:27:36 UTC and ended at 07:35:09 UTC. Its unchanged 47-gate plan retained
252 mandatory cases, original commands, ordering and deadlines. Four gates
passed; the fifth was explicitly interrupted; 42 later gates did not run.

| Gate | Outcome | Seconds | Test result |
| --- | --- | --- | --- |
| workspace-all-targets-check | passed | 258.057 | workspace all targets/features compiled |
| workspace-format | passed | 2.408 | workspace formatting |
| rmcp-terminal-ownership | passed | 42.386 | 9 passed, 0 failed |
| rmcp-upstream-protocol | passed | 93.645 | 60 passed, 0 failed across six targets |
| raft-application-write-classification | interrupted; raw status `failed` | 50.277 | no test summary or assertion outcome |

The coordinating release task stopped the external runner to comply with the
user's instruction that all further work use `/Users/mtakemiya/dev/kasumi` on
`master` only. It reported runner PID 77801. The original process receipt
independently records SIGTERM 15, process group 82510, process termination `-15`
and normalized exit code 143, with no timeout. The runner PID and reason for
interruption come from the coordinator, not from the raw process receipt.

The interrupted gate compiled its test binary and began launching its unit tests,
but produced no test result. This is an intentional interruption, **not an
established code-test failure**. The original runner records the gate and overall
run as `failed`; those bytes and its generic gate-failure error are preserved
without reinterpretation as a pass. The original commands must be rerun against
the newly frozen main source before qualification.

All five dispatched process groups drained, with empty terminal membership and
no cleanup errors. Source comparison remained unchanged. The 42 withheld gates
include the corrected store allocation boundaries and Control genesis cases, so
this run does not validate those corrections. The 69 passing rmcp cases and
compilation/formatting are scoped results for this historical source. They do
not qualify merged master, installed disk admission, final platform/live-provider
operation, capacity, endurance or release artifacts.

Nine raw files were copied byte-for-byte from
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-6d969f3-ownership-disk-startup`.
[copied-files.json](copied-files.json) records original paths, sizes and SHA-256
values. Source-manifest, plan, runner and all five log hashes match
[evidence.json](evidence.json). The lockfile and process-helper hashes also match
the frozen source's Git objects and source manifest. Historical worktree paths in
the original records remain provenance; no work resumes there.

[preserved-executables.json](preserved-executables.json) records eight binaries
whose hashes and sizes were verified at their original external paths, totaling
287,064,176 bytes. Their bytes were not copied into Git and their presence here
does not imply the interrupted Raft tests passed. No original binary was executed
during preservation. [summary.json](summary.json) records both raw and interpreted
gate counts, process receipts and the exact 42 unrun gates.

The preceding [failed `c681ba3` cohort](../first-release-c681ba3-check-20260920/README.md)
remains preserved, including its three allocation assertions. This interrupted
successor neither replaces nor resolves that failure.
