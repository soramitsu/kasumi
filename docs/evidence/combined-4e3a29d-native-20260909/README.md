# Combined native SDK and workspace validation

Frozen source `4e3a29d9b459690072ecf13a570d1869e3070427` passed all
eleven selected native and codec tests, strict workspace Clippy and production
binary compilation without default features on Rust 1.97.1/macOS ARM64.

| Gate | Actual result | Seconds |
| --- | --- | ---: |
| SDK schema, mutation, query, feed and admission over pinned TLS | 1 passed | 19.609 |
| Pool receipt routing and historical pagination | 1 passed | 1.693 |
| Guarded stop through secure SDK | 1 passed | 1.717 |
| Local recovery phases and old-resource fencing | 1 passed | 8.311 |
| Pinned TLS 1.3 native channel | 1 passed | 102.977 |
| Atomic TLS reload and invalid replacement | 1 passed | 1.725 |
| Audit TLS pagination and original response fences | 1 passed | 31.741 |
| Canonical snapshot literal values | 1 passed | 0.943 |
| Native, MCP and history literal codecs | 3 passed | 0.577 |
| Strict workspace, all targets and features | passed | 132.639 |
| Production server binaries, no default features (`cargo check`) | passed | 51.732 |

The final formatting command failed on one line wrap in the indexed staged
lineage fix. The original cohort remains failed. Successor
`980daa4c1378813cd98da69045d46f0b77b75bd6` changes only that whitespace and
passes formatting in 1.321 seconds. Tests were not repeated for this formatting
change. Earlier failed canonical-exponent setup and lineage validation remain
in their separate evidence directories.

All twelve original command groups and the format successor group drained.
Source/tree/lock hashes remained unchanged in each execution. The exact logs,
plans, compiler feature records, source inventories, binary hashes and original
deadlines are retained in [4e3a29d/evidence.json](4e3a29d/evidence.json) and
[980daa4-format/evidence.json](980daa4-format/evidence.json).
[preservation.json](preservation.json) binds copied raw files. Actual test/build
executables were separately copied and hash-verified before target reuse.

The focused test passes cover the combined SDK, receipt, canonical JSON and
shutdown changes. They do not cover the separately staged permanent-prefix,
target receiver/status and signer dispatch changes. Compilation is not a
production release build; complete workspace tests, final Linux and macOS
release gates, capacity workloads and endurance acceptance remain open.
