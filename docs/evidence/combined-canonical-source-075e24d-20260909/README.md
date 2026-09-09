# Combined source and type checks

Frozen validation source `075e24dc95c39be8e2c63baf63aa22aae78539ea`, tree
`4326a8ab9fb669c1444c97d46902175fb14e828f`, combines the corrected JSON
dependency, canonical payload encoding, admitted SDK decoding, shutdown/receipt
changes and current release tooling. This is macOS ARM64 shared-host evidence.

| Gate | Result |
| --- | --- |
| Release-tool Python tests | 36 passed, 1.669 s |
| Exact dependency resolution and source hashes | Passed, 0.631 s; bitmaps 11 inputs, lru 8 inputs, serde_json 90 inputs |
| Workspace formatting | Passed, 1.389 s |
| Canonical typed payload tests | 6 passed, 9.590 s |
| Type-library unit tests | 13 passed, 7.368 s |
| Strict type-library lint, all targets/features | Passed, 10.855 s |

The canonical tests exercise actual typed writers/digests for mutations, staged
chunks, schema changes and archived documents, plus literal marker keys, exact
numbers and bounded writer failure. This invocation uses the recorded combined
workspace dependency graph; it does not alone prove the external preserve-order
graph. Both source and type runners completed successfully, kept source/lock
identities unchanged, and drained every owned process group.

No engine/store/server/Raft compilation, native listener, external provider,
full workspace, production build, capacity or endurance gate ran in these scopes.
Actual external-consumer tests and native integration remain required. Raw logs,
commands, source/tool/lock identities and executable hashes are retained here;
preserved-executables manifests refer to the local executable copies.
