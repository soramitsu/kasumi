# redb capacity prototype: retained leaf-gate attempts

This is an experimental, unintegrated storage dependency prototype. Kasumi's
production dependency graph is unchanged. Tests run on macOS ARM64 with pinned
Rust 1.97.1, one Cargo job and a 300-second deadline per command. Full upstream
`just test`, fuzzing, database-wide disk ownership, commit preparation and Kasumi
production acceptance remain unfinished.

| Attempt | Actual result |
| --- | --- |
| `6226-offline` | Dependency preparation failed before compilation: the cache lacked the upstream `redb 2.6.0` development dependency. |
| `6226-fetch` | Target-specific locked dependency fetch passed; source and lock stayed unchanged. |
| `6226-compile` | Compilation failed after 10.712 s: three missing `GrowthState` test imports and one unused import. No tests ran. |
| `ccf76d6` | Compilation passed; seven focused tests ran, one passed and six failed. Total 9.888 s. |

In `ccf76d6`, the shared allocator/system-namespace state regression passed.
Five tests failed at reopening their 512-byte-page fixture with a builder that
expected 4096-byte pages. The replacement test failed a fixed 128 KiB file-size
assumption before its capacity assertions. These failures remain recorded; the
rollback, retained-charge, restart and genuine-I/O-failure assertions have not
been accepted as passing complete tests.

All attempts are terminal, sources stayed unchanged, and owned process groups
drained. Per-attempt evidence records source trees, root and leaf lock hashes,
tool and runner hashes, exact commands, raw output, and actual test executable
hashes. Preserved local executable copies are listed separately.

The older redb dependency belongs only to the unmodified upstream development
graph. It adds no Kasumi legacy storage decoder or compatibility mode. The
first-release design continues to reject unsupported Kasumi formats directly.
