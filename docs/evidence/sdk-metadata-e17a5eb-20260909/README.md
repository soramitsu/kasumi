# SDK response metadata regressions

Combined source `e17a5eb802487417da0ca90b7e09e2f9bef72ab0`, tree
`4e90cd5437552d4d913bb75eb954c2cab10fa858`, passed the literal decoder's
11 tests, client strict Clippy and workspace formatting on Rust 1.97.1,
macOS ARM64. The tests include exact change-feed after-image identity and
commit version, plus schema and collection epoch consistency. Positive cases
retain historical events beneath a newer outer revision and requested absent
collections. No backward compatibility decoder or alternate format was added.

The gates took 33.183, 26.438 and 1.960 seconds respectively. Each had one
compiler job and a 300-second original deadline. The test target used one test
thread; 22 unrelated tests were filtered out, and none were ignored. All three
owned process groups drained, and source, tree, tracked-file hashes and lockfile
remained unchanged. The actual test executable was copied and hash-verified
before target reuse; its SHA-256 is
`c956d9e65d90a5877f84cc9dec5ebc888ce5258e6db49cd1b301117a813b6402`.

[evidence.json](evidence.json) records commands, original timeouts, actual
compiled features, executable paths and terminal results; its SHA-256 is
`3ce051ebe6333d8959fc3ff6de5b2241399f66c080f62b7f3eb7b9ebf1f71f04`.
[preservation.json](preservation.json) binds the copied logs, frozen plan,
runner and source inventory to their original paths and bytes. The executable
itself is retained separately and is not included here.

The runner's isolated process checks covered a normal exit, a child surviving
its leader, and repeated cancellation. The initial existence probe failed on
Darwin with `PermissionError` for a reaped process group; the corrected probe
checks exact numeric process-group membership. These helper checks exercise
process ownership only. Their recorded runner hash precedes the final review
fixes for uncertain cleanup, failed source inspection and mandatory test
executable evidence; the actual Cargo cohort used the captured final runner.

Only the SDK dependency graph compiled during these gates. The new server TLS
regression is present in this source, but no engine/store/server/Raft compilation,
native listener or recovery test ran here. The host overlapped another task's
native test. These results do not establish capacity, performance, final-source
workspace acceptance or release readiness.
