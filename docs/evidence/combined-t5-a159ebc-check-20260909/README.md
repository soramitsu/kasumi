# Combined typed restore fixture compilation failure

Frozen source `a159ebc78abfa8acbefd66e54e102f96b64c819e`, tree `c6e88007e653a38845e54294994d5a4185a24354`, failed the combined workspace
all-target/all-feature check after 118.880 seconds on Rust
1.97.1/macOS ARM64. Compilation reached the engine library tests and reported
11 missing type/function imports in the new public restore fixture and changed
coordinator snapshot fixture. The earlier verifier admission type error did
not recur. Formatting and functional tests were unrun.

Owned process group 2407 drained and source/tree/lock hashes
remained unchanged. Raw diagnostics, exact source inventory, plan, dispatcher
and process evidence are preserved byte-for-byte by `preservation.json`.
Successor `1682a8f` adds canonical imports and does not change test assertions.
Its verification is separate; this attempt remains failed.
