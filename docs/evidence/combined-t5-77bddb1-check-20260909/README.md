# Combined typed snapshot and recovery compilation failure

Frozen source `77bddb1ccd56068e51e0990b7363331836b26933`, tree
`d67525a660fe6780bcea838eccdbd3812a2cf758`, failed the first combined
workspace all-target/all-feature check after 19.386 seconds on Rust 1.97.1,
macOS ARM64. The backup verifier received an owned admission Arc where its
signature requires a borrow; two added history-loop bindings were unused.
Formatting and every functional gate were unrun. No functional result is
claimed by this compilation attempt.

The owned process group 99802 drained. All source/tree/lock hashes remained
unchanged. Raw diagnostics and the exact plan, source inventory, runner and
process evidence are preserved byte-for-byte with `preservation.json` hashes.
Successor `a159ebc` passes the original borrow to verification and separately
captures an owned admission Arc for the relocation worker. It removes the two
unused bindings. Its verification is a separate source-bound attempt; this
failure remains failed. Final release and capacity acceptance remain open.
