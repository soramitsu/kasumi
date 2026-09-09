# Complete upstream verification dependency graphs

Network-enabled Cargo metadata resolved both unmodified workspace scopes after
the preserved offline cache failures: upstream3.261s and fuzz0.316s, both exit0.
Owned process groups81937/81972 drained. The124 tracked source files and pinned
process helper remained unchanged. No compiler ran and no target was created.
No workspace member or verification dependency was removed.

The resulting root lock SHA256 is
`de059020b773066b6abc56c3efe207eb6e6106f19a9145eaa9f41c6ceff4bcaf`;
the separate fuzz lock is
`4095adc5bd8218e8d8f72ad9476344ca3793d2f2996e795607910666f385ec3e`.
Both exact locks were committed in the separate verification checkout at
`3a8715417fea3f0eb38d3ed8e8b73c41752a8034` (tree `568d5a076b1583dc16afb9898fc883020ea93c0b`). This changes no Kasumi production lockfile.

Raw metadata, exact locks, source inventory, dispatcher and custody evidence are
retained here. Preparation is not an upstream test or fuzz result. Pinned tools,
isolated offline harness, complete just test scope and bounded fuzzing remain
unrun. The original upstream Rust1.90 declaration remains in this source;
verification explicitly invoked the recorded Rust1.97.1 toolchain.
