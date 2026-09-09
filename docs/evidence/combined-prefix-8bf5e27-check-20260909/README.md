# Reconciled permanent-prefix compilation

Frozen source `8bf5e274ee14336dbf0817b7a4f111de5d9de4f6`, tree
`7b30baa4273cafa2bfb0b570c9b823b38401e490`, passes workspace `cargo check`
with every target and feature in 40.770 seconds, then formatting in 1.340
seconds on Rust 1.97.1/macOS ARM64. The earlier six fixture API errors at
`743754d` are preserved separately; only those fixtures changed here.

Both owned command groups drained and all source/tree/lock hashes remained
unchanged. [evidence.json](evidence.json) records commands, actual compiler
features, deadlines and process receipts. [preservation.json](preservation.json)
binds raw diagnostics, source inventory, plan and dispatcher.

These are compilation and formatting results only. No test executed in this
cohort. Permanent terminal prefixes, atomic replacement, target completion and
signer recovery require their separately dispatched functional gates; final
release, capacity and endurance acceptance remain open.
