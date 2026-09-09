# Pinned redb verification preparation: Python guards

Seven Python source/provenance guard tests passed on frozen redb harness source
`7f47aa77cab17af832543c3e2550e6bac5fbf21d`, tree
`ef6acf2734e2e1007e33b5c28ac82110b7748e10`. The retained raw test log reports
0.177 seconds; the supervised command elapsed 0.405 seconds. Source hashes,
modes and clean status remained unchanged. `evidence.json` SHA-256 is
`7072ad05dfe9597700abfd3612300765247d91901a53e1f5c42583dc3426cb7c`.

The six files under `harness/` are byte-exact copies of that commit's new
preparation harness. It preserves the original upstream source, workspace,
features, test scope and both locked dependency graphs. Review corrected
incomplete content-only inventories, the writable lock required by offline
cargo-deny, and upstream context ignore rules that excluded required inputs.

These results cover only Python input guards. No image, tool installation,
upstream Rust suite, fuzzer, prototype integration or production build ran.
The bounded outer container runner remains required, including its exact
container ownership/drain, disk and memory limits, writable advisory lock mount
and full source comparison. This evidence does not close a release gate.
