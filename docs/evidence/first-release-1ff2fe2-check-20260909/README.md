# Frozen first-release workspace compiler check

Actual macOS ARM64 Rust 1.97.1 check of source
`1ff2fe2691bb3adfe74da762b3a64204c941ebfd`, tree
`10eb44a92929ad9bfd6ca764f464d628225d3ef4`, on September 9, 2026.
It includes permanent mutation point receipts and T6 snapshots, strict node and
authority genesis, explicit cold enrollment, retained fresh catalog handoff and
bounded retirement scanning. It excludes the later startup-owner, target
operational-membership, canonical administration and foreign ordered-seek work.

The all-target/all-feature workspace check failed with Cargo exit 101 after
134.325 seconds (14:03:03.784938 to 14:05:18.552430 UTC). Its process group 70556
was fully drained, with no remaining members, signals or cleanup errors. The
source remained unchanged. The following format gate was not run under the
original stop-on-failure plan. No tests were executed.

Ten distinct diagnostics require source corrections: two uses of a missing
production `Uuid` import; a test `WriteReceipt` import; an obsolete authority
settings bootstrap selector; two vector references requiring slices; and four
recovery fixtures omitting their explicit existing-file open argument. All four
recovery calls follow close/snapshot and must reopen existing state. No missing
argument is permission to introduce a create-or-open constructor.

The raw log and source/runner/plan receipts are preserved byte-for-byte. Evidence
SHA-256: `b9fabb77aec67ec2970992e1027bc23b9c65710aa989c1cb8e66ad5af81f4afc`.
Raw log SHA-256: `f1dc75ec0333677d84e611cfd082c185e40c8098f71b7a550908c90ce92cc165`.
The compiler correction is separate source `6995711`; its successor check and
functional tests remain unrun. This failure does not certify any release gate.
