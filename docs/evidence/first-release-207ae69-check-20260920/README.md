# Frozen authority/proposal ownership successor: visibility compile failure

Native macOS ARM64 / Rust 1.97.1 ran clean source `207ae69` with the retained
46-gate / 247-mandatory-case plan. Its first workspace all-targets/features
compilation gate failed because the authority request helper moved to a child
module with private visibility. The parent service, two sibling services and a
test require access. All 45 later gates were unrun. The process group drained
without survivors or cleanup errors; the source remained unchanged.

The correction gives the helper parent-module visibility, removes an unused
import, constructs the panic guard inside the actual child future and explicitly
drops it after normal return, and replaces a deprecated test election setter
with the current API. The compiler warned that the previous guard capture wrote
an otherwise unread field; the successor must exercise the existing actual-panic
admission-fencing regression. Authority/proposal behavior and the retired-core
fixture correction remain unqualified until the successor runs.

Raw copies and hashes are preserved in `copied-files.json`, with originals at
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-207ae69-ownership-proposals`.
No original gate, mandatory case or deadline is waived. This failed scoped build
does not qualify any final release gate.
