# Coordinator fixture head compilation failure

Frozen source `1682a8fbfee0dad3ad412aec0f9a53c18e3f941c`, tree `b932ad071bc7acd8606f06c3677c9fc06d2f0cd0`, failed workspace all-target/
all-feature compilation after 20.616 seconds on Rust 1.97.1,
macOS ARM64. The root fixture correction used nonexistent `TargetResolutionHead`;
the canonical tenant field is `TargetResolutionPrefixHead`. All ten other
previous missing-import diagnostics were corrected. This is a root source
mistake, not a dependency or environment failure.

Process group 5932 drained and source/tree/lock hashes remained
unchanged. Formatting and functional tests were unrun. Raw diagnostics and exact
source, plan, runner and process evidence remain hashed in `preservation.json`.
Successor `0336024` uses the existing canonical type without introducing an alias
or changing assertions. Its validation is separate; this failed attempt stays
failed. No production, recovery or capacity acceptance is claimed.
