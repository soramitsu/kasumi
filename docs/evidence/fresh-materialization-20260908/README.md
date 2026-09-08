# Fresh authorization for exact retained materialization

Intermediate macOS ARM64 evidence for `00b1446`, integrated at `cf369cd`.
An independently committed `ResumeMaterialize` intent authorizes only the exact
retained original materialization origin and authenticated source-purpose digest.
The original intent's deadline remains unchanged.

Ten authority materialization tests, five Control lifecycle tests, strict
workspace Clippy, fixture-free server binary checks, and formatting passed.
`evidence.json` records exact source, lockfile, executable, and log hashes. All
listed logs were hash-checked when copied here, including the initial assertion
failure and its successful corrected rerun.

This prerequisite does not complete the distributed recovery coordinator and
does not supply a new native TLS resume acceptance test. Cross-platform and
final release acceptance remain open.
