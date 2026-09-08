# Candidate workflow implementation checks

The workflow binds native acceptance hosts, exact gate commands and job counts,
source inventory, compiler dependencies, binary hashes and retained failed logs.
It uses immutable action commits and base-image digests and a dated Debian
package snapshot. The OCI recipe verifies binary hashes and Linux architecture.

All 16 Python tests and the actual native macOS host preflight passed on
5deefbf. The first workflow lint failed because runner context was used in a job
environment expression. Commit 42bf607 moves path construction into a step and
binds artifact paths to permitted contexts; the final actionlint check passes.
That commit changes only YAML, so the earlier Python result retains its source.

These checks validate tooling. They do not claim an executed acceptance workflow,
a built OCI artifact, a final release package, or reproducible compiler output.
Raw failures, final logs and executable provenance are retained beside this file.
