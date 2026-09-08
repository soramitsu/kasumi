# Frozen Linux ARM64 functional attempt — failed

Exact source `8e90ff2747b349394409954147437bb78214a020`, Rust 1.97.1,
native Linux ARM64 in the dedicated Debian 13 VZ VM (2 CPUs, 8 GiB RAM).
The complete runner finished in 46 minutes. This attempt remains **failed**.

Workspace results: 499 passed, three failed, two ignored. Failures were the
second authority Fence after encrypted restart (ambiguous acknowledgement),
staged append in the cold-history backup test (ambiguous acknowledgement), and
the lifecycle audit exhaustion assertion (hot count did not demonstrate capacity
exhaustion). Exact-outcome and audit-boundary fixture corrections are separate
later commits and cannot change this run's classification. The preceding
3ee5787 failures passed in this full run, including replicated restore under
its unchanged default 512 MiB budget.

Formatting, Python, vendored dependency checks, doctests, strict workspace
Clippy, fixture-free feature verification and all three release binaries passed.
Production compilation took 1110.499 seconds. `evidence.json` binds every gate,
source inventory/archive, lockfile and recorded executable. Copied gate logs
and source inventory were checked against it; source.tar was independently
hashed during export. Raw preparation records retain an initial clone failure
from a bundle with no default HEAD and the explicit detached checkout correction.

The original source/archive, target and evidence remain at
`/opt/kasumi-acceptance/8e90ff2-functional-arm64/run` in the validation VM.
The transport export is `/tmp/kasumi-linux-functional-8e90ff2-evidence.tar.gz`
on the host. No source changes occurred during the gates. The source predates
mandatory staged scopes and current recovery/rotation work. This does not close
final-source, cross-platform, 3 GiB, 24-hour endurance or artifact acceptance.
