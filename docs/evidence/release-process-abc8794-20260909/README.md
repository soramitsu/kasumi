# Release runner process custody

Source `abc879423e14b29453b4d756f6e20d30d2b76d27`, tree
`99c24a7aa1b3956f4c82633c7bdba0a807f035f2`, passed all 44 release-tool
Python tests on macOS ARM64 in 4.127 seconds. The exact five process/packaging
Python source files also passed all 20 relevant tests on native Linux ARM64
in 1.354 seconds. Linux ran Python 3.13.5 in the existing Debian reference VM;
macOS used the recorded bundled Python 3.12 executable. No Cargo command,
database listener, capacity workload or production acceptance gate ran here.

The shipped runner now enforces the original per-command timeout independently
of output. Non-raising signal handlers retain a child even when cancellation
arrives before `Popen` returns. It checks the entire owned process group after
normal completion, attempts termination despite inventory failure, and refuses
to parse logs or hash executables until cleanup is verified. Process inspection
uncertainty remains a failure. Packaging requires exact drained process receipts
and the hashes of the actual runner/helper matched to the frozen source.

The initial complete 44-test attempt on `03545c1` failed one new deadline
counterexample: an already exited child could be signaled before it was reaped.
The successor reaps that leader before inspecting remaining ownership. The
original deadline remains unchanged, and a terminal observation after it still
fails. That failed log is retained alongside the passing successor; earlier
12-, 41- and 42-test development runs and the launch-race check are also kept.

[evidence.json](evidence.json) binds source, tools, copied logs and actual Linux
input hashes. The Linux transfer retained five inert AppleDouble metadata files
from the host tar implementation; they are listed in the complete Linux file
inventory and were not Python modules or selected tests. The five executable
Python inputs exactly match the frozen source. These are process-harness tests
in the VM host environment, not a run of the final container release workflow.

The earlier database/SDK and Linux functional results remain separate evidence.
This change does not turn an earlier failed or incomplete release into a pass.
