# Retired-source deadline reproduction

This diagnostic reruns only the failed gate from the full frozen `f2921f5`
cohort, preserving both cases and its 900-second process deadline. The exact
clean source and original executable remain unchanged. `RUST_BACKTRACE=1`
identifies the elapsed ten-second wait at
`runtime_retired_source_tests.rs:322`: the test never received its core-entry
acknowledgement. One test passed and one failed again; the process group drained.
This reproduction does not replace the complete mandatory cohort.

The fixture blocks a Tokio executor thread directly inside the real Raft core
callback, immediately after waking the opener through a oneshot. Tokio's local
LIFO scheduling can strand that acknowledgement on the blocked worker. The
pending correction uses `block_in_place` for the same actual core hold, handing
executor work to another thread. It preserves the 20-second core hold, every
ten-second observation/drain deadline, all ownership assertions and production
code. Its results require a new frozen source run.

Raw copies are hash-bound in `copied-files.json`; their originals and the
independently rehashed executable remain under
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-f2921f5-retired-source-diagnostic`.
