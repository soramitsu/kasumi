# Frozen proposal and authority ownership checkpoint

Native macOS ARM64 / Rust 1.97.1 ran clean source `5233e96` with all original
46 gates and 247 mandatory cases. **26 gates passed, one failed and 19 later
gates were unrun.** The source remained unchanged and all 27 dispatched process
groups drained without survivors or cleanup errors. All 13 preserved executable
files were independently rehashed after completion.

Passing gates include workspace all-target compilation, formatting, the 69 SDK
cases, proposal registration and actual cancellation/panic/leadership/deadline
cases, authority request custody, response fencing, the complete store/serving
libraries, strict store lint, database/audit worker outcomes, Control engine
genesis, serving owners, both retired-source cases and serving-task drain.

`server-control-genesis` aborted with a stack overflow in
`cancelled_ha_genesis_retains_actual_node_and_error_until_acknowledged_drain`.
The process exited 101 after its child received SIGABRT; this was not the
900-second gate deadline. No case in this aborted gate is counted as passed.
The original fixture deadlines and all later gates remain required.

Raw logs, runner, plan, source inventory and terminal evidence are unchanged
copies indexed by `copied-files.json`. Original executable custody remains at
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-5233e96-ownership-proposals`.
`summary.json` records the terminal counts and reverified executable hashes.
This scoped failed run does not qualify final native, live, capacity, endurance
or release acceptance gates.
