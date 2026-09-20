# September 19 baseline compiler failure

The frozen `46ae68f5a4d294efed889b00c2ee495b30be4db6` source (tree
`6796167a2cf73c4b67c734b053debf72cd38a1c1`) failed the workspace all-targets,
all-features compiler checkpoint in 218.329 seconds. Exit code was 101; the
original 900-second deadline did not expire. Source stayed unchanged and process
group 25360 drained without signals, remaining children or inspection errors.

Diagnostics were two unresolved `tracing` uses and two ambiguous string inference
diagnostics in the engine, plus 15 Raft snapshot test calls missing the explicit
creation/reopen argument. The later formatting, complete-store, strict-store and
ownership tests did not run. These compiler fixes are included in successor
integration `055a9b6`; only its own actual validation can qualify them.

The five raw files are copied unchanged; `copied-files.json` records their hashes.
The exact command, dependency/toolchain inventory and runner/helper identities
are recorded in the evidence. This is a failed diagnostic checkpoint, not release
acceptance. An initial wrapper launch under the host Python 3.10 failed before
any gate dispatch because `hashlib.file_digest` requires Python 3.11; this actual
run used the bundled newer Python interpreter without changing the runner.
