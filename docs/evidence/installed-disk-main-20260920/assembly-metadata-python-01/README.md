# Assembly metadata prerequisite Python validation

The applied five-file patch `fbd5f8ff5cee7c0818ffe3c8ea63fdfdbbf84829d2497e04d85f7bc206b637a8` passed all 50 selected Python tests. The test suite includes eight actual synthetic-process metadata custody tests, the pre-existing process-gate tests, package provenance/determinism tests and final acceptance verifier counterexamples.

`run.py` records the exact original test command, bundled Python version/path/hash, fixed 600-second deadline and workspace-only TMPDIR/PYTHONPATH overrides in `invocation.json`. Eight relevant Python sources, including imports and all selected tests, are copied in `sources/` and hashed in `source-before.json` / `source-after.json`. Those inventories match. `process.json` is the actual original process-group receipt; the process exited zero, no deadline or signal was used, cleanup completed, and the independent final process census was empty. Separate stdout and stderr files are hashed in `result.json`.

This run qualifies Python behavior for the metadata custody prerequisite. The tests use synthetic Cargo programs to exercise actual process ownership; they do not execute native Cargo or two package assembly invocations. No final-release domain is registered, and this is not complete repeatable-assembly or release acceptance evidence.

No Rust source changes, Cargo commands or commits were performed by this validation.
