# Combined history and recovery functional cohort

Frozen `f4a472ffa510cead0a5383a5a199a7e5f47560ef`, tree
`ebfb0b3592d03ed8a26bcbe0a9b106edb2ae3ef7`, passed 18 actual tests across
ten gates, then failed the third replicated recovery gate with a stack overflow.
The cohort remains failed. Eighteen later gates, including native TLS and strict
workspace lint, were not run. This is Rust 1.97.1 on macOS ARM64.

Passing scopes: external-history peak admission/failed-worker ownership (3),
original-scope staged outcome restoration (1), canonical permanent staged
transaction fixtures including killed-upload recovery (5), recovery receiver
state machine including established quorum and unchanged original caps (7),
and actual replicated Control journal/planned-retirement fixtures (2).
The Control fixtures use synthetic signed target/issuer facts; they do not prove
actual source-unavailable target recovery.

`recovery_control::recovery_uncertain_activation_resolves_original_winner_and_confirms_every_voter_forward`
compiled, ran, then aborted its test thread with stack overflow (SIGABRT) after
28.063 seconds. Its Cargo exit was101. No test summary was produced for it.
Owned process group65791 and every earlier group drained. All source, tree and
lockfile hashes stayed unchanged. The failure requires diagnosis and a separately
bound successor; increasing the stack limit is not a passed release gate.

Captured libtest output retained the three expected-panic ownership tests without
the previous output-interleaving guard ambiguity. All successful gates meet exact
required-name and all-pass-summary checks. Raw logs, source inventory, plan,
runner and feature/executable provenance are retained byte-for-byte. Executable
copies remain at the hashed paths recorded by evidence.json.
