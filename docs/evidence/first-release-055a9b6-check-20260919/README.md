# Integrated convergence compiler failure

Source `055a9b6b987158464ed80c308feba36de68a7dcf` / tree `a3158704dcd09a0cbd65839fa9f391da0e9746f0` ran the original locked offline
workspace all-targets/all-features compiler command on Rust 1.97.1. It failed
with exit 101 in 138.021 seconds. The only compiler error was
`Analyzer::English` in a query test; the canonical variant is `EnglishV1`.
The successor fixes that test and removes the unused imports and superseded
methods identified by compiler warnings. It does not add a compatibility alias.

Process group 29617 drained without signals, remaining processes
or inspection errors, and the exact source remained unchanged. All subsequent
19 planned gates were withheld by the original stop-on-failure rule. No deadline
was extended. The 110 mandatory ownership cases remain required on the successor.
Raw evidence is preserved byte-for-byte with `copied-files.json` hashes. This
failed compiler checkpoint provides no release acceptance.
