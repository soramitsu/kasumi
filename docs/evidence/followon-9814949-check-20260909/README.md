# Combined follow-on history ownership compilation failure

Frozen `981494949767fa52a81937a58914bf5aba030ee5`, tree `2d3b40f66d9d7f17ed79b4777fa4fd940b05010f`, failed all-target/all-feature
workspace compilation after 79.184 seconds on Rust 1.97.1 /
macOS ARM64. The actual backup plaintext is `Zeroizing<Vec<u8>>`; the new history
helper accepted `Vec<u8>`. The compiler rejected that ownership mismatch. The
check used `--keep-going`; no other compilation error was reported. Formatting
and functional tests were unrun. Owned process group 42655
drained, and source/tree/lock hashes remained unchanged.

Successor `899ca3d` retains the actual zeroizing buffer through verification and
drop, including test inputs, rather than copying plaintext. It adds an explicit
engine dependency on the already locked zeroize1.9.0; `f4a472f` records its sole
new lockfile dependency edge after offline metadata resolution. No package
version changed. These successors require separate verification; this run stays
failed. The source combines terminal-only status, quorum scheduling/cap checks,
NodeDisk foundation, external history admission and staged-fixture reconciliation;
none is approved for final production use by this compiler attempt.

Raw logs, source inventory, plan, dispatcher and process evidence are retained
byte-for-byte with `preservation.json` hashes.
