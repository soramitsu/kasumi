# Actual restore worker drain

The expiry regression now waits for actual admission counters to drain after the
last `Arc` becomes unavailable. It retains the existing timeout and verifies the
worker keeps its charge until completion. One focused test passed at `b395d1e`.

The initial `a047d4f` test build exposed a missing mandatory source-purpose field
in the combined recovery snapshot fixture. Both that failure and the corrected
run are preserved with hashes in `evidence.json`. This macOS result does not
replace the failed frozen Linux workspace attempt.
