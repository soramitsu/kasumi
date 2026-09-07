# Failed initial snapshot custody gate

The immutable receipt records 300 passing tests, one failing upstream OpenRaft
storage conformance test and two explicitly opt-in integration tests. All 141
native source inputs remained unchanged during this run.

The initial adapter rejected every append beneath a committed snapshot. OpenRaft
permits physical log repair beneath that position, so this was too restrictive.
The correction permits repair while preserving the exact accepted retirement
entry and excluding unmatched candidate seeds from snapshot coverage. A later
gate validates the corrected implementation; this run remains failed evidence.
