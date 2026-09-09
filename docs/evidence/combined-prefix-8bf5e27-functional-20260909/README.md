# First permanent-prefix functional checks

Frozen source `8bf5e274ee14336dbf0817b7a4f111de5d9de4f6` passed all six
staged terminal-prefix tests in 164.489 seconds, including compilation, then
the indexed intermediate-genesis regression in 2.385 seconds. These tests cover
exact original replay, visibility of committed prefixes, encrypted reopen,
point-read admission, reserved terminal capacity and provenance across restores.

The two joint immutable-table snapshot publication tests then failed during
fixture initialization in 56.405 seconds, including compilation. The fixture
gave `EncryptedTable` a 1 MiB spool budget. Pinned redb 4.2.0 initializes at
least 1 MiB of usable pages plus region-tracker and header space, so the spool
correctly rejected its initial resize before either fault sweep could begin.
Both raw failures remain retained. Successor `769b834` funds that fixture with
8 MiB; it changes no publication or crash assertions. This is not a passing
fault-injection result.

All three command groups drained, and source/tree/lock hashes stayed unchanged.
The cohort remains failed; its later 22 gates did not run. Exact commands,
features, original 900-second deadlines, executable hashes and process receipts
are in [evidence.json](evidence.json). [preservation.json](preservation.json)
binds copied raw logs, source inventory, dispatcher and plan. Actual executables
were separately preserved and hash-verified before target reuse.

Source review also found that the recovery codec fixture changed its tenant and
incarnation without resetting the empty target-resolution head. `769b834`
corrects that identity setup too; that later test was not executed in this
cohort. Complete functional, recovery, capacity and release acceptance remain
open.
