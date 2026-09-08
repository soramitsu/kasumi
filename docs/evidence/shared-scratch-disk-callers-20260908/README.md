# Installed scratch disk ownership evidence

Source `cc7fbeb` propagates explicit installed scratch owners through NodeStore,
tenant stores, snapshots, backups, authority, standalone and recovery. The store
suite passed 80 tests with one external-service test ignored, Raft 44, engine
snapshot filters 15, backups ten, standalone two, local recovery two and signer
four. Strict workspace Clippy, fixture-free server checks and formatting passed.

The first standalone/recovery/signer filters selected zero tests and are retained
as non-gates. The corrected `*-actual` invocations ran the real module tests
against the same hashed server executable. Integration `42b9fba` subsequently
passed a combined workspace/all-features/all-targets check (67 seconds).

Scratch admission does not reserve persistent database/index/WAL capacity or
close the native reservation, 3 GiB, RSS or endurance gates.
