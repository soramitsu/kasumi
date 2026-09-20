# Local recovery requires installed Control state

After local activation commits, recovery publishes its target route by comparing
and replacing the retained Control topology version. It now requires the installed
reserved schema and current topology document. Missing state is an error; recovery
cannot initialize the schema or reconstruct the topology from configuration.
The fallback topology builder has been removed.

The new regression source
`local_recovery::tests::activated_local_recovery_never_recreates_missing_control_topology`
creates an actual encrypted backup, executes the local phases through activation,
deletes the actual Control topology document, and attempts publication. It checks
that the original activation and publication phase identity remain, no topology
is recreated, and stopping the activated operation remains forbidden.

Only Rust 1.97.1 formatting and whitespace checks have run for this checkpoint.
Compilation and the regression remain UNRUN. This change does not complete stopped
operator ownership, HA Control genesis, topology repair, source-unavailable recovery,
or any final release gate.
