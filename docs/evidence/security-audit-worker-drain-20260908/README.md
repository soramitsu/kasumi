# Security audit archive worker ownership

Source base: `3a8d512`. This change is initially source-only; no successful build,
test or reproduction is claimed by this record.

The frozen Linux workspace run reported a database-lock failure while
`three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls`
reopened a stopped installation at `runtime.rs:4177` (82 server tests passed,
one failed). That error does not identify the specific remaining owner.

Independent source review found a concrete drain gap: the detached security audit
archive worker upgrades a weak writer before registering its work. Shutdown can
observe an empty work counter during that interval while the worker still holds
`AuditWriter → TenantStore → NodeStore`. A work-counter drain alone therefore
does not prove that the durable file owner is released. This is a source-supported
ownership defect; it is not yet proven to be the sole cause of the Linux failure.

The fix retains the actual archive worker handle before exposing the writer.
Shutdown seals admission, wakes the worker, joins it without aborting archive
publication, then drains other admitted work and the store. The join handle stays
in place across awaits so cancellation and repeated shutdown preserve ownership.

The deterministic regression pauses the actual worker after its strong upgrade
and before admission. It first drains the key monitors to isolate that exact
ownership gap. Shutdown must remain pending even with no registered audit work;
cancelling and resuming shutdown must still wait for the same worker. After
release, the test drops all explicit owners, checks that the weak node is gone,
immediately reopens the same encrypted database and verifies its retained record.
No sleep or lock-retry loop substitutes for ownership drainage.

Required validation remains the deterministic regression, existing security audit
shutdown/retention tests, the actual replicated TLS runtime restart fixture,
strict Clippy and a production build without fixture features. Evidence must bind
those results to the final source and executable hashes. The original Linux
failure remains retained regardless of later results.
