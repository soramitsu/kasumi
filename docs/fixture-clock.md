# Paired clock for encrypted fixtures

Enable `kasumi-engine`'s `test-utils` feature only in a test dependency. Call
`open_fixture_with_epoch_clock(stores, policy, limits, audit, admission, epoch)`
with one `Arc<kasumi_clock::EpochClock>`; `stores.application()` must have the
explicit `LocalFixture` purpose. Standalone, HA, Control, authority, and other
production catalogs are rejected before bootstrap writes. The private Database
constructor also checks that the Raft group owns the exact fixture application
store; callers cannot supply a different engine or Raft group.

Create the test's finite `RequestAuthorization::from_verified_credential` from
that same epoch's original `observe()` result. Advancing its elapsed clock then
advances command admission UTC, receipt lookup, snapshot leases, cursor leases,
and those original credential deadlines together. Obtain a new observation for
a later credential; cloning or renewing it never extends the old invocation or
an already captured response fence.

This API exists only under `test-utils` (or this crate's unit tests). There is no
runtime clock setter or request clock field. Production constructors retain
their existing process UTC floor and suspend-aware elapsed clocks, storage key
leases retain their own production clocks, and Tokio queue timeout behavior and
all configured TTL bounds remain unchanged.

Run its encrypted-file regressions with:

```sh
cargo +1.97.1 test -p kasumi-engine --features test-utils --test fixture_epoch_clock
```
