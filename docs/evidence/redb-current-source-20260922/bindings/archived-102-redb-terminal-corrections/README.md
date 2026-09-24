# Run 102: preserve physical I/O causes and reopen the actual fixture format

Status: target-only, reviewable, uncompiled. No actual source files or Cargo state were modified. This package is restricted to `/Users/mtakemiya/dev/kasumi`, branch `master`.

## Observed failures and causes

`102-retained-redb-terminal.log` records 8 retained-terminal tests: 5 passed and 3 failed in 0.91 seconds. The original sync-failure test failed at `retained_transaction_tests.rs:420` because `CheckedBackend::io` (`cached_file.rs:170`) discarded the backend's actual I/O object and returned `OwnerFailed`. Two independent reopen assertions failed at lines 307 and 511: the fixture creates 512-byte pages, but `Database::open` selects its default 4096-byte page size. Both failures report the exact 512-versus-4096 format mismatch.

## Proposed production behavior

`CheckedBackend::io` still calls the same idempotent `fail_owner` before returning, but returns `StorageError::Io(error)` containing the actual original error. The helper is shared by backend length, read, growth/shrink, write, sync, and explicit close. The existing atomic fence and admission callback remain unchanged; later ordinary accesses return `OwnerFailed` before entering the backend. Access after an explicit close attempt still returns `DatabaseClosed`.

This changes the first failing operation's diagnostic, not the failed owner's eligibility. Capacity-denial and admission-settlement errors are unchanged. No allocation, clone, error-string conversion, compatibility branch, second terminal invocation, deadline change, or workload change is introduced.

Four existing first-failure expectations are migrated to the original typed `Io` result: publication/sync uncertainty, explicit backend-close uncertainty, allocation-free post-header uncertainty, and the database transient-I/O test. Later-fence expectations remain `OwnerFailed`; publication/sync tests now assert the exact later read/write variant. Existing integration tests for an earlier iterator/backend failure correctly continue expecting `OwnerFailed` on subsequent operations.

## Verification added or retained

The new checked-backend test drives each of the six real wrapper methods through a faulting `StorageBackend` with a real `InMemoryBackend` behind it. It transfers one original `io::Error` into the backend, requires that the returned error contains the exact same nonzero-sized inner object pointer, and checks its original error kind. It verifies the physical owner is failed exactly once; every later data method is fenced without increasing any physical backend call count; and explicit close/destruction invokes backend close once. The local helper's existing repeated-close `Ok` does not claim that an uncertain close became successful or complete: the original error remains owned by the test throughout. Retained database close is a separate prerequisite.

The retained sync-failure regression keeps its original `StorageError::Io` expectation, original marker identity, exact transaction identity, original outcome pointer, rollback-not-entered assertion, retained custody, and no-terminal-replay assertions. It additionally requires both later read and write admission to fail with `OwnerFailed`, without any backend count changing. Both reopen tests now repeat the fixture's actual 512-byte page and 16-KiB region settings, including the independent crash-image verification after the real winning-header sync panic.

Static checks: proposed Rust formatting, exact actual-source/base equality, `git apply --check`, and patch statistics are recorded in `static-checks.json`. No Rust compilation or tests have run for these proposed bytes. Coordinated gates should cover retained terminal tests, the new checked-backend test, admission tests (including zero allocation after winning-header uncertainty), and `db::test::transient_io_error`; the parent owns runner scheduling and any broader gates.

## Scope limits

Only the error-preserving mapping is a production change. The `db.rs` hunk changes one test expectation and does not touch consuming database-close implementation. This package does not complete retained database close, Kasumi adapter adoption, snapshot ownership, workspace coefficients, or staging batching. The externally owned retained transaction and its original error still require registered owner custody; a wrapper is not a self-retaining lifetime guarantee.
