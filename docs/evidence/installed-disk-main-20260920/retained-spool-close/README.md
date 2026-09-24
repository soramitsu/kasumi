# Borrowed encrypted-spool close prerequisite

Target-only, uncompiled. This is a primitive and actual-resource regression package, not the mandatory production NodeDatabase adopter or release completion. No actual source edits or Cargo runs were performed. All work uses `/Users/mtakemiya/dev/kasumi`, `master`.

## Concrete defect and boundary

The existing `scratch_table::Backend::close` calls `owner.take().map_or(Ok(()), EncryptedSpool::close)`. The consuming spool close calls `sync_all` and then drops itself. If sync unwinds, its file, key, buffers and disk charge are destroyed before an outer retained redb Database can catch the panic. Keeping only the Database cannot conserve resources already consumed by this backend.

`EncryptedSpool::retain()` now constructs an inline `RetainedSpool`. Its borrowed close latches entry before actual sync. On the first error, it returns the original io::Error unchanged and keeps the exact spool in FailedTransferred. On sync unwind, an inline guard records InterruptedTransferred while the original payload unwinds to the aggregate's existing outcome cell. There is no duplicate error ownership, proxy allocation, string conversion, or detached cleanup. A repeat after uncertainty returns an inline BrokenPipe fence; it is explicitly not the original diagnostic. The aggregate owns the original cause and must never substitute that retry result. After a successful sync, actual disposal occurs before Complete; Complete retries perform no physical work.

The spool's disk Charge moves to the last declared field. File, key Box, plaintext Vec and ciphertext Vec are therefore physically retired before the charge can return anonymous-extent credit. The field change also corrects allocation ordering for existing spool destruction. No memory coefficient or new resident lease is invented: spool/redb resident memory admission is still a separate open prerequisite. DisposalInterrupted is distinct from a sync interruption and cannot be reclassified as Complete or retried.

## Prepared tests

1. An actual encrypted spool backs an actual redb Database, whose new RetainedDatabase is retained in a fixed test aggregate. The final borrowed spool close performs real sync, then returns one prefabricated uncertainty error. The exact nonzero-sized inner error object and io::Error cell are owned only by the database backend outcome and stay identical across repeated reports. The exact spool address, file descriptor, file contents extent, disk bytes and live-file count remain retained. Neither aggregate close nor direct spool close retries physical sync.
2. The same actual aggregate performs real terminal sync, then resumes a prefabricated original panic payload. The Database catches that exact payload; the wrapper remains InterruptedTransferred with the actual file and charge. Mutex poison is recovered for observation, not treated as cleanup. Both uncertain aggregates remain in two fixed test-process census slots with their original outcomes.
3. Three independent real spools pause the already-installed allocation observer at the actual System.dealloc of the key, plaintext buffer and ciphertext buffer. At each paused boundary, the original anonymous descriptor has retired (or its number was reused for another inode), while the old extent credit is still charged and competing full-budget growth is denied. After releasing and joining the actual worker, credit is available and the original close plus repeated close allocate zero. An RAII test owner releases and joins the worker even if a controlling assertion unwinds. No allocator observer implementation is changed.

The fault tests inject uncertainty after successful real final sync; they do not claim to provoke an operating-system fsync error. This deterministic point deliberately models a failed/unknown terminal acknowledgement after physical work and proves resources do not disappear when control unwinds. Existing operation workloads, limits, deadlines and tests are unchanged.

## Deliberate adopter dependency

The production scratch Backend still uses the existing consuming path. It cannot switch alone: current NodeDatabase consumes Database and labels CloseError complete, which would then misreport a backend that correctly retained its spool. The existing `explicit_scratch_close_retains_original_physical_failure_on_retry` must not be weakened into accepting that false completion. The production change must replace Backend and NodeDatabase together with admitted, strongly retained aggregate custody and borrowed original reports. The old path is not an approved compatibility fallback for that migration. This prerequisite does not make the first release qualified.

A supported aggregate must be registered before dispatch, own both RetainedSpool and its permanent original outcome, and perform no fallible work between receiving that error/panic and recording it. The fixed tests use the actual retained redb outcome cells; the wrapper alone is not self-retaining. Dropping an uncertain aggregate remains invalid cleanup evidence. Further design findings are recorded in `node-database-migration.md`.

## Static validation

`static-checks.json` records proposed rustfmt, exact actual-source/base equality, patch applicability and diff statistics. Compilation and all three runtime tests remain pending the parent's coordinated runner. The tests depend on the applied run102 original-I/O fix, retained Database-close revision2, and disk-memory lease retirement's actual deallocation observer.
