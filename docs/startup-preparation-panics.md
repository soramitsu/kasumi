# Startup preparation panic ownership

Data and authority startup now capture preparation unwinds while their pending
resource inventories remain outside the caught future. Data startup also retains
its partially assembled `NodeRuntime` outside that future. A preparation error or
panic drains those exact owners before its outcome reaches the existing startup
ticket. The original panic payload remains in the error object; its display omits
the payload because provider panic messages may contain private material.

The helper catches only polling of the preparation future. It never resumes a
panicked future or treats potentially poisoned runtime state as a usable server.
It does not catch process abort, allocation abort, destructor panic, or a panic
inside the cleanup implementation itself. Typed worker drain results and explicit
stopped-installation recovery remain separate requirements.

`NodeRuntime::open_database` now receives the external pending inventory and
retains every newly created database before fallible cluster registration. Early
audit/store rejection returns to that same inventory rather than independently
discarding a shutdown result. A full runtime receives its installation lock only
after successful preparation; pending resource ownership protects earlier phases.

New source regressions are **UNRUN**:

- `preparation_panic_keeps_original_payload_without_exposing_it` unwinds after an
  actual yield, retains the original typed payload and verifies its redacted display.
- `panicked_cold_preparation_drains_actual_nodes_stores_and_partial_runtime` uses
  real standalone files and keyrings. It injects panic after security acquisition,
  database acquisition and partial runtime construction, requires the typed panic
  outcome, then immediately reopens the same physical and encrypted installation
  and performs another full startup/shutdown.

Pinned Rust 1.97.1 direct formatting and whitespace checks passed. No Cargo,
runtime, native, platform or production gate has executed for this patch.
The authority wrapper is source-reviewed but has no new authority-specific panic
process test in this checkpoint. Existing cancellation and shutdown tests remain
required, as does the complete final-source release suite.
