# Startup preparation panic ownership

Data and authority startup now capture preparation unwinds while their pending
resource inventories remain outside the caught future. Data startup also retains
its partially assembled `NodeRuntime` outside that future. A preparation error or
panic drains those exact owners before its outcome reaches the existing startup
ticket. The original panic payload remains in the error object; its display omits
the payload because provider panic messages may contain private material. This
redaction applies to the returned error's display. The existing process panic hook
runs before `catch_unwind`; this patch does not suppress or redact hook output.

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

## Nested owners and alternate standalone generations

The follow-up keeps an opened restored-generation NodeStore in the external pending
inventory before its first provider/custody/catalog operation. It cannot rely on
the primary node's initializer registry to join a different physical node. On
successful startup the installed stores/databases retain it; on failure the same
pending inventory drains its actual initializers before returning the original
outcome. No missing catalog or alternate directory grants creation permission.

HA initialization, per-domain enrollment, the surrounding signer-verifier scope,
and node provisioning now capture preparation while their own inventories remain
outside the caught futures. Node provisioning retains the physical node before
catalog initialization, the returned store before audit initialization, and the
returned audit writer before further work. Successful provisioning transfers the
actual node/audit tuple, while any captured error drains the retained inventory.
The local runtime test installer uses the same pattern. These helpers preserve
the existing acknowledged startup handoff and typed drain completion contract.

HA first-enrollment leases are deliberately nonrenewing: acquisition starts no
renewal worker. This change preserves the original grant, deadline and shutdown
path. It does not introduce new boot acquisition, provider retry, or admission.

Authority registration failure and restored-lineage mismatch now return their
original preparation error directly to the outer retained cleanup path. An inner
shutdown failure can no longer replace that original cause. Cleanup failures remain
additional context. Leaf shutdown signatures are unchanged.

Additional regressions are written but **UNRUN**:

- `panicked_ha_enrollment_drains_nested_node_audit_pair_and_database_owners`
  injects at six points after actual node, singleton, audit, transferred node,
  Control pair and Control database acquisition. It requires the typed original
  panic, immediate physical/encrypted reopen and no completed enrollment marker.
- `failed_restored_generation_startup_retains_alternate_node_through_cancelled_drain`
  restores an actual encrypted backup through local recovery, then unwinds after
  opening its distinct active-generation node. Cleanup pauses after the caught
  preparation future has unwound and before any returned target pair/database can
  own that node. The test rejects physical reopen, abandons the public reply and
  first drain, rejects reopen again, joins the original panic, and finally opens
  the exact restored node and performs a normal startup/shutdown.

The pause is test-only, keyed to the exact configured node UUID and released by its
guard on test failure. No pause, injected panic, fixture storage purpose or mutable
startup outcome is introduced into production. General cleanup/destructor panics,
process abort and child initializer internals that do not return an owner remain
outside this bounded capture change. No Cargo or runtime tests were executed here.
