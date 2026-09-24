# Combined storage and namespace prerequisite

This target-only package composes the frozen 14-file storage census adoption revision3 with the frozen 57-file backup namespace admission revision4 cumulative patch. The 69-file union is based on actual master HEAD 600c0ca2b2c4c22b89b44ccd932eca02272c70f1. Actual source is unchanged.

Both overlapping files (`crates/kasumi-store/src/lib.rs` and `crates/kasumi-store/src/node_disk/tests.rs`) were independently three-way merged against their exact common actual base. `composition.json` records every input/output hash; the two overlap delta patches show the changes retained from each side. Every non-overlapping proposed file is byte-identical to its frozen input. The cumulative patch passes actual-base `git apply --check` and exact target-copy apply/readback.

`assembly/` copies the actual root workspace, vendor sources and test inputs, then overlays the cumulative candidate. `native-01/` records the full offline locked all-target/all-feature workspace check and strict Clippy cohort, bounded to 1200 seconds total, with a fresh candidate-specific Cargo target directory, exact input/tool inventories, process-group observations and selected compiler artifact hashes. No runtime test pass is claimed by check or Clippy. See the terminal receipt rather than treating a started command as passed.

The scope remains prerequisites: neither input migrates every storage consumer or establishes a complete allocator/workspace/RSS bound. The namespace input retains its explicitly documented inherited native file/close and supported-filesystem limitations. Original candidates and failed native attempts are preserved.

The independent overlap review (`../storage-and-namespace-overlap-independent-review/receipt.json`) confirms exact composition. It also records a separate inherited namespace test assertion defect: the shrink-failure test adds directory namespace charge to file observed EOF, although only charged bytes should include that charge. This frozen package preserves that input unchanged; a later successor must correct and qualify the assertion.
