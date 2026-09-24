# Combined prerequisite revision2

Distinct successor to the preserved failed full-workspace check. `correction.patch` contains four narrow changes: consume the concrete Directory wrapper into its exact NodeDiskDirectory owner after initial synchronization and clone that same managed owner into async audit publication (no new Arc allocation or second PathBuf clone); remove an unused production MetadataExt import (tests import their own); and remove directory charge only from the observed EOF assertion in the original shrink-failure test. Aggregate charged-byte assertions and all test cases remain.

The earlier two-file overlap proof is inherited and preserved. `combined.patch` remains a cumulative patch against actual master. This package contains no actual source edits, compatibility path, complete memory bound, or claim that production storage callers have all migrated.
