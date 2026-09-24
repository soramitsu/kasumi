# Gate 77 server correction

Proposed only, main/master. Remove the unused test-only parent re-export of `tenant_stage_status_with_storage`. Its tests are children of `tenant_staging` and already obtain the function directly through `super::*`; the production public status wrapper continues to call it directly. Keep the sibling-callers' used `stage_tenant_with_storage` re-export. No allow/dead-code suppression or behavior change.

Read-only RuntimeStorage sweep found no additional obvious constructor arity, private API, factory fallback, or facade-before-disk defect. The captured server lib-test gate diagnostic reports this warning only. Formatting via stdin, exact source/proposed hashes, and git apply --check passed; no build or source edit.
