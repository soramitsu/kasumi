# Tenant audit memory guard fixture correction

Proposed and unapplied. Main/master only. This is a first-release fixture correction, with no production contract changes or compatibility fallback.

Run 89 reported that both new maintenance memory guard tests stopped at `TenantEngine::new` because `Policy::default()` has no tenant administrator. The production `validate_policy` check correctly rejects that policy before either intended guard assertion runs.

The patch gives each fixture one tenant-wide `owner` grant containing `Action::Admin`, using the existing tenant fixture policy pattern and retaining default limits. All existing missing-storage/foreign-core rejection, exact shared-core success, unchanged admission and physical counters, pool identity reuse, charge release, and explicit shutdown assertions remain unchanged. It does not relax the production policy validator or storage memory identity check.

Validation performed: rustfmt via stdin, source/proposed hash inventory and `git apply --check`. No Cargo compilation or test execution has been performed for this patch.
