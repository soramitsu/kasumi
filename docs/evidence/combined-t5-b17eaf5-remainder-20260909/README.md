# Permanent staged restore regression failure

Frozen `b17eaf5bd558f6b629d8cbf68efdbc2dd4aa090e` passed point-read admission
and encrypted missing-stop restart (one test each), then failed
`encrypted_restore_preserves_original_stage_scope_without_reviving_historical_uploads`.
The test completed its original-resource fencing, historical-upload rejection,
exact finished replay and stop/status checks, then its final assertion expected
two resident staged transactions and observed zero. The new contract stores
completed outcomes in encrypted permanent point tables; the resident map owns
unfinished uploads. This original test run remains FAILED. Sixteen later gates
were not executed.

The source successor checks the empty resident map, exact two-row permanent
head and both original-scope public status outcomes, including the exact finished
receipt. It does not add a resident compatibility copy or waive replay/fencing
assertions. Its functional verification is pending.

All three process groups drained, source/tree/lock hashes remained unchanged,
and exact logs, source inventory, runner, commands and executable hashes are
preserved. `preservation.json` binds committed records; the original output keeps
hashed executable copies. Timings and actual compiler features are in
`evidence.json`. This focused result is not final release acceptance.
