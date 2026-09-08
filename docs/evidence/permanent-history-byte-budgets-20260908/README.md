# Permanent history byte budgets

Schema activation and retirement identities use mandatory checked 64-bit byte
budgets, exact retained usage and positive configurable capacity. Old count
fields are rejected. Admission reserves a bounded terminal outcome before any
schema publication, source fence, retirement backup I/O or positive Raft seed.
Exact prior outcomes remain readable and retryable at exhaustion; operators may
increase budgets beyond 2 GiB without deleting identities.

The focused engine tests passed 23 cases, and all 45 Raft tests passed. A strict
Clippy failure from a redundant fixture cast is preserved. Its one-line fix
passes strict full-workspace Clippy, fixture-free server checks and formatting.
Each result retains its own source identity and executable hashes where captured.

The large-history test generates and validates 100001 permanent records through
a snapshot, then admits one new engine operation. This checks removal of a
former count ceiling; it is not a live 100001-command performance result. The
permanent point-table migration and persistent disk/native reservations remain
required. Capacity metrics report logical record bytes, not physical disk usage.
