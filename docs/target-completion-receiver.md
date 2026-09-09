# Target completion receiver implementation record

This staged implementation starts from validation source `e17a5eb`, reconciles
the prepared terminal publication source `e18bdd9`, and carries the reviewed
exact completion protocol from `c8c5edb`. It is not release validation.

The target owns a distinct encrypted point and ordinal table. A bounded resident
head selects its immutable prefix; bytes persisted ahead of the applied position
remain invisible and can be reused only by exact original replay. Target facts
bind the installed physical origin, Control incarnation, original attempt, actual
applying command and position. Canonical snapshot record kind 22 carries these
rows; verified replacement tables and checkpoint catalog writes publish with the
same application/custody snapshot and applied cursor transaction as staged
terminal kind 21.

`max_target_resolution_bytes` charges both permanent row/index bytes, keys and
framing. It is independent of the application snapshot envelope. Snapshot spools
admit their checked combined size on the installed scratch owner; indexed backup
verification subtracts the exact target stream span when checking the application
quota. This accounting does not provide persistent node disk admission.

The first increment supplies storage, metadata, restore and snapshot hooks plus
three source regression tests. PrepareComplete, ResolveComplete and typed budget
maintenance dispatch are the next increment. No automatic Control successor is
enabled by these storage hooks. Original deadlines and the global activation
winner remain unchanged. Namespace reclamation, physical disk ownership and
capacity, complete receiver/native crash tests, and the linked Control successor
remain open.

Only direct Rust 1.97.1 rustfmt and whitespace checks have been run for this
increment. Compilation and all functional tests require the scheduled frozen
validation cohort; earlier prepared-prefix check evidence is not evidence for
this combined source.
