# Custody candidate verification — superseded design

This run freezes the recorded source inputs while exercising the full native
workspace. Its exit results apply only to those inputs.

Independent review during the run identified a custody availability defect:
ordinary proof/status reads allocate permanent observation command identities,
which can exhaust the configured mutation/audit budgets and prevent later
administrator rotation or expansion. This candidate is not a release checkpoint,
regardless of whether its regression tests pass. The correction is drafted
separately and will have a new source-bound receipt. No prior test or output is
overwitten or attributed to the corrected source.
