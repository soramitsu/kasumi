# Repeatable assembly successor after root review

This target-only replacement preserves revision 2 and its patch
`b46712155c26ad053d4c45c106c2cf61d727e0e90bbef222a9f86cf3d051291b`
unchanged. Apply this replacement patch only, never both patches.

The documented command now invokes the runner from the actual frozen source:
`/absolute/evidence/final-functional/source/scripts/repeatable_assembly.py`.
The former checkout command was rejected by the existing imported-module binding
because the runner and imported project modules were outside its frozen source.
No binding is weakened and the CI commands already use the frozen source.

A new actual-subprocess regression executes identical module bytes from a frozen
source and a separate synthetic checkout, both with checkout as working directory.
Frozen dispatch passes input binding before any native child starts. Checkout
dispatch fails with an unbound Python module, drains its original process group,
and cannot become a qualified assembly invocation. This also confirms changing
cwd does not make an undeclared imported module acceptable.

The final epoch passed 45 Python tests. Imported-file inventories remained
unchanged with no new imports, and its original process group drained without
signals or timeout. Exact counts, command, interpreter hash, outputs and receipts
are in `python-tests-01`; all processes/files stayed inside the mandated checkout
and workspace target temporary directories. No Cargo process was run.

The nine-file implementation and limitations otherwise match revision 2:
owned two-invocation assembly, direct native tool declarations, retained source
and dependency inputs, semantic verification and unregistered acceptance bridge,
plus direct supported-CI caller migration. Native tool probes, complete frozen
candidate assembly, full acceptance-positive native adapter execution, CI,
Cargo-home operational-state behavior and platform host library declarations
remain unvalidated. The domain registry is still empty. This is a proposal for
review, not native qualification or G11 completion.
