# Bounded retirement seed recovery

`ControlLog::recover_retired` visits retained encrypted seed records with a
stable read view and keeps at most one successful candidate. It no longer
collects and sorts every seed identity, or rejects recovery at 100,000 retained
identities. The control mutation gate keeps the candidate set and committed
coverage stable. The view releases its key-state read guard before each
callback, allowing the existing point validation to run without recursively
holding the key-state lock across a pending renewal writer.

Every candidate still passes the existing exact source, bootstrap, encryption
binding, committed position, immutable header and snapshot-coverage checks.
Uncommitted physical rows cannot publish a retirement boundary. Multiple
committed successes fail closed, independent of physical record order. The
matching boundary, custody head and applied position still commit atomically.
No storage format or compatibility path was added.

Two new regressions are prepared but have not been compiled or executed. One
builds 100,001 authenticated seed rows in small batches: a real retirement seed
and 100,000 deliberately uninterpreted physical tail rows beyond committed
coverage. It requires no retirement before commit, then exactly the original
retirement after its commit. This exercises the former count ceiling and
uncommitted-tail exclusion; it does not claim that 100,000 successful retirements
are valid. The other requires rejection without publication when two successful
seeds have committed. Existing crash recovery, source-key revocation, failed
retirement and already-applied boundary tests remain required.

This change removes one retained-identity ceiling and its proportional in-memory
collection. It does not complete persistent disk admission, general lifetime
record retention, recovery scheduling or final release validation. The separate
header scan work limit and per-record limits are unchanged.
