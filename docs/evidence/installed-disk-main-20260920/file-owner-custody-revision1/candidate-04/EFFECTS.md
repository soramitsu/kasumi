# File descriptor effects and custody plan

Base: frozen backup-namespace-admission-revision4 proposed source. This successor is target-only and cannot modify actual source or the frozen base.

The affected paths are generic file open/create preparation (two inherited parent walks), PreparedFile execution and all error/unwind exits, generic publication destination preparation and old-parent retirement, operational parent/leaf verification, ordinary last-owner Drop, and reclaim's explicitly removed data descriptor. Generic directory Drop and configured-root acquisition remain separate inherited gaps.

All fallible allocation and bounded failure-slot admission must precede the first descriptor acquisition. A checked H+1 fixed slot bank funds at most H live file owners and one serialized publication/preparation. Owner/path/parent/native mutex backing remains covered before allocation. This does not lower H, F, depth, byte limits or the 2GiB policy.

Native descriptor slots retain each actual File until an explicit one-shot close. On native close error, the original io::Error and diagnostic descriptor number are retained; that number is never retried. Uncertain physical drain prevents handle, registration and disk-byte credit and prevents census reopening. Ordinary operation errors retain their original native outcome and actual resources until drain and accepted census. Known io::Error structure geometry is distinct from arbitrary opaque report payload, native allocator and RSS qualification; this code does not invent a finite allowance for arbitrary opaque payloads.

A prepared guard must move failed/unwound resources into the installed slot while State remains held. Live owner verification uses preallocated descriptor slots. Last-owner retirement closes outside State where existing physical-drain regressions require concurrent observation; an unwind guard retains unfinished resources before returning. Reclaim keeps State serialized through closure and accounting, as before. Successful resource, name and actual Arc-backing retirement precedes slot/handle credit.

Implementation and regression qualification are in progress. No claim of completed custody or first-release qualification is made here.
