# Control recovery target quorum phase evidence

Checkpoint `cabebf8` requires exact signed three-voter materialization/start
facts, dispatches initialization only to the designated voter, and retains each
completion retry under the original target command and deadline. Signed target
completion advances the coordinator to source fencing/retirement.

Two replicated recovery tests and fifteen snapshot tests pass, as do strict
workspace Clippy, fixture-free server checks and formatting. The journal tests
use explicit cryptographic target fixtures, not three real target processes.
Source fencing/retirement, activation, local confirmation, route publication and
fresh resolution of an expired ambiguous Complete remain incomplete. Earlier
native TLS evidence is not this checkpoint's native acceptance. A subsequent
full lifecycle test exposed an ambiguous StopTarget fixture acknowledgment;
its failed log is retained in the audit-boundary follow-up evidence.
