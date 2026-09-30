# Current Control topology development checkpoint

The external `7c0c4ef1373ace1cef8222e3be4b6396b45ccfcc` merge contains the
initial Control topology model, engine observation, and signing code. A moved
type still referenced its former external crate path; the preserved first
compile failure identifies it. The path now resolves inside `kasumi-types`.
Tenant route incarnations require a non-nil canonical UUID.

Actual scoped results:

- 58/58 shared types tests, including four new topology/observation regressions.
- 3/3 new serving signature tests for complete read binding, release identity,
  original digest, non-renewed deadline, signature domains and substitutions.
- Engine, serving, client and server library `cargo check` succeeded.
- One native Control test passed in 2.94 seconds: a real three-voter in-process
  Raft group supplies the original engine observation, signer and final quorum
  release. Changing committed topology invalidates both retained proofs and
  the signed historical read. Original caller/incarnation substitutions reject.

The scoped source archive was captured **after** these tests; it is not a
provenance-bound full release build. Temporary fixture credentials and keys are
disposable. No live network or deployment authority was created. The test is not
a nine-process topology, pinned network-client acceptance or physical HA proof.
Dedicated Control-only processes, authenticated remote data-node consumption,
recovery integration and release qualification remain unfinished.
