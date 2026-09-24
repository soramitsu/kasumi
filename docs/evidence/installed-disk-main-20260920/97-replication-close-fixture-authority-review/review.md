# Independent run97 replication-close fixture review

Verdict: **no blocking finding in the bounded test-only correction**. This is a static read-only review, not a compiled or runtime pass.

Reviewed patch: `target/installed-disk-validation/97-replication-close-fixture/fixture.patch`, SHA256 `12c78bd5fcf406b032e11c8651b68372e455f72e2189687f4bfb875da2d4687d`.

The observed run97 failure is preserved at `97-authority-memory-callers.log:19–20`: the actual shutdown error has no state-machine failure, and one replication owner `{ owner_id: 1, target: 3, stream: Storage(IO(Store, Write, "tenant is sealed: key-access lease unavailable or expired")), snapshot: None }`. The old test incorrectly required an empty replication-error list and a state-machine failure.

The replacement still requires repeated DrainCompletion::Complete, exactly one original OpenRaft runtime issue, and Arc identity of that same original immutable issue across close calls. It downcasts the actual typed ShutdownError and retains rejection of core failure, core join, ticker, snapshot builder, auxiliary and incoming-snapshot failures. Every present state-machine and replication child must carry the exact access-fenced Storage variant. The replication classifier additionally requires a nonzero stable owner ID, a target in this fixture's voter/learner set 1–4, and no snapshot sender failure. ShutdownTaskError::storage_error returns None for Join, so runtime join failures cannot be admitted by the classifier. The exact existing whole Store/Write diagnostic comparison rejects wrong verb, subject, unrelated cause or matching substring.

`observed > 0` prevents an empty child report from satisfying the error path. The healthy pair remains (Ok, Ok); a mixed healthy/error or changed repeated outcome still fails. Outer Arc equality also preserves all nested original child/error allocations and stable owner/target fields without reconstructing a substitute report.

The Store/Write label on an actual replication reader is consistent with the adapter: kasumi-raft storage.rs:37–38 converts errors through StorageIOError::write; try_get_log_entries reads application log bodies through the fenced application store. This patch does not relabel the production error or alter admission/close order.

The existing close callers still assert lifecycle/store/raft fences and drain the target scope to idle; the serving caller still proves its database handle is unavailable and both stores fenced. The new negative classifier test checks absent stream, snapshot presence, zero owner, target outside the fixture set and unrelated storage failure. The existing diagnostic test separately rejects altered subject/verb and string-prefix substitution. No limits, deadlines, workloads or production code change.

Source inspection only. No actual edits, Cargo commands, compilation or test execution were performed. The distinct run97 operational read failure at line1261 is outside this patch's purpose and remains visible.
