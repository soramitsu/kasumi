# Node Lifecycle

## Stopping a Node

`Raft::shutdown()` signals and joins the core and ticker tasks, then joins the
state-machine worker and its snapshot builder. Their join handles
remain owned by the Raft instance if a shutdown future is cancelled. A later call
resumes the joins, and concurrent callers observe the same retained outcomes.

Normal shutdown returns success. A core panic, storage failure, unexpected runtime
cancellation, or ticker failure returns `ShutdownError` after both tasks have
joined. `state_machine()` and `snapshot_builder()` preserve original returned
storage errors or runtime join errors for those tasks. `core()` preserves the core's `Fatal` classification. `core_join_error()`
and `ticker()` retain shared references to the original runtime join errors,
independently for each task. Repeated calls share the same error allocations;
repeating shutdown does not turn an observed failure into success. Runtime errors
are not serialized or replaced by a panic/cancellation label.

The worker and its snapshot builder have two fixed ownership cells outside the
core. A successful builder is joined before the next build reuses its cell.
Snapshot failure stops the worker, and worker termination is observed by the
core directly; no detached monitor task is introduced.

Applications must separately stop request admission and drain replication,
snapshot senders, other network children and application background owners before
releasing installation locks or deleting files. Joining these four task families
is not proof that an application has released every resource.

## Membership

- When a node is added using [`Raft::add_learner()`], it immediately starts receiving log
  replication from the leader, meaning it becomes a `Learner`.

- A `Learner` transitions to a `Voter` when [`Raft::change_membership()`] includes it as a
  `Voter`. A `Voter` can then become a `Candidate` or `Leader`.

- When a node, regardless of being a `Learner` or `Voter`, is removed from membership, the
  leader ceases replication to it immediately, i.e., when the new membership that
  excludes the node is observed (no need for commitment).

  The removed node will not receive any log replication or heartbeat from the
  leader. It will enter the `Candidate` state because it is unaware of its removal.


## Removing a Node from Membership Config

When membership changes, for example, from a joint config `[(1,2,3),
(3,4,5)]` to a uniform config `[3,4,5]` (assuming the leader is `3`), the leader
stops replication to `1,2` when the uniform config `[3,4,5]` is observed (no need for commitment).

This is correct because:

- If the leader (`3`) eventually commits `[3,4,5]`, it will ultimately stop replication to `1,2`.

- If the leader (`3`) crashes before committing `[3,4,5]`:
    - And a new leader observes the membership config log `[3,4,5]`, it will proceed to commit it and finally stop replication to `1,2`.
    - Or a new leader does not observe the membership config log `[3,4,5]`, it will re-establish replication to `1,2`.

In any scenario, stopping replication immediately is acceptable.

One consideration is that nodes, such as `1,2`, are unaware of their removal from the cluster:

- Removed nodes will enter the `Candidate` state and continue to increase their `term` and elect themselves.
  This will not impact the functioning cluster:

    - The nodes in the functioning cluster have more logs; thus, the election will never succeed.

    - The leader will not attempt to communicate with the removed nodes, so it will not see their higher `term`.

- Removed nodes should eventually be shut down. Regardless of whether the leader
  replicates the membership without these removed nodes to them, an external process should
  always shut them down. This is because there is no
  guarantee that a removed node can receive the membership log within a finite time.


[`Raft::add_learner()`]: `crate::Raft::add_learner`
[`Raft::change_membership()`]: `crate::Raft::change_membership`
[`extended_membership`]: `crate::docs::data::extended_membership`
