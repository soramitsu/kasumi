//! Exact independently persisted local application coverage. This confirms a
//! historical commit, never fresh quorum, current policy or new mutation power.
use crate::{
    BasicNode, RaftGroup,
    control::{self, AppliedCursor, META},
};
use anyhow::{Context, Result, ensure};
use kasumi_types::TargetCommitPosition;
use openraft::{CommittedLeaderId, LogId, StoredMembership};
pub struct ConfirmedLocalApplication {
    index: u64,
    term: u64,
    membership: StoredMembership<u64, BasicNode>,
}
impl ConfirmedLocalApplication {
    pub fn index(&self) -> u64 {
        self.index
    }
    pub fn term(&self) -> u64 {
        self.term
    }
    pub fn membership(&self) -> &StoredMembership<u64, BasicNode> {
        &self.membership
    }
}
impl RaftGroup {
    /// Bound to this actual group's custody store. An external expected position
    /// alone cannot construct confirmation or substitute a newer remote cursor.
    pub fn confirm_local_application(
        &self,
        expected: &TargetCommitPosition,
    ) -> Result<ConfirmedLocalApplication> {
        self.check_access()?;
        expected.validate()?;
        let store = self.storage_domains().custody().store();
        let committed =
            control::committed_coverage(store)?.context("local committed coverage missing")?;
        let applied: AppliedCursor =
            control::load(store, META, b"applied")?.context("local applied cursor missing")?;
        let actual = applied.log_id().context("local applied cursor is empty")?;
        let requested = LogId::new(
            CommittedLeaderId::new(expected.term, expected.leader_node_id),
            expected.index,
        );
        ensure!(
            actual.index >= requested.index
                && committed.index >= actual.index
                && actual >= requested
                && committed >= actual
                && (actual.index != requested.index || actual == requested)
                && (committed.index != actual.index || committed == actual),
            "local committed/applied position does not cover exact target"
        );
        let membership = match applied {
            AppliedCursor::Entry(position) => {
                ensure!(
                    actual.index != requested.index
                        || position.command_sha256 == expected.command_sha256,
                    "local applied command differs at exact position"
                );
                position.membership
            }
            AppliedCursor::Snapshot { meta, .. } => meta.last_membership,
        };
        self.check_access()?;
        Ok(ConfirmedLocalApplication {
            membership,
            index: actual.index,
            term: actual.leader_id.term,
        })
    }
}
