//! Fixture-only publication of an actual committed/applied first membership.
//! This feature is unavailable in normal production builds.
use crate::{
    AppliedEntryContext, BasicNode, LogId, LogStore, TargetFirstMembershipPrebind, TypeConfig,
};
use anyhow::Result;
use kasumi_store::TenantStorageSet;
use openraft::storage::{RaftLogStorage, RaftLogStorageExt};
use openraft::{Entry, EntryPayload, Membership, StoredMembership};
use std::{collections::BTreeMap, sync::Arc};

pub async fn publish_committed_first_membership(
    stores: Arc<TenantStorageSet>,
    expected: &TargetFirstMembershipPrebind,
) -> Result<LogId<u64>> {
    expected.validate_unapplied_storage(&stores)?;
    let log_id = LogId::new(
        openraft::CommittedLeaderId::new(3, expected.node.node_id),
        0,
    );
    let membership = Membership::new(
        vec![expected.voters.keys().copied().collect()],
        expected
            .voters
            .iter()
            .map(|(node, endpoint)| (*node, BasicNode::new(endpoint.as_str())))
            .collect::<BTreeMap<_, _>>(),
    );
    let entry = Entry::<TypeConfig> {
        log_id,
        payload: EntryPayload::Membership(membership.clone()),
    };
    let encoded = crate::storage::encode_entry(&entry)?;
    let mut log = LogStore::open(stores.clone(), expected.node.node_id).await?;
    log.blocking_append([entry]).await?;
    log.save_committed(Some(log_id)).await?;
    crate::control::persist_applied(
        &stores,
        &AppliedEntryContext {
            log_id,
            previous: None,
            membership: StoredMembership::new(Some(log_id), membership),
            command_sha256: crate::command::sha256(&encoded),
            retirement_seed: None,
        },
        None,
    )?;
    Ok(log_id)
}
