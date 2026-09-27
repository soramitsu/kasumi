//! Original Initialize cause attached to, committed with, and atomically applied
//! with the first membership. Journal history never reconstructs execution authority.
use crate::{
    BasicNode,
    command::sha256,
    control::{self, AppliedCursor, FirstAppliedMembership, LogHeader, META, load},
};
use anyhow::{Context, Result, ensure};
use kasumi_store::{CustodyStore, TenantStorageSet, WriteOp};
use kasumi_types::{SignedTargetInitializationAssociation, TargetInitialMembershipPosition};
use openraft::SnapshotMeta;
use serde::{Deserialize, Serialize};
const STATE: &[u8] = b"initialization_association_state";
const ANCHOR: &[u8] = b"initialization_association_anchor";
pub(crate) const MAX_BYTES: usize = 256 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedInitializationAssociation {
    pub signed: SignedTargetInitializationAssociation,
    pub position: TargetInitialMembershipPosition,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedAssociation {
    value: CommittedInitializationAssociation,
    header: LogHeader,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum AssociationState {
    Ordinary {},
    Committed(Box<RetainedAssociation>),
}
pub(crate) fn decode(bytes: &[u8]) -> Result<SignedTargetInitializationAssociation> {
    ensure!(
        bytes.len() <= MAX_BYTES,
        "initialization association exceeds metadata bound"
    );
    let signed = control::decode_canonical(bytes)?;
    kasumi_serving::verify_target_initialization_association(&signed)?;
    Ok(signed)
}
impl RetainedAssociation {
    fn validate(&self, first: &FirstAppliedMembership) -> Result<()> {
        let bytes = serde_json::to_vec(&self.value.signed)?;
        let cause = &decode(&bytes)?.association;
        self.value.position.validate()?;
        let id = self.header.log_id;
        ensure!(
            self.header == first.header
                && self.header.initialization.as_deref() == Some(bytes.as_slice())
                && self.value.position
                    == (TargetInitialMembershipPosition {
                        index: id.index,
                        term: id.leader_id.term,
                        leader_node_id: id.leader_id.node_id,
                        command_sha256: sha256(&bytes),
                    }),
            "initial membership cause or actual position differs"
        );
        cause.validate()?;
        Ok(())
    }
    fn check_installation(&self, custody: &CustodyStore) -> Result<()> {
        let prebind: control::TargetFirstMembershipPrebind = load(
            custody.store(),
            control::TARGET_PREBIND_NAMESPACE,
            control::TARGET_PREBIND_KEY,
        )?
        .context("committed initialization cause lacks installed original Start prebind")?;
        prebind.validate_custody(custody)?;
        let cause = &self.value.signed.association;
        let origin = cause.origin()?;
        let voters = origin
            .input
            .voters
            .iter()
            .map(|(node, peer)| (*node, peer.endpoint.clone()))
            .collect();
        let bootstrap =
            kasumi_serving::verify_target_materializations(origin, &cause.quorum.materialized)?;
        ensure!(
            prebind.control_root == cause.control_root
                && prebind.tenant == cause.original_intent.request.tenant
                && prebind.target_incarnation == cause.original_intent.request.target_incarnation
                && prebind.voters == voters
                && prebind.bootstrap_sha256 == bootstrap
                && cause
                    .original_intent
                    .request
                    .target_nodes
                    .get(&prebind.node.node_id)
                    .is_some_and(|node| node.node_id == prebind.node.node_id
                        && node.verifier == prebind.node.verifier
                        && node.principal == prebind.node.principal
                        && node.certificate_sha256 == prebind.node.certificate_sha256),
            "committed initialization cause differs from installed target"
        );
        if prebind.node.node_id == cause.node_id()? {
            ensure!(
                prebind.dispatch
                    == kasumi_types::TargetInitialMembershipStatusInput::dispatch_identity(
                        &cause.start
                    )?,
                "committed initialization cause changed designated Start identity"
            );
        }
        Ok(())
    }
}
impl AssociationState {
    fn anchor(&self) -> Result<Option<String>> {
        Ok(match self {
            Self::Ordinary {} => None,
            Self::Committed(_) => Some(sha256(&serde_json::to_vec(self)?)),
        })
    }
    fn writes(&self) -> Result<Vec<WriteOp>> {
        Ok(vec![
            WriteOp::put(META, STATE, serde_json::to_vec(self)?),
            WriteOp::put(META, ANCHOR, serde_json::to_vec(&self.anchor()?)?),
        ])
    }
}
pub(crate) fn load_state(
    custody: &CustodyStore,
    first: Option<&FirstAppliedMembership>,
) -> Result<Option<AssociationState>> {
    let state: Option<AssociationState> = load(custody.store(), META, STATE)?;
    let anchor: Option<Option<String>> = load(custody.store(), META, ANCHOR)?;
    ensure!(
        state.is_some() == first.is_some() && anchor.is_some() == first.is_some(),
        "first membership association state or atomic anchor missing"
    );
    if let Some(state) = &state {
        ensure!(
            Some(state.anchor()?) == anchor,
            "initialization association anchor differs or state was downgraded"
        );
        match state {
            AssociationState::Committed(record) => {
                record.validate(first.context("first fact absent")?)?;
                record.check_installation(custody)?;
            }
            AssociationState::Ordinary {} => {
                ensure!(
                    first
                        .context("first fact absent")?
                        .header
                        .initialization
                        .is_none(),
                    "ordinary state erased original cause"
                );
                let prebind: Option<control::TargetFirstMembershipPrebind> = load(
                    custody.store(),
                    control::TARGET_PREBIND_NAMESPACE,
                    control::TARGET_PREBIND_KEY,
                )?;
                ensure!(
                    prebind.is_none(),
                    "target first membership cannot have an ordinary state"
                );
            }
        }
    }
    Ok(state)
}
fn initial_state(
    custody: &CustodyStore,
    first: &FirstAppliedMembership,
) -> Result<AssociationState> {
    let prebind: Option<control::TargetFirstMembershipPrebind> = load(
        custody.store(),
        control::TARGET_PREBIND_NAMESPACE,
        control::TARGET_PREBIND_KEY,
    )?;
    let state = match &first.header.initialization {
        Some(bytes) => {
            let id = first.header.log_id;
            let record = RetainedAssociation {
                value: CommittedInitializationAssociation {
                    signed: decode(bytes)?,
                    position: TargetInitialMembershipPosition {
                        index: id.index,
                        term: id.leader_id.term,
                        leader_node_id: id.leader_id.node_id,
                        command_sha256: sha256(bytes),
                    },
                },
                header: first.header.clone(),
            };
            record.validate(first)?;
            record.check_installation(custody)?;
            AssociationState::Committed(Box::new(record))
        }
        None => {
            ensure!(
                prebind.is_none(),
                "target first membership lacks original signed cause"
            );
            AssociationState::Ordinary {}
        }
    };
    Ok(state)
}
pub(crate) fn initial_writes(
    custody: &CustodyStore,
    first: &FirstAppliedMembership,
) -> Result<Vec<WriteOp>> {
    initial_state(custody, first)?.writes()
}
/// Validate signed metadata before the first log can be flushed or replicated.
/// This is admission validation only, never an applied or committed fact.
pub(crate) fn validate_entry(
    custody: &CustodyStore,
    entry: &crate::Entry<crate::TypeConfig>,
) -> Result<()> {
    if entry.initialization.is_some()
        || (entry.log_id.index == 0
            && matches!(entry.payload, openraft::EntryPayload::Membership(_)))
    {
        let bytes = crate::storage::encode_entry(entry)?;
        let (header, _) = control::LogHeader::build(entry, &bytes)?;
        header.validate()?;
        let first = FirstAppliedMembership { header };
        let existing = control::first_applied_membership(custody.store())?;
        if let Some(existing) = &existing {
            anyhow::ensure!(
                existing.header == first.header,
                "initial entry differs from already applied first membership"
            );
        }
        control::local_first_association_write(custody, existing.as_ref(), Some(&first))?;
        initial_state(custody, &first)?;
    }
    Ok(())
}

/// Local retained consensus fact only. Callers require independent current
/// read authorization and a current-term quorum barrier before release.
pub fn read_initialization_association(
    stores: &TenantStorageSet,
) -> Result<Option<CommittedInitializationAssociation>> {
    stores.check_access()?;
    let gate = crate::storage::control_gate(stores.custody())?;
    let _guard = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("initialization association gate poisoned"))?;
    let first = control::first_applied_membership(stores.custody().store())?;
    let Some(AssociationState::Committed(record)) = load_state(stores.custody(), first.as_ref())?
    else {
        return Ok(None);
    };
    let applied: AppliedCursor = load(stores.custody().store(), META, b"applied")?
        .context("association applied cursor absent")?;
    let applied = applied
        .log_id()
        .context("association applied coverage absent")?;
    let committed = control::committed_coverage(stores.custody().store())?
        .context("association committed coverage absent")?;
    ensure!(
        record.header.log_id <= applied && applied <= committed,
        "initialization association lacks actual committed/applied coverage"
    );
    stores.check_access()?;
    Ok(Some(record.value))
}

pub(crate) fn validate_snapshot(
    meta: &SnapshotMeta<u64, BasicNode>,
    first: Option<&FirstAppliedMembership>,
    state: Option<&AssociationState>,
) -> Result<()> {
    ensure!(
        first.is_some() == state.is_some(),
        "snapshot lacks explicit first-membership association state"
    );
    if let Some(AssociationState::Ordinary {}) = state {
        ensure!(
            first
                .context("snapshot first absent")?
                .header
                .initialization
                .is_none(),
            "snapshot erased first membership cause"
        );
    }
    if let Some(AssociationState::Committed(record)) = state {
        record.validate(first.context("snapshot first membership absent")?)?;
        ensure!(
            meta.last_log_id
                .is_some_and(|id| id >= record.header.log_id),
            "snapshot initialization association exceeds coverage"
        );
    }
    Ok(())
}
/// Older captures may preserve a later local association, but a covering
/// snapshot cannot erase it, downgrade it to Ordinary, or invent another cause.
pub(crate) fn snapshot_writes(
    custody: &CustodyStore,
    meta: &SnapshotMeta<u64, BasicNode>,
    first: Option<&FirstAppliedMembership>,
    incoming: Option<&AssociationState>,
) -> Result<Vec<WriteOp>> {
    validate_snapshot(meta, first, incoming)?;
    let local_first = control::first_applied_membership(custody.store())?;
    let local = load_state(custody, local_first.as_ref())?;
    if let Some(state) = incoming {
        ensure!(
            *state == initial_state(custody, first.context("incoming first fact absent")?)?,
            "snapshot association does not match exact installed first entry"
        );
    }
    match (&local, incoming) {
        (Some(AssociationState::Committed(old)), Some(AssociationState::Committed(new))) => {
            ensure!(
                old == new,
                "snapshot would substitute committed initialization association"
            );
            Ok(Vec::new())
        }
        (Some(AssociationState::Committed(old)), _) => {
            ensure!(
                meta.last_log_id.is_none_or(|id| id < old.header.log_id),
                "snapshot would erase committed initialization association"
            );
            Ok(Vec::new())
        }
        (Some(AssociationState::Ordinary {}), None) => {
            ensure!(
                meta.last_log_id.is_none_or(|id| local_first
                    .as_ref()
                    .is_some_and(|first| id < first.header.log_id)),
                "snapshot would erase ordinary initialization association"
            );
            Ok(Vec::new())
        }
        (Some(AssociationState::Ordinary {}), Some(AssociationState::Committed(_))) => {
            anyhow::bail!("snapshot cannot add cause to already applied ordinary membership")
        }
        (_, Some(state)) => state.writes(),
        (None, None) => Ok(Vec::new()),
    }
}
pub(crate) fn check_published(
    custody: &CustodyStore,
    meta: &SnapshotMeta<u64, BasicNode>,
    first: Option<&FirstAppliedMembership>,
    incoming: Option<&AssociationState>,
) -> Result<()> {
    snapshot_writes(custody, meta, first, incoming)?;
    let local_first = control::first_applied_membership(custody.store())?;
    let local = load_state(custody, local_first.as_ref())?;
    if let Some(incoming) = incoming {
        ensure!(
            local.as_ref() == Some(incoming)
                || matches!((&local, incoming),
            (Some(AssociationState::Committed(old)), AssociationState::Ordinary {}) if meta.last_log_id.is_some_and(|id| id < old.header.log_id)),
            "published snapshot association absent locally"
        );
    }
    Ok(())
}

/// Exercise corruption and snapshot negatives against a real fixture's already
/// committed metadata while holding the same publication gate as apply. Every
/// temporary mutation is restored before returning, including failure paths.
#[cfg(any(test, feature = "test-utils"))]
pub fn verify_initialization_association_storage_negatives(
    stores: &TenantStorageSet,
) -> Result<()> {
    let gate = crate::storage::control_gate(stores.custody())?;
    let _guard = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("fixture association gate poisoned"))?;
    let custody = stores.custody();
    let first =
        control::first_applied_membership(custody.store())?.context("fixture first fact absent")?;
    let state = load_state(custody, Some(&first))?.context("fixture association absent")?;
    let AssociationState::Committed(record) = &state else {
        anyhow::bail!("fixture association not committed")
    };
    let original = state.writes()?;
    for change in 0..5 {
        let mutation = match change {
            0 => vec![WriteOp::delete(META, STATE)],
            1 => vec![WriteOp::put(
                META,
                STATE,
                serde_json::to_vec(&AssociationState::Ordinary {})?,
            )],
            2 => vec![WriteOp::delete(META, ANCHOR)],
            3 => vec![WriteOp::put(META, ANCHOR, b"null".to_vec())],
            _ => {
                let mut bad = (**record).clone();
                bad.value.signed.signature = "00".repeat(64);
                AssociationState::Committed(Box::new(bad)).writes()?
            }
        };
        custody.store().write_batch(&mutation)?;
        let rejected = load_state(custody, Some(&first));
        custody.store().write_batch(&original)?;
        ensure!(
            rejected.is_err(),
            "initialization storage corruption {change} was accepted"
        );
        ensure!(
            load_state(custody, Some(&first))?.as_ref() == Some(&state),
            "fixture failed to restore exact association"
        );
    }
    let cursor: AppliedCursor =
        load(custody.store(), META, b"applied")?.context("fixture cursor absent")?;
    let membership = match &cursor {
        AppliedCursor::Entry(position) => position.membership.clone(),
        AppliedCursor::Snapshot { meta, .. } => meta.last_membership.clone(),
    };
    let mut meta = SnapshotMeta {
        last_log_id: cursor.log_id(),
        last_membership: membership,
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    ensure!(
        snapshot_writes(custody, &meta, Some(&first), None).is_err(),
        "snapshot accepted missing association slot"
    );
    ensure!(
        snapshot_writes(
            custody,
            &meta,
            Some(&first),
            Some(&AssociationState::Ordinary {})
        )
        .is_err(),
        "covering snapshot erased committed cause"
    );
    validate_snapshot(&meta, Some(&first), Some(&state))?;
    meta.last_log_id = Some(first.header.log_id);
    validate_snapshot(&meta, Some(&first), Some(&state))?;
    ensure!(
        snapshot_writes(
            custody,
            &meta,
            Some(&first),
            Some(&AssociationState::Ordinary {})
        )
        .is_err(),
        "first-entry snapshot erased atomic cause"
    );
    Ok(())
}
