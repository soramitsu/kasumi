//! The later Initialize packet consumes its own accepted candidate while the
//! original Start owner is held. Its association never replaces the Raft prebind.
use super::*;
use crate::{TargetReplica, target_initial_intent};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialInitializeAssociation {
    format: u8,
    initialize: TargetFirstMembershipPrebind,
    start: TargetFirstMembershipPrebind,
}
impl InitialInitializeAssociation {
    fn key(&self) -> Vec<u8> {
        format!(
            "dispatch-initialize/{}/{}",
            self.initialize.dispatch.operation_id, self.initialize.dispatch.phase_id
        )
        .into_bytes()
    }
}

/// Only a newly accepted Initialize candidate can construct this non-cloneable
/// permit. Decoded association rows are observations and cannot reconstruct it.
pub struct InitialInitializePermit {
    association: InitialInitializeAssociation,
    lifecycle: LifecycleIntent,
    request: TargetRuntimeRequest,
    custody_owner: target_initial_intent::InitializeOwner,
}
impl InitialInitializePermit {
    pub(crate) fn consume(self, owner: &TargetReplica, operation: &TargetOperation) -> Result<()> {
        owner.require_initial_start(&self.association.start)?;
        require_operation(
            operation,
            &self.association.initialize,
            &self.lifecycle,
            &self.request,
        )?;
        let status = target_initial_intent::read_initialize_intent_status(
            owner.database().stores().custody().store(),
            &self.custody_owner,
            &self.association.initialize.control_root,
        )?;
        ensure!(
            status == target_initial_intent::InitializeIntentStatus::OwnedWithoutAppliedProof,
            "Initialize custody owner absent"
        );
        Ok(())
    }
}

fn require_operation(
    operation: &TargetOperation,
    expected: &TargetFirstMembershipPrebind,
    lifecycle: &LifecycleIntent,
    request: &TargetRuntimeRequest,
) -> Result<()> {
    operation.check()?;
    let TargetRuntimeStep::Initialize(input) = &request.step else {
        anyhow::bail!("Initialize permit requires its separately accepted packet")
    };
    let lease = operation.invocation().gate().current()?;
    let admission = operation.prepare(
        LifecyclePhase::Initialize,
        &input.digest()?,
        operation.invocation().gate().admission_time_ms()?,
    )?;
    ensure!(
        lease.commitment().root == expected.control_root
            && lease.commitment().intent == *lifecycle
            && lease.signed().claims.request.target_node == expected.node
            && admission.dispatch_not_after_ms <= request.not_after_ms,
        "Initialize candidate differs from current original phase or deadline"
    );
    Ok(())
}

impl VerifiedInitialMembership {
    pub fn bind_initialize(
        self,
        journal: &TargetJournal,
        operation: &TargetOperation,
        owner: &TargetReplica,
    ) -> Result<InitialInitializePermit> {
        let _workspace = journal.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = journal
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let accepted = &self.prebind;
        let initialize = TargetFirstMembershipPrebind {
            format: 1,
            control_root: accepted.control_root.clone(),
            node: accepted.node.clone(),
            tenant: accepted.tenant.clone(),
            target_incarnation: accepted.target_incarnation,
            group: format!("{}/{}", accepted.tenant, accepted.target_incarnation),
            dispatch: accepted.identity.clone(),
            journal_row_sha256: accepted.journal_row_sha256.clone(),
            voters: self.voters,
            bootstrap_sha256: self.bootstrap_sha256,
        };
        require_operation(
            operation,
            &initialize,
            &accepted.lifecycle,
            &accepted.request,
        )?;
        let start = owner.initial_start_prebind()?.clone();
        let association = InitialInitializeAssociation {
            format: 1,
            initialize,
            start,
        };
        let key = association.key();
        let encoded = serde_json::to_vec(&association)?;
        journal.validate_initial_initialize_record(&key, &encoded)?;
        ensure!(
            journal
                .store
                .get_bounded(NS, &key, DISPATCH_OBSERVATION_LIMIT)?
                .is_none(),
            "Initialize association already consumed; history only"
        );
        // The held actual child and generation serialize this one-way custody
        // transition before any call to Raft initialize. An uncertain write
        // consumes the candidate and never produces a replacement permit.
        owner.bind_initial_initialize(&accepted.control_root, &accepted.phase)?;
        let mut metadata = journal.metadata()?;
        metadata.dispatch_initializes = metadata
            .dispatch_initializes
            .checked_add(1)
            .context("Initialize association count exhausted")?;
        ensure!(
            metadata
                .dispatch_starts
                .checked_add(metadata.dispatch_initializes)
                .is_some_and(|count| count <= metadata.dispatches),
            "Initialize reservation absent"
        );
        owner.require_initial_start(&association.start)?;
        journal
            .store
            .write_batch(&[
                WriteOp::put(NS, key.clone(), encoded.clone()),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        ensure!(
            journal
                .store
                .get_bounded(NS, &key, DISPATCH_OBSERVATION_LIMIT)?
                .as_deref()
                == Some(encoded.as_slice()),
            "Initialize association readback differs"
        );
        owner.require_initial_start(&association.start)?;
        Ok(InitialInitializePermit {
            association,
            lifecycle: accepted.lifecycle.clone(),
            request: accepted.request.clone(),
            custody_owner: target_initial_intent::InitializeOwner::from_marked_phase(
                &accepted.control_root,
                &accepted.phase,
            )?,
        })
    }
}

impl TargetJournal {
    fn accepted_prebind_record(
        &self,
        expected: &TargetFirstMembershipPrebind,
    ) -> Result<AcceptedInitialDispatch> {
        expected.validate()?;
        let key = format!(
            "dispatch/{}/{}",
            expected.dispatch.operation_id, expected.dispatch.phase_id
        );
        let bytes = self
            .store
            .get_bounded(NS, key.as_bytes(), MAX_RECORD)?
            .context("Initialize association accepted dispatch absent")?;
        self.validate_dispatch_record(key.as_bytes(), &bytes)?;
        let accepted: AcceptedInitialDispatch = decode_current(&bytes)?;
        ensure!(
            accepted.expected_raft_prebind(&bytes)? == *expected,
            "Initialize association differs from accepted dispatch"
        );
        Ok(accepted)
    }

    pub(crate) fn validate_initial_initialize_record(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<InitialInitializeAssociation> {
        ensure!(
            bytes.len() <= DISPATCH_OBSERVATION_LIMIT,
            "Initialize association exceeds reservation"
        );
        let row: InitialInitializeAssociation = decode_current(bytes)?;
        let initialize = self.accepted_prebind_record(&row.initialize)?;
        let start = self.accepted_prebind_record(&row.start)?;
        start.require_start_prebind(&row.start)?;
        ensure!(
            row.format == 1
                && row.key() == key
                && matches!(&initialize.phase.input, RecoveryDispatch::Target { request, .. }
                if matches!(request.step, TargetRuntimeStep::Initialize(_)))
                && row.initialize.control_root == row.start.control_root
                && row.initialize.node == row.start.node
                && row.initialize.tenant == row.start.tenant
                && row.initialize.target_incarnation == row.start.target_incarnation
                && row.initialize.group == row.start.group
                && row.initialize.voters == row.start.voters
                && row.initialize.bootstrap_sha256 == row.start.bootstrap_sha256
                && row.initialize.dispatch.operation_id == row.start.dispatch.operation_id
                && row.initialize.dispatch.phase_id != row.start.dispatch.phase_id
                && row.initialize.dispatch.attempt_id != row.start.dispatch.attempt_id
                && Some(&row.initialize.node.node_id) == row.initialize.voters.keys().next()
                && initialize.lifecycle == start.lifecycle
                && initialize.phase.sequence > start.phase.sequence,
            "Initialize association differs from original Start owner or phase"
        );
        let start_key = format!(
            "dispatch-start/{}/{}",
            row.start.dispatch.operation_id, row.start.dispatch.phase_id
        );
        let observed_start = self
            .store
            .get_bounded(NS, start_key.as_bytes(), DISPATCH_OBSERVATION_LIMIT)?
            .context("Initialize association lacks retained successful Start")?;
        self.validate_initial_start_record(start_key.as_bytes(), &observed_start)?;
        Ok(row)
    }

    pub(super) fn initialized_start_prebind(
        &self,
        expected: &TargetFirstMembershipPrebind,
        stores: Option<&TenantStorageSet>,
    ) -> Result<TargetFirstMembershipPrebind> {
        let key = format!(
            "dispatch-initialize/{}/{}",
            expected.dispatch.operation_id, expected.dispatch.phase_id
        );
        let bytes = self
            .store
            .get_bounded(NS, key.as_bytes(), DISPATCH_OBSERVATION_LIMIT)?
            .context("Initialize association absent")?;
        let row = self.validate_initial_initialize_record(key.as_bytes(), &bytes)?;
        ensure!(
            row.initialize == *expected,
            "Initialize association belongs to another accepted packet"
        );
        if let Some(stores) = stores {
            let accepted = self.accepted_prebind_record(expected)?;
            let owner = target_initial_intent::InitializeOwner::from_marked_phase(
                &expected.control_root,
                &accepted.phase,
            )?;
            ensure!(
                target_initial_intent::read_initialize_intent_status(
                    stores.custody().store(),
                    &owner,
                    &expected.control_root
                )? == target_initial_intent::InitializeIntentStatus::OwnedWithoutAppliedProof,
                "Initialize custody association absent"
            );
        }
        Ok(row.start)
    }
}
