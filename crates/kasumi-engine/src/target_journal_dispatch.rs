//! Exact first-membership dispatch reservation. A local row is not a Control
//! commitment or a Raft outcome. The receiver must authenticate the phase
//! through installed Control before calling this method, and only a new
//! reservation may ever be considered for a one-use child ticket.
#![allow(dead_code)]
use super::*;
use kasumi_raft::{
    TARGET_PREBIND_KEY, TARGET_PREBIND_NAMESPACE, TargetFirstMembershipHistory,
    TargetFirstMembershipPrebind, read_target_first_membership_history,
    read_target_first_membership_prebind,
};
use kasumi_serving::VerifiedControlIntent;
use kasumi_store::TenantStorageSet;
use kasumi_types::{
    RecoveryDispatch, RecoveryEffect, RecoveryPhase, RecoveryPhaseRecord,
    TargetInitialDispatchIdentity, TargetReplicaInput, TargetRuntimeRequest, TargetRuntimeStep,
    staged_digest,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[path = "target_journal_initialize.rs"]
mod initialize;
pub use initialize::InitialInitializePermit;

/// A complete immutable local admission record. Keeping the frozen phase and
/// lifecycle intent makes startup validation independent of a live Control read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcceptedInitialDispatch {
    control_root: ControlSigningRoot,
    node: NodeIdentity,
    lifecycle: LifecycleIntent,
    phase: RecoveryPhaseRecord,
    terminal_reserve_bytes: u64,
}

/// Permanent local observation, written only after exact Control, journal and
/// committed/applied Raft history agree. This is not a current quorum proof or
/// a permission to send another Execute packet. A read must reverify custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialMembershipTerminal {
    format: u8,
    identity: TargetInitialDispatchIdentity,
    journal_row_sha256: String,
    prebind_sha256: String,
    first_fact_sha256: String,
    first_log_id: kasumi_raft::LogId<u64>,
    observed_applied_log_id: kasumi_raft::LogId<u64>,
    observed_committed_log_id: kasumi_raft::LogId<u64>,
}

impl InitialMembershipTerminal {
    fn from_history(history: &ResolvedInitialMembershipHistory) -> Result<Self> {
        Ok(Self {
            format: 1,
            identity: history.identity.clone(),
            journal_row_sha256: history.journal_row_sha256.clone(),
            prebind_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&history.prebind)?)),
            first_fact_sha256: history.local.first_fact_sha256().to_owned(),
            first_log_id: history.local.first_log_id(),
            observed_applied_log_id: history.local.applied_log_id(),
            observed_committed_log_id: history.local.committed_log_id(),
        })
    }

    fn key(&self) -> Vec<u8> {
        format!(
            "dispatch-terminal/{}/{}",
            self.identity.operation_id, self.identity.phase_id
        )
        .into_bytes()
    }

    fn require_current_history(&self, history: &ResolvedInitialMembershipHistory) -> Result<()> {
        let current = Self::from_history(history)?;
        ensure!(
            self.identity == current.identity
                && self.journal_row_sha256 == current.journal_row_sha256
                && self.prebind_sha256 == current.prebind_sha256
                && self.first_fact_sha256 == current.first_fact_sha256
                && self.first_log_id == current.first_log_id
                && self.observed_applied_log_id <= current.observed_applied_log_id
                && self.observed_committed_log_id <= current.observed_committed_log_id,
            "first-membership terminal differs from retained local history"
        );
        Ok(())
    }
}

/// One-use, in-process evidence of the exact canonical row returned only after
/// its first durable journal write and readback. It is neither a Raft prebind
/// nor a child ticket. No decoder or public constructor can manufacture one.
#[derive(Debug)]
pub struct AcceptedInitialDispatchPrebind {
    control_root: ControlSigningRoot,
    node: NodeIdentity,
    identity: TargetInitialDispatchIdentity,
    tenant: String,
    target_incarnation: Uuid,
    lifecycle: LifecycleIntent,
    request: TargetRuntimeRequest,
    journal_row_sha256: String,
    phase: RecoveryPhaseRecord,
}

/// The expected first membership derived from the accepted Control quorum and
/// all three installed target attestation signatures. This carries no issuer
/// lease, durable Raft prebind, or permission to create a child.
#[derive(Debug)]
pub struct VerifiedInitialMembership {
    prebind: AcceptedInitialDispatchPrebind,
    voters: BTreeMap<u64, String>,
    bootstrap_sha256: String,
}

impl VerifiedInitialMembership {
    pub(crate) fn start_owner(&self) -> Result<crate::target_initial_intent::StartOwner> {
        crate::target_initial_intent::StartOwner::from_marked_phase(
            &self.prebind.control_root,
            &self.prebind.phase,
        )
    }

    pub(crate) fn prepared_start_intent(
        &self,
        origin: kasumi_types::TargetOrigin,
        input: kasumi_types::TargetQuorumInput,
    ) -> Result<crate::target_initial_intent::InitialTargetIntent> {
        crate::target_initial_intent::InitialTargetIntent::prepared(
            origin,
            self.prebind.lifecycle.clone(),
            input,
            &self.prebind.control_root,
            &self.prebind.control_root,
            &self.prebind.phase,
        )
    }

    pub(crate) fn require_start_operation(
        &self,
        operation: &TargetOperation,
        input: &TargetReplicaInput,
        node_id: u64,
    ) -> Result<()> {
        operation.check()?;
        let lease = operation.invocation().gate().current()?;
        let admission = operation.prepare(
            LifecyclePhase::Initialize,
            &input.quorum().digest()?,
            operation.invocation().gate().admission_time_ms()?,
        )?;
        ensure!(
            lease.commitment().root == self.prebind.control_root
                && lease.commitment().intent == self.prebind.lifecycle
                && lease.signed().claims.request.target_node == self.prebind.node
                && self.prebind.node.node_id == node_id
                && admission.dispatch_not_after_ms <= self.prebind.request.not_after_ms
                && matches!(&self.prebind.request.step,
                    TargetRuntimeStep::Start(actual) if actual == input),
            "initial child requires the exact accepted Start and original phase"
        );
        Ok(())
    }

    pub fn prebind(&self) -> &AcceptedInitialDispatchPrebind {
        &self.prebind
    }
    pub fn voters(&self) -> &BTreeMap<u64, String> {
        &self.voters
    }
    pub fn bootstrap_sha256(&self) -> &str {
        &self.bootstrap_sha256
    }

    /// Consume the only candidate returned by a first journal reservation.
    /// A pre-existing row, a lost journal row, or an uncertain custody commit
    /// fails closed; none of these outcomes mints another child ticket.
    pub fn persist_target_raft_prebind(
        self,
        journal: &TargetJournal,
        stores: &TenantStorageSet,
    ) -> Result<TargetFirstMembershipPrebind> {
        let accepted = self.prebind;
        let _journal_guard = journal
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        ensure!(
            journal.installed.root == accepted.control_root
                && journal.installed.node == accepted.node,
            "target Raft prebind differs from installed journal"
        );
        ensure!(
            journal.read_initial_dispatch_status(
                &accepted.control_root,
                &accepted.identity,
                &accepted.request,
            )? == InitialDispatchStatus::AcceptedOnly,
            "target Raft prebind lacks accepted journal dispatch"
        );
        let key = format!(
            "dispatch/{}/{}",
            accepted.identity.operation_id, accepted.identity.phase_id
        );
        let row = journal
            .store
            .get_bounded(NS, key.as_bytes(), MAX_RECORD)?
            .context("target Raft prebind journal row absent")?;
        journal.validate_dispatch_record(key.as_bytes(), &row)?;
        ensure!(
            hex::encode(Sha256::digest(&row)) == accepted.journal_row_sha256,
            "target Raft prebind journal row digest differs"
        );
        let expected = TargetFirstMembershipPrebind {
            format: 1,
            control_root: accepted.control_root,
            node: accepted.node,
            tenant: accepted.tenant.clone(),
            target_incarnation: accepted.target_incarnation,
            group: format!("{}/{}", accepted.tenant, accepted.target_incarnation),
            dispatch: accepted.identity,
            journal_row_sha256: accepted.journal_row_sha256,
            voters: self.voters,
            bootstrap_sha256: self.bootstrap_sha256,
        };
        expected.validate_unbound_storage(stores)?;
        let mut identity =
            kasumi_raft::initial_storage_identity(expected.node.node_id, &expected.group)?
                .into_iter()
                .collect::<Vec<_>>();
        identity.push(WriteOp::put(
            TARGET_PREBIND_NAMESPACE,
            TARGET_PREBIND_KEY,
            serde_json::to_vec(&expected)?,
        ));
        stores
            .custody()
            .store()
            .write_batch(&identity)
            .context("target Raft prebind custody write outcome uncertain")?;
        read_target_first_membership_prebind(stores, &expected)?;
        Ok(expected)
    }
}

/// Historical observation only. This value cannot be used to reissue the
/// one-use prebind candidate or start a target child.
pub struct ResolvedInitialMembershipHistory {
    identity: TargetInitialDispatchIdentity,
    journal_row_sha256: String,
    prebind: TargetFirstMembershipPrebind,
    local: TargetFirstMembershipHistory,
}

impl ResolvedInitialMembershipHistory {
    pub fn require_owner(&self, owner: &crate::TargetReplica) -> Result<()> {
        owner.require_initial_start(&self.prebind)
    }

    pub fn identity(&self) -> &TargetInitialDispatchIdentity {
        &self.identity
    }
    pub fn local(&self) -> &TargetFirstMembershipHistory {
        &self.local
    }
}

impl AcceptedInitialDispatchPrebind {
    /// Derive the exact original voter map before any target child startup.
    /// The Control phase and lifecycle were authenticated before journal
    /// reservation; this verifies the materialization set against that frozen
    /// lifecycle. The result is still only a prebind candidate.
    pub fn verify_initial_membership(
        self,
        expected_node: u64,
        expected_phase: LifecyclePhase,
    ) -> Result<VerifiedInitialMembership> {
        ensure!(
            self.node.node_id == expected_node && expected_phase == LifecyclePhase::Initialize,
            "initial membership node or lifecycle phase differs"
        );
        self.identity.validate_for(expected_node, &self.request)?;
        let (voters, bootstrap_sha256) = verify_first_membership_values(
            &self.control_root,
            &self.lifecycle,
            &self.request,
            &self.tenant,
            self.target_incarnation,
            expected_node,
        )?;
        Ok(VerifiedInitialMembership {
            prebind: self,
            voters,
            bootstrap_sha256,
        })
    }

    pub fn control_root(&self) -> &ControlSigningRoot {
        &self.control_root
    }
    pub fn node(&self) -> &NodeIdentity {
        &self.node
    }
    pub fn identity(&self) -> &TargetInitialDispatchIdentity {
        &self.identity
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    pub fn target_incarnation(&self) -> Uuid {
        self.target_incarnation
    }
    pub fn request(&self) -> &TargetRuntimeRequest {
        &self.request
    }
    pub fn journal_row_sha256(&self) -> &str {
        &self.journal_row_sha256
    }
}

fn verify_first_membership_values(
    control_root: &ControlSigningRoot,
    lifecycle: &LifecycleIntent,
    request: &TargetRuntimeRequest,
    tenant: &str,
    target_incarnation: Uuid,
    expected_node: u64,
) -> Result<(BTreeMap<u64, String>, String)> {
    let quorum = match &request.step {
        TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input))
        | TargetRuntimeStep::Initialize(input) => input,
        _ => anyhow::bail!("initial membership request has another step"),
    };
    let original = &quorum
        .materialized
        .values()
        .next()
        .context("initial membership has no signed materialization")?
        .fact
        .origin;
    original.accepts_phase(lifecycle, LifecyclePhase::Initialize)?;
    ensure!(
        original.digest()? == quorum.origin_sha256
            && original.input.target_incarnation == target_incarnation
            && lifecycle.request.tenant == tenant
            && lifecycle.control_incarnation == control_root.control_incarnation
            && lifecycle.request.target_nodes.contains_key(&expected_node),
        "initial membership differs from accepted Control origin or node"
    );
    let bootstrap_sha256 =
        kasumi_serving::verify_target_materializations(original, &quorum.materialized)?;
    let voters = original
        .input
        .voters
        .iter()
        .map(|(node, peer)| (*node, peer.endpoint.clone()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        voters.len() == 3 && voters.contains_key(&expected_node),
        "initial membership lacks exact three-voter placement"
    );
    Ok((voters, bootstrap_sha256))
}

/// `ExistingStatusOnly` cannot be converted into a second Execute permission.
/// Even `NewlyAccepted` is only a durable reservation, not a child ticket.
#[derive(Debug)]
pub enum InitialDispatchReservation {
    NewlyAccepted(AcceptedInitialDispatchPrebind),
    ExistingStatusOnly,
}

/// Both observations remain unresolved; absent local bytes never prove that
/// a sent packet did not reach a child or that Raft did not commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialDispatchStatus {
    NoLocalRecord,
    AcceptedOnly,
}

impl AcceptedInitialDispatch {
    pub(super) fn require_start_prebind(
        &self,
        expected: &TargetFirstMembershipPrebind,
    ) -> Result<()> {
        ensure!(
            matches!(&self.phase.input, RecoveryDispatch::Target { request, .. }
                if matches!(request.step, TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_)))),
            "Start observation must refer to an accepted Start packet"
        );
        ensure!(
            self.expected_raft_prebind(&serde_json::to_vec(self)?)? == *expected,
            "Start observation prebind differs from its accepted dispatch"
        );
        Ok(())
    }

    /// Derive an inert expectation for validation. This does not recreate the
    /// one-use candidate returned by the original reservation.
    fn expected_raft_prebind(&self, canonical: &[u8]) -> Result<TargetFirstMembershipPrebind> {
        let RecoveryDispatch::Target { node_id, request } = &self.phase.input else {
            anyhow::bail!("accepted dispatch target input absent")
        };
        let (voters, bootstrap_sha256) = verify_first_membership_values(
            &self.control_root,
            &self.lifecycle,
            request,
            &self.lifecycle.request.tenant,
            self.lifecycle.request.target_incarnation,
            *node_id,
        )?;
        let tenant = &self.lifecycle.request.tenant;
        let target_incarnation = self.lifecycle.request.target_incarnation;
        Ok(TargetFirstMembershipPrebind {
            format: 1,
            control_root: self.control_root.clone(),
            node: self.node.clone(),
            tenant: tenant.clone(),
            target_incarnation,
            group: format!("{tenant}/{target_incarnation}"),
            dispatch: TargetInitialDispatchIdentity {
                operation_id: self.phase.operation_id,
                phase_id: self.phase.phase_id,
                attempt_id: self.marker()?.attempt_id,
                input_sha256: self.phase.input_sha256.clone(),
            },
            journal_row_sha256: hex::encode(Sha256::digest(canonical)),
            voters,
            bootstrap_sha256,
        })
    }

    fn prebind(&self, canonical: &[u8]) -> Result<AcceptedInitialDispatchPrebind> {
        ensure!(
            serde_json::to_vec(self)? == canonical,
            "first-membership journal prebind lacks exact canonical row"
        );
        let RecoveryDispatch::Target { node_id, request } = &self.phase.input else {
            anyhow::bail!("first-membership prebind target input absent")
        };
        let identity = TargetInitialDispatchIdentity {
            operation_id: self.phase.operation_id,
            phase_id: self.phase.phase_id,
            attempt_id: self.marker()?.attempt_id,
            input_sha256: self.phase.input_sha256.clone(),
        };
        identity.validate_marked_phase(
            &self.control_root,
            *node_id,
            request,
            &self.lifecycle,
            &self.phase,
        )?;
        Ok(AcceptedInitialDispatchPrebind {
            control_root: self.control_root.clone(),
            node: self.node.clone(),
            identity,
            tenant: self.lifecycle.request.tenant.clone(),
            target_incarnation: self.lifecycle.request.target_incarnation,
            lifecycle: self.lifecycle.clone(),
            request: (**request).clone(),
            journal_row_sha256: hex::encode(Sha256::digest(canonical)),
            phase: self.phase.clone(),
        })
    }

    fn marker(&self) -> Result<&kasumi_types::RecoveryEffectAttempt> {
        self.phase
            .effect_attempts
            .get(&RecoveryEffect::TargetCommand)
            .context("target initial dispatch lacks committed effect marker")
    }

    fn key(&self) -> Result<Vec<u8>> {
        self.marker()?;
        Ok(format!(
            "dispatch/{}/{}",
            self.phase.operation_id, self.phase.phase_id
        )
        .into_bytes())
    }

    fn validate(&self, installed: &TargetJournalInstallation) -> Result<()> {
        self.control_root.validate()?;
        self.node.validate()?;
        self.lifecycle.request.validate()?;
        self.phase.validate()?;
        kasumi_types::validate_name(&self.lifecycle.original_principal)?;
        let marker = self.marker()?;
        let RecoveryDispatch::Target { node_id, request } = &self.phase.input else {
            anyhow::bail!("target initial dispatch is not a target request")
        };
        request.validate()?;
        let quorum = match &request.step {
            TargetRuntimeStep::Start(TargetReplicaInput::Quorum(input))
            | TargetRuntimeStep::Initialize(input) => input,
            _ => anyhow::bail!("only first-membership Start/Initialize may be reserved"),
        };
        let exact_node = self
            .lifecycle
            .request
            .target_nodes
            .get(node_id)
            .context("first-membership target node absent from lifecycle intent")?;
        ensure!(
            self.control_root == installed.root
                && self.node == installed.node
                && *node_id == installed.node.node_id
                && exact_node.node_id == installed.node.node_id
                && exact_node.verifier == installed.node.verifier
                && exact_node.principal == installed.node.principal
                && exact_node.certificate_sha256 == installed.node.certificate_sha256
                && self.phase.phase == RecoveryPhase::Initialize
                && self.phase.outcome.is_none()
                && self.phase.resolved_revision.is_none()
                && marker.input_sha256 == self.phase.input_sha256
                && marker.begun_revision > self.phase.prepared_revision
                && self.phase.input_sha256
                    == staged_digest(&RecoveryDispatch::Target {
                        node_id: *node_id,
                        request: request.clone(),
                    })?
                    .0
                && self.phase.principal == self.lifecycle.original_principal
                && self.lifecycle.control_incarnation == installed.root.control_incarnation
                && self.lifecycle.request.phase == LifecyclePhase::Initialize
                && self.lifecycle.request.command_id == request.command_id
                && self.lifecycle.request.tenant == request.tenant
                && self.lifecycle.request.phase_input_sha256 == quorum.digest()?
                && self.lifecycle.request_sha256
                    == kasumi_serving::digest(&self.lifecycle.request)?
                && self.lifecycle.installation_generation > 0
                && self.lifecycle.revision > 0
                && self.lifecycle.accepted_at_ms < self.lifecycle.original_credential_expires_at_ms
                && self.lifecycle.accepted_at_ms <= self.phase.admitted_at_ms
                && request.not_after_ms <= self.phase.original_credential_expires_at_ms
                && self.terminal_reserve_bytes == DISPATCH_TERMINAL_RESERVE,
            "first-membership journal dispatch differs from installed identity or frozen Control input"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECORD,
            "first-membership dispatch record exceeds bound"
        );
        Ok(())
    }
}

impl TargetJournal {
    pub(super) fn validate_dispatch_terminal(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<InitialMembershipTerminal> {
        ensure!(
            bytes.len() <= DISPATCH_OBSERVATION_LIMIT,
            "first-membership terminal exceeds its original reservation"
        );
        let terminal: InitialMembershipTerminal = decode_current(bytes)?;
        ensure!(
            terminal.format == 1
                && key == terminal.key()
                && terminal.first_log_id <= terminal.observed_applied_log_id
                && terminal.observed_applied_log_id <= terminal.observed_committed_log_id,
            "first-membership terminal key, format or log coverage differs"
        );
        kasumi_types::validate_sha256(&terminal.first_fact_sha256)?;
        let accepted_key = format!(
            "dispatch/{}/{}",
            terminal.identity.operation_id, terminal.identity.phase_id
        );
        let accepted = self
            .store
            .get_bounded(NS, accepted_key.as_bytes(), MAX_RECORD)?
            .context("first-membership terminal lacks its accepted dispatch")?;
        self.validate_dispatch_record(accepted_key.as_bytes(), &accepted)?;
        let row: AcceptedInitialDispatch = decode_current(&accepted)?;
        let expected = row.expected_raft_prebind(&accepted)?;
        let local_prebind = match &row.phase.input {
            RecoveryDispatch::Target { request, .. }
                if matches!(request.step, TargetRuntimeStep::Initialize(_)) =>
            {
                self.initialized_start_prebind(&expected, None)?
            }
            _ => expected.clone(),
        };
        ensure!(
            terminal.identity == expected.dispatch
                && terminal.journal_row_sha256 == expected.journal_row_sha256
                && terminal.prebind_sha256
                    == hex::encode(Sha256::digest(serde_json::to_vec(&local_prebind)?)),
            "first-membership terminal differs from its accepted dispatch"
        );
        Ok(terminal)
    }

    pub(super) fn validate_dispatch_record(&self, key: &[u8], bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_RECORD,
            "target dispatch record exceeds bound"
        );
        let row: AcceptedInitialDispatch = serde_json::from_slice(bytes)?;
        row.validate(&self.installed)?;
        ensure!(
            key == row.key()? && serde_json::to_vec(&row)? == bytes,
            "target dispatch key or canonical bytes differ"
        );
        Ok(())
    }

    /// Read only the exact accepted identity. This does not open a generation
    /// or infer an outcome from a row or its absence. A historical caller must
    /// separately authenticate the original phase through installed Control.
    pub fn read_initial_dispatch_status(
        &self,
        claimed_root: &ControlSigningRoot,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
    ) -> Result<InitialDispatchStatus> {
        ensure!(
            claimed_root == &self.installed.root,
            "target dispatch historical identity differs from installed journal"
        );
        request.validate()?;
        identity.validate_for(self.installed.node.node_id, request)?;
        self.metadata()?;
        let key = format!("dispatch/{}/{}", identity.operation_id, identity.phase_id).into_bytes();
        let Some(bytes) = self.store.get_bounded(NS, &key, MAX_RECORD)? else {
            return Ok(InitialDispatchStatus::NoLocalRecord);
        };
        self.validate_dispatch_record(&key, &bytes)?;
        let row: AcceptedInitialDispatch = serde_json::from_slice(&bytes)?;
        let RecoveryDispatch::Target {
            node_id,
            request: stored,
        } = &row.phase.input
        else {
            anyhow::bail!("accepted dispatch target input absent")
        };
        ensure!(
            row.marker()?.attempt_id == identity.attempt_id
                && row.phase.input_sha256 == identity.input_sha256
                && *node_id == self.installed.node.node_id
                && **stored == *request,
            "historical target dispatch differs from accepted row"
        );
        Ok(InitialDispatchStatus::AcceptedOnly)
    }

    /// Resolve an already accepted first membership from retained history.
    /// The caller must obtain `control` from a fresh installed-Control signed
    /// intent read and `marked` from a fresh ReadPhase quorum barrier. This
    /// method rechecks their exact bytes against the canonical one-use journal
    /// row and independently verifies signed materializations and local Raft
    /// history. It performs no write and cannot revive an Execute packet.
    pub fn resolve_initial_membership_history(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        stores: &TenantStorageSet,
    ) -> Result<ResolvedInitialMembershipHistory> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        self.resolve_initial_membership_history_locked(control, marked, identity, request, stores)
    }

    fn resolve_initial_membership_history_locked(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        stores: &TenantStorageSet,
    ) -> Result<ResolvedInitialMembershipHistory> {
        let accepted = self.authenticate_initial_dispatch(control, marked, identity, request)?;
        let expected_prebind = if matches!(request.step, TargetRuntimeStep::Initialize(_)) {
            self.initialized_start_prebind(&accepted, Some(stores))?
        } else {
            accepted.clone()
        };
        let local = read_target_first_membership_history(stores, &expected_prebind)?;
        self.store.check_access()?;
        let history = ResolvedInitialMembershipHistory {
            identity: identity.clone(),
            journal_row_sha256: accepted.journal_row_sha256,
            prebind: expected_prebind,
            local,
        };
        let key = InitialMembershipTerminal::from_history(&history)?.key();
        if let Some(bytes) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            self.validate_dispatch_terminal(&key, &bytes)?
                .require_current_history(&history)?;
        }
        Ok(history)
    }

    pub(super) fn authenticate_initial_dispatch(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
    ) -> Result<TargetFirstMembershipPrebind> {
        let observation = control.observation();
        ensure!(
            observation.root == self.installed.root,
            "historical Control root differs from installed journal"
        );
        let lifecycle = &observation.intent;
        identity.validate_marked_phase(
            &self.installed.root,
            self.installed.node.node_id,
            request,
            lifecycle,
            marked,
        )?;
        let expected_row = AcceptedInitialDispatch {
            control_root: self.installed.root.clone(),
            node: self.installed.node.clone(),
            lifecycle: lifecycle.clone(),
            phase: marked.clone(),
            terminal_reserve_bytes: DISPATCH_TERMINAL_RESERVE,
        };
        expected_row.validate(&self.installed)?;
        self.metadata()?;
        let key = expected_row.key()?;
        let bytes = self
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("accepted first-membership journal row absent")?;
        self.validate_dispatch_record(&key, &bytes)?;
        ensure!(
            bytes == serde_json::to_vec(&expected_row)?,
            "accepted first-membership journal row differs from fresh Control originals"
        );
        let expected_prebind = expected_row.expected_raft_prebind(&bytes)?;
        Ok(expected_prebind)
    }

    /// Retain a positive historical observation in its precharged permanent
    /// slot. The caller must obtain both fresh installed-Control reads exactly
    /// as for `resolve_initial_membership_history`; this call rereads and checks
    /// current local custody before writing. It never starts or retries a child.
    /// Lost write replies remain unresolved; repeating these same reads may
    /// verify and return the immutable original terminal without overwriting it.
    pub fn record_initial_membership_history(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        stores: &TenantStorageSet,
    ) -> Result<ResolvedInitialMembershipHistory> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let history = self.resolve_initial_membership_history_locked(
            control, marked, identity, request, stores,
        )?;
        let terminal = InitialMembershipTerminal::from_history(&history)?;
        let key = terminal.key();
        if let Some(bytes) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            self.validate_dispatch_terminal(&key, &bytes)?
                .require_current_history(&history)?;
            return Ok(history);
        }
        let encoded = serde_json::to_vec(&terminal)?;
        self.validate_dispatch_terminal(&key, &encoded)?;
        let mut metadata = self.metadata()?;
        metadata.dispatch_terminals = metadata
            .dispatch_terminals
            .checked_add(1)
            .context("target dispatch terminal count exhausted")?;
        ensure!(
            metadata.dispatch_terminals <= metadata.dispatches,
            "target dispatch terminal lacks original capacity"
        );
        self.store
            .write_batch(&[
                WriteOp::put(NS, key.clone(), encoded.clone()),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        let readback = self
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("first-membership terminal absent after write")?;
        self.validate_dispatch_terminal(&key, &readback)?
            .require_current_history(&history)?;
        ensure!(
            readback == encoded,
            "first-membership terminal changed after write"
        );
        self.store.check_access()?;
        Ok(history)
    }

    /// Reserve one exact Start(Quorum) or Initialize packet before any future
    /// child. The caller must first make a fresh pinned Control phase/status
    /// read, compare the authenticated wire envelope, and check the original
    /// mutation deadline. This method performs no issuer or Raft work.
    pub fn reserve_initial_dispatch(
        &self,
        claimed_root: &ControlSigningRoot,
        phase: &RecoveryPhaseRecord,
        lifecycle: &LifecycleIntent,
        request: &TargetRuntimeRequest,
    ) -> Result<InitialDispatchReservation> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let mut metadata = self.metadata()?;
        ensure!(
            claimed_root == &self.installed.root
                && phase.input
                    == RecoveryDispatch::Target {
                        node_id: self.installed.node.node_id,
                        request: Box::new(request.clone()),
                    },
            "target dispatch differs from installed root or exact marked phase"
        );
        let row = AcceptedInitialDispatch {
            control_root: claimed_root.clone(),
            node: self.installed.node.clone(),
            lifecycle: lifecycle.clone(),
            phase: phase.clone(),
            terminal_reserve_bytes: DISPATCH_TERMINAL_RESERVE,
        };
        row.validate(&self.installed)?;
        let key = row.key()?;
        let encoded = serde_json::to_vec(&row)?;
        if let Some(old) = self.store.get_bounded(NS, &key, MAX_RECORD)? {
            self.validate_dispatch_record(&key, &old)?;
            ensure!(
                old == encoded,
                "target phase has a conflicting accepted dispatch"
            );
            return Ok(InitialDispatchReservation::ExistingStatusOnly);
        }
        ensure!(
            self.store
                .get_bounded(
                    NS,
                    &stop_key(
                        &row.lifecycle.request.tenant,
                        row.lifecycle.request.target_incarnation,
                    ),
                    MAX_RECORD,
                )?
                .is_none(),
            "target incarnation permanently stopped locally"
        );
        metadata.dispatches = metadata
            .dispatches
            .checked_add(1)
            .context("target dispatch count exhausted")?;
        metadata.charged_bytes = metadata
            .charged_bytes
            .checked_add(encoded.len() as u64 + DISPATCH_TERMINAL_RESERVE)
            .context("target dispatch capacity exhausted")?;
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "target dispatch terminal reserve exceeds permanent journal capacity"
        );
        self.store
            .write_batch(&[
                WriteOp::put(NS, key.clone(), encoded.clone()),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        let readback = self
            .store
            .get_bounded(NS, &key, MAX_RECORD)?
            .context("accepted first-membership journal row absent after write")?;
        self.validate_dispatch_record(&key, &readback)?;
        ensure!(
            readback == encoded,
            "accepted first-membership journal row changed after write"
        );
        Ok(InitialDispatchReservation::NewlyAccepted(
            row.prebind(&readback)?,
        ))
    }
}
