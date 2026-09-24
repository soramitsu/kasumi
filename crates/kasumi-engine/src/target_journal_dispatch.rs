//! Dormant exact first-membership dispatch reservation. A local row is not a
//! Control commitment or a Raft outcome. The future receiver must authenticate
//! the phase through installed Control before calling this method, and only a
//! new reservation may ever be considered for a one-use child ticket.
#![allow(dead_code)]
use super::*;
use kasumi_types::{
    RecoveryDispatch, RecoveryEffect, RecoveryPhase, RecoveryPhaseRecord, TargetReplicaInput,
    TargetRuntimeRequest, TargetRuntimeStep, staged_digest,
};

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

/// `ExistingStatusOnly` cannot be converted into a second Execute permission.
/// Even `NewlyAccepted` is only a durable reservation, not a child ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitialDispatchReservation {
    NewlyAccepted,
    ExistingStatusOnly,
}

/// Both observations remain unresolved; absent local bytes never prove that
/// a sent packet did not reach a child or that Raft did not commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitialDispatchStatus {
    NoLocalRecord,
    AcceptedOnly,
}

impl AcceptedInitialDispatch {
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
    pub(crate) fn read_initial_dispatch_status(
        &self,
        claimed_root: &ControlSigningRoot,
        operation_id: Uuid,
        phase_id: Uuid,
        attempt_id: Uuid,
        input_sha256: &str,
        request: &TargetRuntimeRequest,
    ) -> Result<InitialDispatchStatus> {
        ensure!(
            claimed_root == &self.installed.root
                && !operation_id.is_nil()
                && !phase_id.is_nil()
                && !attempt_id.is_nil(),
            "target dispatch historical identity differs from installed journal"
        );
        request.validate()?;
        kasumi_types::validate_sha256(input_sha256)?;
        ensure!(
            input_sha256
                == staged_digest(&RecoveryDispatch::Target {
                    node_id: self.installed.node.node_id,
                    request: Box::new(request.clone()),
                })?
                .0,
            "historical target input digest differs from full request"
        );
        self.metadata()?;
        let key = format!("dispatch/{operation_id}/{phase_id}").into_bytes();
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
            row.marker()?.attempt_id == attempt_id
                && row.phase.input_sha256 == input_sha256
                && *node_id == self.installed.node.node_id
                && **stored == *request,
            "historical target dispatch differs from accepted row"
        );
        Ok(InitialDispatchStatus::AcceptedOnly)
    }

    /// Reserve one exact Start(Quorum) or Initialize packet before any future
    /// child. The caller must first make a fresh pinned Control phase/status
    /// read, compare the authenticated wire envelope, and check the original
    /// mutation deadline. This dormant method performs no issuer or Raft work.
    pub(crate) fn reserve_initial_dispatch(
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
                WriteOp::put(NS, key, encoded),
                WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
            ])
            .map_err(journal_unknown)?;
        Ok(InitialDispatchReservation::NewlyAccepted)
    }
}
