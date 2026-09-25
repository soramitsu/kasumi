//! Lost-Start-reply observations require the continuously owned original child.
//! Retained bytes never reconstruct a worker or authorize another Start packet.
use super::*;
use crate::TargetReplica;
use kasumi_raft::TargetFirstMembershipPrebind;
use kasumi_serving::VerifiedControlIntent;
use kasumi_types::{
    RecoveryPhaseRecord, TargetInitialDispatchIdentity, TargetReplicaInput, TargetRuntimeRequest,
    TargetRuntimeStep,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialStartRecord {
    format: u8,
    prebind: TargetFirstMembershipPrebind,
}
impl InitialStartRecord {
    fn key(&self) -> Vec<u8> {
        format!(
            "dispatch-start/{}/{}",
            self.prebind.dispatch.operation_id, self.prebind.dispatch.phase_id
        )
        .into_bytes()
    }
}

/// Borrowing the actual owner prevents a retained Start row from standing in
/// for a running child. The native response must check again at its release
/// boundary, while that same generation remains locked and owned.
pub struct ResolvedInitialStart<'a> {
    owner: &'a TargetReplica,
    prebind: TargetFirstMembershipPrebind,
}
impl ResolvedInitialStart<'_> {
    pub fn identity(&self) -> &TargetInitialDispatchIdentity {
        &self.prebind.dispatch
    }
    pub fn check(&self) -> Result<()> {
        self.owner.require_initial_start(&self.prebind)
    }
}

impl TargetJournal {
    pub(super) fn validate_initial_start_record(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<InitialStartRecord> {
        ensure!(
            bytes.len() <= DISPATCH_OBSERVATION_LIMIT,
            "Start observation exceeds original reserved capacity"
        );
        let row: InitialStartRecord = decode_current(bytes)?;
        row.prebind.validate()?;
        ensure!(
            row.format == 1
                && row.key() == key
                && row.prebind.control_root == self.installed.root
                && row.prebind.node == self.installed.node,
            "Start observation differs from installed journal"
        );
        let accepted_key = format!(
            "dispatch/{}/{}",
            row.prebind.dispatch.operation_id, row.prebind.dispatch.phase_id
        );
        let accepted = self
            .store
            .get_bounded(NS, accepted_key.as_bytes(), MAX_RECORD)?
            .context("Start observation lacks accepted dispatch")?;
        self.validate_dispatch_record(accepted_key.as_bytes(), &accepted)?;
        ensure!(
            hex::encode(Sha256::digest(&accepted)) == row.prebind.journal_row_sha256,
            "Start observation accepted dispatch digest differs"
        );
        let accepted: super::dispatch::AcceptedInitialDispatch = decode_current(&accepted)?;
        accepted.require_start_prebind(&row.prebind)?;
        Ok(row)
    }

    fn resolve_initial_start_locked<'a>(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        owner: &'a TargetReplica,
        require_record: bool,
    ) -> Result<ResolvedInitialStart<'a>> {
        ensure!(
            matches!(
                request.step,
                TargetRuntimeStep::Start(TargetReplicaInput::Quorum(_))
            ),
            "Start observation cannot resolve Initialize or another target step"
        );
        let prebind = self.authenticate_initial_dispatch(control, marked, identity, request)?;
        owner.require_initial_start(&prebind)?;
        let row = InitialStartRecord {
            format: 1,
            prebind: prebind.clone(),
        };
        let key = row.key();
        match self
            .store
            .get_bounded(NS, &key, DISPATCH_OBSERVATION_LIMIT)?
        {
            Some(bytes) => ensure!(
                self.validate_initial_start_record(&key, &bytes)? == row,
                "Start observation differs from current owned child"
            ),
            None => ensure!(!require_record, "retained Start observation absent"),
        }
        owner.require_initial_start(&prebind)?;
        Ok(ResolvedInitialStart { owner, prebind })
    }

    /// Both Control originals must come from fresh installed reads. This
    /// status path neither writes nor revives a stopped/expired original child.
    pub fn resolve_initial_start<'a>(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        owner: &'a TargetReplica,
    ) -> Result<ResolvedInitialStart<'a>> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        self.resolve_initial_start_locked(control, marked, identity, request, owner, true)
    }

    /// Publish the exact successful Start observation only while the original
    /// prebound child is actually owned and healthy. Repeating this method
    /// preserves the first bytes and cannot consume another dispatch ticket.
    pub fn record_initial_start<'a>(
        &self,
        control: &VerifiedControlIntent,
        marked: &RecoveryPhaseRecord,
        identity: &TargetInitialDispatchIdentity,
        request: &TargetRuntimeRequest,
        owner: &'a TargetReplica,
    ) -> Result<ResolvedInitialStart<'a>> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let proof =
            self.resolve_initial_start_locked(control, marked, identity, request, owner, false)?;
        let row = InitialStartRecord {
            format: 1,
            prebind: proof.prebind.clone(),
        };
        let key = row.key();
        if self
            .store
            .get_bounded(NS, &key, DISPATCH_OBSERVATION_LIMIT)?
            .is_none()
        {
            let encoded = serde_json::to_vec(&row)?;
            self.validate_initial_start_record(&key, &encoded)?;
            let mut metadata = self.metadata()?;
            metadata.dispatch_starts = metadata
                .dispatch_starts
                .checked_add(1)
                .context("Start observation count exhausted")?;
            ensure!(
                metadata.dispatch_starts <= metadata.dispatches,
                "Start observation lacks original reservation"
            );
            proof.check()?;
            self.store
                .write_batch(&[
                    WriteOp::put(NS, key.clone(), encoded.clone()),
                    WriteOp::put(NS, b"metadata", serde_json::to_vec(&metadata)?),
                ])
                .map_err(journal_unknown)?;
            let readback = self
                .store
                .get_bounded(NS, &key, DISPATCH_OBSERVATION_LIMIT)?
                .context("Start observation absent after publication")?;
            ensure!(
                readback == encoded,
                "Start observation changed after publication"
            );
            self.validate_initial_start_record(&key, &readback)?;
        }
        proof.check().map_err(journal_unknown)?;
        Ok(proof)
    }
}
