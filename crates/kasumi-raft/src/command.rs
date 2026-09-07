//! Closed metadata input retained before commitment. None of these records is
//! a retirement proof: only the source's applied/current-authority path may
//! produce that proof. Application bytes never enter control storage.
use anyhow::{Context, Result, ensure};
use kasumi_types::{
    Command, Operation, RequestAuthorization, RetireSourceRequest, RetirementObservation,
    StoredRetirement, validate_name, validate_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_RETIREMENT_SEED_BYTES: usize = 256 << 10;

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Compact source-state inputs captured by the serialized leader. Counts and
/// exact byte accounting allow a custody reducer to reproduce resource denials
/// without reading document bodies. Seed eligibility still requires commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementReplayState {
    pub tenant: String,
    pub incarnation: String,
    pub previous_revision: u64,
    pub revision_base: u64,
    pub policy_epoch: u64,
    pub administrators: BTreeSet<String>,
    pub suspended: bool,
    pub retired: bool,
    pub pending_restore: bool,
    pub existing_identity: Option<StoredRetirement>,
    pub retirement_count: usize,
    pub retirement_bytes: usize,
    pub max_retirements: usize,
    pub audit_count: usize,
    pub max_audit_records: usize,
    pub snapshot_bytes: usize,
    pub max_snapshot_bytes: usize,
    pub staged_outcome_headroom: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementLogSeed {
    command_sha256: String,
    principal: String,
    request_id: String,
    scopes: BTreeSet<kasumi_types::Action>,
    authorization: RequestAuthorization,
    admitted_at_ms: u64,
    request: RetireSourceRequest,
    verified_closure_digest: String,
    observation: RetirementObservation,
    source: RetirementReplayState,
}
impl RetirementLogSeed {
    /// Trusted producer boundary. The native API cannot submit this seed or a
    /// prepared retirement command. Deserialization never restores live auth.
    pub fn prepare(command: &Command, source: RetirementReplayState) -> Result<Self> {
        let Operation::RetireSource(prepared) = &command.operation else {
            anyhow::bail!("custody seed requires planned retirement");
        };
        let seed = Self {
            command_sha256: sha256(&serde_json::to_vec(command)?),
            principal: command.context.principal.clone(),
            request_id: command.context.request_id.clone(),
            scopes: command.context.scopes.clone(),
            authorization: command.context.authorization.clone(),
            admitted_at_ms: command.timestamp_ms,
            request: prepared.request.clone(),
            verified_closure_digest: prepared.verified_closure_digest.clone(),
            observation: prepared
                .observation
                .clone()
                .context("retirement closure observation absent")?,
            source,
        };
        seed.validate()?;
        ensure!(
            command.context.tenant == seed.source.tenant,
            "retirement seed tenant differs"
        );
        ensure!(
            serde_json::to_vec(&seed)?.len() <= MAX_RETIREMENT_SEED_BYTES,
            "retirement seed quota exceeded"
        );
        Ok(seed)
    }

    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        for name in [
            &self.principal,
            &self.request_id,
            &self.source.tenant,
            &self.source.incarnation,
        ] {
            validate_name(name)?;
        }
        for digest in [
            &self.command_sha256,
            &self.verified_closure_digest,
            &self.observation.closure_digest,
        ] {
            validate_sha256(digest)?;
        }
        ensure!(
            self.source.tenant == self.request.checkpoint.tenant
                && self.source.incarnation == self.request.expected_source_incarnation
                && self.source.previous_revision >= self.source.revision_base
                && self.observation.revision == self.source.previous_revision
                && self.source.administrators.len() <= 1024
                && self.source.max_retirements <= 100_000
                && self.source.retirement_count <= self.source.max_retirements
                && self.source.audit_count <= self.source.max_audit_records
                && self.source.snapshot_bytes <= self.source.max_snapshot_bytes,
            "retirement seed source binding differs"
        );
        for principal in &self.source.administrators {
            validate_name(principal)?;
        }
        let command = Command {
            context: kasumi_types::RequestContext {
                authorization: self.authorization.clone(),
                principal: self.principal.clone(),
                tenant: self.source.tenant.clone(),
                scopes: self.scopes.clone(),
                request_id: self.request_id.clone(),
            },
            timestamp_ms: self.admitted_at_ms,
            operation: Operation::RetireSource(kasumi_types::PreparedRetirement {
                request: self.request.clone(),
                verified_closure_digest: self.verified_closure_digest.clone(),
                observation: Some(self.observation.clone()),
            }),
        };
        ensure!(
            sha256(&serde_json::to_vec(&command)?) == self.command_sha256,
            "retirement seed reconstructed command differs"
        );
        if let Some(record) = &self.source.existing_identity {
            ensure!(
                record.request.reference()? == self.request.reference()?
                    && record.accepted_revision <= self.source.previous_revision,
                "retirement seed retained identity differs"
            );
        }
        Ok(())
    }
    pub fn request(&self) -> &RetireSourceRequest {
        &self.request
    }
    pub fn source(&self) -> &RetirementReplayState {
        &self.source
    }
    pub(crate) fn validate_receipt(
        &self,
        revision: u64,
        receipt: &kasumi_types::RetirementReceipt,
    ) -> Result<()> {
        receipt.validate()?;
        self.authorization.check_admitted_at(self.admitted_at_ms)?;
        ensure!(
            self.scopes.contains(&kasumi_types::Action::Admin)
                && self.source.administrators.contains(&self.principal)
                && !self.source.retired
                && !self.source.pending_restore
                && self.source.existing_identity.is_none()
                && receipt.revision == revision
                && revision > self.source.previous_revision
                && receipt.tenant == self.source.tenant
                && receipt.principal == self.principal
                && receipt.source_incarnation == self.source.incarnation
                && receipt.target_incarnation == self.request.target_incarnation
                && receipt.request_digest == self.request.reference()?.request_digest
                && receipt.retirement_id == self.request.retirement_id
                && receipt.checkpoint == self.request.checkpoint
                && self.source.policy_epoch.checked_add(1) == Some(receipt.policy_epoch)
                && receipt.admitted_at_ms == self.admitted_at_ms
                && self.admitted_at_ms <= self.request.not_after_ms
                && receipt.closure_digest == self.verified_closure_digest
                && self.observation.closure_digest == self.verified_closure_digest,
            "applied retirement outcome differs from committed seed"
        );
        Ok(())
    }
    pub fn command_sha256(&self) -> &str {
        &self.command_sha256
    }
    pub fn encoded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_RETIREMENT_SEED_BYTES,
            "retirement seed quota exceeded"
        );
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_RETIREMENT_SEED_BYTES,
            "retirement seed quota exceeded"
        );
        let result: Self = serde_json::from_slice(bytes)?;
        result.validate()?;
        // Reject discarded nested fields as well as alternate wire spellings.
        ensure!(
            serde_json::to_vec(&result)? == bytes,
            "retirement seed is not canonical closed metadata"
        );
        Ok(result)
    }
    fn check_command(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            sha256(bytes) == self.command_sha256,
            "retirement seed command digest differs"
        );
        let command: Command = serde_json::from_slice(bytes)?;
        let rebuilt = Self::prepare(&command, self.source.clone())?;
        ensure!(
            rebuilt.encoded()? == self.encoded()?,
            "retirement seed command metadata differs"
        );
        Ok(())
    }
}

/// Typed Raft command. Metadata has its own closed encoding because postcard
/// does not support serde's internally tagged authorization enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaftCommand {
    application: Vec<u8>,
    retirement_seed: Option<Vec<u8>>,
}
impl RaftCommand {
    pub fn application(bytes: Vec<u8>) -> Self {
        Self {
            application: bytes,
            retirement_seed: None,
        }
    }
    pub fn retirement(bytes: Vec<u8>, seed: RetirementLogSeed) -> Result<Self> {
        seed.check_command(&bytes)?;
        Ok(Self {
            application: bytes,
            retirement_seed: Some(seed.encoded()?),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.application
    }
    pub fn seed(&self) -> Result<Option<RetirementLogSeed>> {
        self.retirement_seed
            .as_ref()
            .map(|bytes| {
                let seed = RetirementLogSeed::decode(bytes)?;
                seed.check_command(&self.application)?;
                Ok(seed)
            })
            .transpose()
    }
    pub(crate) fn seed_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.seed()?;
        Ok(self.retirement_seed.clone())
    }
}
