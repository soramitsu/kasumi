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
    pub retirement_bytes: u64,
    pub max_retirement_bytes: u64,
    pub audit_hot_bytes: u64,
    pub max_audit_hot_bytes: u64,
    pub snapshot_bytes: u64,
    pub max_snapshot_bytes: u64,
    pub staged_outcome_headroom: u64,
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
                && self.source.max_retirement_bytes > 0
                && self.source.retirement_bytes <= self.source.max_retirement_bytes
                && self.source.audit_hot_bytes <= self.source.max_audit_hot_bytes
                && self.source.snapshot_bytes <= self.source.max_snapshot_bytes,
            "retirement seed source binding differs"
        );
        for principal in &self.source.administrators {
            validate_name(principal)?;
        }
        let command = self.command();
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
    fn command(&self) -> Command {
        Command {
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
        }
    }
    pub(crate) fn reconstructed_command(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(&self.command())?)
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
        self.reserve_success_capacity()?;
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

    fn successful_candidate(&self) -> bool {
        self.authorization
            .check_admitted_at(self.admitted_at_ms)
            .is_ok()
            && self.scopes.contains(&kasumi_types::Action::Admin)
            && self.source.administrators.contains(&self.principal)
            && !self.source.retired
            && !self.source.pending_restore
            && self.source.existing_identity.is_none()
            && self.source.policy_epoch < u64::MAX
            && self.admitted_at_ms <= self.request.not_after_ms
            && self.request.checkpoint.revision <= self.source.previous_revision
            && self.observation.revision == self.source.previous_revision
            && self.observation.closure_digest == self.verified_closure_digest
    }

    fn receipt_at(&self, revision: u64) -> kasumi_types::RetirementReceipt {
        kasumi_types::RetirementReceipt {
            tenant: self.source.tenant.clone(),
            source_incarnation: self.source.incarnation.clone(),
            target_incarnation: self.request.target_incarnation.clone(),
            retirement_id: self.request.retirement_id.clone(),
            principal: self.principal.clone(),
            admitted_at_ms: self.admitted_at_ms,
            request_digest: self
                .request
                .reference()
                .expect("validated request")
                .request_digest,
            checkpoint: self.request.checkpoint.clone(),
            revision,
            policy_epoch: self.source.policy_epoch.saturating_add(1),
            closure_digest: self.verified_closure_digest.clone(),
        }
    }

    /// The serialized leader reserves completion before proposing a potentially
    /// successful retirement. Replicas recompute this from the exact same
    /// source-generation seed. No future index width or post-fence application
    /// quota consumer can make a committed positive seed unmaterializable.
    pub fn reserve_success_capacity(&self) -> kasumi_types::Result<()> {
        if !self.successful_candidate() {
            return Ok(());
        }
        let permanent = StoredRetirement::reservation_bytes(&self.principal, &self.request)?;
        if self
            .source
            .retirement_bytes
            .checked_add(permanent)
            .is_none_or(|bytes| bytes > self.source.max_retirement_bytes)
        {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::QuotaExceeded,
                "retirement permanent outcome capacity unavailable",
            ));
        }
        let record = StoredRetirement {
            principal: self.principal.clone(),
            request: self.request.clone(),
            request_digest: self.request.reference()?.request_digest,
            accepted_revision: u64::MAX,
            outcome: Ok(self.receipt_at(u64::MAX)),
        };
        let audit = kasumi_types::AuditEvent {
            event_id: format!("{}:{}", self.source.incarnation, u64::MAX),
            principal: self.principal.clone(),
            action: "retire".into(),
            request_id: self.request_id.clone(),
            timestamp_ms: self.admitted_at_ms,
            data_revision: Some(u64::MAX),
            outcome: "committed".into(),
            collection: None,
        };
        let record_bytes = serde_json::to_vec(&record)
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Corruption,
                    "retirement reservation encoding failed",
                )
            })?
            .len();
        let audit_bytes = serde_json::to_vec(&audit)
            .map_err(|_| {
                kasumi_types::Error::new(
                    kasumi_types::ErrorCode::Corruption,
                    "retirement reservation encoding failed",
                )
            })?
            .len();
        if self
            .source
            .audit_hot_bytes
            .checked_add(audit_bytes as u64)
            .is_none_or(|bytes| bytes > self.source.max_audit_hot_bytes)
        {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::AuditUnavailable,
                "retirement completion audit capacity unavailable",
            ));
        }
        // The only other changes are a 64-byte identity map key, commas,
        // retired/suspended flags and decimal revision/policy/accounting scalars.
        // 1024 bytes covers their complete worst-case growth without needing
        // application collections, definitions, policy or document bodies.
        let required = self
            .source
            .snapshot_bytes
            .checked_add(record_bytes as u64)
            .and_then(|n| n.checked_add(audit_bytes as u64))
            .and_then(|n| n.checked_add(1024))
            .and_then(|n| n.checked_add(self.source.staged_outcome_headroom));
        if required.is_none_or(|bytes| bytes > self.source.max_snapshot_bytes) {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::QuotaExceeded,
                "retirement completion capacity unavailable",
            ));
        }
        Ok(())
    }

    /// Deterministic success derivation for an independently validated committed
    /// seed. Commitment and exact installed log coverage are checked separately;
    /// this method alone is neither a current-authority proof nor a mode switch.
    pub(crate) fn recovered_success(
        &self,
        revision: u64,
    ) -> Result<Option<kasumi_types::RetirementReceipt>> {
        self.validate()?;
        if !self.successful_candidate() || revision <= self.source.previous_revision {
            return Ok(None);
        }
        self.reserve_success_capacity()?;
        let receipt = self.receipt_at(revision);
        self.validate_receipt(revision, &receipt)?;
        Ok(Some(receipt))
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
pub enum RaftCommand {
    Application(Vec<u8>),
    Retirement { application: Vec<u8>, seed: Vec<u8> },
    Custody(Vec<u8>),
}
impl RaftCommand {
    pub fn application(bytes: Vec<u8>) -> Self {
        Self::Application(bytes)
    }
    pub fn retirement(bytes: Vec<u8>, seed: RetirementLogSeed) -> Result<Self> {
        seed.check_command(&bytes)?;
        Ok(Self::Retirement {
            application: bytes,
            seed: seed.encoded()?,
        })
    }
    pub fn custody(command: &crate::CustodyCommand) -> Result<Self> {
        Ok(Self::Custody(command.encoded()?))
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Application(bytes) | Self::Custody(bytes) => bytes,
            Self::Retirement { application, .. } => application,
        }
    }
    pub fn custody_command(&self) -> Result<Option<crate::CustodyCommand>> {
        match self {
            Self::Custody(bytes) => Ok(Some(crate::CustodyCommand::decode(bytes)?)),
            _ => Ok(None),
        }
    }
    pub fn seed(&self) -> Result<Option<RetirementLogSeed>> {
        match self {
            Self::Retirement { application, seed } => {
                let seed = RetirementLogSeed::decode(seed)?;
                seed.check_command(application)?;
                Ok(Some(seed))
            }
            _ => Ok(None),
        }
    }
    pub(crate) fn seed_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.seed()?.map(|seed| seed.encoded()).transpose()
    }
}
