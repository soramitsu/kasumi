//! Exact local live trust. Historical signatures cannot enter this mutation path.
use crate::{
    GenerationSignature, HistoricalSigningTrust, SigningCertificate,
    SigningCertificateVerification, SigningDomain,
};
use anyhow::{Context, Result, ensure};
use kasumi_clock::LeaseClock;
use kasumi_types::RequestContext;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

pub const MAX_SIGNER_TRUST_RECORD_BYTES: usize = 32 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustVerifierIdentity {
    pub installation_id: Uuid,
    pub node_id: u64,
}
impl TrustVerifierIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.installation_id.is_nil() && self.node_id > 0,
            "invalid local verifier identity"
        );
        Ok(())
    }
    pub fn tenant(&self) -> String {
        format!("kasumi.trust.{}.{}", self.installation_id, self.node_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedSignerTrust {
    pub operation_id: Uuid,
    pub certificate: SigningCertificate,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRetirement {
    pub operation_id: Uuid,
    pub retired_generation: u64,
    pub retired_certificate_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSignerTrustRecord {
    pub format: u32,
    pub verifier: TrustVerifierIdentity,
    pub revision: u64,
    pub active: SigningCertificate,
    pub staged: Option<StagedSignerTrust>,
    pub retirement: Option<SignerRetirement>,
}
impl LocalSignerTrustRecord {
    pub fn initial(verifier: TrustVerifierIdentity, active: SigningCertificate) -> Result<Self> {
        ensure!(
            active.identity.generation == 1,
            "initial signer generation must be one"
        );
        let record = Self {
            format: 1,
            verifier,
            revision: 0,
            active,
            staged: None,
            retirement: None,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == 1, "unsupported local signer trust format");
        self.verifier.validate()?;
        self.active.verify(&self.active.identity.domain)?;
        ensure!(
            self.revision != 0
                || (self.active.identity.generation == 1
                    && self.staged.is_none()
                    && self.retirement.is_none()),
            "initial trust record cannot contain an operational transition"
        );
        if let Some(staged) = &self.staged {
            ensure!(
                self.retirement.is_none(),
                "cannot stage during signer retirement"
            );
            ensure!(!staged.operation_id.is_nil(), "nil staged signer operation");
            staged.certificate.verify(&self.active.identity.domain)?;
            ensure!(
                self.active.identity.generation.checked_add(1)
                    == Some(staged.certificate.identity.generation),
                "staged signer generation must be the exact successor"
            );
        }
        if let Some(retirement) = &self.retirement {
            ensure!(
                !retirement.operation_id.is_nil()
                    && retirement.retired_generation.checked_add(1)
                        == Some(self.active.identity.generation),
                "retired signer identity differs"
            );
            kasumi_types::validate_sha256(&retirement.retired_certificate_sha256)?;
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_SIGNER_TRUST_RECORD_BYTES,
            "local signer record exceeds bounded record size"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerTrustAction {
    Stage {
        certificate: SigningCertificate,
    },
    StopStage {
        staged_operation_id: Uuid,
    },
    Activate {
        staged_operation_id: Uuid,
        certificate_sha256: String,
    },
    CompleteRetirement {
        activation_operation_id: Uuid,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustCommand {
    pub operation_id: Uuid,
    pub expected_revision: u64,
    pub action: SignerTrustAction,
}
impl SignerTrustCommand {
    pub fn digest(&self) -> Result<String> {
        ensure!(!self.operation_id.is_nil(), "nil signer trust operation");
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_SIGNER_TRUST_RECORD_BYTES,
            "signer trust command exceeds bounded record size"
        );
        crate::digest(&("kasumi.local-signer-command.v1", self))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustReceipt {
    pub command: SignerTrustCommand,
    pub command_sha256: String,
    pub principal: String,
    pub revision: u64,
    pub active_generation: u64,
    pub active_certificate_sha256: String,
    pub retirement_pending: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerKeyUse {
    pub domain_sha256: String,
    pub generation: u64,
    pub certificate_sha256: String,
}
impl SignerKeyUse {
    pub fn for_certificate(certificate: &SigningCertificate) -> Result<Self> {
        Ok(Self {
            domain_sha256: certificate.identity.domain.digest()?,
            generation: certificate.identity.generation,
            certificate_sha256: certificate.digest()?,
        })
    }
}

/// Installed current administrative authorization, including exact resource
/// binding and current policy. A signature verifier is not an implementation.
/// Native adapters must supply the verified request context, never JSON claims.
pub trait LiveTrustAdministrator: Send + Sync {
    fn authorize(&self, context: &RequestContext) -> Result<()>;
}

/// Trusted local persistence. Compare the exact prior record and atomically
/// commit its replacement with a permanent, point-addressed operation receipt.
/// A commit error may mean publication succeeded; callers must close live trust
/// and reopen from durable state before granting another live capability.
pub trait LiveTrustPersistence: Send + Sync {
    fn check_access(&self) -> Result<()>;
    fn load(&self) -> Result<LocalSignerTrustRecord>;
    fn receipt(&self, operation_id: Uuid) -> Result<Option<SignerTrustReceipt>>;
    fn key_use(&self, public_key: &str) -> Result<Option<SignerKeyUse>>;
    fn commit(
        &self,
        previous: &LocalSignerTrustRecord,
        next: &LocalSignerTrustRecord,
        receipt: &SignerTrustReceipt,
    ) -> Result<()>;
}

struct RetirementWitness {
    started: Duration,
    last: Duration,
}
struct LiveState {
    record: LocalSignerTrustRecord,
    active_certificate_sha256: String,
    witness: Option<RetirementWitness>,
    closed: bool,
}
pub struct LiveSignerTrust {
    historical: HistoricalSigningTrust,
    persistence: Arc<dyn LiveTrustPersistence>,
    administrator: Arc<dyn LiveTrustAdministrator>,
    clock: Arc<dyn LeaseClock>,
    state: Mutex<LiveState>,
    generation: watch::Sender<u64>,
}
impl LiveSignerTrust {
    /// Trusted local installer only. The persistence provider has already bound
    /// exclusive local storage ownership; this cannot be constructed from wire
    /// evidence. All serving users of one record must share the returned owner.
    pub fn open(
        verifier: &TrustVerifierIdentity,
        domain: SigningDomain,
        persistence: Arc<dyn LiveTrustPersistence>,
        administrator: Arc<dyn LiveTrustAdministrator>,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Arc<Self>> {
        persistence.check_access()?;
        let record = persistence.load()?;
        record.validate()?;
        ensure!(
            record.verifier == *verifier && record.active.identity.domain == domain,
            "durable signer trust installation differs"
        );
        let witness = record.retirement.as_ref().map(|_| {
            let now = clock.now();
            RetirementWitness {
                started: now,
                last: now,
            }
        });
        Ok(Arc::new(Self {
            historical: HistoricalSigningTrust::install(domain)?,
            persistence,
            administrator,
            clock,
            generation: watch::channel(record.active.identity.generation).0,
            state: Mutex::new(LiveState {
                active_certificate_sha256: record.active.digest()?,
                record,
                witness,
                closed: false,
            }),
        }))
    }
    pub fn same_administrator(&self, administrator: &Arc<dyn LiveTrustAdministrator>) -> bool {
        Arc::ptr_eq(&self.administrator, administrator)
    }
    pub fn is_closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.closed)
    }
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.generation.send_replace(0);
    }
    pub fn historical(&self) -> &HistoricalSigningTrust {
        &self.historical
    }
    pub fn current(&self) -> Result<LocalSignerTrustRecord> {
        self.check_persistence()?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("live trust poisoned"))?;
        ensure!(!state.closed, "live signer trust closed");
        Ok(state.record.clone())
    }
    /// Capture current local state for an authenticated acknowledgement. The
    /// adapter must check this after encoding, along with current administrative
    /// response authority; a permanent operation receipt alone is historical.
    pub fn observe(self: &Arc<Self>) -> Result<LocalSignerTrustObservation> {
        let observation = LocalSignerTrustObservation {
            owner: self.clone(),
            record: self.current()?,
        };
        observation.check()?;
        Ok(observation)
    }
    fn authorize(&self, context: &RequestContext) -> Result<()> {
        context.authorization.check_live()?;
        self.administrator.authorize(context)?;
        self.check_persistence()
    }
    pub fn status(
        &self,
        context: &RequestContext,
        operation_id: Uuid,
    ) -> Result<Option<SignerTrustReceipt>> {
        self.authorize(context)?;
        self.current()?;
        let receipt = self.persistence.receipt(operation_id)?;
        self.authorize(context)?;
        Ok(receipt)
    }
    fn check_persistence(&self) -> Result<()> {
        let result = self.persistence.check_access();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// This is the current administrative mutation path. A root certificate or
    /// a historically valid operational signature supplies no permission here.
    pub fn administer(
        &self,
        context: &RequestContext,
        command: SignerTrustCommand,
    ) -> Result<SignerTrustReceipt> {
        self.authorize(context)?;
        let command_sha256 = command.digest()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("live trust poisoned"))?;
        ensure!(!state.closed, "live signer trust closed");
        if let Some(retained) = self.persistence.receipt(command.operation_id)? {
            ensure!(
                retained.command_sha256 == command_sha256 && retained.command == command,
                "permanent signer trust identity has different input"
            );
            drop(state);
            self.authorize(context)?;
            return Ok(retained);
        }
        ensure!(
            command.expected_revision == state.record.revision,
            "signer trust revision changed"
        );
        let mut next = state.record.clone();
        match &command.action {
            SignerTrustAction::Stage { certificate } => {
                ensure!(
                    next.staged.is_none() && next.retirement.is_none(),
                    "signer transition pending"
                );
                certificate.verify(self.historical.domain())?;
                if let Some(previous) =
                    self.persistence.key_use(&certificate.identity.public_key)?
                {
                    ensure!(
                        previous == SignerKeyUse::for_certificate(certificate)?,
                        "operational signing key was already used by another generation or domain"
                    );
                }
                ensure!(
                    next.active.identity.generation.checked_add(1)
                        == Some(certificate.identity.generation),
                    "only the exact next generation can be staged"
                );
                next.staged = Some(StagedSignerTrust {
                    operation_id: command.operation_id,
                    certificate: certificate.clone(),
                });
            }
            SignerTrustAction::StopStage {
                staged_operation_id,
            } => {
                ensure!(
                    next.staged
                        .as_ref()
                        .is_some_and(|staged| staged.operation_id == *staged_operation_id),
                    "exact staged signer operation differs"
                );
                next.staged = None;
            }
            SignerTrustAction::Activate {
                staged_operation_id,
                certificate_sha256,
            } => {
                let staged = next.staged.take().context("no staged signer")?;
                ensure!(
                    staged.operation_id == *staged_operation_id
                        && staged.certificate.digest()? == *certificate_sha256,
                    "exact staged signer activation differs"
                );
                next.retirement = Some(SignerRetirement {
                    operation_id: command.operation_id,
                    retired_generation: next.active.identity.generation,
                    retired_certificate_sha256: next.active.digest()?,
                });
                next.active = staged.certificate;
            }
            SignerTrustAction::CompleteRetirement {
                activation_operation_id,
            } => {
                ensure!(
                    next.retirement.as_ref().is_some_and(
                        |retirement| retirement.operation_id == *activation_operation_id
                    ),
                    "exact signer retirement differs"
                );
                let witness = state
                    .witness
                    .as_mut()
                    .context("retirement witness absent")?;
                let now = self.clock.now();
                if now < witness.last || now < witness.started {
                    state.closed = true;
                    self.generation.send_replace(0);
                    anyhow::bail!(
                        "signer retirement clock regressed; reopen for a fresh complete drain"
                    );
                }
                witness.last = now;
                ensure!(
                    now.saturating_sub(witness.started)
                        >= Duration::from_millis(self.historical.domain().retirement_drain_ms),
                    "complete signer retirement interval has not elapsed"
                );
                next.retirement = None;
            }
        }
        next.revision = next
            .revision
            .checked_add(1)
            .context("signer trust revision exhausted")?;
        next.validate()?;
        let receipt = SignerTrustReceipt {
            command,
            command_sha256,
            principal: context.principal.clone(),
            revision: next.revision,
            active_generation: next.active.identity.generation,
            active_certificate_sha256: next.active.digest()?,
            retirement_pending: next.retirement.is_some(),
        };
        let previous = state.record.clone();
        // Current policy authorization can itself consult a live generation
        // fence. Do not invoke the installed callback under this owner's lock.
        drop(state);
        self.authorize(context)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("live trust poisoned"))?;
        ensure!(
            !state.closed && state.record == previous,
            "signer trust changed during administrative authorization"
        );
        if let Err(error) = self.persistence.commit(&state.record, &next, &receipt) {
            state.closed = true;
            self.generation.send_replace(0);
            return Err(error.context(
                "signer trust publication is uncertain; reopen and resolve the exact operation",
            ));
        }
        if next.retirement != state.record.retirement {
            state.witness = next.retirement.as_ref().map(|_| {
                let now = self.clock.now();
                RetirementWitness {
                    started: now,
                    last: now,
                }
            });
        }
        self.generation.send_if_modified(|generation| {
            if *generation == next.active.identity.generation {
                return false;
            }
            *generation = next.active.identity.generation;
            true
        });
        state.active_certificate_sha256 = receipt.active_certificate_sha256.clone();
        state.record = next;
        drop(state);
        self.authorize(context)
            .context("signer trust committed but administrator response is fenced")?;
        Ok(receipt)
    }
    pub fn verify_live<T: Serialize>(
        self: &Arc<Self>,
        purpose: &str,
        value: &T,
        signed: &GenerationSignature,
    ) -> Result<SignerGenerationFence> {
        self.historical.verify(purpose, value, signed)?;
        let fence = SignerGenerationFence {
            owner: self.clone(),
            certificate_sha256: signed.certificate.digest()?,
            generation: signed.certificate.identity.generation,
        };
        fence.check()?;
        Ok(fence)
    }
}

pub struct LocalSignerTrustObservation {
    owner: Arc<LiveSignerTrust>,
    record: LocalSignerTrustRecord,
}
impl LocalSignerTrustObservation {
    pub fn record(&self) -> &LocalSignerTrustRecord {
        &self.record
    }
    pub fn check(&self) -> Result<()> {
        self.owner.check_persistence()?;
        let state = self
            .owner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("live trust poisoned"))?;
        ensure!(
            !state.closed && state.record.revision == self.record.revision,
            "local signer trust changed before response release"
        );
        Ok(())
    }
}

/// This is an additional generation fence, not a lease or a new clock anchor.
/// Existing lease and credential deadlines must still be checked by the owner.
#[derive(Clone)]
pub struct SignerGenerationFence {
    owner: Arc<LiveSignerTrust>,
    certificate_sha256: String,
    generation: u64,
}
impl SignerGenerationFence {
    pub fn check(&self) -> Result<()> {
        self.owner.check_persistence()?;
        let state = self
            .owner
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("live trust poisoned"))?;
        ensure!(
            !state.closed
                && state.record.active.identity.generation == self.generation
                && state.active_certificate_sha256 == self.certificate_sha256,
            "operational signer generation is no longer live"
        );
        Ok(())
    }
    pub fn notifications(&self) -> watch::Receiver<u64> {
        self.owner.generation.subscribe()
    }
}
