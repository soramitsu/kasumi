use anyhow::{Context, Result, ensure};
use kasumi_raft::{
    AppliedEntryContext, AppliedResponse, BackendSnapshot, RetiredSnapshotState,
    StateMachineBackend,
};
use kasumi_serving::*;
use kasumi_store::{TenantStore, WriteOp};
use kasumi_types::{Error, ErrorCode, RequestContext};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[path = "lifecycle_state.rs"]
pub(crate) mod lifecycle_state;

const NS: &str = "kasumi.independent-authority";
const META: &[u8] = b"meta";
const MAX_RECORD_BYTES: usize = 256 << 10;
pub const MAX_SNAPSHOT_BYTES: usize = 64 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInstallation {
    pub manifest: AuthorityManifest,
    pub partition: u16,
    pub administrators: BTreeSet<String>,
    pub max_tenants: u64,
    pub max_receipts: u64,
    pub max_state_bytes: u64,
}
impl AuthorityInstallation {
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        ensure!(
            self.manifest.partitions.contains_key(&self.partition),
            "unknown installed partition"
        );
        ensure!(
            !self.administrators.is_empty() && self.administrators.len() <= 64,
            "invalid initial administrators"
        );
        for principal in &self.administrators {
            kasumi_types::validate_name(principal)?;
        }
        ensure!(
            (1..=10_000).contains(&self.max_tenants)
                && (1..=100_000).contains(&self.max_receipts)
                && (4096..=32 << 20).contains(&self.max_state_bytes),
            "authority hard quota exceeded"
        );
        Ok(())
    }
    pub fn tenant(&self) -> String {
        format!(
            "kasumi.authority.{}.{}",
            self.manifest.authority_id, self.partition
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    installation: AuthorityInstallation,
    administrators: BTreeSet<String>,
    policy_epoch: u64,
    revision: u64,
    tenants: u64,
    receipts: u64,
    state_bytes: u64,
    active_fences: u64,
    preparations: u64,
    incarnations: u64,
    target_stops: u64,
    lifecycle_receipts: u64,
    lifecycle_epochs: u64,
    open_control_epochs: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantRecord {
    pub tenant: String,
    pub incarnation: Uuid,
    pub authority_epoch: u64,
    pub nodes: BTreeSet<NodeIdentity>,
    pub activation_digest: String,
    pub recovery_checkpoint: Option<kasumi_types::FullBackupCheckpoint>,
    pub fence: Option<AuthorityReceipt>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "record", deny_unknown_fields)]
enum Record {
    Tenant(TenantRecord),
    Receipt(AuthorityReceipt),
    Preparation(PreparationRecord),
    Incarnation(IncarnationRecord),
    TargetStop(AuthorityReceipt),
    Lifecycle(Box<LifecycleAuthorityReceipt>),
    ControlEpoch(lifecycle_state::ControlEpochRecord),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IncarnationRecord {
    tenant: String,
    incarnation: Uuid,
    authority_epoch: u64,
    receipt: AuthorityReceipt,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationRecord {
    tenant: String,
    source_incarnation: Uuid,
    source_epoch: u64,
    target: RecoveryTarget,
    receipt: AuthorityReceipt,
}
pub(crate) struct LeaseMaterial {
    pub activation_digest: String,
    pub recovery_checkpoint: Option<kasumi_types::FullBackupCheckpoint>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    meta: Meta,
    records: BTreeMap<String, Record>,
}

/// Internal leader preparation. No native decoder accepts this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedCommand {
    pub context: RequestContext,
    pub command: AuthorityCommand,
    pub admitted_at_ms: u64,
    pub authority_term: u64,
    /// The exact committed fence observed for a complete live elapsed interval.
    /// The leader fills this after checking its private term-bound witness.
    pub drained_fence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "prepared",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum PreparedOperation {
    Administrative(Box<PreparedCommand>),
    Lifecycle(Box<lifecycle_state::PreparedLifecycle>),
}

pub(crate) struct Backend {
    store: Arc<TenantStore>,
    installation: AuthorityInstallation,
    mutation: Mutex<()>,
}
fn key_tenant(tenant: &str) -> String {
    format!("t/{tenant}")
}
fn key_receipt(tenant: &str, command: Uuid) -> String {
    format!("r/{tenant}/{command}")
}
fn key_preparation(tenant: &str, incarnation: Uuid) -> String {
    format!("p/{tenant}/{incarnation}")
}
fn key_target_stop(tenant: &str, incarnation: Uuid) -> String {
    format!("s/{tenant}/{incarnation}")
}
fn key_incarnation(tenant: &str, incarnation: Uuid) -> String {
    format!("i/{tenant}/{incarnation}")
}
fn conflict(message: &str) -> Error {
    Error::new(ErrorCode::Conflict, message)
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorCode::Unavailable, error.to_string())
}
impl Backend {
    pub fn install(
        store: Arc<TenantStore>,
        installation: AuthorityInstallation,
    ) -> Result<Arc<Self>> {
        installation.validate()?;
        ensure!(
            store.tenant() == installation.tenant(),
            "authority store installation identity differs"
        );
        ensure!(
            store.storage_access().purpose()
                == kasumi_store::StorageAccess::independent_authority(
                    &installation.manifest,
                    installation.partition
                )?
                .purpose(),
            "independent authority requires its exact installed storage root"
        );
        if let Some(bytes) = store.get_bounded(NS, META, MAX_RECORD_BYTES)? {
            let meta: Meta = serde_json::from_slice(&bytes)?;
            ensure!(
                meta.installation == installation,
                "authority installation differs from durable genesis"
            );
        } else {
            let meta = Meta {
                administrators: installation.administrators.clone(),
                installation: installation.clone(),
                policy_epoch: 1,
                revision: 0,
                tenants: 0,
                receipts: 0,
                state_bytes: 0,
                active_fences: 0,
                preparations: 0,
                incarnations: 0,
                target_stops: 0,
                lifecycle_receipts: 0,
                lifecycle_epochs: 0,
                open_control_epochs: 0,
            };
            store.write_batch(&[WriteOp::put(NS, META, serde_json::to_vec(&meta)?)])?;
        }
        Ok(Arc::new(Self {
            store,
            installation,
            mutation: Mutex::new(()),
        }))
    }
    pub fn installation(&self) -> &AuthorityInstallation {
        &self.installation
    }
    fn meta(&self) -> Result<Meta> {
        Ok(serde_json::from_slice(
            &self
                .store
                .get_bounded(NS, META, MAX_RECORD_BYTES)?
                .context("authority metadata absent")?,
        )?)
    }
    fn record(&self, key: &str) -> Result<Option<Record>> {
        self.store
            .get_bounded(NS, key.as_bytes(), MAX_RECORD_BYTES)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }
    pub fn tenant_record(&self, tenant: &str) -> Result<Option<TenantRecord>> {
        match self.record(&key_tenant(tenant))? {
            Some(Record::Tenant(value)) => Ok(Some(value)),
            None => Ok(None),
            _ => anyhow::bail!("authority record type differs"),
        }
    }
    pub fn receipt(&self, tenant: &str, command: Uuid) -> Result<Option<AuthorityReceipt>> {
        match self.record(&key_receipt(tenant, command))? {
            Some(Record::Receipt(value)) => Ok(Some(value)),
            None => Ok(None),
            _ => anyhow::bail!("authority receipt type differs"),
        }
    }
    pub fn revision(&self) -> Result<u64> {
        Ok(self.meta()?.revision)
    }
    pub fn stopped_target(&self, reference: &TargetStopReference) -> Result<AuthorityReceipt> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let request = self
            .receipt(&reference.tenant, reference.command_id)?
            .context("target stop absent")?;
        ensure!(
            request.digest()? == reference.receipt_digest,
            "exact target stop receipt differs"
        );
        let AuthorityOutcome::TargetStopped { target, .. } = &request.outcome else {
            anyhow::bail!("target stop did not commit");
        };
        match self.record(&key_target_stop(&reference.tenant, target.incarnation))? {
            Some(Record::TargetStop(original)) => {
                ensure!(
                    original.outcome == request.outcome,
                    "target stop identity differs"
                );
                Ok(original)
            }
            _ => anyhow::bail!("target incarnation tombstone absent"),
        }
    }
    pub fn authorize_admin(&self, context: &RequestContext) -> kasumi_types::Result<u64> {
        let _lock = self.mutation.lock().map_err(unavailable)?;
        self.authorize(&self.meta().map_err(unavailable)?, context)
    }
    fn authorize(&self, meta: &Meta, context: &RequestContext) -> kasumi_types::Result<u64> {
        context.authorization.require_authority(
            self.installation.manifest.authority_id,
            self.installation.partition,
        )?;
        if context.tenant != self.installation.tenant()
            || !context.scopes.contains(&kasumi_types::Action::Admin)
            || !meta.administrators.contains(&context.principal)
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "current independent authority Admin required",
            ));
        }
        Ok(meta.policy_epoch)
    }
    pub fn lease_view(&self, request: &LeaseRequest) -> Result<(LeaseMaterial, u64)> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let record = self
            .tenant_record(&request.identity.tenant)?
            .context("tenant is not enrolled")?;
        ensure!(
            self.record(&key_target_stop(
                &request.identity.tenant,
                request.identity.incarnation
            ))?
            .is_none(),
            "target incarnation is permanently stopped"
        );
        let view = match request.purpose {
            LeasePurpose::Serving => {
                ensure!(
                    record.fence.is_none()
                        && record.incarnation == request.identity.incarnation
                        && record.authority_epoch == request.identity.authority_epoch
                        && record.nodes.contains(&request.identity.node),
                    "serving incarnation, epoch or node is not active"
                );
                LeaseMaterial {
                    activation_digest: record.activation_digest,
                    recovery_checkpoint: record.recovery_checkpoint,
                }
            }
            LeasePurpose::RestorePreparation => {
                let Some(Record::Preparation(prepared)) = self.record(&key_preparation(
                    &request.identity.tenant,
                    request.identity.incarnation,
                ))?
                else {
                    anyhow::bail!("target preparation is not installed");
                };
                ensure!(
                    record.incarnation == prepared.source_incarnation
                        && record.authority_epoch == prepared.source_epoch
                        && request.identity.authority_epoch == prepared.source_epoch + 1
                        && prepared.target.nodes.contains(&request.identity.node),
                    "preparation source epoch or target credential differs"
                );
                LeaseMaterial {
                    activation_digest: prepared.receipt.digest()?,
                    recovery_checkpoint: Some(prepared.target.checkpoint),
                }
            }
        };
        Ok((view, self.meta()?.revision))
    }
    pub fn discover(&self, request: &LeaseDiscovery) -> Result<ServingIdentity> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let record = self
            .tenant_record(&request.tenant)?
            .context("tenant is not enrolled")?;
        ensure!(
            self.record(&key_target_stop(&request.tenant, request.incarnation))?
                .is_none(),
            "target incarnation is permanently stopped"
        );
        let epoch = match request.purpose {
            LeasePurpose::Serving => {
                ensure!(
                    record.fence.is_none()
                        && record.incarnation == request.incarnation
                        && record.nodes.contains(&request.node),
                    "requested incarnation or credential is not serving"
                );
                record.authority_epoch
            }
            LeasePurpose::RestorePreparation => {
                let Some(Record::Preparation(prepared)) =
                    self.record(&key_preparation(&request.tenant, request.incarnation))?
                else {
                    anyhow::bail!("requested target is not prepared");
                };
                ensure!(
                    record.incarnation == prepared.source_incarnation
                        && record.authority_epoch == prepared.source_epoch
                        && prepared.target.nodes.contains(&request.node),
                    "requested preparation epoch or credential differs"
                );
                prepared
                    .source_epoch
                    .checked_add(1)
                    .context("authority epoch exhausted")?
            }
        };
        Ok(ServingIdentity {
            tenant: request.tenant.clone(),
            incarnation: request.incarnation,
            authority_epoch: epoch,
            node: request.node.clone(),
        })
    }
    fn reduce(
        &self,
        position: &AppliedEntryContext,
        prepared: PreparedCommand,
    ) -> Result<kasumi_types::Result<AuthorityReceipt>> {
        let mut meta = self.meta()?;
        let request = &prepared.command;
        if let Err(error) = prepared
            .context
            .authorization
            .check_admitted_at(prepared.admitted_at_ms)
        {
            return Ok(Err(error));
        }
        if let Err(error) = self.authorize(&meta, &prepared.context) {
            return Ok(Err(error));
        }
        if request.validate().is_err()
            || self.installation.manifest.partition(&request.tenant)? != self.installation.partition
        {
            return Ok(Err(Error::new(
                ErrorCode::InvalidArgument,
                "authority command routing or structure differs",
            )));
        }
        if prepared.authority_term != position.log_id.leader_id.term {
            return Ok(Err(conflict(
                "prepared authority term differs from ordered execution",
            )));
        }
        let request_digest = request.digest()?;
        if let Some(receipt) = self.receipt(&request.tenant, request.command_id)? {
            return Ok(if receipt.command_digest == request_digest {
                Ok(receipt)
            } else {
                Err(conflict("permanent authority command identity differs"))
            });
        }
        if prepared.admitted_at_ms > request.not_after_ms
            || request.expected_policy_epoch != meta.policy_epoch
        {
            return Ok(Err(conflict(
                "authority deadline or current policy epoch changed",
            )));
        }
        let mut tenant = self.tenant_record(&request.tenant)?;
        let mut additions = BTreeMap::new();
        let outcome = self.effect(
            &mut meta,
            &mut tenant,
            &prepared,
            position.log_id.index,
            &mut additions,
        );
        let outcome = match outcome {
            Ok(value) => value,
            Err(error) => AuthorityOutcome::Rejected {
                code: error.code,
                message: error.message,
            },
        };
        let receipt = AuthorityReceipt {
            authority_id: self.installation.manifest.authority_id,
            manifest_digest: self.installation.manifest.digest()?,
            partition: self.installation.partition,
            command: request.clone(),
            command_digest: request_digest,
            principal: prepared.context.principal.clone(),
            term: position.log_id.leader_id.term,
            revision: position.log_id.index,
            outcome,
        };
        // A successful fence retains its complete immutable accepted identity.
        if matches!(receipt.outcome, AuthorityOutcome::Fenced { .. }) {
            tenant.as_mut().context("fence has no tenant")?.fence = Some(receipt.clone());
        }
        if matches!(
            receipt.outcome,
            AuthorityOutcome::Activated { .. } | AuthorityOutcome::Enrolled { .. }
        ) {
            let activated = tenant.as_mut().context("activation has no tenant")?;
            activated.activation_digest = receipt.digest()?;
            additions.insert(
                key_incarnation(&request.tenant, activated.incarnation),
                Record::Incarnation(IncarnationRecord {
                    tenant: request.tenant.clone(),
                    incarnation: activated.incarnation,
                    authority_epoch: activated.authority_epoch,
                    receipt: receipt.clone(),
                }),
            );
        }
        if let (
            AuthorityAction::PrepareTarget {
                source_incarnation,
                source_epoch,
                target,
            },
            AuthorityOutcome::TargetPrepared { .. },
        ) = (&request.action, &receipt.outcome)
        {
            additions.insert(
                key_preparation(&request.tenant, target.incarnation),
                Record::Preparation(PreparationRecord {
                    tenant: request.tenant.clone(),
                    source_incarnation: *source_incarnation,
                    source_epoch: *source_epoch,
                    target: target.clone(),
                    receipt: receipt.clone(),
                }),
            );
        }
        if let AuthorityOutcome::TargetStopped { target, .. } = &receipt.outcome {
            // The first exact stop remains authoritative. Retries under another
            // command ID cannot replace its original actor/position/identity.
            if self
                .record(&key_target_stop(&request.tenant, target.incarnation))?
                .is_none()
            {
                additions.insert(
                    key_target_stop(&request.tenant, target.incarnation),
                    Record::TargetStop(receipt.clone()),
                );
            }
        }
        if let Some(tenant) = tenant {
            additions.insert(key_tenant(&request.tenant), Record::Tenant(tenant));
        }
        additions.insert(
            key_receipt(&request.tenant, request.command_id),
            Record::Receipt(receipt.clone()),
        );
        let mut writes = Vec::new();
        for (key, value) in additions {
            let bytes = serde_json::to_vec(&value)?;
            ensure!(
                bytes.len() <= MAX_RECORD_BYTES,
                "authority record byte quota exceeded"
            );
            let previous = self
                .store
                .get_bounded(NS, key.as_bytes(), MAX_RECORD_BYTES)?;
            if let Record::Tenant(record) = &value {
                let previous_fenced = previous
                    .as_ref()
                    .map(|bytes| -> Result<bool> {
                        Ok(matches!(
                            serde_json::from_slice::<Record>(bytes)?,
                            Record::Tenant(TenantRecord { fence: Some(_), .. })
                        ))
                    })
                    .transpose()?
                    .unwrap_or(false);
                meta.active_fences = meta
                    .active_fences
                    .checked_sub(u64::from(previous_fenced))
                    .context("fence reservation accounting underflow")?
                    .checked_add(u64::from(record.fence.is_some()))
                    .context("fence reservation accounting overflow")?;
            }
            if previous.is_none() {
                match &value {
                    Record::Tenant(_) => meta.tenants += 1,
                    Record::Receipt(_) => meta.receipts += 1,
                    Record::Preparation(_) => meta.preparations += 1,
                    Record::Incarnation(_) => meta.incarnations += 1,
                    Record::TargetStop(_) => meta.target_stops += 1,
                    Record::Lifecycle(_) | Record::ControlEpoch(_) => {
                        unreachable!("administrative reducer cannot issue lifecycle records")
                    }
                }
            }
            meta.state_bytes = meta
                .state_bytes
                .checked_sub(previous.as_ref().map_or(0, |bytes| bytes.len() as u64))
                .context("authority byte accounting underflow")?
                .checked_add(bytes.len() as u64)
                .context("authority byte accounting overflow")?;
            writes.push(WriteOp::put(NS, key.as_bytes(), bytes));
        }
        // Every frozen source retains one successful activation receipt plus a
        // maximum-sized tenant update and permanent incarnation record. Other commands cannot spend that reserved
        // completion capacity. Rejecting a new fence leaves the source active.
        if meta.tenants > self.installation.max_tenants
            || meta
                .receipts
                .saturating_add(meta.lifecycle_receipts)
                .saturating_add(meta.active_fences)
                .saturating_add(meta.open_control_epochs)
                > self.installation.max_receipts
            || meta.state_bytes.saturating_add(
                meta.active_fences
                    .saturating_mul(3 * MAX_RECORD_BYTES as u64)
                    .saturating_add(
                        meta.open_control_epochs
                            .saturating_mul(MAX_RECORD_BYTES as u64),
                    ),
            ) > self.installation.max_state_bytes
        {
            return Ok(Err(Error::new(
                ErrorCode::ResourceExhausted,
                "independent authority permanent state quota exhausted",
            )));
        }
        meta.revision = position.log_id.index;
        writes.push(WriteOp::put(NS, META, serde_json::to_vec(&meta)?));
        self.store.write_batch(&writes)?;
        Ok(Ok(receipt))
    }
    fn effect(
        &self,
        meta: &mut Meta,
        tenant: &mut Option<TenantRecord>,
        prepared: &PreparedCommand,
        accepted_revision: u64,
        additions: &mut BTreeMap<String, Record>,
    ) -> kasumi_types::Result<AuthorityOutcome> {
        let request = &prepared.command;
        match &request.action {
            AuthorityAction::Enroll { incarnation, nodes } => {
                if self
                    .record(&key_target_stop(&request.tenant, *incarnation))
                    .map_err(unavailable)?
                    .is_some()
                {
                    return Err(conflict("target incarnation is permanently stopped"));
                }
                if tenant.is_some() {
                    return Err(conflict("tenant already enrolled"));
                }
                *tenant = Some(TenantRecord {
                    tenant: request.tenant.clone(),
                    incarnation: *incarnation,
                    authority_epoch: 1,
                    nodes: nodes.clone(),
                    activation_digest: "0".repeat(64),
                    recovery_checkpoint: None,
                    fence: None,
                });
                Ok(AuthorityOutcome::Enrolled {
                    incarnation: *incarnation,
                    authority_epoch: 1,
                })
            }
            AuthorityAction::Fence {
                incarnation,
                authority_epoch,
            } => {
                let record = tenant
                    .as_mut()
                    .ok_or_else(|| conflict("tenant is not enrolled"))?;
                if record.incarnation != *incarnation
                    || record.authority_epoch != *authority_epoch
                    || record.fence.is_some()
                {
                    return Err(conflict(
                        "source incarnation is not the active unfenced epoch",
                    ));
                }
                Ok(AuthorityOutcome::Fenced {
                    incarnation: *incarnation,
                    authority_epoch: *authority_epoch,
                })
            }
            AuthorityAction::PrepareTarget {
                source_incarnation,
                source_epoch,
                target,
            } => {
                let record = tenant
                    .as_ref()
                    .ok_or_else(|| conflict("source is not enrolled"))?;
                if record.incarnation != *source_incarnation
                    || record.authority_epoch != *source_epoch
                    || record.fence.is_some()
                {
                    return Err(conflict(
                        "target preparation needs the active unfenced source epoch",
                    ));
                }
                if self
                    .record(&key_target_stop(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    .is_some()
                {
                    return Err(conflict("target incarnation is permanently stopped"));
                }
                if self
                    .record(&key_preparation(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    .is_some()
                    || self
                        .record(&key_incarnation(&request.tenant, target.incarnation))
                        .map_err(unavailable)?
                        .is_some()
                {
                    return Err(conflict(
                        "target incarnation already has a permanent preparation identity",
                    ));
                }
                Ok(AuthorityOutcome::TargetPrepared {
                    target: target.clone(),
                    authority_epoch: source_epoch + 1,
                })
            }
            AuthorityAction::Activate {
                fence_id,
                fence_digest,
                target,
            } => {
                let record = tenant
                    .as_mut()
                    .ok_or_else(|| conflict("tenant is not enrolled"))?;
                let fence = record
                    .fence
                    .as_ref()
                    .ok_or_else(|| conflict("source incarnation has no authoritative fence"))?;
                if fence.command.command_id != *fence_id
                    || fence.digest().map_err(unavailable)? != *fence_digest
                    || prepared.drained_fence.as_ref() != Some(fence_digest)
                {
                    return Err(conflict("exact source fence lacks a live complete drain"));
                }
                target
                    .validate(&request.tenant, record.incarnation)
                    .map_err(|_| conflict("backup or target incarnation differs"))?;
                if self
                    .record(&key_target_stop(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    .is_some()
                {
                    return Err(conflict("target incarnation is permanently stopped"));
                }
                if self
                    .record(&key_incarnation(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    .is_some()
                {
                    return Err(conflict(
                        "an incarnation can never be reactivated after replacement",
                    ));
                }
                if let Some(preparation) = self
                    .record(&key_preparation(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    && !matches!(preparation, Record::Preparation(ref value) if value.target == *target && value.source_incarnation == record.incarnation && value.source_epoch == record.authority_epoch)
                {
                    return Err(conflict(
                        "activation differs from permanent target preparation",
                    ));
                }
                record.authority_epoch = record
                    .authority_epoch
                    .checked_add(1)
                    .ok_or_else(|| conflict("authority epoch exhausted"))?;
                record.incarnation = target.incarnation;
                record.nodes = target.nodes.clone();
                record.recovery_checkpoint = Some(target.checkpoint.clone());
                record.fence = None;
                Ok(AuthorityOutcome::Activated {
                    target: target.clone(),
                    authority_epoch: record.authority_epoch,
                })
            }
            AuthorityAction::StopTarget {
                source_incarnation,
                source_epoch,
                target,
            } => {
                if let Some(Record::Incarnation(accepted)) = self
                    .record(&key_incarnation(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                {
                    if !matches!(&accepted.receipt.outcome,AuthorityOutcome::Activated { target:actual,authority_epoch } if actual==target && *authority_epoch==source_epoch.saturating_add(1))
                    {
                        return Err(conflict(
                            "target has another permanent incarnation identity",
                        ));
                    }
                    return Ok(AuthorityOutcome::TargetAlreadyActivated {
                        original: Box::new(accepted.receipt),
                    });
                }
                if let Some(record) = self
                    .record(&key_target_stop(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                {
                    return match record {
                        Record::TargetStop(prior) if matches!(&prior.outcome,AuthorityOutcome::TargetStopped {source_incarnation:source,source_epoch:epoch,target:actual} if source==source_incarnation && epoch==source_epoch && actual==target) => {
                            Ok(prior.outcome)
                        }
                        _ => Err(conflict("target stop permanent identity differs")),
                    };
                }
                let source = tenant
                    .as_ref()
                    .ok_or_else(|| conflict("source is not enrolled"))?;
                if source.incarnation != *source_incarnation
                    || source.authority_epoch != *source_epoch
                {
                    return Err(conflict("target stop source epoch differs"));
                }
                if let Some(record) = self
                    .record(&key_preparation(&request.tenant, target.incarnation))
                    .map_err(unavailable)?
                    && !matches!(record,Record::Preparation(ref p) if p.source_incarnation==*source_incarnation && p.source_epoch==*source_epoch && p.target==*target)
                {
                    return Err(conflict("target stop preparation differs"));
                }
                Ok(AuthorityOutcome::TargetStopped {
                    source_incarnation: *source_incarnation,
                    source_epoch: *source_epoch,
                    target: target.clone(),
                })
            }
            AuthorityAction::StopActivation { original } => {
                let original_digest = original.digest().map_err(unavailable)?;
                let outcome = match self
                    .receipt(&request.tenant, original.command_id)
                    .map_err(unavailable)?
                {
                    Some(receipt) => {
                        if receipt.command_digest != original_digest {
                            return Err(conflict("original permanent activation identity differs"));
                        }
                        receipt
                    }
                    None => AuthorityReceipt {
                        authority_id: self.installation.manifest.authority_id,
                        manifest_digest: self
                            .installation
                            .manifest
                            .digest()
                            .map_err(unavailable)?,
                        partition: self.installation.partition,
                        command: *original.clone(),
                        command_digest: original_digest.clone(),
                        principal: prepared.context.principal.clone(),
                        term: prepared.authority_term,
                        revision: accepted_revision,
                        outcome: AuthorityOutcome::ActivationStopped { original_digest },
                    },
                };
                additions.insert(
                    key_receipt(&request.tenant, original.command_id),
                    Record::Receipt(outcome.clone()),
                );
                Ok(AuthorityOutcome::ActivationResolved {
                    original: Box::new(outcome),
                })
            }
            AuthorityAction::ReplaceAdministrators { administrators } => {
                meta.policy_epoch = meta
                    .policy_epoch
                    .checked_add(1)
                    .ok_or_else(|| conflict("authority policy epoch exhausted"))?;
                meta.administrators = administrators.clone();
                Ok(AuthorityOutcome::AdministratorsReplaced {
                    policy_epoch: meta.policy_epoch,
                })
            }
        }
    }
}
impl StateMachineBackend for Backend {
    fn apply(&self, position: &AppliedEntryContext, bytes: &[u8]) -> Result<AppliedResponse> {
        ensure!(
            bytes.len() <= MAX_RECORD_BYTES,
            "authority command byte limit exceeded"
        );
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let prepared: PreparedOperation = serde_json::from_slice(bytes)?;
        let bytes = match prepared {
            PreparedOperation::Administrative(prepared) => {
                serde_json::to_vec(&self.reduce(position, *prepared)?)?
            }
            PreparedOperation::Lifecycle(prepared) => {
                serde_json::to_vec(&self.reduce_lifecycle(position, *prepared)?)?
            }
        };
        Ok(AppliedResponse::application(bytes))
    }
    fn snapshot(&self) -> Result<BackendSnapshot> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let mut records = BTreeMap::new();
        self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
            if key != META {
                records.insert(
                    String::from_utf8(key.to_vec())?,
                    serde_json::from_slice(bytes)?,
                );
            }
            Ok(())
        })?;
        let bytes = serde_json::to_vec(&Snapshot {
            meta: self.meta()?,
            records,
        })?;
        ensure!(
            bytes.len() <= MAX_SNAPSHOT_BYTES,
            "authority snapshot limit exceeded"
        );
        Ok(BackendSnapshot::application(bytes))
    }
    fn validate_snapshot(&self, bytes: &[u8]) -> Result<Option<RetiredSnapshotState>> {
        self.decode_snapshot(bytes)?;
        Ok(None)
    }
    fn restore(&self, bytes: &[u8]) -> Result<()> {
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        let snapshot = self.decode_snapshot(bytes)?;
        self.validate_lifecycle_history(&snapshot)?;
        let mut writes = Vec::new();
        self.store.visit(NS, MAX_RECORD_BYTES, |key, _| {
            writes.push(WriteOp::delete(NS, key));
            Ok(())
        })?;
        writes.push(WriteOp::put(NS, META, serde_json::to_vec(&snapshot.meta)?));
        for (key, value) in snapshot.records {
            writes.push(WriteOp::put(
                NS,
                key.as_bytes(),
                serde_json::to_vec(&value)?,
            ));
        }
        self.store.write_batch(&writes)
    }
    fn close_application(&self) {
        self.store.seal();
    }
}
impl Backend {
    fn decode_snapshot(&self, bytes: &[u8]) -> Result<Snapshot> {
        ensure!(
            bytes.len() <= MAX_SNAPSHOT_BYTES,
            "authority snapshot byte limit exceeded"
        );
        let snapshot: Snapshot = serde_json::from_slice(bytes)?;
        ensure!(
            snapshot.meta.installation == self.installation
                && snapshot.meta.policy_epoch > 0
                && !snapshot.meta.administrators.is_empty()
                && snapshot.meta.administrators.len() <= 64,
            "authority snapshot installation or policy differs"
        );
        let (
            mut tenants,
            mut receipts,
            mut state_bytes,
            mut active_fences,
            mut preparations,
            mut incarnations,
            mut target_stops,
        ) = (0, 0, 0, 0, 0, 0, 0);
        for (key, record) in &snapshot.records {
            let bytes = serde_json::to_vec(record)?;
            ensure!(
                bytes.len() <= MAX_RECORD_BYTES,
                "authority snapshot record too large"
            );
            state_bytes += bytes.len() as u64;
            match record {
                Record::Lifecycle(_) | Record::ControlEpoch(_) => {}
                Record::Tenant(record) => {
                    tenants += 1;
                    ensure!(
                        *key == key_tenant(&record.tenant)
                            && self.installation.manifest.partition(&record.tenant)?
                                == self.installation.partition
                            && !record.incarnation.is_nil()
                            && record.authority_epoch > 0,
                        "authority tenant snapshot identity differs"
                    );
                    validate_nodes(&record.nodes)?;
                    kasumi_types::validate_sha256(&record.activation_digest)?;
                    ensure!(
                        (record.authority_epoch == 1) == record.recovery_checkpoint.is_none(),
                        "authority recovery checkpoint absent or unexpected"
                    );
                    if let Some(checkpoint) = &record.recovery_checkpoint {
                        checkpoint.validate()?;
                        ensure!(
                            checkpoint.tenant == record.tenant
                                && checkpoint.source_incarnation != record.incarnation.to_string(),
                            "authority recovery checkpoint differs"
                        );
                    }
                    match snapshot
                        .records
                        .get(&key_incarnation(&record.tenant, record.incarnation))
                    {
                        Some(Record::Incarnation(accepted)) => {
                            ensure!(
                                accepted.authority_epoch == record.authority_epoch
                                    && accepted.receipt.digest()? == record.activation_digest,
                                "active incarnation receipt differs"
                            );
                            match &accepted.receipt.command.action {
                                AuthorityAction::Enroll { nodes, .. } => ensure!(
                                    nodes == &record.nodes && record.recovery_checkpoint.is_none(),
                                    "enrollment nodes differ"
                                ),
                                AuthorityAction::Activate { target, .. } => ensure!(
                                    target.nodes == record.nodes
                                        && record.recovery_checkpoint.as_ref()
                                            == Some(&target.checkpoint),
                                    "activated target differs"
                                ),
                                _ => anyhow::bail!(
                                    "active incarnation is not an accepted activation"
                                ),
                            }
                        }
                        _ => anyhow::bail!("active incarnation receipt absent"),
                    }
                    if let Some(fence) = &record.fence {
                        active_fences += 1;
                        ensure!(
                            matches!(fence.outcome, AuthorityOutcome::Fenced { incarnation, authority_epoch } if incarnation == record.incarnation && authority_epoch == record.authority_epoch),
                            "authority fence snapshot differs"
                        );
                        match snapshot
                            .records
                            .get(&key_receipt(&record.tenant, fence.command.command_id))
                        {
                            Some(Record::Receipt(retained)) => {
                                ensure!(retained == fence, "authority fence receipt substituted")
                            }
                            _ => anyhow::bail!("authority fence receipt missing"),
                        }
                    }
                }
                Record::Receipt(receipt) => {
                    receipts += 1;
                    ensure!(
                        *key == key_receipt(&receipt.command.tenant, receipt.command.command_id)
                            && receipt.command_digest == receipt.command.digest()?
                            && receipt.authority_id == self.installation.manifest.authority_id
                            && receipt.manifest_digest == self.installation.manifest.digest()?
                            && receipt.partition == self.installation.partition
                            && receipt.revision > 0
                            && receipt.revision <= snapshot.meta.revision,
                        "authority receipt snapshot differs"
                    );
                }
                Record::Preparation(prepared) => {
                    preparations += 1;
                    ensure!(
                        *key == key_preparation(&prepared.tenant, prepared.target.incarnation)
                            && prepared.source_epoch > 0
                            && prepared.source_epoch < u64::MAX,
                        "preparation snapshot identity differs"
                    );
                    prepared
                        .target
                        .validate(&prepared.tenant, prepared.source_incarnation)?;
                    ensure!(
                        matches!(&prepared.receipt.outcome, AuthorityOutcome::TargetPrepared { target, authority_epoch } if target == &prepared.target && *authority_epoch == prepared.source_epoch + 1),
                        "preparation snapshot outcome differs"
                    );
                    match snapshot.records.get(&key_receipt(
                        &prepared.tenant,
                        prepared.receipt.command.command_id,
                    )) {
                        Some(Record::Receipt(receipt)) => ensure!(
                            receipt == &prepared.receipt,
                            "preparation snapshot receipt differs"
                        ),
                        _ => anyhow::bail!("preparation snapshot receipt absent"),
                    }
                }
                Record::TargetStop(stop) => {
                    target_stops += 1;
                    let (source, epoch, target) = match (&stop.command.action, &stop.outcome) {
                        (
                            AuthorityAction::StopTarget {
                                source_incarnation,
                                source_epoch,
                                target,
                            },
                            AuthorityOutcome::TargetStopped {
                                source_incarnation: actual_source,
                                source_epoch: actual_epoch,
                                target: actual,
                            },
                        ) if source_incarnation == actual_source
                            && source_epoch == actual_epoch
                            && target == actual =>
                        {
                            (*source_incarnation, *source_epoch, target)
                        }
                        _ => anyhow::bail!("target stop snapshot outcome differs"),
                    };
                    target.validate(&stop.command.tenant, source)?;
                    ensure!(
                        epoch > 0
                            && epoch < u64::MAX
                            && *key == key_target_stop(&stop.command.tenant, target.incarnation)
                            && !snapshot.records.contains_key(&key_incarnation(
                                &stop.command.tenant,
                                target.incarnation
                            )),
                        "target stop snapshot identity differs"
                    );
                    ensure!(
                        matches!(snapshot.records.get(&key_receipt(&stop.command.tenant,stop.command.command_id)),Some(Record::Receipt(receipt)) if receipt==stop),
                        "target stop receipt absent or substituted"
                    );
                }
                Record::Incarnation(accepted) => {
                    incarnations += 1;
                    ensure!(
                        *key == key_incarnation(&accepted.tenant, accepted.incarnation)
                            && accepted.authority_epoch > 0,
                        "incarnation snapshot identity differs"
                    );
                    let bound = match (&accepted.receipt.command.action, &accepted.receipt.outcome)
                    {
                        (
                            AuthorityAction::Enroll { incarnation, .. },
                            AuthorityOutcome::Enrolled {
                                incarnation: actual,
                                authority_epoch,
                            },
                        ) => {
                            *incarnation == accepted.incarnation
                                && actual == incarnation
                                && *authority_epoch == 1
                                && accepted.authority_epoch == 1
                        }
                        (
                            AuthorityAction::Activate { target, .. },
                            AuthorityOutcome::Activated {
                                target: actual,
                                authority_epoch,
                            },
                        ) => {
                            target == actual
                                && target.incarnation == accepted.incarnation
                                && *authority_epoch == accepted.authority_epoch
                                && *authority_epoch > 1
                        }
                        _ => false,
                    };
                    ensure!(
                        bound && accepted.receipt.command.tenant == accepted.tenant,
                        "incarnation snapshot outcome differs"
                    );
                    match snapshot.records.get(&key_receipt(
                        &accepted.tenant,
                        accepted.receipt.command.command_id,
                    )) {
                        Some(Record::Receipt(receipt)) => ensure!(
                            receipt == &accepted.receipt,
                            "incarnation receipt substituted"
                        ),
                        _ => anyhow::bail!("incarnation receipt absent"),
                    }
                }
            }
        }
        ensure!(
            (
                tenants,
                receipts,
                state_bytes,
                active_fences,
                preparations,
                incarnations,
                target_stops
            ) == (
                snapshot.meta.tenants,
                snapshot.meta.receipts,
                snapshot.meta.state_bytes,
                snapshot.meta.active_fences,
                snapshot.meta.preparations,
                snapshot.meta.incarnations,
                snapshot.meta.target_stops
            ) && target_stops <= receipts
                && preparations <= receipts
                && incarnations >= tenants
                && incarnations <= receipts
                && tenants <= self.installation.max_tenants
                && receipts
                    + snapshot.meta.lifecycle_receipts
                    + active_fences
                    + snapshot.meta.open_control_epochs
                    <= self.installation.max_receipts
                && state_bytes
                    + active_fences * (3 * MAX_RECORD_BYTES as u64)
                    + snapshot.meta.open_control_epochs * MAX_RECORD_BYTES as u64
                    <= self.installation.max_state_bytes,
            "authority snapshot accounting differs"
        );
        self.validate_lifecycle_snapshot(&snapshot)?;
        Ok(snapshot)
    }
}
