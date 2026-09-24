//! Installed native target runner. Independent metadata precedes application
//! provider construction; all physical owners survive caller cancellation.
use crate::{
    cluster::ClusterNetwork,
    runtime::{RuntimeConfig, SecurityAudit, read_private_file},
    serving_runtime::CredentialSource,
    target_phase_runtime::RuntimeTargetPhase,
    target_runtime_config::{TargetRecoveryConfig, TargetTenantTemplate},
};
use anyhow::{Context, Result, ensure};
use kasumi_engine::{
    TargetJournal, TargetJournalInstallation, TargetOperation, TargetReplica,
    TargetRequestAdmission, TargetSigner, admission::NodeAdmission,
};
use kasumi_serving::*;
use kasumi_store::{
    BackupDestination, NodeDiskDirectory, NodeStore, StorageAccess, TenantStorageSet, TenantStore,
};
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainReport, DrainResult};
use kasumi_types::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;
use zeroize::Zeroizing;
const MAX_CALLS: u32 = 64;
type GenerationKey = (String, Uuid);
#[path = "target_call_jobs.rs"]
mod target_call_jobs;
use target_call_jobs::TargetCallJobs;
#[path = "target_serving_runtime.rs"]
mod serving;
#[cfg(test)]
#[path = "target_runtime_shutdown_tests.rs"]
mod shutdown_tests;
#[derive(Default)]
struct Generation {
    report: DrainReport,
    custody: Option<(GenerationKey, Arc<kasumi_engine::RetiredCustody>)>,
    custody_probe: Option<Arc<kasumi_store::CustodyStore>>,
    serving: Option<kasumi_engine::TargetServingReplica>,
    lease: Option<Arc<crate::serving_runtime::RuntimeLease>>,
    registered_data: Option<(GenerationKey, Arc<kasumi_engine::Database>)>,
    phase: Option<Arc<RuntimeTargetPhase>>,
    node: Option<Arc<NodeStore>>,
    // Consumed only from the journal's original Created outcome. A lost
    // attempt cannot recover creation permission from missing catalogs.
    fresh_catalogs: bool,
    stores: Option<Arc<TenantStorageSet>>,
    replica: Option<TargetReplica>,
    #[cfg(test)]
    sealed_restore_observation: RestoreDrainObservation,
    registered_group: Option<String>,
}
/// A test observer holds metadata only; it cannot keep a physical generation,
/// Raft task, key provider, database, route, or serving authority alive.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct RestoreDrainObservation(Arc<std::sync::Mutex<Option<Option<PendingRestore>>>>);
#[cfg(test)]
impl RestoreDrainObservation {
    fn record(&self, marker: Option<PendingRestore>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(marker);
    }
    pub(crate) fn marker(&self) -> Result<Option<PendingRestore>> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .context("no actual committed marker captured at target drain")
    }
}
impl Generation {
    async fn close(
        &mut self,
        cluster: &ClusterNetwork,
        registry: &crate::api::DatabaseRegistry,
    ) -> DrainResult {
        let mut retained = None;
        let mut custody_route_closed = true;
        if let Some(lease) = &self.lease {
            lease.close();
        }
        if let Some(phase) = &self.phase {
            phase.close();
        }
        if let Some((key, database)) = &self.registered_data {
            match serving::detach_owned_data(registry, key, database) {
                Ok(()) => self.registered_data = None,
                Err(error) => {
                    retained = Some(DrainFailure::retained(self.report.record(
                        "target data route",
                        0,
                        error,
                    )))
                }
            }
        }
        if let Some((key, custody)) = &self.custody
            && let Err(error) = registry.detach_target_custody(&key.0, &key.1.to_string(), custody)
        {
            custody_route_closed = false;
            retained = Some(DrainFailure::retained(self.report.record(
                "target custody route",
                0,
                error.into(),
            )));
        }
        if let Some(group) = &self.registered_group {
            match cluster.unregister_group(group) {
                Ok(()) => self.registered_group = None,
                Err(error) => {
                    retained = Some(DrainFailure::retained(self.report.record(
                        "target group route",
                        0,
                        error,
                    )))
                }
            }
        }
        if let Some((_, custody)) = &self.custody {
            match custody.shutdown().await {
                Ok(()) => {
                    if custody_route_closed {
                        self.custody.take();
                    }
                }
                Err(failure) => {
                    self.report.merge(&failure);
                    if failure.completion() == DrainCompletion::Retained {
                        retained = Some(failure);
                    } else if custody_route_closed {
                        self.custody.take();
                    }
                }
            }
        }
        if let Some(probe) = &self.custody_probe {
            match probe.store().shutdown().await {
                Ok(()) => {
                    self.custody_probe.take();
                }
                Err(failure) => {
                    self.report.merge(&failure);
                    if failure.completion() == DrainCompletion::Retained {
                        retained = Some(failure);
                    } else {
                        self.custody_probe.take();
                    }
                }
            }
        }
        if let Some(serving) = &mut self.serving {
            match serving.close().await {
                Ok(()) => {
                    self.serving.take();
                }
                Err(failure) => {
                    self.report.merge(&failure);
                    if failure.completion() == DrainCompletion::Retained {
                        retained = Some(failure);
                    } else {
                        self.serving.take();
                    }
                }
            }
        }
        if let Some(replica) = &mut self.replica {
            match replica.close().await {
                Ok(()) => {
                    #[cfg(test)]
                    {
                        self.sealed_restore_observation.record(
                            replica
                                .database()
                                .engine()
                                .fixture_pending_restore_at_seal()
                                .expect("drained replica seal observation"),
                        );
                    }
                    self.replica.take();
                }
                Err(failure) => {
                    self.report.merge(&failure);
                    if failure.completion() == DrainCompletion::Retained {
                        retained = Some(failure);
                    } else {
                        #[cfg(test)]
                        {
                            self.sealed_restore_observation.record(
                                replica
                                    .database()
                                    .engine()
                                    .fixture_pending_restore_at_seal()
                                    .expect("completed replica seal observation"),
                            );
                        }
                        self.replica.take();
                    }
                }
            }
        }
        if let Some(phase) = &self.phase {
            match phase.shutdown().await {
                Ok(()) => {
                    self.phase.take();
                }
                Err(error) => {
                    self.report.merge(&error);
                    if error.completion() == DrainCompletion::Retained {
                        retained = Some(error);
                    } else {
                        self.phase.take();
                    }
                }
            }
        }
        if let Some(lease) = &self.lease {
            match lease.shutdown().await {
                Ok(()) => {
                    self.lease.take();
                }
                Err(error) => {
                    self.report.merge(&error);
                    if error.completion() == DrainCompletion::Retained {
                        retained = Some(error);
                    } else {
                        self.lease.take();
                    }
                }
            }
        }
        if let Some(stores) = &self.stores {
            match stores.shutdown().await {
                Ok(()) => {
                    self.stores.take();
                }
                Err(failure) => {
                    self.report.merge(&failure);
                    if failure.completion() == DrainCompletion::Retained {
                        retained = Some(failure);
                    } else {
                        self.stores.take();
                    }
                }
            }
        }
        if retained.is_none()
            && let Some(node) = &self.node
            && let Err(failure) = node.shutdown().await
        {
            self.report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        self.fresh_catalogs = false;
        if retained.is_none()
            && let Some(node) = self.node.take()
        {
            match Arc::try_unwrap(node) {
                Ok(node) => drop(node),
                Err(node) => {
                    self.node = Some(node);
                    retained = Some(DrainFailure::retained(self.report.record(
                        "target physical owner",
                        0,
                        anyhow::anyhow!("target file still has an actual detached owner"),
                    )));
                }
            }
        }
        self.report.outcome(retained)
    }
}
enum ResponseEvidence {
    Receiver(Box<kasumi_engine::VerifiedTargetReceiver>),
    Materialized(Box<kasumi_engine::VerifiedTargetMaterialization>),
    Completed(Box<kasumi_engine::VerifiedTargetCompletion>),
    Activated(Box<kasumi_engine::VerifiedTargetActivation>),
    Inspected(Box<kasumi_engine::VerifiedTargetInspection>),
    Started(Arc<TenantStorageSet>),
    Stopped(Box<VerifiedTargetStop>, GenerationKey),
}
pub(crate) struct TargetRuntimeReply {
    pub(crate) response: TargetRuntimeResponse,
    runtime: Arc<TargetRecoveryRuntime>,
    phase: Arc<RuntimeTargetPhase>,
    operation: TargetOperation,
    bearer: Zeroizing<String>,
    evidence: ResponseEvidence,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl TargetRuntimeReply {
    pub(crate) async fn release(&self) -> Result<()> {
        ensure!(
            !self.runtime.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        self.phase
            .check_operation(&self.operation, &self.bearer)
            .await?;
        match &self.evidence {
            ResponseEvidence::Materialized(p) => p.release(&self.operation).await?,
            ResponseEvidence::Receiver(p) => p.release(&self.operation).await?,
            ResponseEvidence::Completed(p) => p.release(&self.operation).await?,
            ResponseEvidence::Activated(p) => p.release(&self.operation).await?,
            ResponseEvidence::Inspected(p) => p.release(&self.operation).await?,
            ResponseEvidence::Started(db) => {
                db.check_access()?;
                self.operation.check()?;
            }
            ResponseEvidence::Stopped(stop, key) => {
                self.runtime.journal.stop(&self.operation, stop)?;
                let path = self.runtime.path(key)?;
                ensure!(
                    !target_file_exists(&path)?,
                    "target storage reappeared after stop"
                );
                target_absence_from_installed_disk(
                    &self.runtime.config.persistent_disk,
                    self.runtime.audit.store().persistent_disk(),
                    &path,
                )?;
            }
        }
        self.operation.check()?;
        Ok(())
    }
}
pub struct TargetRecoveryRuntime {
    recovery_health: std::sync::Mutex<serving::RecoveryHealth>,
    registry: crate::api::DatabaseRegistry,
    serving_monitor: crate::runtime_worker::RuntimeWorker,
    shutdown_gate: Mutex<DrainReport>,
    config: RuntimeConfig,
    authority_trusts: BTreeMap<String, AuthorityTrust>,
    installed: TargetRecoveryConfig,
    credential: CredentialSource,
    journal: Arc<TargetJournal>,
    journal_node: Arc<NodeStore>,
    signer: TargetSigner,
    cleanup_key: Ed25519KeyPair,
    admission: Arc<NodeAdmission>,
    audit: Arc<SecurityAudit>,
    cluster: Arc<ClusterNetwork>,
    destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
    root: PathBuf,
    generation_directory: NodeDiskDirectory,
    generations: Mutex<BTreeMap<GenerationKey, Arc<Mutex<Generation>>>>,
    calls: Arc<Semaphore>,
    call_jobs: TargetCallJobs,
    closing: AtomicBool,
}
/// Keep the outer owner reachable across cancellation of its recursive drain.
pub(crate) async fn shutdown_target(owner: &mut Option<Arc<TargetRecoveryRuntime>>) -> DrainResult {
    if let Some(target) = owner.as_ref()
        && let Err(failure) = target.shutdown().await
    {
        if failure.completion() == DrainCompletion::Complete {
            // The original diagnostic has been returned to the caller, and
            // no child or physical generation remains. Do not strand the
            // fully drained runtime merely because its report is nonempty.
            owner.take();
        }
        return Err(failure);
    }
    owner.take();
    Ok(())
}
impl TargetRecoveryRuntime {
    /// Inspect an already owned target in the native integration fixture. This
    /// never opens storage, publishes a route, or creates serving authority.
    #[cfg(test)]
    pub(crate) async fn test_owned_database(
        &self,
        tenant: &str,
        incarnation: Uuid,
    ) -> Option<Arc<kasumi_engine::Database>> {
        let generation = self
            .generations
            .lock()
            .await
            .get(&(tenant.to_owned(), incarnation))
            .cloned()?;
        let generation = generation.lock().await;
        if let Some(replica) = &generation.replica {
            Some(replica.database().clone())
        } else {
            generation.serving.as_ref()?.database().ok()
        }
    }

    /// Observe the next actual drain without retaining its generation owner.
    #[cfg(test)]
    pub(crate) async fn test_restore_drain_observer(
        &self,
        tenant: &str,
        incarnation: Uuid,
    ) -> Result<RestoreDrainObservation> {
        let generation = self
            .generations
            .lock()
            .await
            .get(&(tenant.to_owned(), incarnation))
            .cloned()
            .context("target generation absent")?;
        let generation = generation.lock().await;
        Ok(generation.sealed_restore_observation.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open(
        config: RuntimeConfig,
        authority_trusts: BTreeMap<String, AuthorityTrust>,
        credential: CredentialSource,
        admission: Arc<NodeAdmission>,
        audit: Arc<SecurityAudit>,
        cluster: Arc<ClusterNetwork>,
        destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
        registry: crate::api::DatabaseRegistry,
    ) -> Result<Arc<Self>> {
        let installed = config
            .target_recovery
            .clone()
            .context("target recovery not configured")?;
        installed.validate(&config)?;
        let monitor_bytes = kasumi_serving::BackgroundWorkBudget::required_bytes(1, 1)?;
        let mut monitor_charge = admission.reserve(monitor_bytes, None)?;
        monitor_charge.retain(monitor_bytes);
        let monitor_budget =
            kasumi_serving::BackgroundWorkBudget::new(1, Arc::new(monitor_charge))?;
        let call_jobs = TargetCallJobs::new(&admission)?;
        // Finish fallible filesystem setup before a journal catalog can start
        // renewal workers. This directory is under an already-censused NodeDisk;
        // every new component must publish through its managed namespace.
        let generation_directory = crate::persistent_disk::open_or_create_directory(
            &config.persistent_disk,
            audit.store().persistent_disk(),
            &installed.generation_root,
        )?;
        ensure!(
            !std::fs::symlink_metadata(&installed.generation_root)?
                .file_type()
                .is_symlink(),
            "target root cannot be a symlink"
        );
        let root = std::fs::canonicalize(&installed.generation_root)?;
        generation_directory.sync_all()?;
        let key = read_private_file(&installed.attestation_key, 1 << 20)?;
        let signer = TargetSigner::from_pkcs8(installed.node.clone(), &key)?;
        let cleanup_key =
            Ed25519KeyPair::from_pkcs8(&key).map_err(|_| anyhow::anyhow!("invalid target key"))?;
        // Only the independent journal KMS provider is constructed at startup.
        let provider = installed.journal_keys.provider(credential.clone())?;
        let node = NodeStore::open_existing(
            &installed.journal_path,
            kasumi_store::node_store_ids::target_journal(
                installed.control_root.control_incarnation,
                &installed.node.verifier,
            )?,
            audit.store().persistent_disk().clone(),
            audit.store().scratch_disk().clone(),
        )?;
        let access = StorageAccess::target_journal(&installed.control_root, &installed.node)?;
        let store = TenantStore::open_existing(
            node.clone(),
            format!(
                "kasumi.target.{}.{}",
                installed.control_root.control_incarnation, installed.node.node_id
            ),
            provider,
            access,
        )
        .await;
        let store = match store {
            Ok(store) => store,
            Err(error) => {
                let mut pending = crate::startup_resources::Resources::default();
                pending.owned_nodes.push(node);
                return Err(match crate::startup_owner::finish(&mut pending).await {
                    Ok(()) => error,
                    Err(drain) => error.context(drain),
                });
            }
        };
        let journal = TargetJournal::open_existing(
            store.clone(),
            TargetJournalInstallation {
                root: installed.control_root.clone(),
                node: installed.node.clone(),
            },
            installed.limits.journal.clone(),
            admission.clone(),
        );
        let journal = match journal {
            Ok(journal) => journal,
            Err(error) => {
                let mut pending = crate::startup_resources::Resources::default();
                pending.owned_nodes.push(node);
                pending.stores.push(store);
                return Err(match crate::startup_owner::finish(&mut pending).await {
                    Ok(()) => error,
                    Err(drain) => error.context(drain),
                });
            }
        };
        let runtime = Arc::new(Self {
            recovery_health: std::sync::Mutex::new(serving::RecoveryHealth::new()),
            registry,
            serving_monitor: Default::default(),
            shutdown_gate: Mutex::new(DrainReport::default()),
            config,
            authority_trusts,
            installed,
            credential,
            journal,
            journal_node: node,
            signer,
            cleanup_key,
            admission,
            audit,
            cluster,
            destinations,
            root,
            generation_directory,
            generations: Mutex::new(BTreeMap::new()),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            call_jobs,
            closing: AtomicBool::new(false),
        });
        if let Err(error) = runtime.start_serving_reconciliation(&monitor_budget) {
            // The actual unpublished target remains owned while its journal and
            // any started monitor drain, even if the outer request loses its reply.
            struct FailedMonitor(Arc<TargetRecoveryRuntime>);
            impl crate::startup_owner::Runtime for FailedMonitor {
                fn close(
                    &mut self,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DrainResult> + Send + '_>>
                {
                    Box::pin(self.0.shutdown())
                }
            }
            let mut failed = FailedMonitor(runtime);
            return Err(match crate::startup_owner::finish(&mut failed).await {
                Ok(()) => error,
                Err(drain) => error.context(drain),
            });
        }
        Ok(runtime)
    }
    pub fn control_root(&self) -> &ControlSigningRoot {
        &self.installed.control_root
    }
    pub(crate) async fn execute(
        self: &Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        request: TargetRuntimeRequest,
    ) -> Result<TargetRuntimeReply> {
        let admission = TargetRequestAdmission::capture_until(
            context.clone(),
            self.installed.limits.operation_timeout_ms,
            request.not_after_ms,
        )?;
        let deadline = admission.response_deadline()?;
        context
            .authorization
            .require_control(&self.installed.control_root.control_incarnation.to_string())?;
        ensure!(
            context.tenant == "__kasumi_control" && context.scopes.contains(&Action::Admin),
            "target requires current Control Admin"
        );
        request.validate()?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .context("target invocation capacity exhausted")?;
        ensure!(
            !self.closing.load(Ordering::Acquire),
            "target runtime closing"
        );
        let this = self.clone();
        // The response deadline was captured before authority acquisition and
        // cannot extend the coordinator's original not_after cap.
        let receive = self
            .call_jobs
            .submit(deadline, async move {
                let mut reply = this
                    .execute_owned(context, bearer, request, admission)
                    .await?;
                reply.permit = Some(permit);
                Ok::<_, anyhow::Error>(reply)
            })
            .await?;
        // A lost waiter returns UnknownOutcome. The private ticket owns a
        // completed result until a synchronous claim; the child retires any
        // unclaimed reply and preserves its exact terminal outcome.
        self.call_jobs.await_reply(deadline, receive).await
    }
    async fn execute_owned(
        self: Arc<Self>,
        context: RequestContext,
        bearer: Zeroizing<String>,
        request: TargetRuntimeRequest,
        admission: TargetRequestAdmission,
    ) -> Result<TargetRuntimeReply> {
        let template = self
            .installed
            .tenants
            .get(&request.tenant)
            .context("target template not installed")?
            .clone();
        let authority = self
            .config
            .serving_authorities
            .get(&template.authority)
            .context("target issuer missing")?;
        let phase = RuntimeTargetPhase::acquire(
            &self.installed,
            authority,
            self.authority_trusts
                .get(&template.authority)
                .context("live phase verifier absent")?
                .clone(),
            self.credential.clone(),
            self.installed.node.node_id,
            context.clone(),
            Zeroizing::new(bearer.to_string()),
            request.command_id,
            &admission,
        )
        .await?;
        let intent = phase.original().observation().intent.clone();
        ensure!(
            intent.request.tenant == request.tenant,
            "target request tenant differs from committed phase"
        );
        let node = intent
            .request
            .target_nodes
            .get(&self.installed.node.node_id)
            .context("target node missing")?;
        ensure!(
            node.attestation_public_key == self.signer.public_key(),
            "installed target attestation key differs"
        );
        let (expected_phase, input_hash) = self.input(&phase, &request.step, &admission).await?;
        ensure!(
            intent.request.phase == expected_phase
                && intent.request.phase_input_sha256 == input_hash,
            "target operation differs from exact committed phase"
        );
        let key = (request.tenant.clone(), intent.request.target_incarnation);
        self.prune_expired(&admission).await?;
        let target = admission
            .run(async {
                let mut all = self.generations.lock().await;
                ensure!(
                    !self.closing.load(Ordering::Acquire),
                    "target runtime closing"
                );
                if let Some(target) = all.get(&key) {
                    return Ok(target.clone());
                }
                let bound = self.installed.limits.max_live_generations as usize
                    + usize::from(expected_phase == LifecyclePhase::StopLocal);
                ensure!(
                    all.len() < bound,
                    "target live generation capacity exhausted"
                );
                let target = Arc::new(Mutex::new(Generation::default()));
                all.insert(key.clone(), target.clone());
                Ok(target)
            })
            .await?;
        let mut generation = admission.run(async { Ok(target.lock().await) }).await?;
        if expected_phase == LifecyclePhase::StopLocal {
            let TargetRuntimeStep::Stop(reference) = &request.step else {
                unreachable!()
            };
            phase.check_request(&admission, &context, &bearer).await?;
            let operation = phase.scope().begin_admitted(admission)?;
            let proof = phase.target_stop(&operation, reference).await?;
            self.journal.stop(&operation, &proof)?;
            operation
                .run(async {
                    generation
                        .close(&self.cluster, &self.registry)
                        .await
                        .map_err(Into::into)
                })
                .await
                .map_err(unknown)?;
            let outcome = self
                .cleanup(&operation, &proof, &key)
                .await
                .map_err(unknown)?;
            phase
                .check_operation(&operation, &bearer)
                .await
                .map_err(unknown)?;
            drop(generation);
            self.generations.lock().await.remove(&key);
            let reply = TargetRuntimeReply {
                response: TargetRuntimeResponse {
                    command_id: request.command_id,
                    node_id: self.installed.node.node_id,
                    outcome: TargetRuntimeOutcome::Stopped(Box::new(outcome)),
                },
                runtime: self,
                phase,
                operation,
                bearer,
                evidence: ResponseEvidence::Stopped(Box::new(proof), key),
                permit: None,
            };
            reply.release().await.map_err(unknown)?;
            return Ok(reply);
        }
        // Reuse only a continuously live phase. A new request retains its own
        // verified context and timeout without renewing the old phase.
        let continuing = generation
            .phase
            .as_ref()
            .filter(|old| {
                old.original().observation().intent == intent
                    && old.scope().invocation().check().is_ok()
            })
            .cloned();
        let phase = if let Some(old) = continuing {
            phase.shutdown().await?;
            drop(phase);
            old
        } else {
            admission
                .run(async {
                    generation
                        .close(&self.cluster, &self.registry)
                        .await
                        .map_err(Into::into)
                })
                .await?;
            generation.phase = Some(phase.clone());
            phase
        };
        phase.check_request(&admission, &context, &bearer).await?;
        let operation = phase.scope().begin_followup(admission)?;
        self.journal.prepare(&operation, &input_hash)?;
        // From this accepted durable identity onward, any local failure is an
        // unresolved effect. No caller infers abort from absence or an RPC error.
        let (outcome, evidence) = self
            .perform(
                &mut generation,
                &phase,
                &operation,
                &template,
                &request.step,
            )
            .await
            .map_err(unknown)?;
        phase
            .check_operation(&operation, &bearer)
            .await
            .map_err(unknown)?;
        operation.check().map_err(unknown)?;
        drop(generation);
        let reply = TargetRuntimeReply {
            response: TargetRuntimeResponse {
                command_id: request.command_id,
                node_id: self.installed.node.node_id,
                outcome,
            },
            runtime: self,
            phase,
            operation,
            bearer,
            evidence,
            permit: None,
        };
        reply.release().await.map_err(unknown)?;
        Ok(reply)
    }
    async fn prune_expired(&self, admission: &TargetRequestAdmission) -> Result<()> {
        // At most max_live_generations+one cleanup owner are examined. Remove
        // only fully drained owners with no queued holder of the generation Arc;
        // otherwise a delayed opener could become an untracked live Raft group.
        let candidates = admission
            .run(async {
                Ok(self
                    .generations
                    .lock()
                    .await
                    .iter()
                    .map(|(k, g)| (k.clone(), g.clone()))
                    .collect::<Vec<_>>())
            })
            .await?;
        for (key, owner) in candidates {
            let Ok(mut generation) = owner.try_lock() else {
                continue;
            };
            let expired = generation
                .custody
                .as_ref()
                .is_none_or(|(_, custody)| custody.identity().is_err())
                && generation
                    .serving
                    .as_ref()
                    .is_none_or(|owner| owner.check().is_err())
                && generation
                    .phase
                    .as_ref()
                    .is_none_or(|phase| phase.scope().invocation().check().is_err());
            if !expired {
                continue;
            }
            admission
                .run(async {
                    generation
                        .close(&self.cluster, &self.registry)
                        .await
                        .map_err(Into::into)
                })
                .await?;
            drop(generation);
            let mut all = admission
                .run(async { Ok(self.generations.lock().await) })
                .await?;
            if Arc::strong_count(&owner) == 2
                && all
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
            {
                all.remove(&key);
            }
        }
        Ok(())
    }
    async fn input(
        &self,
        phase: &RuntimeTargetPhase,
        step: &TargetRuntimeStep,
        admission: &TargetRequestAdmission,
    ) -> Result<(LifecyclePhase, String)> {
        Ok(match step {
            TargetRuntimeStep::ResumeMaterialization(origin) => {
                ensure!(
                    phase
                        .original()
                        .observation()
                        .intent
                        .request
                        .resume_origin
                        .as_ref()
                        == Some(origin),
                    "resumption differs from exact retained Control origin"
                );
                (LifecyclePhase::ResumeMaterialize, origin.resume_digest()?)
            }
            TargetRuntimeStep::Materialize(input) => {
                input.validate(&phase.original().observation().intent)?;
                (LifecyclePhase::Materialize, input.digest()?)
            }
            TargetRuntimeStep::Start(input) => match input {
                TargetReplicaInput::Completion(i) => (LifecyclePhase::Complete, i.digest()?),
                TargetReplicaInput::CompletionResolution(i) => {
                    (LifecyclePhase::ResolveComplete, i.digest()?)
                }
                TargetReplicaInput::ResolutionBudget { input, .. } => {
                    (LifecyclePhase::MaintainTarget, input.digest()?)
                }
                TargetReplicaInput::Inspection(i) => (LifecyclePhase::InspectTarget, i.digest()?),
                TargetReplicaInput::CompletionAttemptStatus(i) => {
                    (LifecyclePhase::InspectCompletionAttempt, i.digest()?)
                }
                TargetReplicaInput::CompletionTerminalStatus(i) => {
                    (LifecyclePhase::InspectCompletionResolution, i.digest()?)
                }
                TargetReplicaInput::Quorum(q) => {
                    let p = phase.original().observation().intent.request.phase;
                    ensure!(
                        p == LifecyclePhase::Initialize,
                        "start cannot synthesize activation"
                    );
                    (p, q.digest()?)
                }
            },
            TargetRuntimeStep::Initialize(q) => (LifecyclePhase::Initialize, q.digest()?),
            TargetRuntimeStep::Complete(q) | TargetRuntimeStep::PrepareComplete(q) => {
                (LifecyclePhase::Complete, q.digest()?)
            }
            TargetRuntimeStep::ResolveComplete(input) => {
                (LifecyclePhase::ResolveComplete, input.digest()?)
            }
            TargetRuntimeStep::MaintainBudget { input, .. } => {
                (LifecyclePhase::MaintainTarget, input.digest()?)
            }
            TargetRuntimeStep::ConfirmActivation(signed) => {
                verify_target_activation(&signed.observation.completion.origin, signed)?;
                (
                    LifecyclePhase::Activate,
                    signed
                        .observation
                        .activation
                        .intent
                        .request
                        .phase_input_sha256
                        .clone(),
                )
            }
            TargetRuntimeStep::ConfirmInspection(signed) => {
                verify_target_inspection(&signed.observation.input, signed)?;
                (
                    LifecyclePhase::InspectTarget,
                    signed.observation.input.digest()?,
                )
            }
            TargetRuntimeStep::Inspect(i) => (LifecyclePhase::InspectTarget, i.digest()?),
            TargetRuntimeStep::InspectCompletionAttempt(i) => {
                (LifecyclePhase::InspectCompletionAttempt, i.digest()?)
            }
            TargetRuntimeStep::InspectCompletionResolution(i) => {
                (LifecyclePhase::InspectCompletionResolution, i.digest()?)
            }
            TargetRuntimeStep::StartActivation {
                issuer_command_id, ..
            }
            | TargetRuntimeStep::Activate {
                issuer_command_id, ..
            } => {
                let signed = admission
                    .run(phase.activation_receipt(*issuer_command_id))
                    .await?;
                let AuthorityAction::ActivateCommitted {
                    fence_id,
                    fence_digest,
                    target,
                    control,
                } = signed.receipt.command.action
                else {
                    anyhow::bail!("closed issuer winner required")
                };
                (
                    LifecyclePhase::Activate,
                    ActivateTargetInput {
                        fence_id,
                        fence_digest,
                        target,
                        completion_sha256: control.completion.fact().digest()?,
                    }
                    .digest()?,
                )
            }
            TargetRuntimeStep::Stop(reference) => (
                LifecyclePhase::StopLocal,
                digest(&("kasumi.stop-local-target-input.v1", reference))?,
            ),
        })
    }
    fn generation_file_id(&self, key: &GenerationKey) -> Result<Uuid> {
        kasumi_store::node_store_ids::target_generation(
            self.installed.control_root.control_incarnation,
            &key.0,
            key.1,
            &self.installed.node.verifier,
        )
    }
    fn path(&self, key: &GenerationKey) -> Result<PathBuf> {
        checked_generation_path(
            &self.generation_directory,
            &self.installed.generation_root,
            &self.root,
            key,
        )
    }
    async fn perform(
        &self,
        g: &mut Generation,
        phase: &RuntimeTargetPhase,
        op: &TargetOperation,
        template: &TargetTenantTemplate,
        step: &TargetRuntimeStep,
    ) -> Result<(TargetRuntimeOutcome, ResponseEvidence)> {
        let intent = &phase.original().observation().intent;
        let key = (
            intent.request.tenant.clone(),
            intent.request.target_incarnation,
        );
        if g.node.is_none() {
            op.check()?;
            let path = self.path(&key)?;
            let scratch = self.audit.store().scratch_disk().clone();
            if matches!(step, TargetRuntimeStep::Materialize(_)) {
                match self
                    .journal
                    .reserve_materialization_file(op)?
                    .open(&path, scratch)?
                {
                    kasumi_engine::MaterializationNode::Created(node) => {
                        g.node = Some(node);
                        g.fresh_catalogs = true;
                    }
                    kasumi_engine::MaterializationNode::Existing(node) => {
                        g.node = Some(node);
                        g.fresh_catalogs = false;
                    }
                }
            } else {
                g.node = Some(NodeStore::open_existing(
                    path,
                    self.journal.materialization_file_id(&key.0, key.1)?,
                    self.audit.store().persistent_disk().clone(),
                    scratch,
                )?);
                g.fresh_catalogs = false;
            }
            op.check()?;
        }
        if g.stores.is_none() {
            op.check()?;
            let app = template
                .application_keys
                .provider(self.credential.clone())?;
            let custody = template.custody_keys.provider(self.credential.clone())?;
            let node = g.node.as_ref().unwrap().clone();
            let access = phase.access()?;
            g.stores = Some(if std::mem::take(&mut g.fresh_catalogs) {
                ensure!(
                    matches!(step, TargetRuntimeStep::Materialize(_)),
                    "only original materialization may initialize catalogs"
                );
                op.run(TenantStorageSet::initialize_catalogs(
                    node,
                    key.0.clone(),
                    app,
                    custody,
                    access,
                ))
                .await?
            } else {
                op.run(TenantStorageSet::open_existing(
                    node,
                    key.0.clone(),
                    app,
                    custody,
                    access,
                ))
                .await?
            });
        }

        let stores = g.stores.as_ref().unwrap().clone();
        self.config
            .install_tenant_audit_archive(stores.application(), None)?;
        let materialization = match step {
            TargetRuntimeStep::Materialize(input) => Some((input, None)),
            TargetRuntimeStep::ResumeMaterialization(origin) => Some((&origin.input, Some(origin))),
            _ => None,
        };
        if let Some((input, resume)) = materialization {
            self.placement(input)?;
            let source = template
                .source_backups
                .get(&intent.request.source_incarnation)
                .context("source backup key lineage is not installed")?;
            ensure!(
                source.destination_alias == input.destination_alias,
                "backup destination differs from installed lineage"
            );
            op.check()?;
            let source = kasumi_engine::RestoreSource {
                destination_alias: source.destination_alias.clone(),
                destination: self
                    .destinations
                    .get(&source.destination_alias)
                    .context("backup destination missing")?
                    .clone(),
                keys: source.keys.provider(self.credential.clone())?,
                timeout_ms: self.installed.limits.operation_timeout_ms,
            };
            let configuration = kasumi_engine::TargetMaterializationConfig {
                node_id: self.installed.node.node_id,
                incarnation: key.1,
                voters: input
                    .voters
                    .iter()
                    .map(|(id, p)| {
                        (
                            *id,
                            kasumi_engine::ReplicaPlacement {
                                address: p.endpoint.clone(),
                                failure_domain: p.failure_domain.clone(),
                            },
                        )
                    })
                    .collect(),
                admission: self.admission.clone(),
            };
            let materialized = match resume {
                Some(origin) => {
                    kasumi_engine::resume_target_materialization(
                        op,
                        &source,
                        stores,
                        origin.as_ref().clone(),
                        configuration,
                        self.audit.clone(),
                    )
                    .await?
                }
                None => {
                    kasumi_engine::materialize_target_replica(
                        op,
                        &source,
                        stores,
                        input.clone(),
                        configuration,
                        self.audit.clone(),
                    )
                    .await?
                }
            };
            let signed = self
                .signer
                .sign_materialized(&materialized.proof, op)
                .await?;
            return Ok((
                TargetRuntimeOutcome::Materialized(Box::new(signed)),
                ResponseEvidence::Materialized(Box::new(materialized.proof)),
            ));
        }
        let input = match step {
            TargetRuntimeStep::Start(i) => i.clone(),
            TargetRuntimeStep::Complete(q) | TargetRuntimeStep::PrepareComplete(q) => {
                TargetReplicaInput::Completion(q.clone())
            }
            TargetRuntimeStep::ResolveComplete(input) => {
                TargetReplicaInput::CompletionResolution(input.clone())
            }
            TargetRuntimeStep::MaintainBudget { quorum, input } => {
                TargetReplicaInput::ResolutionBudget {
                    quorum: quorum.clone(),
                    input: input.clone(),
                }
            }
            TargetRuntimeStep::Initialize(q)
            | TargetRuntimeStep::StartActivation { quorum: q, .. }
            | TargetRuntimeStep::Activate { quorum: q, .. } => {
                TargetReplicaInput::Quorum(q.clone())
            }
            TargetRuntimeStep::ConfirmActivation(signed) => {
                TargetReplicaInput::Quorum(TargetQuorumInput {
                    origin_sha256: signed.observation.completion.origin.digest()?,
                    materialized: signed.observation.completion.materialized.clone(),
                })
            }
            TargetRuntimeStep::ConfirmInspection(signed) => {
                TargetReplicaInput::Inspection(Box::new(signed.observation.input.clone()))
            }
            TargetRuntimeStep::Inspect(i) => TargetReplicaInput::Inspection(i.clone()),
            TargetRuntimeStep::InspectCompletionAttempt(i) => {
                TargetReplicaInput::CompletionAttemptStatus(i.clone())
            }
            TargetRuntimeStep::InspectCompletionResolution(i) => {
                TargetReplicaInput::CompletionTerminalStatus(i.clone())
            }
            _ => unreachable!(),
        };
        let first = input
            .quorum()
            .materialized
            .values()
            .next()
            .context("target materializations missing")?;
        self.placement(&first.fact.origin.input)?;
        if g.replica.is_none() {
            let replica = kasumi_engine::open_target_replica(
                op,
                stores.clone(),
                input.clone(),
                kasumi_engine::TargetReplicaConfig {
                    node_id: self.installed.node.node_id,
                    raft: kasumi_raft::Config::default(),
                    admission: self.admission.clone(),
                },
                self.cluster.clone(),
                self.audit.clone(),
            )
            .await?;
            let group = replica.database().raft_group();
            let name = format!("{}/{}", key.0, key.1);
            let check = stores.clone();
            self.cluster.register_group_with_bootstrap(
                name.clone(),
                group.raft().clone(),
                first.fact.origin.input.voters.keys().copied().collect(),
                first.fact.bootstrap_sha256.clone(),
                Arc::new(move || check.check_access()),
            )?;
            g.registered_group = Some(name);
            g.replica = Some(replica);
        }
        let replica = g.replica.as_ref().unwrap();
        match step {
            TargetRuntimeStep::Start(_) | TargetRuntimeStep::StartActivation { .. } => Ok((
                TargetRuntimeOutcome::Started {
                    origin_sha256: input.quorum().origin_sha256.clone(),
                },
                ResponseEvidence::Started(stores.clone()),
            )),
            TargetRuntimeStep::Initialize(_) => {
                replica.initialize(op).await?;
                Ok((
                    TargetRuntimeOutcome::Initialized {
                        origin_sha256: input.quorum().origin_sha256.clone(),
                    },
                    ResponseEvidence::Started(stores.clone()),
                ))
            }
            TargetRuntimeStep::Complete(q) => {
                let proof = replica.database().complete_target(op, q.clone()).await?;
                Ok((
                    TargetRuntimeOutcome::Completed(Box::new(
                        self.signer.sign_completed(&proof, op).await?,
                    )),
                    ResponseEvidence::Completed(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::PrepareComplete(input) => {
                let proof = replica
                    .database()
                    .prepare_target_completion(op, input.clone())
                    .await?;
                Ok((
                    TargetRuntimeOutcome::PreparedCompletion(Box::new(
                        self.signer.sign_completion_preparation(&proof, op).await?,
                    )),
                    ResponseEvidence::Receiver(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::InspectCompletionAttempt(input) => {
                let proof = replica
                    .database()
                    .inspect_target_completion_attempt(op, *input.clone())
                    .await?;
                let signed = self
                    .signer
                    .sign_completion_attempt_status(&proof, op)
                    .await?;
                Ok((
                    TargetRuntimeOutcome::CompletionAttemptStatus(Box::new(signed)),
                    ResponseEvidence::Receiver(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::InspectCompletionResolution(input) => {
                let proof = replica
                    .database()
                    .inspect_target_completion_terminal(op, *input.clone())
                    .await?;
                let signed = self
                    .signer
                    .sign_completion_terminal_status(&proof, op)
                    .await?;
                Ok((
                    TargetRuntimeOutcome::CompletionTerminalStatus(Box::new(signed)),
                    ResponseEvidence::Receiver(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::ResolveComplete(input) => {
                let proof = replica
                    .database()
                    .resolve_target_completion(op, *input.clone())
                    .await?;
                let signed = self.signer.sign_completion_resolution(&proof, op).await?;
                Ok((
                    TargetRuntimeOutcome::ResolvedCompletion(Box::new(signed)),
                    ResponseEvidence::Receiver(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::MaintainBudget { input, .. } => {
                let proof = replica
                    .database()
                    .maintain_target_resolution_budget(op, input.clone())
                    .await?;
                let signed = self.signer.sign_resolution_budget(&proof, op).await?;
                Ok((
                    TargetRuntimeOutcome::ResolutionBudget(Box::new(signed)),
                    ResponseEvidence::Receiver(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::ConfirmActivation(expected) => {
                let proof = replica
                    .database()
                    .confirm_target_activation(op, *expected.clone())
                    .await?;
                self.journal
                    .record_activation(op, &proof, &self.signer)
                    .await?;
                Ok((
                    TargetRuntimeOutcome::Activated(Box::new(
                        self.signer.sign_activated(&proof, op).await?,
                    )),
                    ResponseEvidence::Activated(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::ConfirmInspection(expected) => {
                let proof = replica
                    .database()
                    .confirm_target_inspection(op, *expected.clone())
                    .await?;
                self.journal
                    .record_inspected_activation(op, &proof, &self.signer)
                    .await?;
                Ok((
                    TargetRuntimeOutcome::Inspected(Box::new(
                        self.signer.sign_inspection(&proof, op).await?,
                    )),
                    ResponseEvidence::Inspected(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::Inspect(i) => {
                let proof = replica.database().inspect_target(op, *i.clone()).await?;
                if proof.observation().activation.is_some()
                    && proof.observation().input.original_phase.request.phase
                        == LifecyclePhase::Activate
                {
                    self.journal
                        .record_inspected_activation(op, &proof, &self.signer)
                        .await?;
                }
                Ok((
                    TargetRuntimeOutcome::Inspected(Box::new(
                        self.signer.sign_inspection(&proof, op).await?,
                    )),
                    ResponseEvidence::Inspected(Box::new(proof)),
                ))
            }
            TargetRuntimeStep::Activate {
                issuer_command_id, ..
            } => {
                let signed = op.run(phase.activation_receipt(*issuer_command_id)).await?;
                let proof = replica.database().activate_target(op, signed).await?;
                self.journal
                    .record_activation(op, &proof, &self.signer)
                    .await?;
                Ok((
                    TargetRuntimeOutcome::Activated(Box::new(
                        self.signer.sign_activated(&proof, op).await?,
                    )),
                    ResponseEvidence::Activated(Box::new(proof)),
                ))
            }
            _ => unreachable!(),
        }
    }
    fn placement(&self, input: &TargetMaterializationInput) -> Result<()> {
        let configured = self
            .config
            .replication
            .as_ref()
            .context("replication missing")?;
        ensure!(
            input.voters.len() == 3 && input.voters.keys().eq(configured.voters()?.iter()),
            "target voters differ from installed peer set"
        );
        for (id, p) in &input.voters {
            let expected = configured
                .peers
                .iter()
                .find(|p| p.node_id == *id)
                .context("uninstalled target peer")?;
            ensure!(
                p.endpoint == expected.endpoint && p.failure_domain == expected.failure_domain,
                "target placement differs from installed peer endpoint"
            );
        }
        Ok(())
    }
    async fn cleanup(
        &self,
        op: &TargetOperation,
        proof: &VerifiedTargetStop,
        key: &GenerationKey,
    ) -> Result<SignedLocalTargetCleanup> {
        op.check()?;
        self.journal.stop(op, proof)?;
        let path = self.path(key)?;
        if target_file_exists(&path)? {
            // Permanent journal stop and joined generation owners precede this
            // exact Prepared/Ready file claim. No KV engine or application keys open.
            let node = NodeStore::claim_cleanup(
                &path,
                self.generation_file_id(key)?,
                self.audit.store().persistent_disk().clone(),
            )?;
            ensure!(
                kasumi_store::private_files::file_identity(&path)? == *node.identity(),
                "target cleanup path changed after ownership"
            );
            op.check()?;
            node.delete()?;
        } else {
            // A path-based NotFound is only a hint. Verify it against the
            // installed, enrolled parent before signing an absence claim.
            target_absence_from_installed_disk(
                &self.config.persistent_disk,
                self.audit.store().persistent_disk(),
                &path,
            )?;
        }
        // Keep the same enrolled parent directory under physical ownership
        // through both exact unlink and the absent-file cleanup case.
        self.generation_directory.sync_all()?;
        op.check()?;
        self.journal.stop(op, proof)?;
        let intent = op
            .invocation()
            .gate()
            .current()?
            .commitment()
            .intent
            .clone();
        let fact = LocalTargetCleanupFact {
            intent,
            node_id: self.installed.node.node_id,
            stopped: proof.signed().clone(),
            stop_receipt_sha256: proof.observation().stop.digest()?,
            observed_at_ms: op.invocation().gate().admission_time_ms()?,
        };
        fact.validate()?;
        ensure!(
            fact.intent.request.target_nodes[&fact.node_id].attestation_public_key
                == hex::encode(self.cleanup_key.public_key().as_ref()),
            "cleanup key differs"
        );
        let signature = hex::encode(
            self.cleanup_key
                .sign(&serde_json::to_vec(&(
                    "kasumi.local-target-cleanup.v1",
                    &fact,
                ))?)
                .as_ref(),
        );
        op.check()?;
        Ok(SignedLocalTargetCleanup { fact, signature })
    }
    pub async fn shutdown(&self) -> DrainResult {
        let mut report = self.shutdown_gate.lock().await;
        let mut retained = None;
        self.closing.store(true, Ordering::Release);
        self.call_jobs.close();
        // RuntimeWorker returns only after its exact handle joins. Retain its
        // actual JoinError before waiting for any target or admitted call.
        if let Err(error) = self.serving_monitor.drain().await {
            report.merge(&error);
            if error.completion() == DrainCompletion::Retained {
                retained = Some(error);
            }
        }
        if retained.is_some() {
            return report.outcome(retained);
        }
        if let Err(error) = self.call_jobs.drain().await {
            report.merge(&error);
            if error.completion() == DrainCompletion::Retained {
                retained = Some(error);
            }
        }
        if retained.is_some() {
            return report.outcome(retained);
        }
        // A completed target child may have installed a generation after this
        // shutdown began. Census only after every exact child joins and every
        // claimed response releases its permit.
        let _all = match self.calls.clone().acquire_many_owned(MAX_CALLS).await {
            Ok(all) => all,
            Err(error) => {
                return Err(DrainFailure::retained(report.record(
                    "target admitted calls",
                    0,
                    error.into(),
                )));
            }
        };
        let targets = self
            .generations
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for target in &targets {
            if let Ok(g) = target.try_lock()
                && let Some(p) = &g.phase
            {
                p.close();
            }
        }
        for target in targets {
            if let Err(failure) = target
                .lock()
                .await
                .close(&self.cluster, &self.registry)
                .await
            {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        if let Err(failure) = self.journal.shutdown().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        if retained.is_none()
            && let Err(failure) = self.journal_node.shutdown().await
        {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        report.outcome(retained)
    }
}
// StopLocal resolves this exact path before it can claim or unlink a target
// inode. A retained managed-directory failure is a custody fence, not an
// absent-file observation from which cleanup evidence could be signed.
fn checked_generation_path(
    directory: &NodeDiskDirectory,
    installed_root: &Path,
    opened_root: &Path,
    key: &GenerationKey,
) -> Result<PathBuf> {
    directory.sync_all()?;
    ensure!(
        std::fs::canonicalize(installed_root)? == opened_root
            && !std::fs::symlink_metadata(installed_root)?
                .file_type()
                .is_symlink(),
        "installed target root changed"
    );
    // NodeDisk binds paths against the installed lexical accounting root.
    // Its canonical identity is checked above, but using it to construct the
    // file path can escape that binding (for example /var versus /private/var).
    let path = installed_root.join(format!("{}.{}.kv", digest(&key.0)?, key.1));
    target_file_exists(&path)?;
    Ok(path)
}

// A failed filesystem observation is not an absence proof. In particular,
// Path::exists must not turn permission/I/O failures into successful cleanup.
fn target_file_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "target file is not a regular installed path"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

// NodeDisk opens the final name relative to its verified, enrolled parent.
// Only its healthy NotFound is an absence proof. A path-only observation can
// instead see a transiently substituted root and mistake a retained file for
// absence. Keep the existing UnknownOutcome path for every uncertain result.
fn target_absence_from_installed_disk(
    config: &kasumi_store::NodeDiskConfig,
    disk: &Arc<kasumi_store::NodeDisk>,
    path: &Path,
) -> Result<()> {
    let (root, relative) = config.binding(path)?;
    match disk.open_file(root, relative) {
        Ok(mut file) => {
            file.close()?;
            anyhow::bail!("target storage remains under installed root")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Parent acquisition can also fail with NotFound after sealing the
            // disk. That error is never a successful leaf-absence observation.
            ensure!(
                disk.snapshot().phase == kasumi_store::NodeDiskPhase::Open,
                "target absence observation failed installed disk"
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn unknown(error: impl std::fmt::Display) -> anyhow::Error {
    let _ = error;
    Error::new(
        ErrorCode::UnknownOutcome,
        "target outcome unresolved; recover the exact committed identity",
    )
    .into()
}
