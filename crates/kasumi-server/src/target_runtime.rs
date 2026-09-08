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
use kasumi_store::{BackupDestination, NodeStore, StorageAccess, TenantStorageSet, TenantStore};
use kasumi_types::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;
use zeroize::Zeroizing;
const MAX_CALLS: u32 = 64;
type GenerationKey = (String, Uuid);
#[path = "target_serving_runtime.rs"]
mod serving;
#[derive(Default)]
struct Generation {
    custody: Option<(GenerationKey, Arc<kasumi_engine::RetiredCustody>)>,
    custody_probe: Option<Arc<kasumi_store::CustodyStore>>,
    serving: Option<kasumi_engine::TargetServingReplica>,
    lease: Option<Arc<crate::serving_runtime::RuntimeLease>>,
    registered_data: Option<(GenerationKey, Arc<kasumi_engine::Database>)>,
    phase: Option<Arc<RuntimeTargetPhase>>,
    node: Option<Arc<NodeStore>>,
    stores: Option<Arc<TenantStorageSet>>,
    replica: Option<TargetReplica>,
    registered_group: Option<String>,
}
impl Generation {
    async fn close(
        &mut self,
        cluster: &ClusterNetwork,
        registry: &crate::api::DatabaseRegistry,
    ) -> Result<()> {
        if let Some((key, database)) = &self.registered_data {
            serving::detach_owned_data(registry, key, database)?;
            self.registered_data = None;
        }
        if let Some((key, custody)) = &self.custody {
            registry.detach_target_custody(&key.0, &key.1.to_string(), custody)?;
        }
        if let Some(lease) = &self.lease {
            lease.gate().close();
        }
        if let Some(phase) = &self.phase {
            phase.scope().close();
        }
        if let Some(group) = &self.registered_group {
            cluster.unregister_group(group)?;
            self.registered_group = None;
        }
        if let Some((_, custody)) = self.custody.take() {
            custody.shutdown().await?;
        }
        if let Some(probe) = self.custody_probe.take() {
            probe.store().shutdown().await;
        }
        if let Some(serving) = self.serving.take() {
            serving.close().await?;
        }
        if let Some(replica) = self.replica.take() {
            replica.close().await?;
        }
        if let Some(phase) = self.phase.take() {
            phase.scope().drain().await;
        }
        self.stores.take();
        self.lease.take();
        if let Some(node) = self.node.take() {
            match Arc::try_unwrap(node) {
                Ok(node) => drop(node),
                Err(node) => {
                    self.node = Some(node);
                    anyhow::bail!("target file still has an actual detached owner")
                }
            }
        }
        Ok(())
    }
}
enum ResponseEvidence {
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
            ResponseEvidence::Completed(p) => p.release(&self.operation).await?,
            ResponseEvidence::Activated(p) => p.release(&self.operation).await?,
            ResponseEvidence::Inspected(p) => p.release(&self.operation).await?,
            ResponseEvidence::Started(db) => {
                db.check_access()?;
                self.operation.check()?;
            }
            ResponseEvidence::Stopped(stop, key) => {
                self.runtime.journal.stop(&self.operation, stop)?;
                ensure!(
                    !self.runtime.path(key)?.exists(),
                    "target storage reappeared after stop"
                );
            }
        }
        self.operation.check()?;
        Ok(())
    }
}
pub struct TargetRecoveryRuntime {
    recovery_health: std::sync::Mutex<serving::RecoveryHealth>,
    registry: crate::api::DatabaseRegistry,
    serving_monitor: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    config: RuntimeConfig,
    installed: TargetRecoveryConfig,
    credential: CredentialSource,
    journal: Arc<TargetJournal>,
    signer: TargetSigner,
    cleanup_key: Ed25519KeyPair,
    admission: Arc<NodeAdmission>,
    audit: Arc<SecurityAudit>,
    cluster: Arc<ClusterNetwork>,
    destinations: BTreeMap<String, Arc<dyn BackupDestination>>,
    root: PathBuf,
    generations: Mutex<BTreeMap<GenerationKey, Arc<Mutex<Generation>>>>,
    calls: Arc<Semaphore>,
    closing: AtomicBool,
}
impl TargetRecoveryRuntime {
    pub(crate) async fn open(
        config: RuntimeConfig,
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
        let key = read_private_file(&installed.attestation_key, 1 << 20)?;
        let signer = TargetSigner::from_pkcs8(installed.node.clone(), &key)?;
        let cleanup_key =
            Ed25519KeyPair::from_pkcs8(&key).map_err(|_| anyhow::anyhow!("invalid target key"))?;
        // Only the independent journal KMS provider is constructed at startup.
        let provider = installed.journal_keys.provider(credential.clone())?;
        let node = NodeStore::open(&installed.journal_path)?;
        let access = StorageAccess::target_journal(&installed.control_root, &installed.node)?;
        let store = TenantStore::open(
            node,
            format!(
                "kasumi.target.{}.{}",
                installed.control_root.control_incarnation, installed.node.node_id
            ),
            provider,
            access,
        )
        .await?;
        let journal = TargetJournal::open(
            store,
            TargetJournalInstallation {
                root: installed.control_root.clone(),
                node: installed.node.clone(),
            },
            installed.limits.journal.clone(),
            admission.clone(),
        )?;
        std::fs::create_dir_all(&installed.generation_root)?;
        ensure!(
            !std::fs::symlink_metadata(&installed.generation_root)?
                .file_type()
                .is_symlink(),
            "target root cannot be a symlink"
        );
        let root = std::fs::canonicalize(&installed.generation_root)?;
        std::fs::File::open(&root)?.sync_all()?;
        let runtime = Arc::new(Self {
            recovery_health: std::sync::Mutex::new(serving::RecoveryHealth::new()),
            registry,
            serving_monitor: std::sync::Mutex::new(None),
            config,
            installed,
            credential,
            journal,
            signer,
            cleanup_key,
            admission,
            audit,
            cluster,
            destinations,
            root,
            generations: Mutex::new(BTreeMap::new()),
            calls: Arc::new(Semaphore::new(MAX_CALLS as usize)),
            closing: AtomicBool::new(false),
        });
        runtime.start_serving_reconciliation();
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
        let admission = TargetRequestAdmission::capture(
            context.clone(),
            self.installed.limits.operation_timeout_ms,
        )?;
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
        let timeout = self.installed.limits.operation_timeout_ms;
        let task = tokio::spawn(async move {
            let mut reply = this
                .execute_owned(context, bearer, request, admission)
                .await?;
            reply.permit = Some(permit);
            Ok::<_, anyhow::Error>(reply)
        });
        // A timeout/disconnect drops only the waiter. The task retains the call
        // permit, generation lock and actual engine work until effects finish.
        await_target_task(Duration::from_millis(timeout), task).await
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
                .run(generation.close(&self.cluster, &self.registry))
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
            drop(phase);
            old
        } else {
            admission
                .run(generation.close(&self.cluster, &self.registry))
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
                .run(generation.close(&self.cluster, &self.registry))
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
            TargetRuntimeStep::Materialize(input) => {
                input.validate(&phase.original().observation().intent)?;
                (LifecyclePhase::Materialize, input.digest()?)
            }
            TargetRuntimeStep::Start(input) => match input {
                TargetReplicaInput::Inspection(i) => (LifecyclePhase::InspectTarget, i.digest()?),
                TargetReplicaInput::Quorum(q) => {
                    let p = phase.original().observation().intent.request.phase;
                    ensure!(
                        matches!(p, LifecyclePhase::Initialize | LifecyclePhase::Complete),
                        "start cannot synthesize activation"
                    );
                    (p, q.digest()?)
                }
            },
            TargetRuntimeStep::Initialize(q) => (LifecyclePhase::Initialize, q.digest()?),
            TargetRuntimeStep::Complete(q) => (LifecyclePhase::Complete, q.digest()?),
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
            TargetRuntimeStep::Activate {
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
                        completion_sha256: control.completion.observation.fact.digest()?,
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
    fn path(&self, key: &GenerationKey) -> Result<PathBuf> {
        ensure!(
            std::fs::canonicalize(&self.installed.generation_root)? == self.root
                && !std::fs::symlink_metadata(&self.installed.generation_root)?
                    .file_type()
                    .is_symlink(),
            "installed target root changed"
        );
        let path = self
            .root
            .join(format!("{}.{}.redb", digest(&key.0)?, key.1));
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "target file is not a regular installed path"
            );
        }
        Ok(path)
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
            g.node = Some(NodeStore::open(self.path(&key)?)?);
            op.check()?;
        }
        if g.stores.is_none() {
            op.check()?;
            let app = template
                .application_keys
                .provider(self.credential.clone())?;
            let custody = template.custody_keys.provider(self.credential.clone())?;
            g.stores = Some(
                op.run(TenantStorageSet::open(
                    g.node.as_ref().unwrap().clone(),
                    key.0.clone(),
                    app,
                    custody,
                    phase.access()?,
                ))
                .await?,
            );
        }
        let stores = g.stores.as_ref().unwrap().clone();
        if let TargetRuntimeStep::Materialize(input) = step {
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
            let materialized = kasumi_engine::materialize_target_replica(
                op,
                &source,
                stores,
                input.clone(),
                kasumi_engine::TargetMaterializationConfig {
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
                },
                self.audit.clone(),
            )
            .await?;
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
            TargetRuntimeStep::Initialize(q)
            | TargetRuntimeStep::Complete(q)
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
            TargetRuntimeStep::Start(_) => Ok((
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
        if path.exists() {
            // An exclusive redb owner proves no other process owns the file;
            // no application provider/key is constructed by this closed path.
            let node = NodeStore::open(&path)?;
            let node = Arc::try_unwrap(node)
                .map_err(|_| anyhow::anyhow!("target file has another owner"))?;
            op.check()?;
            std::fs::remove_file(&path)?;
            std::fs::File::open(&self.root)?.sync_all()?;
            drop(node);
        } else {
            std::fs::File::open(&self.root)?.sync_all()?;
        }
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
    pub async fn shutdown(&self) -> Result<()> {
        self.closing.store(true, Ordering::Release);
        let monitor = self
            .serving_monitor
            .lock()
            .map_err(|_| anyhow::anyhow!("target monitor poisoned"))?
            .take();
        if let Some(monitor) = monitor {
            monitor.await?;
        }
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
                p.scope().close();
            }
        }
        let _all = self.calls.clone().acquire_many_owned(MAX_CALLS).await?;
        for target in targets {
            target
                .lock()
                .await
                .close(&self.cluster, &self.registry)
                .await?;
        }
        Ok(())
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

async fn await_target_task<T>(
    timeout: Duration,
    task: tokio::task::JoinHandle<Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, task)
        .await
        .map_err(unknown)?
        .map_err(unknown)?
}
#[cfg(test)]
mod outcome_tests {
    use super::*;
    #[tokio::test]
    async fn panic_and_abort_after_dispatch_are_unknown_but_inner_rejection_is_preserved() {
        let published = Arc::new(AtomicBool::new(false));
        let marker = published.clone();
        let task = tokio::spawn(async move {
            marker.store(true, Ordering::Release);
            panic!("worker lost after publication");
            #[allow(unreachable_code)]
            Ok(())
        });
        let error = await_target_task(Duration::from_secs(1), task)
            .await
            .unwrap_err();
        assert!(published.load(Ordering::Acquire));
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        let task = tokio::spawn(async { std::future::pending::<Result<()>>().await });
        task.abort();
        let error = await_target_task(Duration::from_secs(1), task)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        let task = tokio::spawn(async {
            Err::<(), _>(Error::new(ErrorCode::Forbidden, "definite ordered rejection").into())
        });
        let error = await_target_task(Duration::from_secs(1), task)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::Forbidden
        );
    }
    #[tokio::test]
    async fn timed_out_waiter_keeps_actual_worker_admission_owned_until_completion() {
        let capacity = Arc::new(Semaphore::new(1));
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let (finish, completion) = tokio::sync::oneshot::channel();
        let (done, completed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _permit = permit;
            completion.await?;
            let _ = done.send(());
            Ok::<_, anyhow::Error>(())
        });
        let error = await_target_task(Duration::from_millis(1), task)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().code,
            ErrorCode::UnknownOutcome
        );
        assert_eq!(capacity.available_permits(), 0);
        finish.send(()).unwrap();
        completed.await.unwrap();
        let _permit = tokio::time::timeout(Duration::from_secs(1), capacity.acquire())
            .await
            .unwrap()
            .unwrap();
    }
}
