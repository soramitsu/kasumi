//! Owned target group startup. A disconnected caller cannot abandon Raft tasks:
//! the returned owner closes the original gate and joins actual storage users.
use super::*;
use crate::TargetOperation;
use kasumi_types::{LifecyclePhase, TargetQuorumInput, TargetReplicaInput};

pub struct TargetReplicaConfig {
    pub node_id: u64,
    pub raft: Config,
    pub admission: Arc<crate::admission::NodeAdmission>,
}
pub struct TargetReplica {
    database: Arc<Database>,
    bootstrap: ReplicatedBootstrap,
    input: TargetQuorumInput,
    invocation: crate::TargetLifecycleInvocation,
    registration: Option<crate::admission::WorkRegistration>,
    shutdown_runtime: tokio::runtime::Handle,
}
impl TargetReplica {
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }
    pub async fn close(mut self) -> anyhow::Result<()> {
        self.invocation.gate().close();
        let result = self.database.shutdown().await;
        self.registration.take();
        result
    }
    fn check(&self, operation: &TargetOperation, phase: LifecyclePhase) -> anyhow::Result<()> {
        operation.check()?;
        anyhow::ensure!(
            Arc::ptr_eq(self.invocation.gate(), operation.invocation().gate()),
            "target replica belongs to another original phase"
        );
        operation
            .invocation()
            .check_target(self.database.store(), phase)?;
        Ok(())
    }
    /// Only the designated member may initialize, after all three actual native
    /// materialization signatures have been verified. Existing membership must
    /// equal the installed peers; this does not reconfigure a live group.
    pub async fn initialize(&self, operation: &TargetOperation) -> anyhow::Result<()> {
        self.check(operation, LifecyclePhase::Initialize)?;
        let group = self.database.raft_group();
        let id = group.raft().metrics().borrow().id;
        anyhow::ensure!(
            Some(&id) == self.bootstrap.voters.keys().next(),
            "only the designated target voter may initialize"
        );
        let intent = operation
            .invocation()
            .gate()
            .current()?
            .commitment()
            .intent
            .clone();
        anyhow::ensure!(
            intent.request.phase_input_sha256 == self.input.digest()?,
            "target initialization input differs"
        );
        let initial = !operation
            .run(async { Ok(group.raft().is_initialized().await?) })
            .await?;
        if initial {
            // OpenRaft retains its own exact initialization intent. Caller
            // cancellation does not establish failure or authorize cleanup.
            operation
                .run(
                    group.initialize(
                        self.bootstrap
                            .voters
                            .iter()
                            .map(|(id, peer)| (*id, BasicNode::new(&peer.address)))
                            .collect(),
                    ),
                )
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorCode::UnknownOutcome,
                        "target initialization unresolved; observe exact membership",
                    )
                })?;
        }
        self.check(operation, LifecyclePhase::Initialize)?;
        let metrics = group.raft().metrics().borrow().clone();
        let expected: BTreeSet<_> = self.bootstrap.voters.keys().copied().collect();
        anyhow::ensure!(
            metrics.membership_config.membership().get_joint_config() == &vec![expected]
                && metrics.membership_config.membership().nodes().count()
                    == self.bootstrap.voters.len()
                && metrics
                    .membership_config
                    .membership()
                    .nodes()
                    .all(|(id, node)| self
                        .bootstrap
                        .voters
                        .get(id)
                        .is_some_and(|peer| peer.address == node.addr)),
            "target membership does not match initialized placement"
        );
        self.check(operation, LifecyclePhase::Initialize)
    }
}
impl Drop for TargetReplica {
    fn drop(&mut self) {
        self.invocation.gate().close();
        let Some(registration) = self.registration.take() else {
            return;
        };
        let database = self.database.clone();
        self.shutdown_runtime.spawn(async move {
            let _registration = registration;
            let _ = database.shutdown().await;
        });
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InitialTargetIntent {
    origin: TargetOrigin,
    intent: LifecycleIntent,
    input: TargetQuorumInput,
}
/// Opens only a previously published exact target image. No bootstrap or
/// application key is synthesized on missing state, and no membership starts
/// until the caller has registered the returned peer and invokes initialize.
#[allow(clippy::too_many_arguments)]
pub async fn open_target_replica(
    operation: &TargetOperation,
    stores: Arc<TenantStorageSet>,
    input: TargetReplicaInput,
    config: TargetReplicaConfig,
    transport: Arc<dyn RaftTransport>,
    security_audit: Arc<SecurityAudit>,
) -> anyhow::Result<TargetReplica> {
    security_audit.require_admission(&config.admission)?;
    operation.check()?;
    let invocation = operation.invocation().clone();
    let lease = invocation.gate().current()?;
    let intent = lease.commitment().intent.clone();
    let phase = intent.request.phase;
    anyhow::ensure!(
        matches!(
            phase,
            LifecyclePhase::Initialize
                | LifecyclePhase::Complete
                | LifecyclePhase::Activate
                | LifecyclePhase::InspectTarget
        ) && config.node_id == lease.signed().claims.request.target_node.node_id,
        "target group startup phase or node differs"
    );
    invocation.check_target(stores.application(), phase)?;
    // This worker owns the original operation through actual startup. A closed
    // receiver drops TargetReplica, whose owner joins its real Raft workers.
    let owned = operation.clone();
    let task = tokio::spawn(async move {
        let _gate = owned.run(async { Ok(BOOTSTRAP_GATE.lock().await) }).await?;
        owned.check()?;
        let manifest_bytes = stores
            .application()
            .get_bounded(NS, b"manifest", 64 << 10)?
            .ok_or_else(|| anyhow::anyhow!("published target bootstrap missing"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        anyhow::ensure!(
            manifest.format == 2
                && manifest.bytes > 0
                && manifest.chunks == manifest.bytes.div_ceil(CHUNK as u64),
            "target bootstrap exceeds bound"
        );
        let workspace = Arc::new(config.admission.reserve(
            recovery_workspace_bytes(&stores)?,
            Some(owned.token.clone()),
        )?);
        let material = stores.clone();
        let authority = owned.invocation().clone();
        let verification = owned.clone();
        let input_copy = input.quorum().clone();
        let requested_input = input.clone();
        let (engine, bootstrap) = owned
            .run(
                owned
                    .deadline
                    .blocking(workspace, Some(owned.work.clone()), move || {
                        authority.check_target(material.application(), phase)?;
                        let bytes = load(material.application())?
                            .ok_or_else(|| anyhow::anyhow!("target image missing"))?;
                        validate_bootstrap_control(&material, &bytes)?;
                        let engine = Arc::new(TenantEngine::from_bootstrap(
                            material.application().tenant(),
                            &bytes,
                        )?);
                        let generation = engine.generation()?;
                        let origin = generation
                            .state
                            .target_lifecycle
                            .get(&generation.state.incarnation)
                            .ok_or_else(|| anyhow::anyhow!("target image lacks native origin"))?
                            .origin
                            .clone();
                        origin.accepts_phase(&intent, phase)?;
                        match &requested_input {
                            TargetReplicaInput::Inspection(inspection) => {
                                inspection.validate(&origin, &intent)?;
                            }
                            TargetReplicaInput::Quorum(_) => anyhow::ensure!(
                                phase != LifecyclePhase::InspectTarget,
                                "inspection requires exact original phase input"
                            ),
                        }
                        anyhow::ensure!(
                            origin.digest()? == input_copy.origin_sha256
                                && (matches!(
                                    phase,
                                    LifecyclePhase::Activate | LifecyclePhase::InspectTarget
                                ) || input_copy.digest()? == intent.request.phase_input_sha256),
                            "target group phase input differs"
                        );
                        let expected = kasumi_serving::verify_target_materializations(
                            &origin,
                            &input_copy.materialized,
                        )?;
                        anyhow::ensure!(
                            expected == bytes.sha256(),
                            "target physical bootstrap differs from signed materializations"
                        );
                        let encoded = material
                            .custody()
                            .store()
                            .get_bounded("engine.deployment", b"mode", 256 << 10)?
                            .ok_or_else(|| anyhow::anyhow!("target deployment binding absent"))?;
                        let (mode, bootstrap): (String, ReplicatedBootstrap) =
                            serde_json::from_slice(&encoded)?;
                        bootstrap.validate()?;
                        anyhow::ensure!(
                            mode == "replicated"
                                && bootstrap.incarnation == generation.state.incarnation,
                            "target deployment is not exact replicated generation"
                        );
                        let prior = material.custody().store().get_bounded(
                            "target.lifecycle",
                            b"initialize",
                            256 << 10,
                        )?;
                        if phase == LifecyclePhase::Initialize {
                            let requested = InitialTargetIntent {
                                origin,
                                intent,
                                input: input_copy,
                            };
                            if let Some(prior) = prior {
                                anyhow::ensure!(
                                    serde_json::from_slice::<InitialTargetIntent>(&prior)?
                                        == requested,
                                    "target initialization identity already bound"
                                );
                            } else {
                                authority.check_target(material.application(), phase)?;
                                material.custody().store().write_batch(&[WriteOp::put(
                                    "target.lifecycle",
                                    b"initialize",
                                    serde_json::to_vec(&requested)?,
                                )])?;
                            }
                        } else {
                            let initialized: InitialTargetIntent =
                                serde_json::from_slice(&prior.ok_or_else(|| {
                                    anyhow::anyhow!("target initialization intent missing")
                                })?)?;
                            anyhow::ensure!(
                                initialized.origin == origin && initialized.input == input_copy,
                                "target initialization origin or quorum inputs differ"
                            );
                            initialized
                                .origin
                                .accepts_phase(&initialized.intent, LifecyclePhase::Initialize)?;
                        }
                        drop(generation);
                        engine.install_storage_access(material.application())?;
                        engine.verify_bootstrap_dependencies_checked(|| verification.check())?;
                        authority.check_target(material.application(), phase)?;
                        Ok((engine, bootstrap))
                    }),
            )
            .await?;
        owned.check()?;
        // Do not cancel this future: if its caller disappears, ownership stays
        // here until open returns and the target owner closes any started group.
        let registration = owned.register_group()?;
        engine.install_audit_maintenance(&config.admission)?;
        let group = RaftGroup::open(
            config.node_id,
            format!(
                "{}/{}",
                stores.application().tenant(),
                bootstrap.incarnation
            ),
            stores.clone(),
            engine.clone(),
            transport,
            config.raft,
        )
        .await?;
        let database = Database::new_with_admission(
            engine,
            group,
            stores.application().clone(),
            config.admission,
            security_audit,
        );
        let owner = TargetReplica {
            database,
            bootstrap,
            input: input.quorum().clone(),
            invocation,
            registration: Some(registration),
            shutdown_runtime: tokio::runtime::Handle::current(),
        };
        owned.check()?;
        Ok::<_, anyhow::Error>(owner)
    });
    operation.run(async { task.await? }).await
}
