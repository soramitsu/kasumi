//! Actual encrypted graph/materialization tests with a real three-voter issuer.
//! ControlFixture signs explicit input fixtures here; native Control-quorum
//! issuance is covered separately by the server lifecycle end-to-end tests.
use super::*;
use kasumi_engine::{
    RestoreSource, TargetLifecycleInvocation, TargetMaterializationConfig, TargetOperation,
    TargetOperationScope, TargetReplicaConfig, TargetSigner, materialize_target_replica,
    open_target_replica, resume_target_materialization,
};
use kasumi_store::{FilesystemBackupDestination, StorageAccess, TenantStorageSet, TenantStore};

async fn audit(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    existing: bool,
) -> Arc<kasumi_engine::SecurityAudit> {
    let provider = Arc::new(LocalKeyProvider::new([0xa7; 32]));
    let store = if existing {
        TenantStore::open_existing_fixture(node, kasumi_engine::SECURITY_TENANT.into(), provider)
            .await
    } else {
        TenantStore::open_fixture(node, kasumi_engine::SECURITY_TENANT.into(), provider).await
    }
    .unwrap();
    // These stores model distinct processes. Audit and database on each node
    // share one admission governor, rather than the test-process fallback.
    if existing {
        kasumi_engine::SecurityAudit::open(store, Default::default(), admission)
    } else {
        kasumi_engine::SecurityAudit::initialize(store, Default::default(), admission)
    }
    .unwrap()
}
struct MaterialFixture {
    issuer: Fixture,
    control: ControlFixture,
    target: RecoveryTarget,
    source: RestoreSource,
    input: TargetMaterializationInput,
    intent: SignedControlIntent,
    signers: BTreeMap<u64, TargetSigner>,
    admissions: BTreeMap<u64, Arc<kasumi_engine::admission::NodeAdmission>>,
    target_files: std::sync::Mutex<BTreeSet<u64>>,
}
impl MaterialFixture {
    async fn new() -> Self {
        let control = ControlFixture::new();
        let issuer = control.issuer().await;
        let node = NodeStore::create_new(
            issuer._dir.path().join("source.redb"),
            Uuid::new_v4(),
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let source_admission =
            kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap();
        let security = audit(node.clone(), source_admission.clone(), false).await;
        let sourcekey = Arc::new(LocalKeyProvider::new([51; 32]));
        let app = TenantStore::open_fixture(node, "city".into(), sourcekey.clone())
            .await
            .unwrap();
        let stores =
            kasumi_store::test_utils::with_custody(app, Arc::new(LocalKeyProvider::new([211; 32])))
                .await
                .unwrap();
        let context = RequestContext {
            tenant: "city".into(),
            principal: "source-owner".into(),
            request_id: "backup".into(),
            scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            authorization: RequestAuthorization::service_identity(),
        };
        let source_db = kasumi_engine::open_local(
            stores,
            Policy {
                grants: vec![Grant {
                    principal: context.principal.clone(),
                    collection: None,
                    actions: context.scopes.clone(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
            security.clone(),
        )
        .await
        .unwrap();
        source_db.install_admission(source_admission).unwrap();
        source_db
            .administer(
                context.clone(),
                Operation::CreateCollection(CollectionDefinition {
                    name: "history".into(),
                    schema: serde_json::json!({"type":"object"}),
                    indexes: vec![],
                    write_mode: CollectionWriteMode::AppendOnly,
                    retention_class: CollectionRetentionClass::Operational,
                    strict_read_audit: false,
                }),
            )
            .await
            .unwrap();
        source_db
            .mutate(
                context.clone(),
                MutationBatch {
                    idempotency_key: "original-history".into(),
                    read_set: vec![],
                    operations: vec![Mutation::Put {
                        collection: "history".into(),
                        id: "immutable".into(),
                        expected: Precondition::Absent,
                        body: serde_json::json!({"source":"unchanged"}),
                    }],
                },
            )
            .await
            .unwrap();
        let destination = Arc::new(
            FilesystemBackupDestination::new(issuer._dir.path().join("backups"), 16 << 20).unwrap(),
        );
        let checkpoint = source_db
            .backup_checkpoint(context, destination.as_ref(), uuid::Uuid::new_v4())
            .await
            .unwrap();
        let target = RecoveryTarget {
            incarnation: Uuid::new_v4(),
            nodes: nodes(),
            checkpoint: checkpoint.checkpoint().clone(),
        };
        source_db.shutdown().await.unwrap();
        drop(source_db);
        security.shutdown().await;
        drop(security);
        let source_id = Uuid::parse_str(&target.checkpoint.source_incarnation).unwrap();
        super::activation_gate_tests::exact_administrative(
            &issuer,
            issuer.command(AuthorityAction::Enroll {
                incarnation: source_id,
                nodes: nodes(),
            }),
        )
        .await;
        super::activation_gate_tests::exact_administrative(
            &issuer,
            issuer.command(AuthorityAction::PrepareTarget {
                source_incarnation: source_id,
                source_epoch: 1,
                target: target.clone(),
            }),
        )
        .await;
        let input = TargetMaterializationInput {
            destination_alias: "target-backups".into(),
            backup_id: target.checkpoint.backup_id,
            source_purpose_sha256: digest(&kasumi_store::StoragePurpose::LocalFixture).unwrap(),
            target_incarnation: target.incarnation,
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        TargetPeer {
                            endpoint: format!("target-{id}"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        };
        let mut intent = control.intent(&issuer, &target, 1_500_000);
        intent.observation.intent.request.phase_input_sha256 = input.digest().unwrap();
        let mut signers = BTreeMap::new();
        for n in nodes() {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            intent
                .observation
                .intent
                .request
                .target_nodes
                .get_mut(&n.node_id)
                .unwrap()
                .attestation_public_key = hex::encode(pair.public_key().as_ref());
            signers.insert(
                n.node_id,
                TargetSigner::from_pkcs8(n, pkcs8.as_ref()).unwrap(),
            );
        }
        intent.observation.intent.request_sha256 =
            digest(&intent.observation.intent.request).unwrap();
        control.sign_intent(&mut intent);
        accepted_on_current_leader(&issuer, request(&intent)).await;
        Self {
            issuer,
            control,
            target,
            source: RestoreSource {
                destination_alias: input.destination_alias.clone(),
                destination,
                keys: sourcekey,
                timeout_ms: 60_000,
            },
            input,
            intent,
            signers,
            target_files: Default::default(),
            admissions: (1..=3)
                .map(|id| {
                    (
                        id,
                        kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
                    )
                })
                .collect(),
        }
    }
    async fn phase(
        &self,
        id: u64,
        intent: &SignedControlIntent,
    ) -> (
        Arc<TargetOperationScope>,
        Arc<TenantStorageSet>,
        Arc<kasumi_engine::SecurityAudit>,
    ) {
        let issuer = self.issuer.leader().await;
        let trust = self.issuer.trust_for(id);
        let node_identity = nodes().into_iter().find(|n| n.node_id == id).unwrap();
        let node_store_id = kasumi_store::node_store_ids::target_generation(
            self.control.root.control_incarnation,
            "city",
            self.target.incarnation,
            &node_identity.verifier,
        )
        .unwrap();
        let node_context = AuthenticatedNode::from_verified_transport(
            self.issuer.context(&node_identity.principal),
            node_identity.certificate_sha256.clone(),
        )
        .unwrap();
        let mut serving = ServingBoot::with_test_clock(
            trust.clone(),
            ServingIdentity {
                tenant: "city".into(),
                incarnation: self.target.incarnation,
                authority_epoch: 2,
                node: node_identity.clone(),
            },
            self.issuer.clock.clone(),
        )
        .unwrap();
        if intent.observation.intent.request.phase != LifecyclePhase::Activate {
            serving = serving.for_restore_preparation();
        }
        let attempt = serving.begin_acquisition().unwrap();
        let lease = issuer
            .acquire(
                AuthenticatedNode::from_verified_transport(
                    self.issuer.context(&node_identity.principal),
                    node_identity.certificate_sha256.clone(),
                )
                .unwrap(),
                attempt.request().clone(),
            )
            .await
            .unwrap()
            .0;
        let serving = ServingGate::new(attempt.verify(lease).unwrap()).unwrap();
        let verified = ControlTrust::install(self.control.root.clone())
            .unwrap()
            .verify_intent(intent)
            .unwrap();
        let boot =
            LifecycleBoot::with_clock(trust, node_identity, self.issuer.clock.clone()).unwrap();
        let attempt = boot.begin(&verified).unwrap();
        let lease = issuer
            .acquire_lifecycle(node_context, attempt.request().clone())
            .await
            .unwrap()
            .0;
        let gate = LifecycleGate::with_test_clock(
            super::activation_gate_tests::original_control(
                &self.issuer,
                &self.control,
                intent.observation.intent.original_credential_expires_at_ms,
            ),
            attempt.verify(lease).unwrap(),
            self.issuer.epoch.clone(),
        )
        .unwrap();
        let scope = TargetOperationScope::new(
            TargetLifecycleInvocation::from_verified(gate.clone()).unwrap(),
        )
        .unwrap();
        // Production runner obtains this original operation before providers.
        // The helper's actual opener is under the same opaque gate; each tested
        // materialization still explicitly obtains its registered operation.
        let first_creation = self.target_files.lock().unwrap().insert(id);
        let node = {
            let path = self.issuer._dir.path().join(format!("target-{id}.redb"));
            if first_creation {
                NodeStore::create_new(path, node_store_id, kasumi_store::ScratchDisk::fixture())
            } else {
                NodeStore::open_existing(path, node_store_id, kasumi_store::ScratchDisk::fixture())
            }
            .unwrap()
        };
        let security = audit(node.clone(), self.admissions[&id].clone(), !first_creation).await;
        let stores = if first_creation {
            TenantStorageSet::initialize_catalogs(
                node,
                "city".into(),
                Arc::new(LocalKeyProvider::new([61; 32])),
                Arc::new(LocalKeyProvider::new([221; 32])),
                StorageAccess::target_phase(serving, gate).unwrap(),
            )
            .await
        } else {
            TenantStorageSet::open_existing(
                node,
                "city".into(),
                Arc::new(LocalKeyProvider::new([61; 32])),
                Arc::new(LocalKeyProvider::new([221; 32])),
                StorageAccess::target_phase(serving, gate).unwrap(),
            )
            .await
        }
        .unwrap();
        (scope, stores, security)
    }
    fn config(&self, id: u64) -> TargetMaterializationConfig {
        TargetMaterializationConfig {
            node_id: id,
            incarnation: self.target.incarnation,
            voters: self
                .input
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
            admission: self.admissions[&id].clone(),
        }
    }
    async fn close(self) {
        self.issuer.close().await;
    }
}
#[tokio::test]
async fn actual_target_materialization_preserves_image_and_original_operation_fence() {
    let f = MaterialFixture::new().await;
    let (scope, stores, audit) = f.phase(1, &f.intent).await;
    let early =
        kasumi_engine::TargetRequestAdmission::capture(scope.invocation().context().clone(), 1)
            .unwrap();
    // Native request admission precedes remote acquisition. Expiry before
    // acquiring the phase cannot be replaced with a later operation timeout.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(scope.begin_admitted(early).is_err());
    assert!(
        stores
            .application()
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    let original = scope.invocation().context();
    let mut different =
        super::activation_gate_tests::original_control(&f.issuer, &f.control, 1_500_000);
    different.request_id = original.request_id.clone();
    assert_eq!(different, *original);
    let substituted = kasumi_engine::TargetRequestAdmission::capture(different, 60_000).unwrap();
    assert!(scope.begin_admitted(substituted).is_err());
    let operation = scope.begin_operation(60_000).unwrap();
    let materialized = materialize_target_replica(
        &operation,
        &f.source,
        stores.clone(),
        f.input.clone(),
        f.config(1),
        audit.clone(),
    )
    .await
    .unwrap();
    assert!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"node_id")
            .unwrap()
            .is_none()
    );
    let proof = f.signers[&1]
        .sign_materialized(&materialized.proof, &operation)
        .await
        .unwrap();
    assert_eq!(
        proof.fact.origin.materialization.request.checkpoint,
        f.target.checkpoint
    );
    assert_eq!(proof.fact.revision_base, f.target.checkpoint.revision + 1);
    drop(operation);
    let followup = super::activation_gate_tests::original_control(&f.issuer, &f.control, 1_500_000);
    let fresh = scope
        .begin_followup(
            kasumi_engine::TargetRequestAdmission::capture(followup.clone(), 60_000).unwrap(),
        )
        .unwrap();
    assert!(
        fresh
            .context()
            .authorization
            .same_live_invocation(&followup.authorization)
    );
    assert!(
        !fresh
            .context()
            .authorization
            .same_live_invocation(&scope.invocation().context().authorization)
    );
    assert!(materialized.proof.release(&fresh).await.is_err());
    assert!(
        f.signers[&1]
            .sign_materialized(&materialized.proof, &fresh)
            .await
            .is_err()
    );
    let retried = materialize_target_replica(
        &fresh,
        &f.source,
        stores.clone(),
        f.input.clone(),
        f.config(1),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.signers[&1]
            .sign_materialized(&retried.proof, &fresh)
            .await
            .unwrap(),
        proof
    );
    let wrong = TargetSigner::from_pkcs8(
        nodes().first().unwrap().clone(),
        Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    assert!(
        wrong
            .sign_materialized(&retried.proof, &fresh)
            .await
            .is_err()
    );
    drop(retried);
    drop(materialized);
    drop(fresh);
    scope.close();
    scope.drain().await;
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    audit.shutdown().await;
    drop(audit);
    f.close().await;
}

#[tokio::test]
async fn fresh_materialization_admission_preserves_expired_origin_and_exact_published_image() {
    let mut f = MaterialFixture::new().await;
    // The short original grant is an explicit signed fixture; retained-origin
    // validation by an actual Control quorum is covered in engine/lifecycle.
    f.intent.observation.intent.request.command_id = Uuid::new_v4();
    f.intent
        .observation
        .intent
        .original_credential_expires_at_ms = 1_000_500;
    f.intent.observation.intent.request_sha256 =
        digest(&f.intent.observation.intent.request).unwrap();
    f.control.sign_intent(&mut f.intent);
    accepted_on_current_leader(&f.issuer, request(&f.intent)).await;
    let (scope, stores, audit) = f.phase(1, &f.intent).await;
    let operation = scope.begin_operation(60_000).unwrap();
    let result = materialize_target_replica(
        &operation,
        &f.source,
        stores.clone(),
        f.input.clone(),
        f.config(1),
        audit.clone(),
    )
    .await
    .unwrap();
    let original = f.signers[&1]
        .sign_materialized(&result.proof, &operation)
        .await
        .unwrap();
    let origin = original.fact.origin.clone();
    f.issuer.clock.0.store(600, Ordering::SeqCst);
    assert!(operation.check().is_err());
    assert!(result.proof.release(&operation).await.is_err());
    drop(result);
    drop(operation);
    scope.close();
    scope.drain().await;
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    audit.shutdown().await;
    drop(audit);

    let mut resume = f.intent.clone();
    let next = &mut resume.observation.intent;
    next.request.command_id = Uuid::new_v4();
    next.request.phase = LifecyclePhase::ResumeMaterialize;
    next.request.phase_input_sha256 = origin.resume_digest().unwrap();
    next.request.resume_origin = Some(Box::new(origin.clone()));
    next.request_sha256 = digest(&next.request).unwrap();
    next.accepted_at_ms = 1_000_600;
    next.original_credential_expires_at_ms = 1_500_000;
    next.revision += 1;
    resume.observation.observed_revision = next.revision;
    f.control.sign_intent(&mut resume);
    accepted_on_current_leader(&f.issuer, request(&resume)).await;
    let mut materialized = BTreeMap::new();
    for id in 1..=3 {
        let (scope, stores, audit) = f.phase(id, &resume).await;
        let operation = scope.begin_operation(60_000).unwrap();
        assert!(
            materialize_target_replica(
                &operation,
                &f.source,
                stores.clone(),
                f.input.clone(),
                f.config(id),
                audit.clone(),
            )
            .await
            .is_err()
        );
        let result = resume_target_materialization(
            &operation,
            &f.source,
            stores.clone(),
            origin.clone(),
            f.config(id),
            audit.clone(),
        )
        .await
        .unwrap();
        let proof = f.signers[&id]
            .sign_materialized(&result.proof, &operation)
            .await
            .unwrap();
        assert_eq!(proof.fact.origin, origin);
        assert_eq!(proof.fact.bootstrap_sha256, original.fact.bootstrap_sha256);
        assert_eq!(
            proof
                .fact
                .origin
                .materialization
                .original_credential_expires_at_ms,
            1_000_500
        );
        if id == 1 {
            assert_eq!(proof, original);
        }
        materialized.insert(id, proof);
        drop(result);
        drop(operation);
        scope.close();
        scope.drain().await;
        stores.application().shutdown().await;
        stores.custody().store().shutdown().await;
        drop(stores);
        audit.shutdown().await;
    }
    verify_target_materializations(&origin, &materialized).unwrap();
    f.close().await;
}

#[tokio::test]
async fn materialization_rejects_authenticated_backup_purpose_substitution_before_publication() {
    let mut f = MaterialFixture::new().await;
    f.input.source_purpose_sha256 = "fe".repeat(32);
    let intent = &mut f.intent.observation.intent;
    intent.request.command_id = Uuid::new_v4();
    intent.request.phase_input_sha256 = f.input.digest().unwrap();
    intent.request_sha256 = digest(&intent.request).unwrap();
    f.control.sign_intent(&mut f.intent);
    accepted_on_current_leader(&f.issuer, request(&f.intent)).await;
    let (scope, stores, audit) = f.phase(1, &f.intent).await;
    let operation = scope.begin_operation(60_000).unwrap();
    let error = materialize_target_replica(
        &operation,
        &f.source,
        stores.clone(),
        f.input.clone(),
        f.config(1),
        audit.clone(),
    )
    .await
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("source purpose differs from the authenticated backup root"),
        "{error:#}"
    );
    assert!(
        stores
            .application()
            .get("engine.bootstrap", b"manifest")
            .unwrap()
            .is_none()
    );
    assert!(
        stores
            .custody()
            .store()
            .get("raft.meta", b"application_bootstrap_sha256")
            .unwrap()
            .is_none()
    );
    drop(operation);
    scope.close();
    scope.drain().await;
    stores.application().shutdown().await;
    stores.custody().store().shutdown().await;
    drop(stores);
    audit.shutdown().await;
    f.close().await;
}

struct RunningTarget {
    id: u64,
    operation: TargetOperation,
    scope: Arc<TargetOperationScope>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<kasumi_engine::SecurityAudit>,
    owner: kasumi_engine::TargetReplica,
}
fn initial_complete(input: &TargetQuorumInput) -> kasumi_types::TargetCompletionInput {
    kasumi_types::TargetCompletionInput {
        quorum: input.clone(),
        predecessor: None,
    }
}
impl MaterialFixture {
    async fn commit_phase(
        &self,
        phase: LifecyclePhase,
        input: &TargetQuorumInput,
    ) -> SignedControlIntent {
        let digest = if phase == LifecyclePhase::Complete {
            initial_complete(input).digest().unwrap()
        } else {
            input.digest().unwrap()
        };
        self.commit_phase_input(phase, digest, 1_500_000).await
    }
    async fn commit_phase_input(
        &self,
        phase: LifecyclePhase,
        input_sha256: String,
        expiry: u64,
    ) -> SignedControlIntent {
        let mut signed = self.intent.clone();
        let intent = &mut signed.observation.intent;
        intent.original_credential_expires_at_ms = expiry;
        intent.request.command_id = Uuid::new_v4();
        intent.request.phase = phase;
        intent.request.phase_input_sha256 = input_sha256;
        intent.request_sha256 = digest(&intent.request).unwrap();
        intent.revision += match phase {
            LifecyclePhase::Initialize => 1,
            _ => 2,
        };
        signed.observation.observed_revision = intent.revision;
        self.control.sign_intent(&mut signed);
        accepted_on_current_leader(&self.issuer, request(&signed)).await;
        signed
    }
    async fn materialize_all(&self) -> TargetQuorumInput {
        let mut materialized = BTreeMap::new();
        let mut origin_sha256 = None;
        for id in 1..=3 {
            let (scope, stores, audit) = self.phase(id, &self.intent).await;
            let operation = scope.begin_operation(60_000).unwrap();
            let result = materialize_target_replica(
                &operation,
                &self.source,
                stores.clone(),
                self.input.clone(),
                self.config(id),
                audit.clone(),
            )
            .await
            .unwrap();
            let signed = self.signers[&id]
                .sign_materialized(&result.proof, &operation)
                .await
                .unwrap();
            origin_sha256 = Some(signed.fact.origin.digest().unwrap());
            materialized.insert(id, signed);
            drop(result);
            drop(operation);
            scope.close();
            scope.drain().await;
            stores.application().shutdown().await;
            stores.custody().store().shutdown().await;
            drop(stores);
            audit.shutdown().await;
        }
        let input = TargetQuorumInput {
            origin_sha256: origin_sha256.unwrap(),
            materialized,
        };
        kasumi_serving::verify_target_materializations(
            &input.materialized[&1].fact.origin,
            &input.materialized,
        )
        .unwrap();
        input
    }
    async fn open_targets(
        &self,
        phase: &SignedControlIntent,
        input: &TargetQuorumInput,
        router: &Arc<InProcessRouter>,
    ) -> Vec<RunningTarget> {
        let input = if phase.observation.intent.request.phase == LifecyclePhase::Complete {
            TargetReplicaInput::Completion(initial_complete(input))
        } else {
            TargetReplicaInput::Quorum(input.clone())
        };
        self.open_targets_input(phase, input, router).await
    }
    async fn open_targets_input(
        &self,
        phase: &SignedControlIntent,
        input: TargetReplicaInput,
        router: &Arc<InProcessRouter>,
    ) -> Vec<RunningTarget> {
        let mut targets = vec![];
        for id in 1..=3 {
            let (scope, stores, audit) = self.phase(id, phase).await;
            let operation = scope.begin_operation(60_000).unwrap();
            let owner = open_target_replica(
                &operation,
                stores.clone(),
                input.clone(),
                TargetReplicaConfig {
                    node_id: id,
                    raft: Config {
                        heartbeat_interval: 50,
                        election_timeout_min: 250,
                        election_timeout_max: 400,
                        ..Config::default()
                    },
                    admission: self.admissions[&id].clone(),
                },
                router.clone(),
                audit.clone(),
            )
            .await
            .unwrap();
            router.register(
                format!("city/{}", self.target.incarnation),
                id,
                owner.database().raft_group().raft().clone(),
            );
            targets.push(RunningTarget {
                id,
                operation,
                scope,
                stores,
                audit,
                owner,
            });
        }
        targets
    }
    async fn close_targets(&self, targets: Vec<RunningTarget>, router: &InProcessRouter) {
        for mut t in targets {
            router.unregister(&format!("city/{}", self.target.incarnation), t.id);
            t.owner.close().await.unwrap();
            drop(t.owner);
            drop(t.operation);
            t.scope.close();
            t.scope.drain().await;
            t.stores.custody().store().shutdown().await;
            drop(t.stores);
            t.audit.shutdown().await;
        }
    }
}
async fn current_target(targets: &[RunningTarget]) -> usize {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            for (i, t) in targets.iter().enumerate() {
                let g = t.owner.database().raft_group();
                let m = g.raft().metrics().borrow().clone();
                if m.current_leader == Some(m.id) && g.linearizable_barrier().await.is_ok() {
                    return i;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn three_actual_materializations_initialize_and_commit_completion_with_restart_proof() {
    let f = MaterialFixture::new().await;
    let input = f.materialize_all().await;
    let initialize = f.commit_phase(LifecyclePhase::Initialize, &input).await;
    let router = Arc::new(InProcessRouter::default());
    let targets = f.open_targets(&initialize, &input, &router).await;
    targets[0]
        .owner
        .initialize(&targets[0].operation)
        .await
        .unwrap();
    current_target(&targets).await;
    // Initialization cannot dispatch an ordinary Data command or Complete phase.
    assert!(
        targets[0]
            .owner
            .database()
            .complete_target(&targets[0].operation, initial_complete(&input))
            .await
            .is_err()
    );
    for t in &targets {
        t.owner
            .database()
            .raft_group()
            .linearizable_barrier()
            .await
            .ok();
    }
    f.close_targets(targets, &router).await;
    let complete = f.commit_phase(LifecyclePhase::Complete, &input).await;
    let targets = f.open_targets(&complete, &input, &router).await;
    let index = current_target(&targets).await;
    let selected = &targets[index];
    let proof = selected
        .owner
        .database()
        .complete_target(&selected.operation, initial_complete(&input))
        .await
        .unwrap();
    let signed = f.signers[&selected.id]
        .sign_completed(&proof, &selected.operation)
        .await
        .unwrap();
    kasumi_serving::verify_target_completion(&input.materialized[&1].fact.origin, &signed).unwrap();
    let first = signed.observation.fact.clone();
    assert_eq!(
        first.origin.materialization.request.checkpoint,
        f.target.checkpoint
    );
    assert!(first.revision > f.target.checkpoint.revision);
    let again = selected
        .owner
        .database()
        .complete_target(&selected.operation, initial_complete(&input))
        .await
        .unwrap();
    assert_eq!(again.observation().fact, first);
    drop(again);
    drop(proof);
    f.close_targets(targets, &router).await;
    let targets = f.open_targets(&complete, &input, &router).await;
    let index = current_target(&targets).await;
    let selected = &targets[index];
    let recovered = selected
        .owner
        .database()
        .observe_target_completion(&selected.operation)
        .await
        .unwrap();
    assert_eq!(recovered.observation().fact, first);
    let resigned = f.signers[&selected.id]
        .sign_completed(&recovered, &selected.operation)
        .await
        .unwrap();
    kasumi_serving::verify_target_completion(&input.materialized[&1].fact.origin, &resigned)
        .unwrap();
    let mut substituted = resigned;
    substituted.observation.fact.bootstrap_sha256 = "ab".repeat(32);
    assert!(
        kasumi_serving::verify_target_completion(&input.materialized[&1].fact.origin, &substituted)
            .is_err()
    );
    drop(recovered);
    f.close_targets(targets, &router).await;
    f.close().await;
}

#[path = "target_serving_tests.rs"]
mod serving_tests;

#[tokio::test]
async fn exact_actual_completion_is_required_for_issuer_and_target_activation() {
    Box::pin(exercise_target_activation(false)).await;
}

#[tokio::test]
async fn activated_target_keeps_operational_suspension_and_membership_across_restart() {
    Box::pin(exercise_target_activation(true)).await;
}

async fn exercise_target_activation(maintenance: bool) {
    let f = MaterialFixture::new().await;
    let input = f.materialize_all().await;
    let initialize = f.commit_phase(LifecyclePhase::Initialize, &input).await;
    let router = Arc::new(InProcessRouter::default());
    let targets = f.open_targets(&initialize, &input, &router).await;
    targets[0]
        .owner
        .initialize(&targets[0].operation)
        .await
        .unwrap();
    current_target(&targets).await;
    f.close_targets(targets, &router).await;
    let complete = f.commit_phase(LifecyclePhase::Complete, &input).await;
    let targets = f.open_targets(&complete, &input, &router).await;
    let index = current_target(&targets).await;
    let proof = targets[index]
        .owner
        .database()
        .complete_target(&targets[index].operation, initial_complete(&input))
        .await
        .unwrap();
    let signed = f.signers[&targets[index].id]
        .sign_completed(&proof, &targets[index].operation)
        .await
        .unwrap();
    drop(proof);
    f.close_targets(targets, &router).await;
    let fence = super::activation_gate_tests::exact_administrative(
        &f.issuer,
        f.issuer.command(AuthorityAction::Fence {
            incarnation: Uuid::parse_str(&f.target.checkpoint.source_incarnation).unwrap(),
            authority_epoch: 1,
        }),
    )
    .await;
    let activation_input = ActivateTargetInput {
        completion_sha256: signed.observation.fact.digest().unwrap(),
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: f.target.clone(),
    };
    let mut intent = f.intent.clone();
    intent.observation.intent.request.command_id = Uuid::new_v4();
    intent.observation.intent.request.phase = LifecyclePhase::Activate;
    intent.observation.intent.request.phase_input_sha256 = activation_input.digest().unwrap();
    intent.observation.intent.request_sha256 = digest(&intent.observation.intent.request).unwrap();
    intent.observation.intent.revision += 3;
    intent.observation.observed_revision = intent.observation.intent.revision;
    f.control.sign_intent(&mut intent);
    let (issuer, _) = accepted_on_current_leader(&f.issuer, request(&intent)).await;
    let request_ref = request(&intent);
    let command = f.issuer.command(AuthorityAction::ActivateCommitted {
        fence_id: fence.command.command_id,
        fence_digest: fence.digest().unwrap(),
        target: f.target.clone(),
        control: CommittedActivation {
            completion: Box::new(kasumi_types::CommittedCompletion::Original(Box::new(
                signed.clone(),
            ))),
            reference: request_ref.reference(),
            intent_sha256: request_ref.digest().unwrap(),
        },
    });
    // Actual source fencing alone cannot skip the full original lease drain.
    assert!(
        issuer
            .execute(f.issuer.context("operator"), command.clone())
            .await
            .is_err()
    );
    f.issuer.clock.0.store(1000, Ordering::SeqCst);
    let mut invalid = command.clone();
    invalid.command_id = Uuid::new_v4();
    if let AuthorityAction::ActivateCommitted { control, .. } = &mut invalid.action {
        let kasumi_types::CommittedCompletion::Original(signed) = control.completion.as_mut()
        else {
            unreachable!()
        };
        signed.signature = "00".repeat(64);
    }
    let denied = super::activation_gate_tests::exact_administrative(&f.issuer, invalid).await;
    assert!(matches!(denied.outcome, AuthorityOutcome::Rejected { .. }));
    let accepted =
        super::activation_gate_tests::exact_administrative(&f.issuer, command.clone()).await;
    assert!(matches!(
        accepted.outcome,
        AuthorityOutcome::Activated { .. }
    ));
    let current = f.issuer.leader().await;
    let accepted_signed = current
        .receipt(f.issuer.context("operator"), "city", command.command_id)
        .await
        .unwrap()
        .0
        .unwrap();
    let trust = f.issuer.trust.clone();
    trust.verify_activation(accepted_signed.clone()).unwrap();
    let targets = f.open_targets(&intent, &input, &router).await;
    let index = current_target(&targets).await;
    let selected = &targets[index];
    assert!(selected.owner.database().check_serving().is_err());
    let phase_control = selected.operation.invocation().context().clone();
    assert!(
        selected
            .owner
            .database()
            .administer(phase_control, Operation::Suspend(false))
            .await
            .is_err()
    );
    // Independent journal reserves activation and permanent stop headroom
    // before the actual local effect. It uses neither source nor target key.
    let journal_path = f.issuer._dir.path().join("activation-journal.redb");
    let journal_installation = kasumi_engine::TargetJournalInstallation {
        root: f.control.root.clone(),
        node: nodes()
            .into_iter()
            .find(|n| n.node_id == selected.id)
            .unwrap(),
    };
    let projected_node_id = selected.id;
    let journal_tenant = format!(
        "kasumi.target.{}.{}",
        f.control.root.control_incarnation, selected.id
    );
    let journal_provider = Arc::new(LocalKeyProvider::new([239; 32]));
    let journal_access =
        StorageAccess::target_journal(&journal_installation.root, &journal_installation.node)
            .unwrap();
    let journal_file_id = kasumi_store::node_store_ids::target_journal(
        journal_installation.root.control_incarnation,
        &journal_installation.node.verifier,
    )
    .unwrap();
    let journal_store = TenantStore::open(
        NodeStore::create_new(
            &journal_path,
            journal_file_id,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap(),
        journal_tenant.clone(),
        journal_provider.clone(),
        journal_access.clone(),
    )
    .await
    .unwrap();
    let journal_limits = TargetJournalLimits {
        max_metadata_bytes: 4 << 20,
    };
    let journal = kasumi_engine::TargetJournal::create_new(
        journal_store.clone(),
        journal_installation.clone(),
        journal_limits.clone(),
        f.admissions[&projected_node_id].clone(),
    )
    .unwrap();
    assert!(
        journal
            .serving_projection("city", f.target.incarnation)
            .unwrap()
            .is_none()
    );
    journal
        .prepare(&selected.operation, &activation_input.digest().unwrap())
        .unwrap();
    let completed = selected
        .owner
        .database()
        .activate_target(&selected.operation, accepted_signed.clone())
        .await
        .unwrap();
    assert_eq!(
        completed.fact().issuer_receipt_sha256,
        accepted.digest().unwrap()
    );
    let fact = completed.fact().clone();
    let actual_signed_activation = f.signers[&selected.id]
        .sign_activated(&completed, &selected.operation)
        .await
        .unwrap();
    for follower in targets.iter().filter(|target| target.id != selected.id) {
        let mut forged = actual_signed_activation.clone();
        forged.observation.activation.position.command_sha256 = "ff".repeat(32);
        assert!(
            follower
                .owner
                .database()
                .confirm_target_activation(&follower.operation, forged)
                .await
                .is_err()
        );
        let local = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match follower
                    .owner
                    .database()
                    .confirm_target_activation(
                        &follower.operation,
                        actual_signed_activation.clone(),
                    )
                    .await
                {
                    Ok(proof) => break proof,
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await
        .unwrap();
        let signed_local = f.signers[&follower.id]
            .sign_activated(&local, &follower.operation)
            .await
            .unwrap();
        assert_eq!(signed_local.observation.activation, fact);
        assert_eq!(signed_local.observation.observer_node_id, follower.id);
        verify_target_activation(&input.materialized[&1].fact.origin, &signed_local).unwrap();
        if maintenance {
            serving_tests::record_follower_projection(
                &f,
                follower,
                &local,
                &activation_input.digest().unwrap(),
            )
            .await;
        }
        assert!(follower.owner.database().check_serving().is_err());
    }
    let projected = journal
        .record_activation(&selected.operation, &completed, &f.signers[&selected.id])
        .await
        .unwrap();
    let exact_execution = projected.execution().unwrap();
    assert_eq!(exact_execution.activation.as_ref(), Some(completed.fact()));
    let serving_gate = selected
        .stores
        .application()
        .storage_access()
        .serving_gate()
        .unwrap()
        .clone();
    projected.check(&serving_gate).unwrap();
    let replayed = journal
        .record_activation(&selected.operation, &completed, &f.signers[&selected.id])
        .await
        .unwrap();
    assert_eq!(replayed.execution().unwrap(), exact_execution);
    drop(replayed);
    drop(projected);
    drop(journal);
    journal_store.shutdown().await;
    drop(journal_store);
    // Reopen only the separately encrypted journal, independently of all app
    // providers. Exact signatures survive restart; substituted facts fail closed.
    let journal_store = TenantStore::open(
        NodeStore::open_existing(
            &journal_path,
            journal_file_id,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap(),
        journal_tenant.clone(),
        journal_provider.clone(),
        journal_access.clone(),
    )
    .await
    .unwrap();
    let journal = kasumi_engine::TargetJournal::open_existing(
        journal_store.clone(),
        journal_installation.clone(),
        journal_limits.clone(),
        f.admissions[&projected_node_id].clone(),
    )
    .unwrap();
    let projection = journal
        .serving_projection("city", f.target.incarnation)
        .unwrap()
        .unwrap();
    projection.check(&serving_gate).unwrap();
    assert_eq!(projection.execution().unwrap(), exact_execution);
    let projection_key = format!("activation/city/{}", f.target.incarnation).into_bytes();
    let exact_bytes = journal_store
        .get("target.journal", &projection_key)
        .unwrap()
        .unwrap();
    let mut substituted: serde_json::Value = serde_json::from_slice(&exact_bytes).unwrap();
    substituted["observation"]["Activated"]["observation"]["activation"]["issuer_receipt_sha256"] =
        serde_json::Value::String("00".repeat(32));
    journal_store
        .write_batch(&[kasumi_store::WriteOp::put(
            "target.journal",
            projection_key.clone(),
            serde_json::to_vec(&substituted).unwrap(),
        )])
        .unwrap();
    assert!(projection.check(&serving_gate).is_err());
    assert!(
        journal
            .serving_projection("city", f.target.incarnation)
            .is_err()
    );
    drop(projection);
    drop(journal);
    assert!(
        kasumi_engine::TargetJournal::open_existing(
            journal_store.clone(),
            journal_installation.clone(),
            journal_limits.clone(),
            f.admissions[&projected_node_id].clone()
        )
        .is_err()
    );
    journal_store
        .write_batch(&[kasumi_store::WriteOp::put(
            "target.journal",
            projection_key,
            exact_bytes,
        )])
        .unwrap();
    let journal = kasumi_engine::TargetJournal::open_existing(
        journal_store.clone(),
        journal_installation.clone(),
        journal_limits.clone(),
        f.admissions[&projected_node_id].clone(),
    )
    .unwrap();
    let projection = journal
        .serving_projection("city", f.target.incarnation)
        .unwrap()
        .unwrap();
    projection.check(&serving_gate).unwrap();
    drop(projection);
    drop(journal);
    journal_store.shutdown().await;
    drop(journal_store);
    // A lifecycle-gated handle never turns into an ordinary data route.
    assert!(selected.owner.database().check_serving().is_err());
    drop(completed);
    f.close_targets(targets, &router).await;
    let targets = f.open_targets(&intent, &input, &router).await;
    let index = current_target(&targets).await;
    let recovered = targets[index]
        .owner
        .database()
        .observe_target_activation(&targets[index].operation)
        .await
        .unwrap();
    assert_eq!(recovered.fact(), &fact);
    drop(recovered);
    f.close_targets(targets, &router).await;
    // Ordinary startup uses independent journals and fresh Serving leases.
    // The extended case also reopens after ordinary maintenance; no old phase
    // grant becomes data authority and no original activation fact changes.
    serving_tests::exercise_serving(&f, &router, projected_node_id, &fact, maintenance).await;
    drop(issuer);
    drop(current);
    f.close().await;
}
#[tokio::test]
async fn dropping_target_on_non_runtime_thread_retains_shutdown_work_until_real_drain() {
    let f = MaterialFixture::new().await;
    let input = f.materialize_all().await;
    let initialize = f.commit_phase(LifecyclePhase::Initialize, &input).await;
    let router = Arc::new(InProcessRouter::default());
    let mut targets = f.open_targets(&initialize, &input, &router).await;
    let t = targets.remove(0);
    let handle = t.owner.database().raft_group().clone();
    router.unregister(&format!("city/{}", f.target.incarnation), t.id);
    std::thread::spawn(move || drop(t.owner)).join().unwrap();
    drop(t.operation);
    tokio::time::timeout(Duration::from_secs(10), t.scope.drain())
        .await
        .unwrap();
    assert!(handle.check_access().is_err());
    assert!(t.stores.application().check_access().is_err());
    drop(handle);
    drop(t.stores);
    t.audit.shutdown().await;
    f.close_targets(targets, &router).await;
    f.close().await;
}

#[tokio::test]
async fn expired_completion_with_missing_journal_recovers_only_exact_inspection_facts() {
    let f = MaterialFixture::new().await;
    let input = f.materialize_all().await;
    let initialize = f.commit_phase(LifecyclePhase::Initialize, &input).await;
    let router = Arc::new(InProcessRouter::default());
    let targets = f.open_targets(&initialize, &input, &router).await;
    targets[0]
        .owner
        .initialize(&targets[0].operation)
        .await
        .unwrap();
    current_target(&targets).await;
    f.close_targets(targets, &router).await;
    let complete = f
        .commit_phase_input(
            LifecyclePhase::Complete,
            initial_complete(&input).digest().unwrap(),
            1_000_500,
        )
        .await;
    let targets = f.open_targets(&complete, &input, &router).await;
    let index = current_target(&targets).await;
    let proof = targets[index]
        .owner
        .database()
        .complete_target(&targets[index].operation, initial_complete(&input))
        .await
        .unwrap();
    let original = proof.observation().fact.clone();
    // Do not sign or publish any completion acknowledgement. Only actual target
    // consensus state survives; no independent journal supplies success.
    drop(proof);
    f.close_targets(targets, &router).await;
    f.issuer.clock.0.store(600, Ordering::SeqCst);
    let issuer = f.issuer.leader().await;
    let node_identity = nodes().first().unwrap().clone();
    let trust = f.issuer.trust.clone();
    let old = ControlTrust::install(f.control.root.clone())
        .unwrap()
        .verify_intent(&complete)
        .unwrap();
    let old_boot =
        LifecycleBoot::with_clock(trust.clone(), node_identity.clone(), f.issuer.clock.clone())
            .unwrap();
    let old_attempt = old_boot.begin(&old).unwrap();
    assert!(
        issuer
            .acquire_lifecycle(
                AuthenticatedNode::from_verified_transport(
                    f.issuer.context(&node_identity.principal),
                    node_identity.certificate_sha256.clone()
                )
                .unwrap(),
                old_attempt.request().clone()
            )
            .await
            .is_err()
    );
    let inspection_input = TargetInspectionInput {
        quorum: input.clone(),
        original_phase: complete.observation.intent.clone(),
        predecessor: None,
    };
    let inspection = f
        .commit_phase_input(
            LifecyclePhase::InspectTarget,
            inspection_input.digest().unwrap(),
            1_500_000,
        )
        .await;
    let targets = f
        .open_targets_input(
            &inspection,
            TargetReplicaInput::Inspection(Box::new(inspection_input.clone())),
            &router,
        )
        .await;
    let index = current_target(&targets).await;
    let selected = &targets[index];
    let db = selected.owner.database();
    assert!(
        selected
            .owner
            .initialize(&selected.operation)
            .await
            .is_err()
    );
    assert!(
        db.complete_target(&selected.operation, initial_complete(&input))
            .await
            .is_err()
    );
    assert!(
        db.observe_target_completion(&selected.operation)
            .await
            .is_err()
    );
    assert!(
        db.observe_target_activation(&selected.operation)
            .await
            .is_err()
    );
    assert!(
        db.administer(
            selected.operation.invocation().context().clone(),
            Operation::Suspend(false)
        )
        .await
        .is_err()
    );
    let mut wrong = inspection_input.clone();
    wrong.original_phase.request.command_id = Uuid::new_v4();
    assert!(db.inspect_target(&selected.operation, wrong).await.is_err());
    let mut wrong = inspection_input.clone();
    wrong.quorum.origin_sha256 = "aa".repeat(32);
    assert!(db.inspect_target(&selected.operation, wrong).await.is_err());
    let observed = db
        .inspect_target(&selected.operation, inspection_input.clone())
        .await
        .unwrap();
    assert_eq!(observed.observation().completion, original);
    assert_eq!(
        observed.observation().completion.completion_intent,
        complete.observation.intent
    );
    let signed = f.signers[&selected.id]
        .sign_inspection(&observed, &selected.operation)
        .await
        .unwrap();
    verify_target_inspection(&inspection_input, &signed).unwrap();
    let mut substitution = signed.clone();
    substitution.observation.completion.admitted_at_ms += 1;
    assert!(verify_target_inspection(&inspection_input, &substitution).is_err());
    // Actual issuer stop prevents fresh acquisition; already captured gates
    // are bounded by the full original lease drain, never immediately renewed.
    let stop = f.control.stop(&inspection);
    accepted_on_current_leader(
        &f.issuer,
        LifecycleAuthorityRequest::StopEpoch(Box::new(stop)),
    )
    .await;
    f.issuer.clock.0.store(1600, Ordering::SeqCst);
    assert!(observed.release(&selected.operation).await.is_err());
    assert!(
        f.signers[&selected.id]
            .sign_inspection(&observed, &selected.operation)
            .await
            .is_err()
    );
    drop(observed);
    f.close_targets(targets, &router).await;
    drop(issuer);
    f.close().await;
}

impl MaterialFixture {
    /// Actual issuer phase without constructing any application provider/store.
    async fn journal_scope(&self, intent: &SignedControlIntent) -> Arc<TargetOperationScope> {
        let issuer = self.issuer.leader().await;
        let trust = self.issuer.trust.clone();
        let identity = nodes().first().unwrap().clone();
        let verified = ControlTrust::install(self.control.root.clone())
            .unwrap()
            .verify_intent(intent)
            .unwrap();
        let boot =
            LifecycleBoot::with_clock(trust, identity.clone(), self.issuer.clock.clone()).unwrap();
        let attempt = boot.begin(&verified).unwrap();
        let grant = issuer
            .acquire_lifecycle(
                AuthenticatedNode::from_verified_transport(
                    self.issuer.context(&identity.principal),
                    identity.certificate_sha256,
                )
                .unwrap(),
                attempt.request().clone(),
            )
            .await
            .unwrap()
            .0;
        let gate = LifecycleGate::with_test_clock(
            super::activation_gate_tests::original_control(
                &self.issuer,
                &self.control,
                intent.observation.intent.original_credential_expires_at_ms,
            ),
            attempt.verify(grant).unwrap(),
            self.issuer.epoch.clone(),
        )
        .unwrap();
        TargetOperationScope::new(TargetLifecycleInvocation::from_verified(gate).unwrap()).unwrap()
    }
}
#[tokio::test]
async fn independent_target_journal_reserves_stop_after_normal_quota_and_recovers_encrypted() {
    use kasumi_engine::{TargetJournal, TargetJournalInstallation};
    let f = MaterialFixture::new().await;
    let installation = TargetJournalInstallation {
        root: f.control.root.clone(),
        node: nodes().first().unwrap().clone(),
    };
    let path = f.issuer._dir.path().join("independent-target-journal.redb");
    let file_id = kasumi_store::node_store_ids::target_journal(
        installation.root.control_incarnation,
        &installation.node.verifier,
    )
    .unwrap();
    let node = NodeStore::create_new(&path, file_id, kasumi_store::ScratchDisk::fixture()).unwrap();
    let tenant = format!("kasumi.target.{}.1", f.control.root.control_incarnation);
    let provider = Arc::new(LocalKeyProvider::new([238; 32]));
    let access = StorageAccess::target_journal(&installation.root, &installation.node).unwrap();
    assert!(
        TenantStore::open(
            node.clone(),
            "city".into(),
            provider.clone(),
            access.clone()
        )
        .await
        .is_err()
    );
    let store = TenantStore::open(
        node.clone(),
        tenant.clone(),
        provider.clone(),
        access.clone(),
    )
    .await
    .unwrap();
    let mut limits = TargetJournalLimits {
        max_metadata_bytes: 4 << 20,
    };
    let journal = TargetJournal::create_new(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    let again = TargetJournal::open_existing(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    assert!(Arc::ptr_eq(&journal, &again));
    drop(again);
    let scope = f.journal_scope(&f.intent).await;
    let op = scope.begin_operation(60_000).unwrap();
    let mut jobs = vec![];
    for _ in 0..16 {
        let j = journal.clone();
        let op = op.clone();
        let hash = f.input.digest().unwrap();
        jobs.push(tokio::spawn(async move { j.prepare(&op, &hash).unwrap() }));
    }
    for job in jobs {
        assert_eq!(job.await.unwrap().intent(), &f.intent.observation.intent);
    }
    // Crash after durable creation intent, before the file exists. Losing the
    // first permit must never turn its original replay into a new creator.
    let file_path = f.issuer._dir.path().join("file-intent-target.redb");
    let creation = journal.reserve_materialization_file(&op).unwrap();
    drop(creation);
    assert!(
        journal
            .reserve_materialization_file(&op)
            .unwrap()
            .open(&file_path, kasumi_store::ScratchDisk::fixture())
            .is_err()
    );
    assert!(!file_path.exists());
    // A replacement node, even a canonical Kasumi file, cannot be adopted when
    // its installed UUID differs. The rejected replay must leave its bytes alone.
    let unrelated = NodeStore::create_new(
        &file_path,
        Uuid::new_v4(),
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    drop(unrelated);
    let unrelated_bytes = std::fs::read(&file_path).unwrap();
    assert!(
        journal
            .reserve_materialization_file(&op)
            .unwrap()
            .open(&file_path, kasumi_store::ScratchDisk::fixture())
            .is_err()
    );
    assert_eq!(std::fs::read(&file_path).unwrap(), unrelated_bytes);
    assert_eq!(
        journal
            .materialization_file_id("city", f.target.incarnation)
            .unwrap(),
        kasumi_store::node_store_ids::target_generation(
            f.control.root.control_incarnation,
            "city",
            f.target.incarnation,
            &installation.node.verifier
        )
        .unwrap()
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&store.get("target.journal", b"metadata").unwrap().unwrap())
            .unwrap();
    assert_eq!(metadata["intents"], 1);
    assert_eq!(metadata["generations"], 1);
    // Exhaust the actual charged byte budget, including the already reserved
    // completion/stop/activation records. No lifetime record count is involved.
    limits.max_metadata_bytes = metadata["charged_bytes"].as_u64().unwrap();
    drop(journal);
    let journal = TargetJournal::open_existing(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    let extra = f
        .commit_phase_input(
            LifecyclePhase::Materialize,
            f.input.digest().unwrap(),
            1_500_000,
        )
        .await;
    let extra_scope = f.journal_scope(&extra).await;
    let extra_op = extra_scope.begin_operation(60_000).unwrap();
    assert!(
        journal
            .prepare(&extra_op, &f.input.digest().unwrap())
            .is_err()
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &store.get("target.journal", b"metadata").unwrap().unwrap()
        )
        .unwrap(),
        metadata
    );
    // Operational expansion after owner drain preserves the installation and
    // accepts the exact previously rejected phase under its original deadline.
    drop(journal);
    limits.max_metadata_bytes = limits.max_metadata_bytes.checked_mul(2).unwrap();
    let journal = TargetJournal::open_existing(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    let retained = journal
        .prepare(&extra_op, &f.input.digest().unwrap())
        .unwrap();
    assert_eq!(retained.intent(), &extra.observation.intent);
    let metadata: serde_json::Value =
        serde_json::from_slice(&store.get("target.journal", b"metadata").unwrap().unwrap())
            .unwrap();
    assert_eq!(metadata["intents"], 2);
    assert_eq!(metadata["generations"], 1);
    limits.max_metadata_bytes = metadata["charged_bytes"].as_u64().unwrap();
    drop(journal);
    let journal = TargetJournal::open_existing(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    journal
        .prepare(&extra_op, &f.input.digest().unwrap())
        .unwrap();
    drop(extra_op);
    extra_scope.close();
    extra_scope.drain().await;
    // An independent full issuer stop/drain is required. No local absence or
    // expired preparation can stand in for this authenticated terminal proof.
    let stopped = super::activation_gate_tests::exact_administrative(
        &f.issuer,
        f.issuer.command(AuthorityAction::StopTarget {
            source_incarnation: Uuid::parse_str(&f.target.checkpoint.source_incarnation).unwrap(),
            source_epoch: 1,
            target: f.target.clone(),
        }),
    )
    .await;
    let reference = TargetStopReference {
        tenant: "city".into(),
        command_id: stopped.command.command_id,
        receipt_digest: stopped.digest().unwrap(),
    };
    let issuer = f.issuer.leader().await;
    assert!(
        issuer
            .verify_target_stop(f.issuer.context("operator"), reference.clone())
            .await
            .is_err()
    );
    f.issuer.clock.0.store(1000, Ordering::SeqCst);
    let signed = issuer
        .verify_target_stop(f.issuer.context("operator"), reference.clone())
        .await
        .unwrap()
        .0;
    let trust = f.issuer.trust.clone();
    let proof = trust.verify_target_stop(signed, &reference).unwrap();
    let stop_intent = f
        .commit_phase_input(
            LifecyclePhase::StopLocal,
            digest(&("kasumi.stop-local-target-input.v1", &reference)).unwrap(),
            1_500_000,
        )
        .await;
    let stop_scope = f.journal_scope(&stop_intent).await;
    let stop_op = stop_scope.begin_operation(60_000).unwrap();
    journal.stop(&stop_op, &proof).unwrap();
    assert!(journal.prepare(&op, &f.input.digest().unwrap()).is_err());
    assert!(journal.reserve_materialization_file(&op).is_err());
    let metadata_after: serde_json::Value =
        serde_json::from_slice(&store.get("target.journal", b"metadata").unwrap().unwrap())
            .unwrap();
    assert_eq!(metadata_after, metadata); // reserved stop uses no new capacity
    let stop_key = format!("stop/city/{}", f.target.incarnation);
    let terminal = store
        .get("target.journal", stop_key.as_bytes())
        .unwrap()
        .unwrap();
    drop(op);
    scope.close();
    scope.drain().await;
    drop(journal);
    store.shutdown().await;
    drop(store);
    drop(node);
    let node =
        NodeStore::open_existing(path, file_id, kasumi_store::ScratchDisk::fixture()).unwrap();
    let store = TenantStore::open(node, tenant, provider, access)
        .await
        .unwrap();
    let reopened = TargetJournal::open_existing(
        store.clone(),
        installation.clone(),
        limits.clone(),
        f.admissions[&1].clone(),
    )
    .unwrap();
    reopened.stop(&stop_op, &proof).unwrap();
    assert!(
        reopened
            .materialization_file_id("city", f.target.incarnation)
            .is_ok()
    );

    assert_eq!(
        store
            .get("target.journal", stop_key.as_bytes())
            .unwrap()
            .unwrap(),
        terminal
    );
    assert!(!f.issuer._dir.path().join("target-1.redb").exists());
    drop(stop_op);
    stop_scope.close();
    stop_scope.drain().await;
    drop(reopened);
    // Unsupported or missing heads are rejected without a migration, rewrite,
    // or loss of the permanent stop. Large forged counts cannot truncate to u32.
    let mut no_format = metadata.clone();
    no_format.as_object_mut().unwrap().remove("format");
    let mut unsupported = metadata.clone();
    unsupported["format"] = 99.into();
    let mut forged_count = metadata.clone();
    forged_count["intents"] = (u64::from(u32::MAX) + 1).into();
    for head in [no_format, unsupported, forged_count] {
        let bytes = serde_json::to_vec(&head).unwrap();
        store
            .write_batch(&[kasumi_store::WriteOp::put(
                "target.journal",
                b"metadata",
                bytes.clone(),
            )])
            .unwrap();
        assert!(
            TargetJournal::open_existing(
                store.clone(),
                installation.clone(),
                limits.clone(),
                f.admissions[&1].clone()
            )
            .is_err()
        );
        assert_eq!(
            store.get("target.journal", b"metadata").unwrap().unwrap(),
            bytes
        );
        assert_eq!(
            store
                .get("target.journal", stop_key.as_bytes())
                .unwrap()
                .unwrap(),
            terminal
        );
    }
    store
        .write_batch(&[kasumi_store::WriteOp::delete("target.journal", b"metadata")])
        .unwrap();
    assert!(
        TargetJournal::open_existing(
            store.clone(),
            installation,
            limits,
            f.admissions[&1].clone()
        )
        .is_err()
    );
    assert!(store.get("target.journal", b"metadata").unwrap().is_none());
    assert_eq!(
        store
            .get("target.journal", stop_key.as_bytes())
            .unwrap()
            .unwrap(),
        terminal
    );
    store.shutdown().await;
    drop(store);
    drop(issuer);
    f.close().await;
}

#[tokio::test]
async fn followup_request_keeps_both_original_credential_fences_and_cannot_reopen_phase() {
    use kasumi_engine::TargetRequestAdmission;
    let f = MaterialFixture::new().await;
    let scope = f.journal_scope(&f.intent).await;
    let new_context =
        super::activation_gate_tests::original_control(&f.issuer, &f.control, 1_000_005);
    let mut wrong = new_context.clone();
    wrong.principal = "unapproved-actor".into();
    assert!(
        scope
            .begin_followup(TargetRequestAdmission::capture(wrong, 60_000).unwrap())
            .is_err()
    );
    let mut wrong = new_context.clone();
    wrong.scopes.clear();
    assert!(
        scope
            .begin_followup(TargetRequestAdmission::capture(wrong, 60_000).unwrap())
            .is_err()
    );
    let operation = scope
        .begin_followup(TargetRequestAdmission::capture(new_context, 60_000).unwrap())
        .unwrap();
    assert!(operation.check().is_ok());
    f.issuer.clock.0.store(6, Ordering::SeqCst);
    assert!(scope.invocation().check().is_ok());
    assert!(operation.check().is_err());
    let polled = std::sync::atomic::AtomicBool::new(false);
    assert!(
        operation
            .run(async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .is_err()
    );
    assert!(!polled.load(Ordering::SeqCst));
    drop(operation);
    let current = super::activation_gate_tests::original_control(&f.issuer, &f.control, 1_500_000);
    let request = TargetRequestAdmission::capture(current.clone(), 60_000).unwrap();
    assert!(scope.begin_followup(request).is_ok());
    // Nothing observed the phase during this expired interval. A newly live
    // request cannot re-open its old grant or the old response fences.
    f.issuer.clock.0.store(1001, Ordering::SeqCst);
    let late = TargetRequestAdmission::capture(current, 60_000).unwrap();
    assert!(scope.begin_followup(late).is_err());
    f.close().await;
}

#[tokio::test]
async fn target_file_creation_outcome_distinguishes_original_creation_from_strict_replay() {
    use kasumi_engine::{MaterializationNode, TargetJournal, TargetJournalInstallation};
    let f = MaterialFixture::new().await;
    let installation = TargetJournalInstallation {
        root: f.control.root.clone(),
        node: nodes().first().unwrap().clone(),
    };
    let journal_path = f.issuer._dir.path().join("creation-outcome-journal.redb");
    let node = NodeStore::create_new(
        &journal_path,
        kasumi_store::node_store_ids::target_journal(
            installation.root.control_incarnation,
            &installation.node.verifier,
        )
        .unwrap(),
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let store = TenantStore::open(
        node.clone(),
        format!("kasumi.target.{}.1", installation.root.control_incarnation),
        Arc::new(LocalKeyProvider::new([239; 32])),
        StorageAccess::target_journal(&installation.root, &installation.node).unwrap(),
    )
    .await
    .unwrap();
    let journal = TargetJournal::create_new(
        store,
        installation,
        TargetJournalLimits {
            max_metadata_bytes: 4 << 20,
        },
        f.admissions[&1].clone(),
    )
    .unwrap();
    let scope = f.journal_scope(&f.intent).await;
    let operation = scope.begin_operation(60_000).unwrap();
    journal
        .prepare(&operation, &f.input.digest().unwrap())
        .unwrap();
    let path = f.issuer._dir.path().join("creation-outcome-target.redb");
    let MaterializationNode::Created(target) = journal
        .reserve_materialization_file(&operation)
        .unwrap()
        .open(&path, kasumi_store::ScratchDisk::fixture())
        .unwrap()
    else {
        panic!("original durable file dispatch lost catalog initialization permission")
    };
    target.drain_initializers().await.unwrap();
    drop(target);
    let before = std::fs::read(&path).unwrap();
    let MaterializationNode::Existing(target) = journal
        .reserve_materialization_file(&operation)
        .unwrap()
        .open(&path, kasumi_store::ScratchDisk::fixture())
        .unwrap()
    else {
        panic!("replay regained original catalog initialization permission")
    };
    assert!(
        TenantStorageSet::open_existing_fixture(
            target.clone(),
            "city".into(),
            Arc::new(LocalKeyProvider::new([52; 32])),
            Arc::new(LocalKeyProvider::new([53; 32])),
        )
        .await
        .is_err()
    );
    target.drain_initializers().await.unwrap();
    drop(target);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // Even absence after an earlier creation cannot turn a replay into a creator.
    std::fs::remove_file(&path).unwrap();
    assert!(
        journal
            .reserve_materialization_file(&operation)
            .unwrap()
            .open(&path, kasumi_store::ScratchDisk::fixture())
            .is_err()
    );
    assert!(!path.exists());
    drop(operation);
    scope.close();
    scope.drain().await;
    journal.shutdown().await;
    drop(journal);
    drop(node);
    f.issuer.close().await;
}
