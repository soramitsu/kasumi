use kasumi_engine::test_utils::SnapshotFixture;
use kasumi_engine::test_utils::open_fixture_replicated;
mod common;
use kasumi_engine::{
    Database, LifecycleSigner, ReplicaPlacement, ReplicatedBootstrap, initialize_replicated,
};
use kasumi_raft::{Config, InProcessRouter, StateMachineBackend};
use kasumi_serving::{ControlTrust, control_stop_for, digest};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

struct Fixture {
    root: tempfile::TempDir,
    router: Arc<InProcessRouter>,
    bootstrap: ReplicatedBootstrap,
    nodes: BTreeMap<u64, Arc<Database>>,
    audits: BTreeMap<u64, Arc<kasumi_engine::SecurityAudit>>,
    signer: LifecycleSigner,
    partition_keys: BTreeMap<String, kasumi_serving::GenerationSigner>,
    installation: LifecycleInstallation,
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_pkcs8(
        Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap()
            .as_ref(),
    )
    .unwrap()
}
impl Fixture {
    async fn new() -> Self {
        Self::limits(Limits::default(), 8 << 20).await
    }
    async fn limits(limits: Limits, max_state_bytes: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let incarnation = Uuid::new_v4();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let controlkey = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let rootkey = ControlSigningRoot {
            control_incarnation: incarnation,
            public_key: hex::encode(controlkey.public_key().as_ref()),
        };
        let signer = LifecycleSigner::from_pkcs8(rootkey.clone(), pkcs8.as_ref()).unwrap();
        let authority = Uuid::new_v4();
        let mut partitions = BTreeMap::new();
        let mut partition_keys = BTreeMap::new();
        for partition in 0..2 {
            let signer = key();
            let p = ControlAuthorityPartition {
                authority_id: authority,
                manifest_sha256: "12".repeat(32),
                partition,
                signing_public_key: hex::encode(signer.public_key().as_ref()),
                maximum_lifetime_ms: 1000,
                drain_ms: 1000,
            };
            let operational =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let operational_key = Ed25519KeyPair::from_pkcs8(operational.as_ref()).unwrap();
            let identity = SigningGeneration {
                domain: SigningDomain {
                    authority_id: p.authority_id,
                    partition: p.partition,
                    manifest_sha256: p.manifest_sha256.clone(),
                    root_public_key: p.signing_public_key.clone(),
                    retirement_drain_ms: p.drain_ms,
                },
                generation: 1,
                public_key: hex::encode(operational_key.public_key().as_ref()),
            };
            let certificate = SigningCertificate {
                root_signature: hex::encode(
                    signer
                        .sign(
                            &serde_json::to_vec(&("kasumi.signing-certificate.v1", &identity))
                                .unwrap(),
                        )
                        .as_ref(),
                ),
                identity,
            };
            partition_keys.insert(
                p.key(),
                kasumi_serving::GenerationSigner::from_pkcs8(certificate, operational.as_ref())
                    .unwrap(),
            );
            partitions.insert(p.key(), p);
        }
        let installation = LifecycleInstallation {
            root: rootkey,
            generation: 1,
            partitions,
            max_intents: 100,
            max_changes: 10,
            max_state_bytes,
        };
        let bootstrap = ReplicatedBootstrap {
            incarnation: incarnation.to_string(),
            initial_policy: policy("owner"),
            initial_limits: limits,
            voters: (1..=3)
                .map(|id| {
                    (
                        id,
                        ReplicaPlacement {
                            address: format!("node-{id}"),
                            failure_domain: format!("zone-{id}"),
                        },
                    )
                })
                .collect(),
        };
        let mut result = Self {
            root,
            router: Arc::new(InProcessRouter::default()),
            bootstrap,
            nodes: BTreeMap::new(),
            audits: BTreeMap::new(),
            signer,
            partition_keys,
            installation,
        };
        result.open().await;
        result
            .leader()
            .await
            .lifecycle_control(
                result.context("owner"),
                LifecycleControlCommand::Install {
                    command_id: Uuid::new_v4(),
                    installation: result.installation.clone(),
                },
            )
            .await
            .unwrap();
        result
    }
    async fn open(&mut self) {
        for id in 1..=3 {
            let node = NodeStore::open(
                self.root.path().join(format!("{id}.redb")),
                kasumi_store::ScratchDisk::fixture(),
            )
            .unwrap();
            let audit = common::security_audit(node.clone()).await;
            let store = TenantStore::open_fixture(
                node,
                "__kasumi_control".into(),
                Arc::new(LocalKeyProvider::new([43; 32])),
            )
            .await
            .unwrap();
            let stores = kasumi_store::test_utils::with_custody(
                store,
                Arc::new(LocalKeyProvider::new([241; 32])),
            )
            .await
            .unwrap();
            let db = open_fixture_replicated(
                id,
                stores,
                &self.bootstrap,
                self.router.clone(),
                Config {
                    election_timeout_min: 100,
                    election_timeout_max: 180,
                    heartbeat_interval: 30,
                    ..Config::default()
                },
                audit.clone(),
            )
            .await
            .unwrap();
            self.router.register(
                format!("__kasumi_control/{}", self.bootstrap.incarnation),
                id,
                db.raft_group().raft().clone(),
            );
            self.nodes.insert(id, db);
            self.audits.insert(id, audit);
        }
        initialize_replicated(&self.nodes[&1], &self.bootstrap)
            .await
            .unwrap();
        self.leader().await;
    }
    async fn leader(&self) -> Arc<Database> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                for (id, db) in &self.nodes {
                    if db.raft_group().raft().metrics().borrow().current_leader == Some(*id)
                        && db.raft_group().linearizable_barrier().await.is_ok()
                    {
                        return db.clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    // A lost Raft acknowledgement is ambiguous even for an input expected to
    // reject. Resolve the exact permanent phase and retry the unchanged input
    // with the same original finite authorization; never accept an unresolved
    // unknown or create a new identity/deadline to make this assertion pass.
    async fn rejected_completion(
        &self,
        context: RequestContext,
        request: CompleteControlPolicyChange,
    ) -> Error {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let db = self.leader().await;
                match db
                    .lifecycle_control(
                        context.clone(),
                        LifecycleControlCommand::CompletePolicyChange(request.clone()),
                    )
                    .await
                {
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                        ) =>
                    {
                        let observed = loop {
                            match self
                                .leader()
                                .await
                                .observe_lifecycle_change(context.clone(), request.command_id)
                                .await
                            {
                                Ok(observation) => break observation,
                                Err(error)
                                    if matches!(
                                        error.code,
                                        ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                                    ) => {}
                                Err(error) => {
                                    panic!("original completion status unavailable: {error:?}")
                                }
                            }
                        };
                        let exact = &observed.observation().change;
                        assert_eq!(exact.request.command_id, request.command_id);
                        assert_eq!(exact.request_sha256, request.change_sha256);
                        assert!(
                            exact.completed_revision.is_none(),
                            "invalid completion unexpectedly committed"
                        );
                        assert!(exact.completion_stops.is_none());
                    }
                    Err(error) => return error,
                    Ok(receipt) => panic!("invalid completion unexpectedly accepted: {receipt:?}"),
                }
            }
        })
        .await
        .expect("original rejected completion did not resolve")
    }
    // Resolve an uncertain denial using its original identity and authorization.
    // An unchanged audit count after a transport error is not a budget outcome.
    async fn rejected_intent(
        &self,
        context: RequestContext,
        request: CommitLifecycleIntent,
    ) -> Error {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let result = self
                    .leader()
                    .await
                    .lifecycle_control(
                        context.clone(),
                        LifecycleControlCommand::CommitIntent(request.clone().into()),
                    )
                    .await;
                let db = self.leader().await;
                let generation = db.engine().generation().unwrap();
                let control = generation.state.lifecycle_control.as_ref().unwrap();
                assert!(control.pending_change.is_some());
                assert!(
                    !control.intents.contains_key(&request.command_id),
                    "intent unexpectedly committed while issuance was closed"
                );
                match result {
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::UnknownOutcome | ErrorCode::Unavailable
                        ) => {}
                    Err(error) => return error,
                    Ok(receipt) => panic!("closed issuance accepted an intent: {receipt:?}"),
                }
            }
        })
        .await
        .expect("original denied intent did not resolve")
    }
    fn context(&self, principal: &str) -> RequestContext {
        self.context_for(principal, 60_000)
    }
    fn context_for(&self, principal: &str, duration: u64) -> RequestContext {
        let observation = kasumi_clock::EpochClock::system()
            .unwrap()
            .observe()
            .unwrap();
        RequestContext {
            tenant: "__kasumi_control".into(),
            principal: principal.into(),
            request_id: Uuid::new_v4().to_string(),
            scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            authorization: RequestAuthorization::from_verified_credential(
                observation.utc_ms() + duration,
                &observation,
                CredentialResource::Control {
                    incarnation: Uuid::parse_str(&self.bootstrap.incarnation).unwrap(),
                },
            )
            .unwrap(),
        }
    }
    fn intent(&self, epoch: u64) -> CommitLifecycleIntent {
        let source = Uuid::new_v4();
        CommitLifecycleIntent {
            command_id: Uuid::new_v4(),
            expected_policy_epoch: epoch,
            installation_sha256: digest(&self.installation).unwrap(),
            authority_partition: self
                .installation
                .partitions
                .first_key_value()
                .unwrap()
                .0
                .clone(),
            tenant: "city".into(),
            source_incarnation: source,
            source_authority_epoch: 1,
            target_incarnation: Uuid::new_v4(),
            checkpoint: FullBackupCheckpoint {
                tenant: "city".into(),
                source_incarnation: source.to_string(),
                revision: 123,
                resident_sha256: "12".repeat(32),
                backup_id: Uuid::new_v4(),
                manifest_ciphertext_sha256: "34".repeat(32),
                key_lineage_digest: "56".repeat(32),
            },
            target_nodes: (1..=3)
                .map(|id| {
                    (
                        id,
                        LifecycleNode {
                            node_id: id,
                            verifier: kasumi_serving::test_utils::fixture_verifier(id),
                            principal: format!("target-{id}"),
                            certificate_sha256: format!("{id:064x}"),
                            attestation_public_key: format!("{:064x}", id + 100),
                        },
                    )
                })
                .collect(),
            phase: LifecyclePhase::Materialize,
            phase_input_sha256: "ab".repeat(32),
            resume_origin: None,
        }
    }
    fn change(&self, epoch: u64) -> BeginControlPolicyChange {
        BeginControlPolicyChange {
            command_id: Uuid::new_v4(),
            expected_policy_epoch: epoch,
            installation_sha256: digest(&self.installation).unwrap(),
            candidate: ControlPolicyCandidate {
                policy: policy("replacement"),
                retire_control: false,
            },
        }
    }
    // Cryptographic fixtures only: these test the control reducer's exact-proof
    // verification; actual issuer drain is covered by issuer integration tests.
    fn stop_fixtures(
        &self,
        change: &ControlPolicyChange,
    ) -> BTreeMap<String, SignedControlEpochStop> {
        self.installation
            .partitions
            .iter()
            .map(|(name, partition)| {
                let observation = ControlEpochStopObservation {
                    stop: control_stop_for(change, partition).unwrap(),
                    accepted_revision: 10,
                    accepted_term: 1,
                    observed_revision: 12,
                    observed_term: 2,
                    drain_ms: partition.drain_ms,
                };
                let signature = self.partition_keys[name]
                    .sign("kasumi.control-epoch-drained.v1", &observation)
                    .unwrap();
                (
                    name.clone(),
                    SignedControlEpochStop {
                        observation,
                        signature,
                    },
                )
            })
            .collect()
    }
    async fn close(&mut self) {
        for (id, db) in &self.nodes {
            self.router.unregister(
                &format!("__kasumi_control/{}", self.bootstrap.incarnation),
                *id,
            );
            db.shutdown().await.unwrap();
        }
        self.nodes.clear();
        for audit in self.audits.values() {
            audit.shutdown().await;
        }
        self.audits.clear();
    }

    fn diagnostics(&self) -> String {
        self.nodes
            .iter()
            .map(|(id, database)| {
                format!(
                    "node {id}: {:?}",
                    database.raft_group().raft().metrics().borrow().clone()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
fn policy(principal: &str) -> Policy {
    Policy {
        grants: vec![Grant {
            principal: principal.into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_control_intent_is_exact_original_expiry_bound_current_quorum_and_permanent_after_reopen()
 {
    let mut f = Fixture::new().await;
    let db = f.leader().await;
    let epoch = db.engine().generation().unwrap().state.policy_epoch;
    let request = f.intent(epoch);
    let original = f.context_for("owner", 2000);
    let receipt = db
        .lifecycle_control(
            original.clone(),
            LifecycleControlCommand::CommitIntent((request.clone()).into()),
        )
        .await
        .unwrap_or_else(|error| panic!("{error:?}\n{}", f.diagnostics()));
    let proof = db
        .observe_lifecycle_intent(original, request.command_id)
        .await
        .unwrap_or_else(|error| panic!("{error:?}\n{}", f.diagnostics()));
    let signed = f.signer.sign_intent(&proof).await.unwrap();
    let trust = ControlTrust::install(f.installation.root.clone()).unwrap();
    trust.verify_intent(&signed).unwrap();
    let mut changed = request.clone();
    changed.phase = LifecyclePhase::Activate;
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent((changed).into())
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    let mut bad = signed.clone();
    bad.observation.intent.revision += 1;
    assert!(trust.verify_intent(&bad).is_err());
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent((request.clone()).into())
        )
        .await
        .unwrap()
        .revision,
        receipt.revision
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(f.signer.sign_intent(&proof).await.is_err());
    assert!(
        db.observe_lifecycle_intent(f.context("owner"), request.command_id)
            .await
            .is_err()
    );
    let mut bytes = Vec::new();
    db.engine()
        .capture_snapshot()
        .unwrap()
        .write(&mut bytes)
        .unwrap();
    db.engine()
        .validate_snapshot(&mut bytes.as_slice())
        .unwrap();
    drop(proof);
    drop(db);
    f.close().await;
    f.open().await;
    let db = f.leader().await;
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent((request.clone()).into())
        )
        .await
        .unwrap()
        .revision,
        receipt.revision
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .intents[&request.command_id],
        signed.observation.intent
    );
    assert!(
        db.observe_lifecycle_intent(f.context("owner"), request.command_id)
            .await
            .is_err()
    );
    drop(db);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_control_materialization_requires_exact_retained_original_after_expiry_and_reopen() {
    let mut f = Fixture::new().await;
    let db = f.leader().await;
    let mut request = f.intent(db.engine().generation().unwrap().state.policy_epoch);
    let input = TargetMaterializationInput {
        destination_alias: "backup-source".into(),
        backup_id: request.checkpoint.backup_id,
        source_purpose_sha256: "78".repeat(32),
        target_incarnation: request.target_incarnation,
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
    request.phase_input_sha256 = input.digest().unwrap();
    let original_context = f.context_for("owner", 2000);
    db.lifecycle_control(
        original_context,
        LifecycleControlCommand::CommitIntent(Box::new(request.clone())),
    )
    .await
    .unwrap();
    let materialization = db
        .engine()
        .generation()
        .unwrap()
        .state
        .lifecycle_control
        .as_ref()
        .unwrap()
        .intents[&request.command_id]
        .clone();
    let origin = TargetOrigin {
        authority_manifest_sha256: f.installation.partitions[&request.authority_partition]
            .manifest_sha256
            .clone(),
        materialization,
        input,
    };
    let mut resume = request.clone();
    resume.command_id = Uuid::new_v4();
    resume.phase = LifecyclePhase::ResumeMaterialize;
    resume.phase_input_sha256 = origin.resume_digest().unwrap();
    resume.resume_origin = Some(Box::new(origin.clone()));
    resume.validate().unwrap();
    for variant in 0..3 {
        let mut substituted = resume.clone();
        substituted.command_id = Uuid::new_v4();
        let forged = substituted.resume_origin.as_mut().unwrap();
        match variant {
            0 => {
                forged.materialization.request.command_id = Uuid::new_v4();
                forged.materialization.request_sha256 =
                    digest(&forged.materialization.request).unwrap();
            }
            1 => forged.materialization.accepted_at_ms += 1,
            _ => forged.authority_manifest_sha256 = "91".repeat(32),
        }
        substituted.phase_input_sha256 = forged.resume_digest().unwrap();
        substituted.validate().unwrap();
        assert_eq!(
            db.lifecycle_control(
                f.context("owner"),
                LifecycleControlCommand::CommitIntent(Box::new(substituted))
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::Conflict
        );
    }
    let mut nested = resume.clone();
    nested
        .resume_origin
        .as_mut()
        .unwrap()
        .materialization
        .request = resume.clone();
    assert!(nested.validate().is_err());
    let mut wrong_source = resume.clone();
    wrong_source.source_incarnation = Uuid::new_v4();
    assert!(wrong_source.validate().is_err());
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert!(
        db.observe_lifecycle_intent(f.context("owner"), request.command_id)
            .await
            .is_err()
    );
    let receipt = db
        .lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent(Box::new(resume.clone())),
        )
        .await
        .unwrap();
    let observed = db
        .observe_lifecycle_intent(f.context("owner"), resume.command_id)
        .await
        .unwrap();
    let signed = f.signer.sign_intent(&observed).await.unwrap();
    assert_eq!(
        signed.observation.intent.request.resume_origin.as_deref(),
        Some(&origin)
    );
    assert!(
        signed.observation.intent.original_credential_expires_at_ms
            > origin.materialization.original_credential_expires_at_ms
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .intents[&request.command_id],
        origin.materialization
    );
    drop(observed);
    let mut snapshot = Vec::new();
    db.engine()
        .capture_snapshot()
        .unwrap()
        .write(&mut snapshot)
        .unwrap();
    db.engine()
        .validate_snapshot(&mut snapshot.as_slice())
        .unwrap();
    drop(db);
    f.close().await;
    f.open().await;
    let db = f.leader().await;
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent(Box::new(resume.clone()))
        )
        .await
        .unwrap()
        .revision,
        receipt.revision
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .intents[&resume.command_id],
        signed.observation.intent
    );
    assert!(
        db.observe_lifecycle_intent(f.context("owner"), request.command_id)
            .await
            .is_err()
    );
    drop(db);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replicated_control_change_pins_all_partitions_freezes_issuance_and_recovers_self_revocation()
 {
    let mut f = Fixture::new().await;
    let db = f.leader().await;
    let epoch = db.engine().generation().unwrap().state.policy_epoch;
    let request = f.intent(epoch);
    db.lifecycle_control(
        f.context("owner"),
        LifecycleControlCommand::CommitIntent((request.clone()).into()),
    )
    .await
    .unwrap();
    let old = db
        .observe_lifecycle_intent(f.context("owner"), request.command_id)
        .await
        .unwrap();
    let change = f.change(epoch);
    db.lifecycle_control(
        f.context("owner"),
        LifecycleControlCommand::BeginPolicyChange(change.clone()),
    )
    .await
    .unwrap();
    assert!(f.signer.sign_intent(&old).await.is_err());
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CommitIntent((f.intent(epoch)).into())
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.administer(
            f.context("owner"),
            Operation::SetPolicy(policy("replacement"))
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    let pending = db
        .observe_lifecycle_change(f.context("owner"), change.command_id)
        .await
        .unwrap();
    let signed = f
        .signer
        .sign_change(
            &pending,
            f.installation.partitions.first_key_value().unwrap().0,
        )
        .await
        .unwrap();
    ControlTrust::install(f.installation.root.clone())
        .unwrap()
        .verify_change(&signed)
        .unwrap();
    let stops = f.stop_fixtures(&pending.observation().change);
    let mut complete = CompleteControlPolicyChange {
        command_id: change.command_id,
        change_sha256: digest(&change).unwrap(),
        stops: stops.clone(),
    };
    complete.stops.pop_first();
    assert_eq!(
        f.rejected_completion(f.context("owner"), complete.clone())
            .await
            .code,
        ErrorCode::Conflict
    );
    complete.stops = stops;
    let mut substituted = complete.clone();
    substituted
        .stops
        .first_entry()
        .unwrap()
        .get_mut()
        .observation
        .stop
        .installation_generation += 1;
    assert_eq!(
        f.rejected_completion(f.context("owner"), substituted)
            .await
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CompletePolicyChange(complete.clone())
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::UnknownOutcome
    );
    assert!(
        f.signer
            .sign_change(
                &pending,
                f.installation.partitions.first_key_value().unwrap().0
            )
            .await
            .is_err()
    );
    let receipt = db
        .lifecycle_control(
            f.context("replacement"),
            LifecycleControlCommand::CompletePolicyChange(complete.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        db.engine().generation().unwrap().state.policy_epoch,
        epoch + 1
    );
    assert!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CompletePolicyChange(complete.clone())
        )
        .await
        .is_err()
    );
    drop(old);
    drop(pending);
    drop(db);
    f.close().await;
    f.open().await;
    let db = f.leader().await;
    assert_eq!(
        db.lifecycle_control(
            f.context("replacement"),
            LifecycleControlCommand::CompletePolicyChange(complete)
        )
        .await
        .unwrap()
        .revision,
        receipt.revision
    );
    drop(db);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_completion_audit_reservation_survives_denials_and_current_admin_status_recovery() {
    let mut f = Fixture::limits(
        Limits {
            audit_retention: AuditRetentionBudget {
                hot_bytes: 128 << 10,
                ..AuditRetentionBudget::default()
            },
            ..Limits::default()
        },
        8 << 20,
    )
    .await;
    let db = f.leader().await;
    let epoch = db.engine().generation().unwrap().state.policy_epoch;
    let change = f.change(epoch);
    db.lifecycle_control(
        f.context("owner"),
        LifecycleControlCommand::BeginPolicyChange(change.clone()),
    )
    .await
    .unwrap();
    assert_eq!(db.engine().generation().unwrap().state.audits.len(), 2);
    // Use two bounded large records to bring the real byte budget near full.
    // The following denied lifecycle commands exercise the reserved remainder
    // without making this capacity test depend on hundreds of elections.
    for number in 0..2 {
        let context = f.context("owner");
        let now = kasumi_clock::EpochClock::system()
            .unwrap()
            .now_ms()
            .unwrap();
        let command = Command {
            context: context.clone(),
            timestamp_ms: now,
            operation: Operation::Audit(AuditEvent {
                event_id: format!("{number}:{}", "x".repeat(60_000)),
                principal: context.principal,
                action: "read".into(),
                request_id: context.request_id,
                timestamp_ms: now,
                data_revision: Some(db.engine().generation().unwrap().state.revision),
                outcome: "authorized_release".into(),
                collection: None,
            }),
        };
        let bytes = db
            .raft_group()
            .write(serde_json::to_vec(&command).unwrap())
            .await
            .unwrap();
        serde_json::from_slice::<Result<WriteReceipt>>(&bytes)
            .unwrap()
            .unwrap();
    }
    // Fill the byte budget with denied attempts. Completion reserves the full
    // worst-case record even when the original administrative request was short.
    // This fixture has no archive worker: observe the absolute retained history
    // cursor and require the actual ordered budget rejection, not an unchanged
    // vector length following an unavailable/ambiguous request.
    assert!(db.audit_maintenance_status().is_none());
    let audit_sequence = |db: &Database| {
        let generation = db.engine().generation().unwrap();
        let retention = &generation.state.audit_retention;
        assert_eq!(
            retention.next_sequence - retention.pruned_before,
            generation.state.audits.len() as u64
        );
        retention.next_sequence
    };
    let initial_sequence = audit_sequence(&db);
    let mut retained = initial_sequence;
    for attempt in 0..2000 {
        let error = f.rejected_intent(f.context("owner"), f.intent(epoch)).await;
        let count = audit_sequence(f.leader().await.as_ref());
        match error.code {
            ErrorCode::Conflict => {
                assert_eq!(error.message, "lifecycle issuance is closed");
                assert!(count > retained, "ordered denial must retain its audit");
                retained = count;
            }
            ErrorCode::AuditUnavailable => {
                assert_eq!(
                    error.message,
                    "required audit cannot fit serialized tenant budget"
                );
                // A prior ambiguous retry may already have filled the remaining
                // room, but the definitive capacity rejection adds no event.
                assert!(count >= retained);
                retained = count;
                break;
            }
            _ => panic!("unexpected closed-issuance result: {error:?}"),
        }
        assert!(attempt < 1999, "completion byte budget did not fill");
    }
    assert!(retained > initial_sequence);
    for _ in 0..3 {
        let error = f.rejected_intent(f.context("owner"), f.intent(epoch)).await;
        assert_eq!(error.code, ErrorCode::AuditUnavailable);
        assert_eq!(
            error.message,
            "required audit cannot fit serialized tenant budget"
        );
        assert_eq!(audit_sequence(f.leader().await.as_ref()), retained);
    }
    drop(db);
    let db = f.leader().await;
    let pending = db
        .observe_lifecycle_change(f.context("owner"), change.command_id)
        .await
        .unwrap();
    let complete = CompleteControlPolicyChange {
        command_id: change.command_id,
        change_sha256: digest(&change).unwrap(),
        stops: f.stop_fixtures(&pending.observation().change),
    };
    assert_eq!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::CompletePolicyChange(complete)
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(audit_sequence(f.leader().await.as_ref()), retained + 1);
    let request = ReadLifecycleStatus {
        command_id: change.command_id,
        expected_incarnation: f.installation.root.control_incarnation,
    };
    assert!(
        db.read_lifecycle_status(&f.context("owner"), request.clone())
            .await
            .is_err()
    );
    let status = db
        .read_lifecycle_status(&f.context("replacement"), request.clone())
        .await
        .unwrap();
    assert!(
        matches!(status.command,Some(LifecycleCommandStatus::PolicyChange(ref c)) if c.completed_revision.is_some() && c.completion_stops.as_ref().unwrap().len()==2)
    );
    assert_eq!(audit_sequence(f.leader().await.as_ref()), retained + 1);
    drop(pending);
    drop(db);
    f.close().await;
    f.open().await;
    let db = f.leader().await;
    db.read_lifecycle_status(&f.context("replacement"), request)
        .await
        .unwrap();
    drop(db);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_rejects_unfinishable_byte_budget_and_substituted_authenticated_history() {
    let mut f = Fixture::limits(Limits::default(), 8192).await;
    let db = f.leader().await;
    let epoch = db.engine().generation().unwrap().state.policy_epoch;
    let mut change = f.change(epoch);
    for n in 0..70 {
        change.candidate.policy.grants.push(Grant {
            principal: format!("long-candidate-principal-{n}"),
            collection: None,
            actions: BTreeSet::from([Action::Read]),
        });
    }
    assert!(
        db.lifecycle_control(
            f.context("owner"),
            LifecycleControlCommand::BeginPolicyChange(change)
        )
        .await
        .is_err()
    );
    assert!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .lifecycle_control
            .as_ref()
            .unwrap()
            .pending_change
            .is_none()
    );
    let intent = f.intent(epoch);
    db.lifecycle_control(
        f.context("owner"),
        LifecycleControlCommand::CommitIntent((intent.clone()).into()),
    )
    .await
    .unwrap();
    let original = db.engine().fixture_snapshot().unwrap();
    let mut state: TenantState =
        kasumi_engine::test_utils::decode_snapshot_candidate(&original).unwrap();
    let retained = state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .get_mut(&intent.command_id)
        .unwrap();
    retained.original_credential_expires_at_ms += 1000;
    assert!(
        db.engine()
            .fixture_restore(
                &kasumi_engine::test_utils::encode_snapshot_candidate(&state, 64 << 20).unwrap()
            )
            .is_err()
    );
    assert_eq!(original, db.engine().fixture_snapshot().unwrap());
    let proof = db
        .observe_lifecycle_intent(f.context("owner"), intent.command_id)
        .await
        .unwrap();
    let node = db.raft_group().raft().metrics().borrow().id;
    let group = format!("__kasumi_control/{}", f.bootstrap.incarnation);
    f.router.isolate(&group, node, true);
    assert!(f.signer.sign_intent(&proof).await.is_err());
    f.router.isolate(&group, node, false);
    drop(proof);
    drop(db);
    f.close().await;
}

#[path = "common/recovery_control.rs"]
mod recovery_control;
