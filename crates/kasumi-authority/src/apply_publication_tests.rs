use super::*;
use kasumi_clock::{EpochClock, LeaseClock, WallClock};
use kasumi_raft::PublishCallError;
use kasumi_store::{NodeStore, TenantStorageSet, test_utils::LocalKeyProvider};
use kasumi_types::{Action, CredentialResource, RequestAuthorization};
use std::time::Duration;

struct Clock;
impl LeaseClock for Clock {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
}
impl WallClock for Clock {
    fn now_ms(&self) -> Result<u64> {
        Ok(1_000_000)
    }
}

// No Raft task is started: this local publisher exercises the identical prepared
// path and can stop at its only durable boundary without racing a live group.
struct Fixture {
    backend: Arc<Backend>,
    stores: Arc<TenantStorageSet>,
    node: Arc<NodeStore>,
    context: RequestContext,
    signing_root: InstallationSigningRoot,
    _storage: kasumi_engine::test_utils::FixtureStorage,
    _directory: tempfile::TempDir,
    _scratch_directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let persistent =
            kasumi_store::NodeDisk::fixture_config(directory.path().join("node.kv")).unwrap();
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: scratch_directory.path().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
            native_cache_bytes: 8 << 20,
        };
        let storage = kasumi_engine::test_utils::FixtureStorage::open(
            &persistent,
            &scratch,
            Default::default(),
        )
        .unwrap();
        let node = storage
            .create_new(
                directory.path().join("authority.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let root =
            kasumi_serving::test_utils::FixtureSigningRoot::from_pkcs8(key.as_ref()).unwrap();
        let installation = AuthorityInstallation {
            manifest: AuthorityManifest {
                lifecycle_controls: BTreeMap::new(),
                authority_id: Uuid::new_v4(),
                max_lease_ms: 1000,
                clock_rate_error_ppm: 0,
                partitions: BTreeMap::from([(
                    0,
                    AuthorityPartition {
                        group: "authority-publication".into(),
                        public_key: root.public_key(),
                    },
                )]),
            },
            partition: 0,
        };
        let signing = root.install(installation.manifest.clone(), 0).unwrap();
        let signing_root = InstallationSigningRoot::from_pkcs8(
            installation.manifest.signing_domain(0).unwrap(),
            key.as_ref(),
        )
        .unwrap();
        let bootstrap = AuthorityBootstrap {
            initial_signer_certificate: signing.signer.certificate().clone(),
            administrators: BTreeSet::from(["operator".into()]),
            capacity: AuthorityCapacity {
                max_tenants: 100,
                max_state_bytes: 5 << 20,
                maintenance_reserve_bytes: 1 << 20,
            },
            membership: AuthorityMembership {
                voters: BTreeSet::from([1, 2, 3]),
                members: (1..=3)
                    .map(|id| {
                        (
                            id,
                            AuthorityMember {
                                verifier: kasumi_serving::test_utils::fixture_verifier(id),
                                endpoint: format!("https://authority-{id}.test"),
                                failure_domain: format!("domain-{id}"),
                                certificate_pins: BTreeSet::from([format!("{id:064x}")]),
                            },
                        )
                    })
                    .collect(),
            },
        };
        let stores = TenantStorageSet::initialize_catalogs(
            node.clone(),
            installation.tenant(),
            Arc::new(LocalKeyProvider::new([1; 32])),
            Arc::new(LocalKeyProvider::new([2; 32])),
            kasumi_store::StorageAccess::independent_authority(
                &installation.manifest,
                installation.partition,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        crate::bootstrap::initialize(
            &stores,
            &installation,
            &bootstrap,
            &kasumi_serving::test_utils::fixture_verifier(1),
        )
        .unwrap();
        let backend = Backend::open_existing(
            stores.application().clone(),
            installation.clone(),
            &bootstrap,
            64 << 20,
        )
        .unwrap();
        let epoch = EpochClock::new(Arc::new(Clock), Arc::new(Clock)).unwrap();
        let context = RequestContext {
            tenant: installation.tenant(),
            principal: "operator".into(),
            request_id: Uuid::new_v4().to_string(),
            scopes: BTreeSet::from([Action::Admin, Action::Read]),
            authorization: RequestAuthorization::from_verified_credential(
                2_000_000,
                &epoch.observe().unwrap(),
                CredentialResource::Authority {
                    authority_id: installation.manifest.authority_id,
                    partition: installation.partition,
                },
            )
            .unwrap(),
        };
        Self {
            backend,
            stores,
            node,
            context,
            signing_root,
            _storage: storage,
            _directory: directory,
            _scratch_directory: scratch_directory,
        }
    }
    fn command(&self) -> PreparedCommand {
        PreparedCommand {
            context: self.context.clone(),
            command: AuthorityCommand {
                tenant: "city".into(),
                command_id: Uuid::new_v4(),
                expected_policy_epoch: 1,
                not_after_ms: 1_500_000,
                action: AuthorityAction::Enroll {
                    incarnation: Uuid::new_v4(),
                    nodes: (1..=3)
                        .map(|id| NodeIdentity {
                            node_id: id,
                            verifier: kasumi_serving::test_utils::fixture_verifier(id),
                            principal: format!("node-{id}"),
                            certificate_sha256: format!("{id:064x}"),
                        })
                        .collect(),
                },
            },
            admitted_at_ms: 1_000_000,
            authority_term: 7,
            drained_fence: None,
        }
    }
    fn maintenance(&self, action: AuthorityMaintenanceAction) -> PreparedMaintenance {
        PreparedMaintenance {
            context: self.context.clone(),
            transition: maintenance_state::MaintenanceTransition::Begin {
                command: AuthorityMaintenanceCommand {
                    operation_id: Uuid::new_v4(),
                    expected_policy_epoch: 1,
                    expected_operational_revision: self
                        .backend
                        .meta()
                        .unwrap()
                        .operational
                        .revision,
                    not_after_ms: 1_500_000,
                    action,
                },
            },
            admitted_at_ms: 1_000_000,
            authority_term: 7,
        }
    }
    fn certificate(&self, generation: u64) -> SigningCertificate {
        use ring::signature::KeyPair;
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        self.signing_root
            .certify(generation, hex::encode(key.public_key().as_ref()))
            .unwrap()
    }
    fn publish_maintenance(
        &self,
        index: u64,
        prepared: PreparedMaintenance,
    ) -> AuthorityMaintenanceStatus {
        let bytes =
            serde_json::to_vec(&PreparedOperation::Maintenance(Box::new(prepared))).unwrap();
        let mut publisher = LocalPublisher::new(&self.backend, false);
        let result = self.backend.apply_with_publisher(
            &position(index),
            AppliedInput::Command(&bytes),
            &mut publisher,
        );
        let response = publisher.finish(result).unwrap();
        serde_json::from_slice::<kasumi_types::Result<AuthorityMaintenanceStatus>>(&response.data)
            .unwrap()
            .unwrap()
    }
    fn enroll_signer_verifiers(&self, first_index: u64) {
        for (offset, member) in self
            .backend
            .meta()
            .unwrap()
            .operational
            .membership
            .members
            .values()
            .enumerate()
        {
            let enrollment = self.maintenance(AuthorityMaintenanceAction::EnrollSignerVerifier {
                enrollment: SignerVerifierEnrollment {
                    verifier: member.verifier.clone(),
                    endpoint: format!("{}/", member.endpoint),
                    certificate_pins: member.certificate_pins.clone(),
                },
            });
            assert_eq!(
                self.publish_maintenance(first_index + offset as u64, enrollment)
                    .phase,
                AuthorityMaintenancePhase::Completed
            );
        }
    }
    async fn close(self) {
        self.stores.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

fn position(index: u64) -> AppliedEntryContext {
    AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(7, 1), index),
        previous: None,
        membership: Default::default(),
        command_sha256: "ab".repeat(32),
        retirement_seed: None,
    }
}

#[derive(Debug)]
struct RefusedPublication;
impl std::fmt::Display for RefusedPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixture refused before publication")
    }
}
impl std::error::Error for RefusedPublication {}

struct LocalPublisher<'a> {
    backend: &'a Backend,
    before: Vec<u8>,
    calls: usize,
    writes: usize,
    response: Option<AppliedResponse>,
    failure: Option<anyhow::Error>,
}
impl<'a> LocalPublisher<'a> {
    fn new(backend: &'a Backend, refuse: bool) -> Self {
        Self {
            backend,
            before: backend
                .store
                .get_bounded(NS, META, MAX_RECORD_BYTES)
                .unwrap()
                .unwrap(),
            calls: 0,
            writes: 0,
            response: None,
            failure: refuse.then(|| RefusedPublication.into()),
        }
    }
    fn finish(mut self, result: Result<()>) -> Result<AppliedResponse> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        result?;
        assert_eq!(self.calls, 1);
        Ok(self.response.take().unwrap())
    }
}
impl ApplyPublisher for LocalPublisher<'_> {
    fn with_completion(
        &mut self,
        _: &kasumi_raft::CompletionIdentity,
        _: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        Err(kasumi_raft::CompletionCallError::Unsupported)
    }

    fn commit_with_selection<'call>(
        &mut self,
        _: AppliedResponse,
        _: &[WriteOp],
        _: &mut dyn kasumi_raft::SelectionPreparer,
        _: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<kasumi_raft::JointPublicationReceipt<'call>, PublishCallError> {
        self.failure.get_or_insert_with(|| {
            anyhow::anyhow!("authority-only fixture has no application source plan")
        });
        Err(PublishCallError::Failed)
    }

    fn commit(
        &mut self,
        response: AppliedResponse,
        writes: &[WriteOp],
    ) -> std::result::Result<(), PublishCallError> {
        self.calls += 1;
        assert_eq!(self.calls, 1);
        assert!(self.backend.mutation.try_lock().is_err());
        assert_eq!(
            self.backend
                .store
                .get_bounded(NS, META, MAX_RECORD_BYTES)
                .unwrap()
                .unwrap(),
            self.before,
            "application state changed before its publication callback"
        );
        assert!(response.retirement.is_none());
        if !response.data.is_empty() {
            serde_json::from_slice::<serde_json::Value>(&response.data).unwrap();
        }
        self.writes = writes.len();
        self.response = Some(response);
        if self.failure.is_some() {
            return Err(PublishCallError::Failed);
        }
        if let Err(error) = self.backend.store.write_batch(writes) {
            self.failure = Some(error);
            return Err(PublishCallError::Failed);
        }
        Ok(())
    }
}

#[tokio::test]
async fn command_response_and_writes_are_prepared_before_single_guarded_publication() {
    let fixture = Fixture::new().await;
    let command = fixture.command();
    let bytes = serde_json::to_vec(&PreparedOperation::Administrative(Box::new(
        command.clone(),
    )))
    .unwrap();
    let mut denied = LocalPublisher::new(&fixture.backend, true);
    let result = fixture.backend.apply_with_publisher(
        &position(10),
        AppliedInput::Command(&bytes),
        &mut denied,
    );
    assert!(result.as_ref().unwrap_err().is::<PublishCallError>());
    assert_eq!(denied.calls, 1);
    assert!(denied.writes >= 3);
    let receipt: kasumi_types::Result<AuthorityReceipt> =
        serde_json::from_slice(&denied.response.as_ref().unwrap().data).unwrap();
    assert!(matches!(
        receipt.unwrap().outcome,
        AuthorityOutcome::Enrolled { .. }
    ));
    assert!(
        denied
            .finish(result)
            .err()
            .unwrap()
            .is::<RefusedPublication>()
    );
    assert!(
        fixture
            .backend
            .receipt("city", command.command.command_id)
            .unwrap()
            .is_none()
    );
    assert!(fixture.backend.tenant_record("city").unwrap().is_none());
    assert_eq!(fixture.backend.meta().unwrap().revision, 0);

    let mut publisher = LocalPublisher::new(&fixture.backend, false);
    let result = fixture.backend.apply_with_publisher(
        &position(10),
        AppliedInput::Command(&bytes),
        &mut publisher,
    );
    let response = publisher.finish(result).unwrap();
    let receipt: kasumi_types::Result<AuthorityReceipt> =
        serde_json::from_slice(&response.data).unwrap();
    assert_eq!(receipt.unwrap().revision, 10);
    assert_eq!(fixture.backend.meta().unwrap().revision, 10);
    // Permanent exact replay still calls the joint publisher, without rewriting
    // the original receipt or inventing a newer application generation.
    let mut replay = LocalPublisher::new(&fixture.backend, false);
    let result = fixture.backend.apply_with_publisher(
        &position(11),
        AppliedInput::Command(&bytes),
        &mut replay,
    );
    assert_eq!(replay.writes, 0);
    assert_eq!(replay.finish(result).unwrap().data, response.data);
    assert_eq!(fixture.backend.meta().unwrap().revision, 10);
    fixture.close().await;
}

#[tokio::test]
async fn metadata_publishes_once_for_future_and_covered_positions() {
    let fixture = Fixture::new().await;
    let mut denied = LocalPublisher::new(&fixture.backend, true);
    let result =
        fixture
            .backend
            .apply_with_publisher(&position(3), AppliedInput::Metadata, &mut denied);
    assert_eq!(denied.calls, 1);
    assert_eq!(denied.writes, 1);
    assert!(denied.response.as_ref().unwrap().data.is_empty());
    assert!(
        denied
            .finish(result)
            .err()
            .unwrap()
            .is::<RefusedPublication>()
    );
    assert_eq!(fixture.backend.meta().unwrap().revision, 0);
    for index in [3, 3, 2] {
        let expected_writes = usize::from(fixture.backend.meta().unwrap().revision < index);
        let mut publisher = LocalPublisher::new(&fixture.backend, false);
        let result = fixture.backend.apply_with_publisher(
            &position(index),
            AppliedInput::Metadata,
            &mut publisher,
        );
        assert_eq!(publisher.writes, expected_writes);
        assert!(publisher.finish(result).unwrap().data.is_empty());
        assert_eq!(fixture.backend.meta().unwrap().revision, 3);
    }
    fixture.close().await;
}

#[tokio::test]
async fn maintenance_publication_refusal_preserves_original_capacity_and_receipt_absence() {
    let fixture = Fixture::new().await;
    let before = fixture.backend.meta().unwrap();
    let prepared = fixture.maintenance(AuthorityMaintenanceAction::SetCapacity {
        capacity: AuthorityCapacity {
            max_tenants: 101,
            ..before.operational.capacity.clone()
        },
    });
    let operation_id = prepared.transition.operation_id();
    let bytes = serde_json::to_vec(&PreparedOperation::Maintenance(Box::new(prepared))).unwrap();
    let mut publisher = LocalPublisher::new(&fixture.backend, true);
    let result = fixture.backend.apply_with_publisher(
        &position(4),
        AppliedInput::Command(&bytes),
        &mut publisher,
    );
    assert_eq!(publisher.calls, 1);
    assert_eq!(publisher.writes, 2);
    let status: kasumi_types::Result<AuthorityMaintenanceStatus> =
        serde_json::from_slice(&publisher.response.as_ref().unwrap().data).unwrap();
    assert_eq!(status.unwrap().phase, AuthorityMaintenancePhase::Completed);
    assert!(
        publisher
            .finish(result)
            .err()
            .unwrap()
            .is::<RefusedPublication>()
    );
    assert_eq!(
        fixture.backend.meta().unwrap().operational.capacity,
        before.operational.capacity
    );
    assert!(
        fixture
            .backend
            .maintenance_status(operation_id)
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn private_partial_writes_are_discarded_when_final_quota_rejects() {
    let fixture = Fixture::new().await;
    let mut meta = fixture.backend.meta().unwrap();
    meta.operational.capacity.max_tenants = 0;
    fixture
        .backend
        .store
        .write_batch(&[WriteOp::put(NS, META, serde_json::to_vec(&meta).unwrap())])
        .unwrap();
    let command = fixture.command();
    let bytes = serde_json::to_vec(&PreparedOperation::Administrative(Box::new(
        command.clone(),
    )))
    .unwrap();
    let mut publisher = LocalPublisher::new(&fixture.backend, false);
    let result = fixture.backend.apply_with_publisher(
        &position(4),
        AppliedInput::Command(&bytes),
        &mut publisher,
    );
    assert_eq!(publisher.calls, 1);
    assert_eq!(publisher.writes, 0);
    let response = publisher.finish(result).unwrap();
    let rejected: kasumi_types::Result<AuthorityReceipt> =
        serde_json::from_slice(&response.data).unwrap();
    assert_eq!(rejected.unwrap_err().code, ErrorCode::ResourceExhausted);
    assert_eq!(fixture.backend.meta().unwrap().revision, 0);
    assert!(
        fixture
            .backend
            .receipt("city", command.command.command_id)
            .unwrap()
            .is_none()
    );
    assert!(fixture.backend.tenant_record("city").unwrap().is_none());
    fixture.close().await;
}

#[tokio::test]
async fn effect_and_maintenance_record_decode_failures_never_publish_a_rejection() {
    let fixture = Fixture::new().await;
    let command = fixture.command();
    let AuthorityAction::Enroll { incarnation, .. } = &command.command.action else {
        unreachable!()
    };
    fixture
        .backend
        .store
        .write_batch(&[WriteOp::put(
            NS,
            key_target_stop("city", *incarnation).as_bytes(),
            b"invalid JSON".to_vec(),
        )])
        .unwrap();
    let administrative = PreparedOperation::Administrative(Box::new(command));
    fixture
        .backend
        .store
        .write_batch(&[WriteOp::put(
            NS,
            b"revoked-member/00000000000000000004",
            b"invalid JSON".to_vec(),
        )])
        .unwrap();
    let maintenance = PreparedOperation::Maintenance(Box::new(fixture.maintenance(
        AuthorityMaintenanceAction::EnrollLearner {
            node_id: 4,
            member: AuthorityMember {
                verifier: kasumi_serving::test_utils::fixture_verifier(4),
                endpoint: "https://authority-4.test".into(),
                failure_domain: "domain-4".into(),
                certificate_pins: BTreeSet::from([format!("{:064x}", 4)]),
            },
        },
    )));
    for operation in [administrative, maintenance] {
        let bytes = serde_json::to_vec(&operation).unwrap();
        let mut publisher = LocalPublisher::new(&fixture.backend, false);
        let error = fixture
            .backend
            .apply_with_publisher(&position(4), AppliedInput::Command(&bytes), &mut publisher)
            .unwrap_err();
        assert!(
            error.is::<serde_json::Error>(),
            "original decoding error must survive: {error:#}"
        );
        assert_eq!(publisher.calls, 0);
        assert_eq!(fixture.backend.meta().unwrap().revision, 0);
    }
    let mut publisher = LocalPublisher::new(&fixture.backend, false);
    assert!(
        fixture
            .backend
            .apply_with_publisher(
                &position(4),
                AppliedInput::Command(b"not a command"),
                &mut publisher
            )
            .unwrap_err()
            .is::<serde_json::Error>()
    );
    assert_eq!(publisher.calls, 0);
    fixture.close().await;
}

#[tokio::test]
async fn signer_stage_keeps_prepared_roster_private_and_replays_exact_publication() {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new().await;
    fixture.enroll_signer_verifiers(1);
    let prepared = fixture.maintenance(AuthorityMaintenanceAction::StageSignerGeneration {
        certificate: fixture.certificate(2),
    });
    let operation_id = prepared.transition.operation_id();
    let bytes = serde_json::to_vec(&PreparedOperation::Maintenance(Box::new(prepared))).unwrap();
    let before = fixture.backend.meta().unwrap();
    let mut denied = LocalPublisher::new(&fixture.backend, true);
    let result = fixture.backend.apply_with_publisher(
        &position(4),
        AppliedInput::Command(&bytes),
        &mut denied,
    );
    assert!(result.as_ref().unwrap_err().is::<PublishCallError>());
    assert_eq!(denied.calls, 1);
    assert_eq!(denied.writes, 3);
    let prepared_response = denied.response.as_ref().unwrap().data.clone();
    let prepared_status: kasumi_types::Result<AuthorityMaintenanceStatus> =
        serde_json::from_slice(&prepared_response).unwrap();
    assert_eq!(
        prepared_status.unwrap().phase,
        AuthorityMaintenancePhase::Completed
    );
    assert!(
        denied
            .finish(result)
            .err()
            .unwrap()
            .is::<RefusedPublication>()
    );
    assert_eq!(
        serde_json::to_vec(&fixture.backend.meta().unwrap()).unwrap(),
        serde_json::to_vec(&before).unwrap()
    );
    assert!(
        fixture
            .backend
            .maintenance_status(operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .backend
            .record(&signer_roster::roster_key(operation_id))
            .unwrap()
            .is_none()
    );

    // The fixture's refusal is known to have performed no write. A fresh apply
    // must derive the same roster from the unchanged authoritative generation.
    let mut publisher = LocalPublisher::new(&fixture.backend, false);
    let result = fixture.backend.apply_with_publisher(
        &position(4),
        AppliedInput::Command(&bytes),
        &mut publisher,
    );
    let response = publisher.finish(result).unwrap();
    assert_eq!(response.data, prepared_response);
    let meta = fixture.backend.meta().unwrap();
    let stage = meta.signing.staged.as_ref().unwrap();
    assert_eq!(stage.operation_id, operation_id);
    assert_eq!(stage.revision, 4);
    assert_eq!(meta.signer_rosters, 1);
    let Some(Record::SignerRoster(retained)) = fixture
        .backend
        .record(&signer_roster::roster_key(operation_id))
        .unwrap()
    else {
        panic!("published stage omitted its permanent roster")
    };
    assert_eq!(retained.roster, stage.roster);
    assert_eq!(retained.operation_id, operation_id);
    assert_eq!(retained.revision, 4);

    // The wire digest uses canonical plaintext-key order, independent of the
    // encrypted directory's iteration order and the preparation's scratch owner.
    let mut records = BTreeMap::new();
    for member in meta.operational.membership.members.values() {
        let key = signer_roster::verifier_key(&member.verifier);
        records.insert(key.clone(), fixture.backend.record(&key).unwrap().unwrap());
    }
    let mut hash = Sha256::new();
    hash.update(b"kasumi.physical-verifier-roster.v1");
    for (key, record) in &records {
        let value = serde_json::to_vec(record).unwrap();
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key.as_bytes());
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(&value);
    }
    assert_eq!(
        stage.roster,
        SignerVerifierRoster {
            enrollment_count: 3,
            control_count: 0,
            sha256: hex::encode(hash.finalize()),
        }
    );
    let mut replay = LocalPublisher::new(&fixture.backend, false);
    let result = fixture.backend.apply_with_publisher(
        &position(5),
        AppliedInput::Command(&bytes),
        &mut replay,
    );
    assert_eq!(replay.writes, 0);
    assert_eq!(replay.finish(result).unwrap().data, response.data);
    assert_eq!(
        serde_json::to_vec(&fixture.backend.meta().unwrap()).unwrap(),
        serde_json::to_vec(&meta).unwrap()
    );
    let mut snapshot = Vec::new();
    fixture
        .backend
        .capture_snapshot()
        .unwrap()
        .write(&mut snapshot)
        .unwrap();
    assert!(
        fixture
            .backend
            .validate_snapshot(&mut snapshot.as_slice())
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn signer_stage_preserves_coverage_rejection_order_and_permanent_replay() {
    let fixture = Fixture::new().await;
    // Structurally valid, but generation three is not the initial successor.
    let action = AuthorityMaintenanceAction::StageSignerGeneration {
        certificate: fixture.certificate(3),
    };
    let prepared = fixture.maintenance(action.clone());
    let rejected = fixture.publish_maintenance(1, prepared.clone());
    let AuthorityMaintenancePhase::Rejected { code, message } = &rejected.phase else {
        panic!("missing physical coverage was accepted")
    };
    assert_eq!(*code, ErrorCode::Conflict);
    assert_eq!(
        message,
        "physical verifier lacks its exact permanent administrative enrollment"
    );
    fixture.enroll_signer_verifiers(2);
    // Enrollment does not retroactively replace the original permanent outcome.
    assert_eq!(fixture.publish_maintenance(5, prepared), rejected);
    let rejected = fixture.publish_maintenance(6, fixture.maintenance(action));
    let AuthorityMaintenancePhase::Rejected { code, message } = rejected.phase else {
        panic!("a non-successor certificate was accepted")
    };
    assert_eq!(code, ErrorCode::Conflict);
    assert_eq!(
        message,
        "global signer stage requires an unoccupied exact successor and completed prior retirement"
    );
    let meta = fixture.backend.meta().unwrap();
    assert!(meta.signing.staged.is_none());
    assert_eq!(meta.signer_rosters, 0);
    fixture.close().await;
}

#[tokio::test]
async fn signer_activation_roster_failure_remains_outer_without_publishing_rejection() {
    let fixture = Fixture::new().await;
    fixture.enroll_signer_verifiers(1);
    let certificate = fixture.certificate(2);
    let stage = fixture.publish_maintenance(
        4,
        fixture.maintenance(AuthorityMaintenanceAction::StageSignerGeneration {
            certificate: certificate.clone(),
        }),
    );
    assert_eq!(stage.phase, AuthorityMaintenancePhase::Completed);
    let before = fixture.backend.meta().unwrap();
    let activation = fixture.maintenance(AuthorityMaintenanceAction::ActivateSignerGeneration {
        stage_operation_id: stage.command.operation_id,
        certificate_sha256: certificate.digest().unwrap(),
    });
    let operation_id = activation.transition.operation_id();
    // Simulate losing a required permanent physical fact after staging. The
    // exact stage identity is still valid; activation's coverage failure must
    // retain its outer error and may not become a successful rejected receipt.
    let verifier = &before.operational.membership.members[&1].verifier;
    fixture
        .backend
        .store
        .write_batch(&[WriteOp::delete(
            NS,
            signer_roster::verifier_key(verifier).as_bytes(),
        )])
        .unwrap();
    let bytes = serde_json::to_vec(&PreparedOperation::Maintenance(Box::new(activation))).unwrap();
    let mut publisher = LocalPublisher::new(&fixture.backend, false);
    let error = fixture
        .backend
        .apply_with_publisher(&position(5), AppliedInput::Command(&bytes), &mut publisher)
        .unwrap_err();
    assert!(error.is::<PreparedRejection>());
    assert_eq!(publisher.calls, 0);
    assert!(
        fixture
            .backend
            .maintenance_status(operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        serde_json::to_vec(&fixture.backend.meta().unwrap()).unwrap(),
        serde_json::to_vec(&before).unwrap()
    );
    fixture.close().await;
}
