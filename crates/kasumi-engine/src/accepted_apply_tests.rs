use super::*;
use serde_json::json;

struct Fixture {
    engine: TenantEngine,
    disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let disk = kasumi_store::ScratchDisk::fixture(
            directory.path().join("scratch"),
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        );
        let engine = TenantEngine::new(
            "tenant".into(),
            "incarnation".into(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Read, Action::Write, Action::Admin]
                        .into_iter()
                        .collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        Self {
            engine,
            disk,
            _directory: directory,
        }
    }
    fn lock(&self) -> ApplyOwner<'_> {
        ApplyOwner::lock(&self.engine, || anyhow::anyhow!("fixture apply poisoned")).unwrap()
    }
    fn command(&self, revision: u64, operation: Operation) -> Command {
        Command {
            context: RequestContext {
                authorization: RequestAuthorization::service_identity(),
                principal: "owner".into(),
                tenant: "tenant".into(),
                scopes: [Action::Read, Action::Write, Action::Admin]
                    .into_iter()
                    .collect(),
                request_id: format!("request-{revision}"),
            },
            timestamp_ms: revision,
            operation,
        }
    }
    fn prepare(
        &self,
        owner: &ApplyOwner<'_>,
        revision: u64,
        operation: Operation,
    ) -> PreparedCommand {
        let command = self.command(revision, operation);
        let applied = crate::staged_terminal::AppliedIdentity {
            incarnation: self.engine.incarnation.clone(),
            revision,
            timestamp_ms: command.timestamp_ms,
            command_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&command).unwrap())),
            origin: crate::staged_terminal::AppliedOrigin::Fixture,
        };
        self.engine
            .prepare_command_ordered(
                owner,
                &command,
                &applied,
                &ApplyScope::Fixture(self.disk.clone()),
            )
            .unwrap()
    }
    fn create(&self, history: bool) {
        self.engine
            .apply_command(
                &self.disk,
                1,
                self.command(
                    1,
                    Operation::CreateCollection(CollectionDefinition {
                        name: "docs".into(),
                        schema: json!({"type":"object"}),
                        indexes: vec![],
                        strict_read_audit: false,
                        retention_class: if history {
                            CollectionRetentionClass::ArchivableHistory
                        } else {
                            CollectionRetentionClass::Operational
                        },
                        write_mode: if history {
                            CollectionWriteMode::AppendOnly
                        } else {
                            CollectionWriteMode::Mutable
                        },
                    }),
                ),
            )
            .unwrap()
            .unwrap();
    }
    fn put(&self, revision: u64, key: &str) {
        self.engine
            .apply_command(
                &self.disk,
                revision,
                self.command(revision, mutation(key, Precondition::Any)),
            )
            .unwrap()
            .unwrap();
    }
}
fn mutation(key: &str, expected: Precondition) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "row".into(),
            body: json!({"value":key}),
            expected,
        }],
    })
}
fn locked(engine: &TenantEngine) {
    assert!(matches!(
        engine.apply_lock.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
}
struct Publisher<'a> {
    engine: &'a TenantEngine,
    previous: Arc<Generation>,
    fail: bool,
    calls: usize,
}
impl kasumi_raft::ApplyPublisher for Publisher<'_> {
    fn with_completion(
        &mut self,
        _: &kasumi_raft::CompletionIdentity,
        _: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        Err(kasumi_raft::CompletionCallError::Unsupported)
    }

    fn commit_with_selection<'call>(
        &mut self,
        _: kasumi_raft::AppliedResponse,
        _: &[kasumi_store::WriteOp],
        _: &mut dyn kasumi_raft::SelectionPreparer,
        _: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<
        kasumi_raft::JointPublicationReceipt<'call>,
        kasumi_raft::PublishCallError,
    > {
        panic!("uninstalled fixture cannot publish selected storage")
    }
    fn commit(
        &mut self,
        _: kasumi_raft::AppliedResponse,
        writes: &[kasumi_store::WriteOp],
    ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
        self.calls += 1;
        locked(self.engine);
        assert!(writes.is_empty());
        assert!(Arc::ptr_eq(
            &self.previous,
            &self.engine.generation().unwrap()
        ));
        if self.fail {
            Err(kasumi_raft::PublishCallError::Failed)
        } else {
            Ok(())
        }
    }
}

#[test]
fn accepted_apply_retains_actual_delta_allocation_and_guard_through_publication() {
    let fixture = Fixture::new();
    fixture.create(false);
    let owner = fixture.lock();
    let prepared = fixture.prepare(&owner, 2, mutation("accepted", Precondition::Any));
    assert!(prepared.outcome.is_ok());
    let collection_key = prepared.changed.keys().next().unwrap().as_ptr();
    let row_key = prepared.changed["docs"].first().unwrap().as_ptr();
    let accepted = owner
        .accept(prepared.generation.unwrap(), prepared.changed)
        .unwrap();
    assert_eq!(
        accepted.delta.changed.keys().next().unwrap().as_ptr(),
        collection_key
    );
    assert_eq!(
        accepted.delta.changed["docs"].first().unwrap().as_ptr(),
        row_key
    );
    assert!(
        accepted.owner.current().state.collections["docs"]
            .documents
            .is_empty()
    );
    assert_eq!(
        accepted.candidate().state.collections["docs"].documents["row"].version,
        2
    );
    locked(&fixture.engine);
    let mut publisher = Publisher {
        engine: &fixture.engine,
        previous: fixture.engine.generation().unwrap(),
        fail: false,
        calls: 0,
    };
    fixture
        .engine
        .publish_prepared_generation(
            accepted,
            kasumi_raft::AppliedResponse::application(vec![]),
            None,
            &mut publisher,
        )
        .unwrap();
    assert_eq!(publisher.calls, 1);
    assert_eq!(fixture.engine.generation().unwrap().state.revision, 2);
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
}

#[test]
fn accepted_apply_rejection_and_replay_discard_unaccepted_record_delta() {
    let fixture = Fixture::new();
    fixture.create(false);
    fixture.put(2, "original");
    for (revision, operation, success) in [
        (3, mutation("rejected", Precondition::Absent), false),
        (4, mutation("original", Precondition::Any), true),
    ] {
        let owner = fixture.lock();
        let prepared = fixture.prepare(&owner, revision, operation);
        assert_eq!(prepared.outcome.is_ok(), success);
        if success {
            assert_eq!(prepared.outcome.as_ref().unwrap().revision, 2);
        }
        assert!(prepared.changed.is_empty());
        let accepted = owner
            .accept(prepared.generation.unwrap(), prepared.changed)
            .unwrap();
        assert!(
            accepted.owner.current().state.collections["docs"]
                .documents
                .ptr_eq(&accepted.candidate().state.collections["docs"].documents)
        );
        accepted.publish();
    }
    assert_eq!(fixture.engine.generation().unwrap().state.revision, 4);
    assert_eq!(
        fixture.engine.generation().unwrap().state.collections["docs"].documents["row"].version,
        2
    );
}

#[test]
fn accepted_apply_definition_change_retains_actual_old_and_new_owners() {
    let fixture = Fixture::new();
    fixture.create(false);
    let owner = fixture.lock();
    let mut definition = owner.current().state.collections["docs"].definition.clone();
    definition.strict_read_audit = true;
    let prepared = fixture.prepare(&owner, 2, Operation::ReplaceCollection(definition));
    assert!(prepared.outcome.is_ok());
    assert!(prepared.changed.is_empty());
    let accepted = owner
        .accept(prepared.generation.unwrap(), prepared.changed)
        .unwrap();
    assert!(
        !accepted.owner.current().state.collections["docs"]
            .definition
            .strict_read_audit
    );
    assert!(
        accepted.candidate().state.collections["docs"]
            .definition
            .strict_read_audit
    );
    assert!(
        accepted.owner.current().state.collections["docs"]
            .documents
            .ptr_eq(&accepted.candidate().state.collections["docs"].documents)
    );
    drop(accepted);
    assert!(
        !fixture.engine.generation().unwrap().state.collections["docs"]
            .definition
            .strict_read_audit
    );
}

#[test]
fn accepted_apply_archive_placement_keeps_delta_without_advancing_data_epoch() {
    let fixture = Fixture::new();
    fixture.create(true);
    fixture
        .engine
        .apply_command(
            &fixture.disk,
            2,
            fixture.command(2, mutation("history", Precondition::Absent)),
        )
        .unwrap()
        .unwrap();
    let owner = fixture.lock();
    let state = &owner.current().state;
    let chunk = HistoryArchiveChunk {
        kind: HistoryArchiveKind::HistorySubset,
        archive_id: "archive".into(),
        source_incarnation: state.incarnation.clone(),
        collection: "docs".into(),
        index: 0,
        documents: vec![state.collections["docs"].documents["row"].clone()],
    };
    let (digest, bytes) = staged_digest(&chunk).unwrap();
    let request = PublishHistoryArchive {
        manifest: HistoryArchiveManifest {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id: "archive".into(),
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            collection: "docs".into(),
            cutoff_revision: 2,
            source_schema_epoch: state.schema_epoch,
            destination: "local".into(),
            document_count: 1,
            chunks: vec![ArchiveChunkDescriptor {
                object_id: uuid::Uuid::new_v4().to_string(),
                ciphertext_sha256: "12".repeat(32),
                plaintext_sha256: digest,
                plaintext_bytes: bytes,
                document_count: 1,
                first_id: "row".into(),
                last_id: "row".into(),
            }],
        },
        manifest_object_id: uuid::Uuid::new_v4().to_string(),
        manifest_ciphertext_sha256: "34".repeat(32),
        expected_policy_epoch: state.policy_epoch,
    };
    // Real ordered archive acceptance validates the manifest against actual
    // source rows. This fixture does not claim external archive availability.
    let prepared = fixture.prepare(&owner, 3, Operation::PublishHistoryArchive(request));
    assert!(prepared.outcome.is_ok(), "{:?}", prepared.outcome);
    assert_eq!(prepared.changed["docs"], BTreeSet::from(["row".into()]));
    let accepted = owner
        .accept(prepared.generation.unwrap(), prepared.changed)
        .unwrap();
    let old = &accepted.owner.current().state.collections["docs"];
    let new = &accepted.candidate().state.collections["docs"];
    assert_eq!(old.data_epoch, new.data_epoch);
    assert!(old.archived_documents.is_empty());
    assert!(new.documents.is_empty());
    assert_eq!(new.archived_documents["row"].version, 2);
    assert!(!accepted.delta.changed.is_empty());
}

#[test]
fn accepted_apply_missing_delta_and_scope_substitution_fail_before_publication() {
    for invalid in 0..3 {
        let fixture = Fixture::new();
        fixture.create(false);
        let previous = fixture.engine.generation().unwrap();
        let owner = fixture.lock();
        let mut prepared = fixture.prepare(&owner, 2, mutation("accepted", Precondition::Any));
        match invalid {
            0 => prepared.changed.clear(),
            1 => {
                Arc::get_mut(prepared.generation.as_mut().unwrap())
                    .unwrap()
                    .state
                    .incarnation = "foreign".into()
            }
            _ => {
                Arc::get_mut(prepared.generation.as_mut().unwrap())
                    .unwrap()
                    .state
                    .revision_base = 1
            }
        }
        assert!(
            owner
                .accept(prepared.generation.unwrap(), prepared.changed)
                .is_err()
        );
        assert!(Arc::ptr_eq(
            &previous,
            &fixture.engine.generation().unwrap()
        ));
        assert!(fixture.engine.apply_lock.try_lock().is_ok());
    }
}

#[test]
fn accepted_apply_exact_engine_and_position_required_and_failure_releases_guard() {
    let fixture = Fixture::new();
    fixture.create(false);
    let owner = fixture.lock();
    let prepared = fixture.prepare(&owner, 2, mutation("accepted", Precondition::Any));
    let accepted = owner
        .accept(prepared.generation.unwrap(), prepared.changed)
        .unwrap();
    let foreign = Fixture::new();
    assert!(accepted.require_publication(&foreign.engine, None).is_err());
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 3),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    assert!(
        accepted
            .require_publication(&fixture.engine, Some(&position))
            .is_err()
    );
    let previous = fixture.engine.generation().unwrap();
    let mut publisher = Publisher {
        engine: &fixture.engine,
        previous: previous.clone(),
        fail: true,
        calls: 0,
    };
    assert!(
        fixture
            .engine
            .publish_prepared_generation(
                accepted,
                kasumi_raft::AppliedResponse::application(vec![]),
                None,
                &mut publisher
            )
            .is_err()
    );
    assert_eq!(publisher.calls, 1);
    assert!(Arc::ptr_eq(
        &previous,
        &fixture.engine.generation().unwrap()
    ));
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
}
