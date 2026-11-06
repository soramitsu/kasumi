fn grouped_put(key: &str, id: &str) -> MutationBatch {
    MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"id": id}),
            expected: Precondition::Absent,
        }],
    }
}

async fn queued_group(
    fixture: &CredentialFixture,
    batches: Vec<MutationBatch>,
    cancel: Option<usize>,
) -> Vec<Result<WriteReceipt>> {
    let proposals = batches
        .into_iter()
        .map(|batch| (fixture.context.clone(), batch))
        .collect();
    queued_group_contexts(fixture, proposals, cancel).await
}

async fn queued_group_contexts(
    fixture: &CredentialFixture,
    proposals: Vec<(RequestContext, MutationBatch)>,
    cancel: Option<usize>,
) -> Vec<Result<WriteReceipt>> {
    let gate = fixture.db.proposal_gate.lock().await;
    let mut tasks = Vec::new();
    for (context, batch) in proposals {
        let db = fixture.db.clone();
        tasks.push(tokio::spawn(async move { db.mutate(context, batch).await }));
        let expected = tasks.len();
        tokio::time::timeout(Duration::from_secs(5), async {
            while fixture.db.proposals.queued_for_test() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    if let Some(index) = cancel {
        tasks[index].abort();
    }
    drop(gate);
    let mut responses = Vec::new();
    for (index, task) in tasks.into_iter().enumerate() {
        match task.await {
            Err(error) if cancel == Some(index) => assert!(error.is_cancelled()),
            response => responses.push(response.unwrap()),
        }
    }
    // A cancelled public caller still has its real proposal worker and write.
    fixture.db.work.drain().await;
    responses
}

#[tokio::test]
async fn standalone_group_commit_keeps_member_receipts_and_rejections_independent() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), grouped_put("seed", "exists"))
        .await
        .unwrap();
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let first = grouped_put("first", "a");
    let second = grouped_put("second", "b");
    let refused = grouped_put("conflict", "exists");
    let responses =
        queued_group(&fixture, vec![first.clone(), second.clone(), refused], None).await;
    assert!(responses[0].is_ok());
    assert!(responses[1].is_ok());
    assert_eq!(responses[2].as_ref().unwrap_err().code, ErrorCode::Conflict);
    let after = fixture.db.group.fixture_local_joined_appends().unwrap();
    assert_eq!(after.groups, before.groups + 1);
    assert_eq!(after.applied, before.applied + 3);
    assert!(responses[0].as_ref().unwrap().revision < responses[1].as_ref().unwrap().revision);
    assert_eq!(
        fixture.db.mutate(fixture.context.clone(), first).await,
        responses[0]
    );
    assert_eq!(
        fixture.db.mutate(fixture.context.clone(), second).await,
        responses[1]
    );
    for (key, expected) in ["first", "second", "conflict"].into_iter().zip(responses) {
        assert_eq!(
            fixture
                .db
                .operation_receipt(&fixture.context, key)
                .await
                .unwrap()
                .unwrap()
                .outcome,
            expected
        );
    }
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        3
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_finishes_after_a_member_caller_is_cancelled() {
    let fixture = CredentialFixture::new().await;
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let responses = queued_group(
        &fixture,
        vec![grouped_put("cancelled", "a"), grouped_put("live", "b")],
        Some(0),
    )
    .await;
    assert_eq!(responses.len(), 1);
    assert!(responses[0].is_ok());
    let after = fixture.db.group.fixture_local_joined_appends().unwrap();
    assert_eq!(after.groups, before.groups + 1);
    assert_eq!(after.applied, before.applied + 2);
    assert!(
        fixture
            .db
            .get(&fixture.context, "docs", "a")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        fixture
            .db
            .operation_receipt(&fixture.context, "cancelled")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .is_ok()
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_disk_refusal_leaves_all_members_unwritten() {
    use crate::application_sources::completion::{CompletionCheckpoint, CompletionFault};
    let fixture = CredentialFixture::new().await;
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let revision = fixture.db.engine.generation().unwrap().state.revision;
    fixture
        .db
        .engine
        .application_sources_for_test()
        .unwrap()
        .arm_completion_fault_for_test(
            CompletionCheckpoint::Queued,
            CompletionFault::Window(Box::new(|| {
                kasumi_store::NodeDisk::fixture_refuse_transactions_on_this_thread(1);
            })),
        );
    let responses = queued_group(
        &fixture,
        vec![grouped_put("refused-a", "a"), grouped_put("refused-b", "b")],
        None,
    )
    .await;
    assert!(
        responses
            .iter()
            .all(|response| response.as_ref().unwrap_err().code == ErrorCode::ResourceExhausted)
    );
    let after = fixture.db.group.fixture_local_joined_appends().unwrap();
    assert_eq!(after.applied, before.applied);
    assert_eq!(after.refused_publication, before.refused_publication + 2);
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.revision,
        revision
    );
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        0
    );
    for key in ["refused-a", "refused-b"] {
        assert!(
            fixture
                .db
                .operation_receipt(&fixture.context, key)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(fixture.db.serving_failure_class(), None);
    let retried = queued_group(
        &fixture,
        vec![grouped_put("refused-a", "a"), grouped_put("refused-b", "b")],
        None,
    )
    .await;
    assert!(retried.iter().all(Result::is_ok));
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        2
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_validates_dependencies_against_prior_members() {
    let fixture = CredentialFixture::new().await;
    let mut dependent = grouped_put("dependent", "b");
    dependent.read_set.push(ReadAssertion::Document {
        collection: "docs".into(),
        id: "a".into(),
        expected: ReadPrecondition::Absent,
    });
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let responses = queued_group(
        &fixture,
        vec![
            grouped_put("first", "a"),
            dependent,
            grouped_put("last", "c"),
        ],
        None,
    )
    .await;
    assert!(responses[0].is_ok());
    assert_eq!(responses[1].as_ref().unwrap_err().code, ErrorCode::Conflict);
    assert!(responses[2].is_ok());
    assert_eq!(
        fixture
            .db
            .group
            .fixture_local_joined_appends()
            .unwrap()
            .groups,
        before.groups + 1
    );
    assert!(
        fixture
            .db
            .get(&fixture.context, "docs", "b")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        2
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_duplicate_identity_starts_a_new_prefix() {
    let fixture = CredentialFixture::new().await;
    let first = grouped_put("same-key", "a");
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let responses = queued_group(
        &fixture,
        vec![
            first.clone(),
            first,
            grouped_put("same-key", "b"),
            grouped_put("different-key", "c"),
        ],
        None,
    )
    .await;
    assert_eq!(responses[0], responses[1]);
    assert_eq!(responses[2].as_ref().unwrap_err().code, ErrorCode::Conflict);
    assert!(responses[3].is_ok());
    let after = fixture.db.group.fixture_local_joined_appends().unwrap();
    assert_eq!(after.groups, before.groups + 1);
    assert_eq!(after.applied, before.applied + 4);
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        2
    );
    assert_eq!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        2
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_validates_unique_indexes_against_prior_members() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "unique".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: json!({"type":"object"}),
                indexes: vec![IndexDefinition {
                    name: "value".into(),
                    fields: vec![IndexField {
                        path: "/value".into(),
                        kind: ScalarType::String,
                    }],
                    unique: true,
                    text: None,
                }],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let batches = ["a", "b"].map(|id| MutationBatch {
        idempotency_key: id.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "unique".into(),
            id: id.into(),
            body: json!({"value":"same"}),
            expected: Precondition::Absent,
        }],
    });
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let responses = queued_group(&fixture, batches.into(), None).await;
    assert!(responses[0].is_ok());
    assert_eq!(responses[1].as_ref().unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(
        fixture
            .db
            .group
            .fixture_local_joined_appends()
            .unwrap()
            .groups,
        before.groups + 1
    );
    assert_eq!(
        fixture.db.engine.generation().unwrap().state.document_count,
        1
    );
    fixture.close().await;
}

fn group_feed_bytes(generation: &crate::Generation) -> Vec<u8> {
    let feed = &generation.state.change_feed;
    let commits = feed
        .commits
        .iter()
        .map(|(sequence, commit)| {
            let records = commit
                .records
                .iter()
                .map(|record| {
                    crate::snapshot_codec::WireChangeRecord::from_record(
                        record,
                        generation.document_resolver(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            (
                *sequence,
                commit.revision,
                commit.first_sequence,
                commit.record_bytes,
                records,
            )
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&(
        feed.next_sequence,
        feed.event_count,
        feed.encoded_commit_bytes,
        commits,
    ))
    .unwrap()
}

#[tokio::test]
async fn standalone_group_commit_replays_individual_journal_entries_after_physical_reopen() {
    let fixture = CredentialFixture::new().await;
    // Leave the recovery snapshot before the group, forcing normal journal
    // replay to reconstruct each member from its own original command bytes.
    fixture.db.group.snapshot().await.unwrap();
    let policy = fixture
        .db
        .engine
        .generation()
        .unwrap()
        .state
        .policy
        .as_ref()
        .clone();
    let first = grouped_put("recover-a", "a");
    let second = grouped_put("recover-b", "b");
    let mut refused = grouped_put("recover-refused", "c");
    refused.read_set.push(ReadAssertion::Document {
        collection: "docs".into(),
        id: "a".into(),
        expected: ReadPrecondition::Absent,
    });
    let responses =
        queued_group(&fixture, vec![first.clone(), second.clone(), refused], None).await;
    assert!(responses[0].is_ok());
    assert!(responses[1].is_ok());
    assert_eq!(
        responses[1].as_ref().unwrap().revision,
        responses[0].as_ref().unwrap().revision + 1
    );
    assert_eq!(responses[2].as_ref().unwrap_err().code, ErrorCode::Conflict);
    let selected = fixture.db.engine.generation().unwrap();
    let revision = selected.state.revision;
    let receipt_head = selected.state.mutation_receipt_head.clone();
    let feed = group_feed_bytes(&selected);
    drop(selected);
    let fixture = reopen_group_fixture(fixture, policy, false).await;
    let db = &fixture.db;
    let context = &fixture.context;
    let selected = db.engine.generation().unwrap();
    assert_eq!(selected.state.revision, revision);
    assert_eq!(selected.state.document_count, 2);
    assert_eq!(selected.state.mutation_receipt_head, receipt_head);
    assert_eq!(group_feed_bytes(&selected), feed);
    drop(selected);
    for (key, expected) in ["recover-a", "recover-b", "recover-refused"]
        .into_iter()
        .zip(&responses)
    {
        assert_eq!(
            &db.operation_receipt(context, key)
                .await
                .unwrap()
                .unwrap()
                .outcome,
            expected
        );
    }
    assert_eq!(db.mutate(context.clone(), first).await, responses[0]);
    assert_eq!(db.mutate(context.clone(), second).await, responses[1]);
    assert!(db.get(context, "docs", "a").await.unwrap().is_some());
    assert!(db.get(context, "docs", "b").await.unwrap().is_some());
    assert!(db.get(context, "docs", "c").await.unwrap().is_none());
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_scopes_same_keys_to_their_original_principals() {
    let fixture = CredentialFixture::new().await;
    let mut policy = fixture
        .db
        .engine
        .generation()
        .unwrap()
        .state
        .policy
        .as_ref()
        .clone();
    policy.grants.push(Grant {
        principal: "second-owner".into(),
        collection: None,
        actions: fixture.context.scopes.clone(),
    });
    fixture
        .db
        .administer(fixture.context.clone(), Operation::SetPolicy(policy))
        .await
        .unwrap();
    let second = RequestContext {
        principal: "second-owner".into(),
        ..fixture.context.clone()
    };
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    let responses = queued_group_contexts(
        &fixture,
        vec![
            (fixture.context.clone(), grouped_put("same-key", "a")),
            (second.clone(), grouped_put("same-key", "b")),
        ],
        None,
    )
    .await;
    assert!(responses.iter().all(Result::is_ok));
    assert_ne!(responses[0], responses[1]);
    assert_eq!(
        fixture
            .db
            .group
            .fixture_local_joined_appends()
            .unwrap()
            .groups,
        before.groups + 1
    );
    for (context, expected) in [&fixture.context, &second].into_iter().zip(responses) {
        assert_eq!(
            fixture
                .db
                .operation_receipt(context, "same-key")
                .await
                .unwrap()
                .unwrap()
                .outcome,
            expected
        );
    }
    fixture.close().await;
}

async fn reopen_group_fixture(
    fixture: CredentialFixture,
    policy: Policy,
    uncertain: bool,
) -> CredentialFixture {
    let shutdown = fixture.db.shutdown().await;
    if uncertain {
        assert!(
            shutdown.is_err(),
            "uncertain writer must retain its original failure"
        );
    } else {
        shutdown.unwrap();
    }
    fixture.audit.shutdown().await.unwrap();
    fixture.node.shutdown().await.unwrap();
    let CredentialFixture {
        storage,
        node,
        db,
        audit,
        context,
        _directory,
    } = fixture;
    drop(db);
    drop(audit);
    drop(node);
    let node = storage
        .open_existing(
            _directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let provider = Arc::new(LocalKeyProvider::new([0x97; 32]));
    let stores = kasumi_store::TenantStorageSet::open_existing_fixture(
        node.clone(),
        context.tenant.clone(),
        provider.clone(),
        Arc::new(LocalKeyProvider::new([241; 32])),
    )
    .await
    .unwrap();
    let audit_store =
        TenantStore::open_existing_fixture(node.clone(), crate::SECURITY_TENANT.into(), provider)
            .await
            .unwrap();
    let audit =
        SecurityAudit::open(audit_store, Default::default(), storage.admission.clone()).unwrap();
    let db = crate::test_utils::open_fixture(stores, policy, Limits::default(), audit.clone())
        .await
        .unwrap();
    CredentialFixture {
        storage,
        node,
        db,
        audit,
        context,
        _directory,
    }
}

#[tokio::test]
async fn standalone_group_commit_postcommit_access_loss_recovers_every_member() {
    use crate::application_sources::completion::{CompletionCheckpoint, CompletionFault};
    let fixture = CredentialFixture::new().await;
    fixture.db.group.snapshot().await.unwrap();
    let policy = fixture
        .db
        .engine
        .generation()
        .unwrap()
        .state
        .policy
        .as_ref()
        .clone();
    let application = fixture.db.stores.application().clone();
    fixture
        .db
        .engine
        .application_sources_for_test()
        .unwrap()
        .arm_completion_fault_for_test(
            CompletionCheckpoint::Published,
            CompletionFault::Window(Box::new(move || application.seal())),
        );
    let first = grouped_put("uncertain-a", "a");
    let second = grouped_put("uncertain-b", "b");
    let responses = queued_group(&fixture, vec![first.clone(), second.clone()], None).await;
    assert!(
        responses
            .iter()
            .all(|response| response.as_ref().unwrap_err().code == ErrorCode::UnknownOutcome)
    );
    assert!(fixture.db.serving_failure_class().is_some());
    assert!(
        fixture
            .db
            .mutate(fixture.context.clone(), grouped_put("fenced", "c"))
            .await
            .is_err()
    );
    let fixture = reopen_group_fixture(fixture, policy, true).await;
    let selected = fixture.db.engine.generation().unwrap();
    assert_eq!(selected.state.document_count, 2);
    assert_eq!(selected.state.mutation_receipt_head.count, 2);
    drop(selected);
    let first_receipt = fixture
        .db
        .operation_receipt(&fixture.context, "uncertain-a")
        .await
        .unwrap()
        .unwrap()
        .outcome
        .unwrap();
    let second_receipt = fixture
        .db
        .operation_receipt(&fixture.context, "uncertain-b")
        .await
        .unwrap()
        .unwrap()
        .outcome
        .unwrap();
    assert_eq!(second_receipt.revision, first_receipt.revision + 1);
    assert_eq!(
        fixture
            .db
            .mutate(fixture.context.clone(), first)
            .await
            .unwrap(),
        first_receipt
    );
    assert_eq!(
        fixture
            .db
            .mutate(fixture.context.clone(), second)
            .await
            .unwrap(),
        second_receipt
    );
    assert!(
        fixture
            .db
            .get(&fixture.context, "docs", "c")
            .await
            .unwrap()
            .is_none()
    );
    fixture.close().await;
}

#[tokio::test]
async fn standalone_group_commit_releases_followers_before_unrelated_queued_work() {
    let fixture = CredentialFixture::new().await;
    let gate = fixture.db.proposal_gate.lock().await;
    let db = fixture.db.clone();
    let context = fixture.context.clone();
    let first = tokio::spawn(async move { db.mutate(context, grouped_put("first", "a")).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.db.proposals.queued_for_test() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Place another gate owner after the driver but before the follower. The
    // driver will collect both original requests in its one group. Its result
    // must reach the follower while this unrelated owner still holds the gate.
    let (queued, queued_wait) = tokio::sync::oneshot::channel();
    let (held, held_wait) = tokio::sync::oneshot::channel();
    let (release, release_wait) = tokio::sync::oneshot::channel();
    let blocker_gate = fixture.db.proposal_gate.clone();
    let blocker = tokio::spawn(async move {
        let waiting = blocker_gate.lock_owned();
        tokio::pin!(waiting);
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        queued.send(()).unwrap();
        let _guard = waiting.await;
        held.send(()).unwrap();
        release_wait.await.unwrap();
    });
    queued_wait.await.unwrap();
    let db = fixture.db.clone();
    let context = fixture.context.clone();
    let mut second =
        tokio::spawn(async move { db.mutate(context, grouped_put("second", "b")).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.db.proposals.queued_for_test() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = fixture.db.group.fixture_local_joined_appends().unwrap();
    drop(gate);
    held_wait.await.unwrap();
    first.await.unwrap().unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(2), &mut second).await;
    release.send(()).unwrap();
    blocker.await.unwrap();
    let completed_without_gate = completed.is_ok();
    match completed {
        Ok(result) => {
            result.unwrap().unwrap();
        }
        Err(_) => {
            second.await.unwrap().unwrap();
        }
    }
    assert_eq!(
        fixture
            .db
            .group
            .fixture_local_joined_appends()
            .unwrap()
            .groups,
        before.groups + 1
    );
    fixture.close().await;
    assert!(
        completed_without_gate,
        "completed follower waited for unrelated gate owner"
    );
}

#[tokio::test]
async fn standalone_group_commit_driver_keeps_progress_when_gate_order_differs_from_queue_order() {
    let fixture = CredentialFixture::new().await;
    let release_first = fixture.db.proposals.pause_next_before_gate_for_test();
    let db = fixture.db.clone();
    let context = fixture.context.clone();
    let first = tokio::spawn(async move { db.mutate(context, grouped_put("first", "same")).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.db.proposals.queued_for_test() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let db = fixture.db.clone();
    let context = fixture.context.clone();
    let mut second =
        tokio::spawn(async move { db.mutate(context, grouped_put("second", "same")).await });
    // The second worker wins the gate and drives only the first queued command:
    // their overlapping target prevents one group. Once the first caller can
    // take its ready response, the second must continue driving its own entry.
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    release_first.send(()).unwrap();
    first.await.unwrap().unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(2), &mut second).await;
    let made_progress = completed.is_ok();
    let response = match completed {
        Ok(result) => result.unwrap(),
        Err(_) => {
            // Retire the real queued request even when testing the old stuck
            // driver, so the regression does not leave fixture-owned work.
            fixture
                .db
                .mutate(fixture.context.clone(), grouped_put("rescue", "other"))
                .await
                .unwrap();
            second.await.unwrap()
        }
    };
    assert_eq!(response.unwrap_err().code, ErrorCode::Conflict);
    fixture.close().await;
    assert!(
        made_progress,
        "queued original required an unrelated caller to drive it"
    );
}
