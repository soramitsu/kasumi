async fn retirement_input(
    fixture: &CredentialFixture,
    id: &str,
    deadline: u64,
) -> PreparedRetirement {
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("persistent").join(id),
            16 << 20,
            fixture.storage.persistent.clone(),
        )
        .unwrap(),
    );
    fixture
        .db
        .install_archive_destination(id.into(), destination.clone())
        .unwrap();
    let checkpoint = fixture
        .db
        .backup_checkpoint(
            fixture.context.clone(),
            destination.as_ref(),
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap();
    let request = RetireSourceRequest {
        retirement_id: id.into(),
        expected_source_incarnation: checkpoint.source_incarnation().into(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: checkpoint.checkpoint().clone(),
        destination: id.into(),
        not_after_ms: deadline,
    };
    let verified_closure_digest = fixture
        .db
        .verified_retirement_closure(
            &fixture.context,
            destination.as_ref(),
            request.checkpoint.clone(),
        )
        .await
        .unwrap();
    PreparedRetirement {
        request,
        verified_closure_digest,
        observation: None,
    }
}

#[tokio::test]
async fn queued_retirement_uses_trusted_admission_deadline_and_cancellation_keeps_exact_outcome() {
    for (cancel, expired) in [(false, true), (true, true), (true, false)] {
        let fixture = CredentialFixture::new().await;
        let clock = Arc::new(ControlledCommandClock(std::sync::atomic::AtomicU64::new(
            1000,
        )));
        *fixture.db.command_clock.lock().unwrap() = clock.clone();
        let prepared = retirement_input(&fixture, "queued-retirement", 1000).await;
        let reference = prepared.request.reference().unwrap();
        let gate = fixture.db.proposal_gate.lock().await;
        let mut pending = Box::pin(
            fixture
                .db
                .submit(fixture.context.clone(), Operation::RetireSource(prepared)),
        );
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        if expired {
            clock.0.store(1001, Ordering::SeqCst);
        }
        if cancel {
            drop(pending);
            drop(gate);
            fixture.db.work.drain().await;
        } else {
            drop(gate);
            assert_eq!(pending.await.unwrap_err().code, ErrorCode::Conflict);
        }
        let status = fixture
            .db
            .retirement_status(&fixture.context, &reference)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.outcome.is_err(), expired);
        assert_eq!(
            fixture.db.engine.generation().unwrap().state.retired,
            !expired
        );
        if !expired {
            clock.0.store(10_000, Ordering::SeqCst);
            let proof = fixture
                .db
                .verify_retirement_receipt(fixture.context.clone(), &reference)
                .await
                .unwrap();
            assert_eq!(proof.receipt().admitted_at_ms, 1000);
        }
        fixture.close().await;
    }
}

#[tokio::test]
async fn queued_expired_credential_cannot_accept_retirement_or_its_id() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "credential-retirement", u64::MAX).await;
    let reference = prepared.request.reference().unwrap();
    let clock = Arc::new(CredentialClock(std::sync::atomic::AtomicU64::new(0)));
    let context = fixture.credential(clock.clone());
    let gate = fixture.db.proposal_gate.lock().await;
    let mut pending = Box::pin(
        fixture
            .db
            .submit(context, Operation::RetireSource(prepared)),
    );
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    clock.0.store(1000, Ordering::SeqCst);
    drop(pending);
    drop(gate);
    fixture.db.work.drain().await;
    assert!(
        fixture
            .db
            .retirement_status(&fixture.context, &reference)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!fixture.db.engine.generation().unwrap().state.retired);
    fixture.close().await;
}

struct RetirementObservedClock(std::sync::Weak<TenantEngine>);
impl LeaseClock for RetirementObservedClock {
    fn now(&self) -> Duration {
        let retired = self
            .0
            .upgrade()
            .and_then(|engine| engine.generation().ok())
            .is_some_and(|generation| generation.state.retired);
        Duration::from_millis(if retired { 1000 } else { 0 })
    }
}
#[tokio::test]
async fn committed_retirement_with_expired_reply_has_fresh_authorized_receipt_recovery() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "uncertain-retirement", u64::MAX).await;
    let reference = prepared.request.reference().unwrap();
    // Pair admission and credential clocks: this test advances time only when
    // retirement commits, irrespective of historical backup verification work.
    struct FrozenWall(u64);
    impl kasumi_clock::WallClock for FrozenWall {
        fn now_ms(&self) -> anyhow::Result<u64> {
            Ok(self.0)
        }
    }
    let epoch = Arc::new(
        kasumi_clock::EpochClock::new(
            Arc::new(RetirementObservedClock(Arc::downgrade(&fixture.db.engine))),
            Arc::new(FrozenWall(now_ms().unwrap())),
        )
        .unwrap(),
    );
    *fixture.db.command_clock.lock().unwrap() = Arc::new(FixtureCommandClock(epoch.clone()));
    let observation = epoch.observe().unwrap();
    let credential = RequestContext {
        authorization: RequestAuthorization::from_verified_credential(
            observation.utc_ms() + 1000,
            &observation,
            CredentialResource::Database {
                incarnation: uuid::Uuid::parse_str(
                    &fixture.db.engine.generation().unwrap().state.incarnation,
                )
                .unwrap(),
            },
        )
        .unwrap(),
        ..fixture.context.clone()
    };
    assert_eq!(
        fixture
            .db
            .retire_source(credential.clone(), prepared.request)
            .await
            .unwrap_err()
            .operation_error()
            .expect("actual retirement operation outcome")
            .code,
        ErrorCode::UnknownOutcome
    );
    assert_eq!(
        fixture
            .db
            .verify_retirement_receipt(credential, &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
    let proof = fixture
        .db
        .verify_retirement_receipt(fixture.context.clone(), &reference)
        .await
        .unwrap();
    assert_eq!(proof.receipt().retirement_id, "uncertain-retirement");
    assert_eq!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .retirements
            .len(),
        1
    );
    fixture.close().await;
}

#[tokio::test]
async fn generic_administration_cannot_inject_a_claimed_retirement_preparation() {
    let fixture = CredentialFixture::new().await;
    let prepared = retirement_input(&fixture, "forged-preparation", u64::MAX).await;
    for operation in [
        Operation::RetireSource(prepared.clone()),
        Operation::AbortRetirement(prepared.request),
    ] {
        assert_eq!(
            fixture
                .db
                .administer(fixture.context.clone(), operation)
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    assert!(
        fixture
            .db
            .engine
            .generation()
            .unwrap()
            .state
            .retirements
            .is_empty()
    );
    fixture.close().await;
}

#[tokio::test]
async fn authenticated_retirement_keeps_exact_document_and_snapshot_reads() {
    let fixture = CredentialFixture::new().await;
    let body = json!({"proof": "ab".repeat(8192), "value": 7});
    let mut batch = credential_batch("retained-proof");
    let Mutation::Put {
        body: stored_body, ..
    } = &mut batch.operations[0]
    else {
        unreachable!();
    };
    *stored_body = body.clone();
    fixture
        .db
        .mutate(fixture.context.clone(), batch)
        .await
        .unwrap();
    let before = fixture.db.engine.generation().unwrap();
    assert!(matches!(
        before.state.collections["docs"].documents["retained-proof"].as_ref(),
        kasumi_types::DocumentSlot::Stored(_)
    ));
    let prepared = retirement_input(&fixture, "retained-documents", u64::MAX).await;
    fixture
        .db
        .submit(fixture.context.clone(), Operation::RetireSource(prepared))
        .await
        .unwrap();
    let retired = fixture.db.engine.generation().unwrap();
    assert!(retired.state.retired);
    let selected = retired
        .application_selection
        .get()
        .expect("actual frozen selection");
    {
        let authority = fixture.db.engine.lock_primary_apply().unwrap();
        assert!(
            selected.open_primary_reader(authority.roots()).is_err(),
            "retirement must not permit primary publication readers"
        );
        let documents = selected.open_document_reader(authority.roots()).unwrap();
        documents.check_access().unwrap();
        documents.close().unwrap();
    }
    let retained = retired.state.collections["docs"].documents["retained-proof"]
        .load_owned(retired.document_resolver())
        .unwrap();
    assert_eq!(retained.body, body);
    assert_eq!(
        retained.version,
        before.state.collections["docs"].documents["retained-proof"].version()
    );
    drop(retained);
    let mut documents = 0;
    for record in crate::snapshot_codec::records_with_resolver(
        &retired.state,
        3,
        None,
        retired.document_resolver(),
    )
    .unwrap()
    {
        if let crate::snapshot_codec::Record::Document(collection, document) = record.unwrap() {
            assert_eq!(collection, "docs");
            assert_eq!(document.id, "retained-proof");
            assert_eq!(document.body, body);
            documents += 1;
        }
    }
    assert_eq!(documents, 1);
    let image = fixture
        .db
        .engine
        .logical_snapshot(&fixture.storage.scratch)
        .unwrap();
    drop(image);
    drop(before);
    drop(retired);
    fixture.close().await;
}

#[tokio::test]
async fn verified_restore_rekeys_compact_bodies_before_target_source_installation() {
    let fixture = CredentialFixture::new().await;
    let body = json!({"proof": "cd".repeat(8192), "value": 11});
    let mut batch = credential_batch("restored-proof");
    let Mutation::Put { body: value, .. } = &mut batch.operations[0] else {
        unreachable!();
    };
    *value = body.clone();
    fixture
        .db
        .mutate(fixture.context.clone(), batch)
        .await
        .unwrap();
    let source = fixture.db.engine.generation().unwrap();
    let source_image = fixture
        .db
        .engine
        .logical_snapshot(&fixture.storage.scratch)
        .unwrap();
    let checkpoint = FullBackupCheckpoint {
        tenant: source.state.tenant.clone(),
        source_incarnation: source.state.incarnation.clone(),
        revision: source.state.revision,
        resident_sha256: source_image.sha256().into(),
        backup_id: uuid::Uuid::new_v4(),
        manifest_ciphertext_sha256: "12".repeat(32),
        key_lineage_digest: "34".repeat(32),
    };
    let validated = crate::state::snapshot_validation::ValidatedApplicationSnapshot::validate(
        source_image,
        128 << 20,
        || Ok(()),
    )
    .unwrap();
    let target_incarnation = uuid::Uuid::new_v4().to_string();
    let (target_image, target_engine) = TenantEngine::materialize_verified_restore(
        validated,
        &fixture.context.tenant,
        target_incarnation.clone(),
        checkpoint,
        None,
        || Ok(()),
    )
    .unwrap();
    let target_engine = Arc::new(target_engine);
    let before_install = target_engine.generation().unwrap();
    assert_eq!(before_install.state.incarnation, target_incarnation);
    assert!(matches!(
        before_install.state.collections["docs"].documents["restored-proof"].as_ref(),
        DocumentSlot::Stored(_)
    ));
    assert_eq!(
        before_install.state.collections["docs"].documents["restored-proof"]
            .load_owned(before_install.document_resolver())
            .unwrap()
            .body,
        body
    );
    drop(before_install);

    let node = fixture
        .storage
        .create_new(
            fixture
                ._directory
                .path()
                .join("persistent/restored-documents.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let stores = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        fixture.context.tenant.clone(),
        Arc::new(LocalKeyProvider::new([121; 32])),
        Arc::new(LocalKeyProvider::new([122; 32])),
    )
    .await
    .unwrap();
    let group = format!("{}/{}", fixture.context.tenant, target_incarnation);
    crate::bootstrap::persist_fixture_bootstrap(&stores, &target_image, 1, &group).unwrap();
    crate::test_utils::install_fixture_audit_placement(stores.application()).unwrap();
    target_engine
        .install_storage_access(stores.application())
        .unwrap();
    let restored =
        super::construction::DatabaseConstruction::new(stores.clone(), fixture.audit.clone())
            .unwrap()
            .start_local(target_engine.clone(), &target_image, 1, group)
            .await
            .unwrap();
    let installed = target_engine.generation().unwrap();
    let document = installed.state.collections["docs"].documents["restored-proof"]
        .load_owned(installed.document_resolver())
        .unwrap();
    assert_eq!(document.body, body);
    assert_eq!(
        document.version,
        source.state.collections["docs"].documents["restored-proof"].version()
    );
    assert!(
        installed
            .state
            .change_feed
            .commits
            .values()
            .flat_map(|commit| &commit.records)
            .filter_map(|record| record.document.as_ref())
            .all(|slot| matches!(slot.as_ref(), DocumentSlot::Stored(_)))
    );
    drop(document);
    drop(installed);
    drop(source);
    drop(target_image);
    restored.shutdown().await.unwrap();
    drop(restored);
    drop(target_engine);
    stores.custody().store().shutdown().await.unwrap();
    stores.application().shutdown().await.unwrap();
    drop(stores);
    node.shutdown().await.unwrap();
    drop(node);
    fixture.close().await;
}
