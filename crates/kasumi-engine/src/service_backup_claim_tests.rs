// One actual Control journal for the exercised source. Keeping the handle alive
// and reopening its encrypted stores exercises the production claim path.
async fn backup_test_control(
    source: &Arc<Database>,
    context: &RequestContext,
    create: bool,
) -> std::result::Result<(Arc<Database>, RequestContext), crate::SnapshotFailure> {
    let node = source.store.node_store().clone();
    let tenant = crate::control::CONTROL_TENANT.to_owned();
    let keys = Arc::new(LocalKeyProvider::new([0x4a; 32]));
    let custody = Arc::new(LocalKeyProvider::new([0x4b; 32]));
    let access = kasumi_store::StorageAccess::node_control();
    let stores = if create {
        TenantStorageSet::initialize_catalogs(node, tenant, keys, custody, access).await?
    } else {
        TenantStorageSet::open_existing(node, tenant, keys, custody, access).await?
    };
    let mut operator = context.clone();
    operator.tenant = crate::control::CONTROL_TENANT.into();
    crate::test_utils::install_local_replica_audit_placement(stores.application())?;
    let control = crate::open_local_with_incarnation(
        stores,
        Policy {
            strict_read_audit: false,
            grants: vec![Grant {
                principal: operator.principal.clone(),
                collection: None,
                actions: operator.scopes.clone(),
            }],
        },
        Limits::default(),
        source.security_audit.clone(),
        uuid::Uuid::from_u128(444),
    )
    .await?;
    Ok((control, operator))
}

#[tokio::test]
async fn committed_control_claim_precedes_upload_and_recovers_an_unpublished_intent()
-> std::result::Result<(), crate::SnapshotFailure> {
    let fixture = CredentialFixture::new().await;
    let (control, operator) = backup_test_control(&fixture.db, &fixture.context, true).await?;
    fixture.db.install_backup_control(&control, &operator)?;
    let make_destination = |name| {
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("persistent").join(name),
            32 << 20,
            fixture.storage.persistent.clone(),
        )
    };
    let first = Arc::new(make_destination("original")?);
    let other = Arc::new(make_destination("different")?);
    fixture
        .db
        .install_archive_destination("first".into(), first.clone())?;
    fixture
        .db
        .install_archive_destination("second".into(), other.clone())?;
    // Stopped writes give a recovery capture a stable source. Administration
    // retains the right to take or abort that capture while the data is suspended.
    fixture
        .db
        .administer(fixture.context.clone(), Operation::Suspend(true))
        .await?;
    let state = fixture.db.engine.generation()?;
    let id = uuid::Uuid::new_v4();
    let intent = BackupSessionIntent {
        session_id: id,
        tenant: fixture.context.tenant.clone(),
        source_incarnation: state.incarnation().into(),
        revision: state.state.revision,
        principal: fixture.context.principal.clone(),
        request_id: fixture.context.request_id.clone(),
    };
    let bound = fixture
        .db
        .claim_backup_intent(
            &fixture.context,
            first.as_ref(),
            &intent,
            &state,
            Some("first"),
        )
        .await?;
    let retry = fixture
        .db
        .claim_backup_intent(
            &fixture.context,
            first.as_ref(),
            &intent,
            &state,
            Some("first"),
        )
        .await?;
    assert_eq!(bound.as_bytes(), retry.as_bytes());
    let record = fixture
        .db
        .backup_owner(&fixture.context, first.as_ref(), id)
        .await?
        .unwrap();
    assert_eq!(record.claim.intent_ciphertext, bound.as_bytes());
    assert_eq!(
        control.engine.generation()?.state.backup_binding_head.count,
        1
    );
    assert!(record.position.term > 0 && record.position.index > 0);
    let request = |alias: &str| BackupSessionRequest {
        destination: alias.into(),
        session_id: id,
    };
    assert_eq!(
        fixture
            .db
            .backup_session_status(fixture.context.clone(), request("second"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        other
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, 1)
            .await?
            .is_none()
    );
    assert_eq!(
        fixture
            .db
            .backup_session_status(fixture.context.clone(), request("first"))
            .await?
            .intent,
        intent
    );
    assert!(
        first
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, 1)
            .await?
            .is_none()
    );
    // Stop between the Control terminal commit and the remote outcome creation.
    // Competing aborts must recover the original randomized bytes.
    first.session_put(id, kasumi_store::BackupSessionSlot::Intent, bound.try_clone()?.into()).await?;
    let verified = fixture.db.backup_session(&fixture.context, first.as_ref(), id).await?.unwrap();
    let winner = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        session_id: id, principal: fixture.context.principal.clone(), reason: "first abort wins".into(),
    };
    let selected = fixture.db.select_backup_terminal(&fixture.context, first.as_ref(), &verified, &winner).await?;
    let loser = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        session_id: id, principal: fixture.context.principal.clone(), reason: "late contender".into(),
    };
    let retry = fixture.db.select_backup_terminal(&fixture.context, first.as_ref(), &verified, &loser).await?;
    assert_eq!(selected.as_bytes(), retry.as_bytes());
    assert_eq!(fixture.db.backup_session_status(fixture.context.clone(), request("first")).await?.outcome.as_ref(), Some(&winner));
    assert!(first.session_get(id, kasumi_store::BackupSessionSlot::Outcome, selected.len()).await?.is_none());
    let aborted = fixture
        .db
        .abort_backup_session(
            fixture.context.clone(),
            AbortBackupSession {
                destination: "first".into(),
                session_id: id,
                reason: "interrupted before first upload".into(),
            },
        )
        .await?;
    assert!(matches!(
        aborted.outcome,
        Some(BackupSessionOutcome::Aborted { .. })
    ));
    assert_eq!(
        first
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, bound.len())
            .await?
            .unwrap(),
        bound.as_bytes()
    );
    assert_eq!(aborted.outcome.as_ref(), Some(&winner));
    assert_eq!(first.session_get(id, kasumi_store::BackupSessionSlot::Outcome, selected.len()).await?.unwrap(), selected.as_bytes());
    control.group.snapshot().await?;
    control.shutdown().await?;
    drop(control);
    let (reopened, _) = backup_test_control(&fixture.db, &fixture.context, false).await?;
    let durable = reopened
        .engine
        .generation()?
        .backup_bindings
        .get(id)?
        .unwrap()
        .record;
    assert_eq!(durable, record);
    let decided = reopened.engine.generation()?.backup_bindings.terminal(id)?.unwrap();
    assert_eq!(decided.record, record);
    let terminal = decided.terminal.unwrap();
    assert_eq!(terminal.outcome, winner);
    assert_eq!(terminal.ciphertext, selected.as_bytes());
    reopened.shutdown().await?;
    fixture.close().await;
    Ok(())
}
